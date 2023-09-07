"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

python3 CLI utility for interacting with Network Elements using gNMI.

This utility can be utilized as a reference, or standalone utility, for
interacting with Network Elements which support OpenConfig and gNMI.

Current supported gNMI features:
- GetRequest
- SetRequest (Update, Replace, Delete)
- Target hostname override
- Auto-loads Target cert from Target if not specified
- User/password based authentication
- Certifificate based authentication
- Subscribe request
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import argparse
import json
import logging
import os
import re
import ssl
import sys
import string
import six
import datetime
try:
  import gnmi_pb2
except ImportError:
  print('ERROR: Ensure you\'ve installed dependencies from requirements.txt\n'
        'eg, pip install -r requirements.txt')
import gnmi_pb2_grpc
import grpc

__version__ = '0.5'

_RE_PATH_COMPONENT = re.compile(r'''
^
(?P<pname>[^[]+)  # gNMI path name
(\[(?P<key>\w+)   # gNMI path key
=
(?P<value>.*)    # gNMI path value
\])?$
''', re.VERBOSE)
INVALID_GNMI_CLIENT_CONNECTION_NUMBER = 1
GNMI_SERVER_UNAVAILABLE = 2

class Error(Exception):
  """Module-level Exception class."""


class XpathError(Error):
  """Error parsing xpath provided."""


class ValError(Error):
  """Error parsing provided val from CLI."""


class JsonReadError(Error):
  """Error parsing provided JSON file."""


class FindTypeError(Error):
  """Error identifying type of provided value."""


def _create_parser():
  """Create parser for arguments passed into the program from the CLI.

  Returns:
    Argparse object.
  """
  parser = argparse.ArgumentParser(description='gNMI CLI utility.')
  parser = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExample'
      ' GetRequest without user/password and over-riding Target certificate CN:'
      '\npython py_gnmicli.py -t 127.0.0.1 -p 8080 -x \'/access-points/'
      'access-point[hostname=test-ap]/\' -rcert ~/certs/target-cert.crt -o '
      'openconfig.example.com')
  parser.add_argument('-t', '--target', type=str, help='The gNMI Target',
                      required=True)
  parser.add_argument('-p', '--port', type=str, help='The port the gNMI Target '
                      'is listening on', required=True)
  parser.add_argument('-user', '--username', type=str, help='Username to use'
                      'when establishing a gNMI Channel to the Target',
                      required=False)
  parser.add_argument('-pass', '--password', type=str, help='Password to use'
                      'when establishing a gNMI Channel to the Target',
                      required=False)
  parser.add_argument('-m', '--mode', choices=[
      'get', 'set-update', 'set-replace', 'set-delete', 'subscribe'], help=
                      'Mode of operation when interacting with network element.'
                      ' Default=get. If set, it can be either value \nor JSON '
                      'file (prepend filename with "@")', default='get')
  parser.add_argument('-val', '--value', type=str, help='Value for SetRequest.'
                      '\nCan be Leaf value or JSON file. If JSON file, prepend'
                      ' with "@"; eg "@interfaces.json".'
                      '\n If empty value for delete operation, use "".',
                      nargs="+", required=False)
  parser.add_argument('--proto', type=str, help='Output files for proto bytes',
                      nargs="*", required=False)
  parser.add_argument('-pkey', '--private_key', type=str, help='Fully'
                      'quallified path to Private key to use when establishing'
                      'a gNMI Channel to the Target', required=False)
  parser.add_argument('-rcert', '--root_cert', type=str, help='Fully quallified'
                      'Path to Root CA to use when building the gNMI Channel',
                      required=False)
  parser.add_argument('-cchain', '--cert_chain', type=str, help='Fully'
                      'quallified path to Certificate chain to use when'
                      'establishing a gNMI Channel to the Target', default=None,
                      required=False)
  parser.add_argument('-g', '--get_cert', help='Obtain certificate from gNMI '
                      'Target when establishing secure gRPC channel.',
                      required=False, action='store_true')
  parser.add_argument('-x', '--xpath', type=str, help='The gNMI path utilized'
                      'in the GetRequest or Subscirbe', nargs="+", required=True)
  parser.add_argument('-xt', '--xpath_target', type=str, help='The gNMI prefix'
                      'target in the GetRequest or Subscirbe', default=None,
                      required=False)
  parser.add_argument('-xo', '--xpath_origin', type=str, help='The gNMI prefix'
                      'origin in the GetRequest, SetRequest or Subscirbe', default=None,
                      required=False)
  parser.add_argument('-o', '--host_override', type=str, help='Use this as '
                      'Targets hostname/peername when checking it\'s'
                      'certificate CN. You can check the cert with:\nopenssl '
                      'x509 -in certificate.crt -text -noout', required=False)
  parser.add_argument('-f', '--format', type=str, action='store', help='Format '
                      'of the GetResponse to be printed. Default=JSON.',
                      choices=['json', 'protobuff'], default='json',
                      required=False)
  parser.add_argument('-V', '--version', help='Print program version',
                      action='store_true', required=False)
  parser.add_argument('-d', '--debug', help='Enable gRPC debugging',
                      required=False, action='store_true')
  parser.add_argument('-n', '--notls', help='gRPC insecure mode',
                      required=False, action='store_true')
  parser.add_argument('--interval', default=10000, type=int,
                      help='sample interval in millisecond (default: 10000ms)')
  parser.add_argument('--timeout', type=int, help='subscription'
                      'duration in seconds (default: none)')
  parser.add_argument('--heartbeat', default=0, type=int, help='heartbeat interval (default: None)')
  parser.add_argument('--aggregate', action='store_true', help='allow aggregation')
  parser.add_argument('--suppress', action='store_true', help='suppress redundant')
  parser.add_argument('--submode', default=2, type=int,
                      help='subscription mode [0=TARGET_DEFINED, 1=ON_CHANGE, 2=SAMPLE]')
  parser.add_argument('--update_count', default=0, type=int, help='Max number of streaming updates to receive. 0 means no limit.')
  parser.add_argument('--subscribe_mode', default=0, type=int, help='[0=STREAM, 1=ONCE, 2=POLL]')
  parser.add_argument('--encoding', default=0, type=int, help='[0=JSON, 1=BYTES, 2=PROTO, 3=ASCII, 4=JSON_IETF]')
  parser.add_argument('--qos', default=0, type=int, help='')
  parser.add_argument('--use_alias', action='store_true', help='use alias')
  parser.add_argument('--create_connections', type=int, nargs='?', const=1, default=1,
                      help='Creates specific number of TCP connections with gNMI server side. '
                      'Default number of TCP connections is 1 and use -1 to create '
                      'infinite TCP connections.')
  parser.add_argument('--filter_event_regex', help='Regex to filter event when querying events path')
  parser.add_argument('--prefix', default='', help='gRPC path prefix (default: none)')
  return parser


def _path_names(xpath):
  """Parses the xpath names.

  This takes an input string and converts it to a list of gNMI Path names. Those
  are later turned into a gNMI Path Class object for use in the Get/SetRequests.
  Args:
    xpath: (str) xpath formatted path.

  Returns:
    list of gNMI path names.
  """
  if not xpath or xpath == '/':  # A blank xpath was provided at CLI.
    return []
  xpath = xpath.strip().strip('/')
  path = []
  xpath = xpath + '/'
  # insideBrackets is true when at least one '[' has been found and no
  # ']' has been found. It is false when a closing ']' has been found.
  insideBrackets = False
  # begin marks the beginning of a path element, which is separated by
  # '/' unclosed between '[' and ']'.
  begin = 0
  # end marks the end of a path element, which is separated by '/'
  # unclosed between '[' and ']'.
  end = 0

  # Split the given string using unescaped '/'.
  while end < len(xpath):
    if xpath[end] == '/':
      if not insideBrackets:
        # Current '/' is a valid path element
        # separator.
        if end > begin:
          path.append(xpath[begin:end])
        end += 1
        begin = end
      else:
        # Current '/' must be part of a List key value
        # string.
        end += 1
    elif xpath[end] == '[':
      if (end == 0 or xpath[end-1] != '\\') and not insideBrackets:
        # Current '[' is unescacped, and is the
        # beginning of List key-value pair(s) string.
        insideBrackets = True
      end += 1
    elif xpath[end] == ']':
      if (end == 0 or xpath[end-1] != '\\') and insideBrackets:
        # Current ']' is unescacped, and is the end of
        # List key-value pair(s) string.
        insideBrackets = False
      end += 1
    else:
      end += 1

  if insideBrackets:
    print("missing ] in path string: %s" % xpath)
    return []

  return path


def _parse_path(p_names):
  """Parses a list of path names for path keys.

  Args:
    p_names: (list) of path elements, which may include keys.

  Returns:
    a gnmi_pb2.Path object representing gNMI path elements.

  Raises:
    XpathError: Unabled to parse the xpath provided.
  """
  gnmi_elems = []
  for word in p_names:
    word_search = _RE_PATH_COMPONENT.search(word)
    if not word_search:  # Invalid path specified.
      raise XpathError('xpath component parse error: %s' % word)
    if word_search.group('key') is not None:  # A path key was provided.
      tmp_key = {}
      for x in re.findall(r'\[([^]]*)\]', word):
        tmp_key[x.split("=")[0]] = x.split("=")[-1]
      gnmi_elems.append(gnmi_pb2.PathElem(name=word_search.group(
          'pname'), key=tmp_key))
    else:
      gnmi_elems.append(gnmi_pb2.PathElem(name=word, key={}))
  return gnmi_pb2.Path(elem=gnmi_elems)


def _create_stub(creds, target, port, host_override):
  """Creates a gNMI Stub.

  Args:
    creds: (object) of gNMI Credentials class used to build the secure channel.
    target: (str) gNMI Target.
    port: (str) gNMI Target IP port.
    host_override: (str) Hostname being overridden for Cert check.

  Returns:
    a gnmi_pb2_grpc object representing a gNMI Stub.
  """
  if creds:
    if host_override:
      channel = gnmi_pb2_grpc.grpc.secure_channel(target + ':' + port, creds, ((
          'grpc.ssl_target_name_override', host_override,),))
    else:
      channel = gnmi_pb2_grpc.grpc.secure_channel(target + ':' + port, creds)
  else:
      channel = gnmi_pb2_grpc.grpc.insecure_channel(target + ':' + port)
  return gnmi_pb2_grpc.gNMIStub(channel)


def _format_type(json_value):
  """Helper to determine the Python type of the provided value from CLI.

  Args:
    json_value: (str) Value providing from CLI.

  Returns:
    json_value: The provided input coerced into proper Python Type.
  """
  if (json_value.startswith('-') and json_value[1:].isdigit()) or (
      json_value.isdigit()):
    return int(json_value)
  if (json_value.startswith('-') and json_value[1].isdigit()) or (
      json_value[0].isdigit()):
    return float(json_value)
  if json_value.capitalize() == 'True':
    return True
  if json_value.capitalize() == 'False':
    return False
  return json_value  # The value is a string.


def _get_val(json_value):
  """Get the gNMI val for path definition.

  Args:
    json_value: (str) JSON_IETF or file.

  Returns:
    gnmi_pb2.TypedValue()
  """
  val = gnmi_pb2.TypedValue()
  if '@' in json_value:
    try:
      set_json = json.loads(six.moves.builtins.open(
          json_value.strip('@'), 'rb').read())
    except (IOError, ValueError) as e:
      raise JsonReadError('Error while loading JSON: %s' % str(e))
    val.json_ietf_val = json.dumps(set_json).encode()
    return val
  elif '$' in json_value:
    try:
      proto_bytes = six.moves.builtins.open(json_value.strip('$'), 'rb').read()
    except (IOError, ValueError) as e:
      raise ValueError('Error while loading %s: %s' % (json_value.strip('$'), str(e)))
    val.proto_bytes = proto_bytes
    return val
  elif json_value == '':
    # GNMI client should use delete operation for empty string
    return None
  coerced_val = _format_type(json_value)
  type_to_value = {bool: 'bool_val', int: 'int_val', float: 'float_val',
                   str: 'string_val'}
  if type_to_value.get(type(coerced_val)):
    setattr(val, type_to_value.get(type(coerced_val)), coerced_val)
  return val


def _get(stub, paths, username, password, prefix, encoding):
  """Create a gNMI GetRequest.

  Args:
    stub: (class) gNMI Stub used to build the secure channel.
    paths: (list) gNMI Path
    username: (str) Username used when building the channel.
    password: (str) Password used when building the channel.
    prefix: gNMI Path
    encoding: (int) Encoding
  Returns:
    a gnmi_pb2.GetResponse object representing a gNMI GetResponse.
  """
  kwargs = {}
  if username:  # User/pass supplied for Authentication.
    kwargs = {'metadata': [('username', username), ('password', password)]}
  return stub.Get(
      gnmi_pb2.GetRequest(prefix=prefix, path=paths, encoding=encoding),
                  **kwargs)

def _set(stub, prefix, paths, set_type, username, password, value_list):
  """Create a gNMI SetRequest.

  Args:
    stub: (class) gNMI Stub used to build the secure channel.
    paths: (list) gNMI Path
    set_type: (str) Type of gNMI SetRequest.
    username: (str) Username used when building the channel.
    password: (str) Password used when building the channel.
    value_list: (list) JSON_IETF or file.

  Returns:
    a gnmi_pb2.SetResponse object representing a gNMI SetResponse.
  """
  delete_list = []
  update_list = []
  for path, value in zip(paths, value_list):
    val = _get_val(value)
    if val is None:
      delete_list.append(path)
    else:
      path_val = gnmi_pb2.Update(path=path, val=val,)
      update_list.append(path_val)
  kwargs = {}
  if username:
    kwargs = {'metadata': [('username', username), ('password', password)]}
  return stub.Set(gnmi_pb2.SetRequest(prefix=prefix, delete=delete_list, update=update_list), **kwargs)


def _build_creds(target, port, get_cert, certs, notls):
  """Define credentials used in gNMI Requests.

  Args:
    target: (str) gNMI Target.
    port: (str) gNMI Target IP port.
    get_cert: (str) Certificate should be obtained from Target for gRPC channel.
    certs: (dict) Certificates to use in building the gRPC channel.

  Returns:
    a gRPC.ssl_channel_credentials object.
  """
  if notls:
    return
  if get_cert:
    logging.info('Obtaining certificate from Target')
    rcert = ssl.get_server_certificate((target, port)).encode('utf-8')
    return gnmi_pb2_grpc.grpc.ssl_channel_credentials(
        root_certificates=rcert, private_key=certs['private_key'],
        certificate_chain=certs['cert_chain'])
  return gnmi_pb2_grpc.grpc.ssl_channel_credentials(
    root_certificates=certs['root_cert'], private_key=certs['private_key'],
    certificate_chain=certs['cert_chain'])


def _open_certs(**kwargs):
  """Opens provided certificate files.

  Args:
    root_cert: (str) Root certificate file to use in the gRPC channel.
    cert_chain: (str) Certificate chain file to use in the gRPC channel.
    private_key: (str) Private key file to use in the gRPC channel.

  Returns:
    root_cert: (str) Root certificate to use in the gRPC channel.
    cert_chain: (str) Certificate chain to use in the gRPC channel.
    private_key: (str) Private key to use in the gRPC channel.
  """
  for key, value in kwargs.items():
    if value:
      kwargs[key] = six.moves.builtins.open(value, 'rb').read()
  return kwargs


def gen_request(paths, opt, prefix):
    """Create subscribe request for passed xpath.
    Args:
        paths: (list) gNMI path.
        opt: (dict) Command line argument passed for subscribe reqeust.
    Returns:
      gNMI SubscribeRequest object.
    """
    mysubs = []
    for path in paths:
      mysub = gnmi_pb2.Subscription(path=path, mode=opt["submode"],
        sample_interval=opt["interval"]*1000000,
          heartbeat_interval=opt['heartbeat']*1000000,
            suppress_redundant=opt['suppress'])
      mysubs.append(mysub)

    if prefix:
      myprefix = prefix
    elif opt["prefix"]:
        myprefix = _parse_path(_path_names(opt["prefix"]))
    else:
        myprefix = None

    if opt["qos"]:
        myqos = gnmi_pb2.QOSMarking(marking=opt["qos"])
    else:
        myqos = None
    mysblist = gnmi_pb2.SubscriptionList(prefix=myprefix, mode=opt['subscribe_mode'],
      allow_aggregation=opt['aggregate'], encoding=opt['encoding'],
      subscription=mysubs, use_aliases=opt['use_alias'], qos=myqos)
    mysubreq = gnmi_pb2.SubscribeRequest(subscribe=mysblist)

    print('Sending SubscribeRequest\n'+str(mysubreq))
    yield mysubreq


def check_event_response(response, filter_event_regex):
    resp = str(response)
    match = re.findall(filter_event_regex, resp)
    return match


def subscribe_start(stub, options, req_iterator):
  """ RPC Start for Subscribe reqeust
  Args:
      stub: (class) gNMI Stub used to build the secure channel.
      options: (dict) Command line argument passed for subscribe reqeust.
      req_iterator: gNMI Subscribe Request from gen_request.
  Returns:
      Start Subscribe and printing response of gNMI Subscribe Response.
  """
  metadata = [('username', options['username']), ('password', options['password'])]
  max_update_count = options["update_count"]
  filter_event_regex = options["filter_event_regex"]

  try:
      responses = stub.Subscribe(req_iterator, options['timeout'], metadata=metadata)
      update_count = 0
      for response in responses:
          print('{0} response received: '.format(datetime.datetime.now()))
          if response.HasField('sync_response'):
              print(str(response))
          elif response.HasField('error'):
              print('gNMI Error '+str(response.error.code)+\
                ' received\n'+str(response.error.message) + str(response.error))
          elif response.HasField('update'):
              if filter_event_regex is not None:
                  if filter_event_regex is not "":
                      match = check_event_response(response, filter_event_regex)
                      if len(match) is not 0:
                          print(response)
                          update_count = update_count + 1
                  else:
                      raise Exception("Filter event regex should not be empty")
              else:
                  print(response)
                  update_count = update_count+1
          else:
              print('Unknown response received:\n'+str(response))
          
          if max_update_count != 0 and update_count == max_update_count:
            print("Max update count reached {0}".format(update_count))
            break
  except KeyboardInterrupt:
      print("Subscribe Session stopped by user.")
  except grpc.RpcError as err:
      print("Received an exception from server side and error message is: '{}'.".format(err))
      raise
  except Exception as err:
      print(err)


def main():
  argparser = _create_parser()
  args = vars(argparser.parse_args())
  if args['version']:
    print(__version__)
    sys.exit()
  if args['debug']:
    os.environ['GRPC_TRACE'] = 'all'
    os.environ['GRPC_VERBOSITY'] = 'DEBUG'
  mode = args['mode']
  target = args['target']
  port = args['port']
  notls = args['notls']
  get_cert = args['get_cert']
  root_cert = args['root_cert']
  cert_chain = args['cert_chain']
  value_list = args['value']
  private_key = args['private_key']
  xpath_list = args['xpath']
  proto_list = args['proto']
  # In the case that a prefix is specified, it MUST specify any required origin
  prefix = gnmi_pb2.Path(origin=args['xpath_origin'], target=args['xpath_target'])
  host_override = args['host_override']
  user = args['username']
  password = args['password']
  form = args['format']
  create_connections = args['create_connections']
  encoding = args['encoding']
  paths = []
  if xpath_list:
    for xpath in xpath_list:
      paths.append(_parse_path(_path_names(xpath)))
  kwargs = {'root_cert': root_cert, 'cert_chain': cert_chain,
            'private_key': private_key}
  certs = _open_certs(**kwargs)
  creds = _build_creds(target, port, get_cert, certs, notls)

  if create_connections < -1:
    print('''
          Default number of TCP connections with gNMI server is 1.
          Please use the '--create_connections <positive_number>' to
          create TCP connections or use '--create_connections -1' to
          create infinite TCP connections.
          ''', file=sys.stderr)
    sys.exit(INVALID_GNMI_CLIENT_CONNECTION_NUMBER)

  while True:
    if create_connections > 0:
        create_connections -= 1
    elif create_connections == 0:
        break

    try:
      stub = _create_stub(creds, target, port, host_override)
      if mode == 'get':
        print('Performing GetRequest, encoding=JSON_IETF', 'to', target,
              ' with the following gNMI Path\n', '-'*25, '\n', paths)
        response = _get(stub, paths, user, password, prefix, encoding)
        print('The GetResponse is below\n' + '-'*25 + '\n')
        if encoding == 2:
          i = 0
          for notification in response.notification:
            for update in notification.update:
              if i >= len(proto_list):
                print("Not enough files: %s" % str(proto_list))
                sys.exit(1)
              with open(proto_list[i], 'wb') as fp:
                fp.write(update.val.proto_bytes)
              i += 1
        elif form == 'protobuff':
          print(response)
        elif response.notification[0].update[0].val.json_ietf_val:
          for notification in response.notification:
            for update in notification.update:
              print(json.dumps(json.loads(update.val.json_ietf_val), indent=2))
              print('-'*25 + '\n')
        elif response.notification[0].update[0].val.string_val:
          print(response.notification[0].update[0].val.string_val)
        else:
          print('JSON Format specified, but gNMI Response was not json_ietf_val')
          print(response)
      elif mode == 'set-update':
        print('Performing SetRequest Update, encoding=JSON_IETF', ' to ', target,
              ' with the following gNMI Path\n', '-'*25, '\n', paths, value_list)
        response = _set(stub, prefix, paths, 'update', user, password, value_list)
        print('The SetRequest response is below\n' + '-'*25 + '\n', response)
      elif mode == 'set-replace':
        print('Performing SetRequest Replace, encoding=JSON_IETF', ' to ', target,
              ' with the following gNMI Path\n', '-'*25, '\n', paths)
        response = _set(stub, prefix, paths, 'replace', user, password, value_list)
        print('The SetRequest response is below\n' + '-'*25 + '\n', response)
      elif mode == 'set-delete':
        print('Performing SetRequest Delete, encoding=JSON_IETF', ' to ', target,
              ' with the following gNMI Path\n', '-'*25, '\n', paths)
        response = _set(stub, prefix, paths, 'delete', user, password, value_list)
        print('The SetRequest response is below\n' + '-'*25 + '\n', response)
      elif mode == 'subscribe':
        request_iterator = gen_request(paths, args, prefix)
        subscribe_start(stub, args, request_iterator)
    except grpc.RpcError as err:
      if err.code() == grpc.StatusCode.UNAVAILABLE:
        print("Client receives an exception '{}' indicating gNMI server is shut down and Exiting ..."
              .format(err.details()))
        sys.exit(GNMI_SERVER_UNAVAILABLE)
      else:
        print("GRPC error\n {}".format(err.details()))
        sys.exit(1)


if __name__ == '__main__':
  main()
