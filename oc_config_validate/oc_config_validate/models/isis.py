# -*- coding: utf-8 -*-
from operator import attrgetter
from pyangbind.lib.yangtypes import RestrictedPrecisionDecimalType
from pyangbind.lib.yangtypes import RestrictedClassType
from pyangbind.lib.yangtypes import TypedListType
from pyangbind.lib.yangtypes import YANGBool
from pyangbind.lib.yangtypes import YANGListType
from pyangbind.lib.yangtypes import YANGDynClass
from pyangbind.lib.yangtypes import ReferenceType
from pyangbind.lib.base import PybindBase
from collections import OrderedDict
from decimal import Decimal
from bitarray import bitarray
import six

# PY3 support of some PY2 keywords (needs improved)
if six.PY3:
  import builtins as __builtin__
  long = int
elif six.PY2:
  import __builtin__

class openconfig_isis_lsdb_types(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-lsdb-types - based on the path /openconfig-isis-lsdb-types. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module contains general LSDB type definitions for use in
ISIS YANG model. 
  """
  _pyangbind_elements = {}

  

class openconfig_isis_lsp(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-lsp - based on the path /openconfig-isis-lsp. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This sub-module describes a YANG model for the IS-IS Link State
Database (LSDB).

Portions of this code were derived from IETF RFCs relating to the
IS-IS protocol.
Please reproduce this note if possible.
IETF code is subject to the following copyright and license:
Copyright (c) IETF Trust and the persons identified as authors of
the code.
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in
Section 4.c of the IETF Trust's Legal Provisions Relating
to IETF Documents (http://trustee.ietf.org/license-info).
  """
  _pyangbind_elements = {}

  

class openconfig_isis_policy(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-policy - based on the path /openconfig-isis-policy. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module contains data definitions for ISIS routing policy.
It augments the base routing-policy module with BGP-specific
options for conditions and actions.
  """
  _pyangbind_elements = {}

  

class openconfig_isis_routing(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-routing - based on the path /openconfig-isis-routing. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module describes YANG model for ISIS Routing
  """
  _pyangbind_elements = {}

  

class openconfig_isis_types(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-types - based on the path /openconfig-isis-types. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module contains general data definitions for use in ISIS YANG
model.
  """
  _pyangbind_elements = {}

  

class openconfig_isis(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis - based on the path /openconfig-isis. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module describes a YANG model for ISIS protocol configuration.
It is a limited subset of all of the configuration parameters
available in the variety of vendor implementations, hence it is
expected that it would be augmented with vendor - specific configuration
data as needed. Additional modules or submodules to handle other
aspects of ISIS configuration, including policy, routing, types,
LSDB and additional address families are also expected. This model
supports the following ISIS configuration level hierarchy:

ISIS
+-> { global ISIS configuration}
   +-> levels +-> { level config}
       +-> { system-level-counters }
       +-> { level link-state-database}
   +-> interface +-> { interface config }
       +-> { circuit-counters }
       +-> { levels config }
       +-> { level adjacencies }
  """
  _pyangbind_elements = {}

  

class openconfig_isis_lsp(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-lsp - based on the path /openconfig-isis-lsp. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This sub-module describes a YANG model for the IS-IS Link State
Database (LSDB).

Portions of this code were derived from IETF RFCs relating to the
IS-IS protocol.
Please reproduce this note if possible.
IETF code is subject to the following copyright and license:
Copyright (c) IETF Trust and the persons identified as authors of
the code.
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in
Section 4.c of the IETF Trust's Legal Provisions Relating
to IETF Documents (http://trustee.ietf.org/license-info).
  """
  _pyangbind_elements = {}

  

class openconfig_isis_routing(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-isis-routing - based on the path /openconfig-isis-routing. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module describes YANG model for ISIS Routing
  """
  _pyangbind_elements = {}

  

