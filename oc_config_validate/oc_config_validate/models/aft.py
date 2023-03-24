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

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ethernet(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ethernet - based on the path /openconfig-aft-ethernet. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for Ethernet.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ipv4(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ipv4 - based on the path /openconfig-aft-ipv4. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for IPv4.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ipv6(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ipv6 - based on the path /openconfig-aft-ipv6. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for IPv6.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_mpls(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-mpls - based on the path /openconfig-aft-mpls. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding table for MPLS label forwarding.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_network_instance(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-network-instance - based on the path /openconfig-aft-network-instance. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module provides augmentations that are utilized
when building the OpenConfig network instance model to
add per-NI AFTs.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_pf(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-pf - based on the path /openconfig-aft-pf. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding table(s) for policy forwarding entries. These are
defined to be forwarding tables that allow matches on
fields other than the destination address that is used in
other forwarding tables.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_state_synced(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-state-synced - based on the path /openconfig-aft-state-synced. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the state
synced signals corresponding to various abstract forwarding tables.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_types(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-types - based on the path /openconfig-aft-types. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Types related to the OpenConfig Abstract Forwarding
Table (AFT) model
  """
  _pyangbind_elements = {}

  

class openconfig_aft(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft - based on the path /openconfig-aft. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: A model describing the forwarding entries installed on a network
element. It should be noted that this model is not expected to
align 1:1 with the underlying structure used directly by a
forwarding element (e.g., linecard), but rather provide an
abstraction that can be consumed by an NMS to observe, and in some
cases manipulate, the internal forwarding database in a simplified
manner. Since the underlying model of the forwarding table is not
expected to align with this model, the structure described herein
is referred to as an Abstract Forwarding Table (AFT), rather than
the FIB.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ipv4(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ipv4 - based on the path /openconfig-aft-ipv4. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for IPv4.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ipv6(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ipv6 - based on the path /openconfig-aft-ipv6. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for IPv6.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_mpls(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-mpls - based on the path /openconfig-aft-mpls. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding table for MPLS label forwarding.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_pf(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-pf - based on the path /openconfig-aft-pf. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding table(s) for policy forwarding entries. These are
defined to be forwarding tables that allow matches on
fields other than the destination address that is used in
other forwarding tables.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_ethernet(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-ethernet - based on the path /openconfig-aft-ethernet. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the abstract
forwarding tables for Ethernet.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_common(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-common - based on the path /openconfig-aft-common. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings that are re-used
across multiple contexts within the AFT model.
  """
  _pyangbind_elements = {}

  

class openconfig_aft_state_synced(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module openconfig-aft-state-synced - based on the path /openconfig-aft-state-synced. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Submodule containing definitions of groupings for the state
synced signals corresponding to various abstract forwarding tables.
  """
  _pyangbind_elements = {}

  

