"""Import all parser modules so their @register_* hooks run.

Add a new parser by creating a module here and importing it below.
"""

from parsers import apache_parser  # noqa: F401
from parsers import firewall_parser  # noqa: F401
from parsers import generic_parser  # noqa: F401
from parsers import structured_parser  # noqa: F401
from parsers import syslog_parser  # noqa: F401
from parsers import vendor_registry  # noqa: F401  (M4: named vendor parsers)
from parsers import windows_parser  # noqa: F401
from parsers import vmware_esxi_parser  # noqa: F401  (M5: VMware parsers)
from parsers import vmware_nsx_parser  # noqa: F401
from parsers import vmware_vcenter_parser  # noqa: F401
