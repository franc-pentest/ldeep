from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.protocol.formatters.validators import validate_guid, validate_sid

from ldeep.views.constants import EXTENDED_RIGHTS_MAP, SCHEMA_GUIDS_MAP

ALL_ATTRIBUTES = ALL_ATTRIBUTES
ALL_OPERATIONAL_ATTRIBUTES = ALL_OPERATIONAL_ATTRIBUTES
ALL = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
validate_sid = validate_sid
validate_guid = validate_guid


class ActiveDirectoryView(object):
    """
    Manage a view of a Active Directory.
    """

    class ActiveDirectoryInvalidSID(Exception):
        pass

    class ActiveDirectoryInvalidGUID(Exception):
        pass

    def get_guid_maps(self):
        """
        Return the (schema objects, extended rights) maps of GUID to name used to display ACEs.
        """
        return SCHEMA_GUIDS_MAP, EXTENDED_RIGHTS_MAP
