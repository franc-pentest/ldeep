
from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.protocol.formatters.validators import validate_sid, validate_guid

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
