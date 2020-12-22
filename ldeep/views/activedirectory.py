
from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES

ALL_ATTRIBUTES = ALL_ATTRIBUTES
ALL_OPERATIONAL_ATTRIBUTES = ALL_OPERATIONAL_ATTRIBUTES
ALL = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]


class ActiveDirectoryView(object):
	"""
	Manage a view of a Active Directory.
	"""

	class ActiveDirectoryInvalidSID(Exception):
		pass

	class ActiveDirectoryInvalidGUID(Exception):
		pass
