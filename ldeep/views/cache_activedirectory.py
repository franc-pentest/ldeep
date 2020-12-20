
from os import path
from json import load as json_load
from ldeep.views.activedirectory import ActiveDirectoryView, ALL
from ldeep.views.constants import WELL_KNOWN_SIDs


# case insenitive equal when x and y are str instances
def eq(x, y):
	if isinstance(x, str) and isinstance(y, str):
		return x.lower() == y.lower()
	else:
		return x == y


class CacheActiveDirectoryView(ActiveDirectoryView):

	# Constant functions (s -> self but we don't need it)
	USER_LOCKED_FILTER = lambda s: {"files": ["users_locked"]}
	GROUPS_FILTER = lambda s: {"files": ["groups"]}
	USER_ALL_FILTER = lambda s: {"files": ["users_all"]}
	USERS_SPN_FILTER = lambda s: {"files": ["users_spn"]}
	COMPUTERS_FILTER = lambda s: {"files": ["machines"]}
	ANR = lambda s, u: {"files": ["users_all", "groups", "machines"], "filter": lambda x: eq(x["sAMAccountName"], u)}
	GROUP_DN_FILTER = lambda s, g: {"fmt": "json", "files": ["groups"], "filter": lambda x: eq(x["sAMAccountName"], g)}
	USERS_IN_GROUP_FILTER = lambda s, p, g: {
		"files": ["users_all", "groups"],
		"filter": lambda x: ("primaryGroupID" in x and eq(p, x["primaryGroupID"])) or ("memberOf" in x and g in x["memberOf"])
	}
	USER_IN_GROUPS_FILTER = lambda s, u: {
		"fmt": "json",
		"files": ["users_all", "machines"],
		"filter": lambda x: eq(x["sAMAccountName"], u)
	}
	DISTINGUISHED_NAME = lambda s, n: {
		"fmt": "json",
		"files": ["users_all", "groups", "machines"],
		"filter": lambda x: eq(x["distinguishedName"], n)
	}
	# Not implemented:
	DOMAIN_INFO_FILTER = lambda s: None
	GPO_INFO_FILTER = lambda s: None
	OU_FILTER = lambda s: None
	PSO_INFO_FILTER = lambda s: None
	TRUSTS_INFO_FILTER = lambda s: None
	ZONES_FILTER = lambda s: None
	ZONE_FILTER = lambda s: None
	USER_ACCOUNT_CONTROL_FILTER = lambda s: None
	USER_ACCOUNT_CONTROL_FILTER_NEG = lambda s: None
	USER_LOCKED_FILTER = lambda s: None

	class CacheActiveDirectoryException(Exception):
		pass

	def __init__(self, cache_dir=".", prefix="ldeep_"):
		"""
		CacheActiveDirectoryView constructor.
		Initialize the cache state with the provided directory and file prefixes.

		@cache_dir: directory containing ldeep files
		@prefix: prefix of the files
		"""
		self.path = cache_dir
		self.prefix = prefix
		self.domain, self.base_dn = self.__get_domain_info()

	def query(self, cachefilter, attributes=ALL, base=None, scope=None, **filter_args):
		"""
		Perform a query to cache files.

		@cachefilter: a dict containing the following fields: fmt (optional), files and filter (optional).
		@attributes: only use to deduce the file formats to use (`lst` or `json`).
		@base: Not implemented.
		@scope: Not implemented.

		@return a list of records.
		"""
		
		# Process unimplemented queries
		if cachefilter is None:
			raise self.OfflineActiveDirectoryCacheException("Cache query not supported.")

		# Get format of cache files to use: either `lst` or `json`
		if "fmt" in cachefilter:
			fmt = cachefilter["fmt"]
		elif attributes == ALL:
			fmt = "json"
		else:
			fmt = "lst"

		data = []
		# For each file, retrieve result based on a filter
		for fil in cachefilter["files"]:
			filename = "{prefix}_{file}.{ext}".format(
						prefix=self.prefix,
						file=fil,
						ext=fmt)

			with open(path.join(self.path, filename)) as fp:
				if fmt == "json":
					json = json_load(fp)
					if "filter" in cachefilter:
						for record in json:
							if cachefilter["filter"](record):
								data.append(record)
					else:
						data += json								
				else:
					data += map(lambda x: x.strip(), fp.readlines())
		return data

	def resolve_sid(self, sid):
		"""
		Two cases:
			* the SID is a WELL KNOWN SID and a local SID, the name of the corresponding account is returned;
			* else, the SID is search through the cache and the corresponding record is returned.

		@sid: the sid to search for.
		
		@throw ActiveDirectoryInvalidSID if the SID is not a valid SID.
		@return the record corresponding to the SID queried.
		"""
		if sid in WELL_KNOWN_SIDs:
			return WELL_KNOWN_SIDs[sid]
		elif validate_sid(sid):
			results = self.query({
				"files": ["users_all", "groups", "machines"],
				"filter": lambda x: x["objectSid"] == sid
			})
			if results:
				return results
		raise self.ActiveDirectoryInvalidSID(f"SID: {sid}")

	def resolve_guid(self, guid):
		"""
		Return the cache record with the provided GUID.

		@guid: the guid to search for.

		@throw ActiveDirectoryInvalidGUID if the GUID is not a valid GUID.
		@return the record corresponding to the guid queried.
		"""
		if validate_guid(guid):
			results = self.query({
				"files": ["users_all", "groups", "machines"],
				"filter": lambda x: x["objectGUID"] == guid
			})
			if results:
				return results
		raise self.ActiveDirectoryInvalidGUID(f"GUID: {guid}")

	def __get_domain_info(self):
		"""
		Private functions to retrieve the cache domain name.
		"""
		filename = "{prefix}_domain_policy.lst".format(prefix=self.prefix)
		with open(path.join(self.path, filename)) as fp:
			for line in fp:
				if line.startswith("distinguishedName:"):
					base = line.split(" ")[1].strip()
					domain = base.replace("DC=", ".")[1:].replace(",", "")
					return domain, base
