from json import load as json_load
from os import path

from ldeep.utils import error
from ldeep.views.activedirectory import (
    ALL,
    ALL_ATTRIBUTES,
    ActiveDirectoryView,
    validate_guid,
    validate_sid,
)
from ldeep.views.constants import WELL_KNOWN_SIDS

warned_missing_files = set()
FILE_CONTENT_DICT = dict()


class UnexpectedFormatException(Exception):
    pass


# case insenitive equal when x and y are str instances
def eq(x, y):
    if isinstance(x, str) and isinstance(y, str):
        return x.lower() == y.lower()
    else:
        return x == y


# respect the ANR field
def eq_anr(record, value):
    def fmap(f, obj):
        if isinstance(obj, dict):
            return any(fmap(f, sub) for sub in obj.values())
        elif isinstance(obj, list):
            return any(fmap(f, k) for k in obj)
        elif isinstance(obj, str):
            return f(obj)
        else:
            raise UnexpectedFormatException(
                f"Unexpected value, expected: dict, list or str, obtained: {type(obj)}."
            )

    validate = lambda x: x.lower().startswith(value.lower())

    keys = [
        "displayName",
        "givenName",
        "legacyExchangeDN",
        "physicalDeliveryOfficeName",
        "proxyAddresses",
        "Name",
        "sAMAccountName",
        "sn",
    ]
    for k in keys:
        if k in record and fmap(validate, record[k]):
            return True


class CacheActiveDirectoryView(ActiveDirectoryView):
    USER_CACHE_FILES = (
        "users_all",
        "users_enabled",
        "users_disabled",
        "users_locked",
        "users_nopasswordexpire",
        "users_passwordexpired",
        "users_passwordnotrequired",
        "users_nokrbpreauth",
        "users_reversible",
        "users_spn",
    )
    DELEGATION_CACHE_FILES = (
        "delegations_all",
        "delegations_unconstrained",
        "delegations_constrained",
        "delegations_rbcd",
    )

    # Constant functions (first arg -> self but we don't need it)
    GROUPS_FILTER = lambda _: {"files": ["groups"]}
    USER_SPN_FILTER = lambda _: {
        "files": ["users_spn"],
        "replacement": {
            "files": ["users_all"],
            "filter": lambda x: (
                x.get("servicePrincipalName", None) is not None
                and x["sAMAccountName"] != "krbtgt"
            ),
        },
    }
    DC_FILTER = lambda _: {
        "files": ["machines"],
        "filter": lambda x: True if int(x["primaryGroupID"]) == 516 else False,
    }
    ANR = lambda _, u: {
        "files": ["users_all", "groups", "machines"],
        "filter": lambda record: eq_anr(record, u),
    }
    GROUP_DN_FILTER = lambda _, g: {
        "fmt": "json",
        "files": ["groups"],
        "filter": lambda x: eq(x["sAMAccountName"], g),
    }
    ACCOUNTS_IN_GROUP_FILTER = lambda _, p, g: {
        "fmt": "json",
        "files": ["users_all", "smsa", "gmsa", "groups", "machines"],
        "filter": lambda x: (
            ("primaryGroupID" in x and eq(p, x["primaryGroupID"]))
            or ("memberOf" in x and g in x["memberOf"])
        ),
    }
    ACCOUNT_IN_GROUPS_FILTER = lambda _, u: {
        "fmt": "json",
        "files": ["users_all", "groups", "machines"],
        "filter": lambda x: eq(x["sAMAccountName"], u),
    }
    DISTINGUISHED_NAME = lambda _, n: {
        "fmt": "json",
        "files": [
            "users_all",
            "gmsa",
            "groups",
            "machines",
            "shadow_principals",
        ],
        "filter": lambda x: eq(x["distinguishedName"], n),
    }
    PRIMARY_GROUP_ID = lambda _, i: {
        "fmt": "json",
        "files": ["users_all", "groups", "machines"],
        "filter": lambda x: x["objectSid"].endswith(f"-{i}"),
    }
    AUTH_POLICIES_FILTER = lambda _: {"files": ["auth_policies"]}
    SILOS_FILTER = lambda _: {"files": ["silos"]}
    SILO_FILTER = lambda _, s: {
        "fmt": "json",
        "files": ["silos"],
        "filter": lambda x: eq(x["cn"], s),
    }
    ZONES_FILTER = lambda _: {
        "fmt": "json",
        "files": ["zones"],
    }
    DNS_FILTER = lambda _: {
        "fmt": "json",
        "files": ["dns_records"],
    }
    GPO_INFO_FILTER = lambda _, n: {
        "files": ["gpo"],
        "filter": lambda x: True if n == "*" else eq(x["displayName"], n),
    }
    OU_FILTER = lambda _, n: {
        "files": ["ou"],
        "filter": lambda x: True if n == "*" else eq(x["distinguishedName"], n),
    }
    PKI_FILTER = lambda _: {"files": ["pkis"]}
    ALL_FILTER = lambda _: {"files": ["conf"]}
    BITLOCKERKEY_FILTER = lambda _: {"files": ["bitlockerkeys"]}
    FSP_FILTER = lambda _, n: {
        "files": ["fsp"],
        "filter": lambda x: True if n == "*" else eq(x["cn"], n),
    }
    ALL_DELEGATIONS_FILTER = lambda _: {
        "files": ["delegations_all"],
        "replacement": {
            "files": ["users_all", "machines"],
            "filter": lambda x: (
                "TRUSTED_FOR_DELEGATION" in x["userAccountControl"]
                or x.get("msDS-AllowedToDelegateTo", None) is not None
                or x.get("msDS-AllowedToActOnBehalfOfOtherIdentity") is not None
            ),
        },
    }
    UNCONSTRAINED_DELEGATION_FILTER = lambda _: {
        "files": ["delegations_unconstrained"],
        "replacement": {
            "files": ["users_all", "machines"],
            "filter": lambda x: "TRUSTED_FOR_DELEGATION" in x["userAccountControl"],
        },
    }
    CONSTRAINED_DELEGATION_FILTER = lambda _: {
        "files": ["delegations_constrained"],
        "replacement": {
            "files": ["users_all", "machines"],
            "filter": lambda x: x.get("msDS-AllowedToDelegateTo", None) is not None,
        },
    }
    RESOURCE_BASED_CONSTRAINED_DELEGATION_FILTER = lambda _: {
        "files": ["delegations_rbcd"],
        "replacement": {
            "files": ["users_all", "machines"],
            "filter": lambda x: (
                x.get("msDS-AllowedToActOnBehalfOfOtherIdentity", None) is not None
            ),
        },
    }
    # TODO: Handle FSMO, SCCM cases later, file is composed of 3 JSON array
    FSMO_DOMAIN_NAMING_FILTER = lambda _: None
    PRIMARY_SCCM_FILTER = lambda _: None

    GMSA_FILTER = lambda _, n: {
        "files": ["gmsa"],
        "filter": lambda x: True if n == "*" else eq(x["sAMAccountName"], n),
    }
    SMSA_FILTER = lambda _: {"files": ["smsa"]}
    USER_LOCKED_FILTER = lambda _: {
        "files": ["users_locked"],
        "replacement": {
            "files": ["users_all"],
            "filter": lambda x: x.get("lockoutTime", None) is not None,
        },
    }
    USER_ACCOUNT_CONTROL_FILTER = lambda _, n: {
        "files": ["users_disabled"],
        "replacement": {
            "files": ["users_all"],
            "filter": lambda x: n in x["userAccountControl"],
        },
    }
    USER_ACCOUNT_CONTROL_FILTER_NEG = lambda _, n: {
        "files": ["users_enabled"],
        "replacement": {
            "files": ["users_all"],
            "filter": lambda x: n not in x["userAccountControl"],
        },
    }
    SHADOW_PRINCIPALS_FILTER = lambda _: {"files": ["shadow_principals"]}
    TRUSTS_INFO_FILTER = lambda _: {"files": ["trusts"]}
    DOMAIN_INFO_FILTER = lambda _: {
        "files": ["domain_policy"],
        "fmt": "lst",
    }
    PSO_INFO_FILTER = lambda _: {"files": ["pso"]}
    LAPS_FILTER = lambda _, n: {
        "files": ["machines"],
        "filter": lambda x: (
            x.get("ms-Mcs-AdmPwdExpirationTime", None) is not None and eq(x["cn"], n)
            if n != "*"
            else True
        ),
    }
    LAPS2_FILTER = lambda _, n: {
        "files": ["machines"],
        "filter": lambda x: (
            x.get("msLAPS-PasswordExpirationTime", None) is not None and eq(x["cn"], n)
            if n != "*"
            else True
        ),
    }

    def has_cache_file(self, name):
        return any(
            path.exists(path.join(self.path, f"{self.prefix}_{name}.{extension}"))
            for extension in ("json", "lst")
        )

    def delegation_cache_files(self):
        available = [
            name for name in self.DELEGATION_CACHE_FILES if self.has_cache_file(name)
        ]
        return ["delegations_all"] if "delegations_all" in available else available

    def user_cache_files(self):
        available = [
            name for name in self.USER_CACHE_FILES if self.has_cache_file(name)
        ]
        if "users_all" in available:
            return ["users_all"] + (["smsa"] if self.has_cache_file("smsa") else [])
        return (
            available
            + (["smsa"] if self.has_cache_file("smsa") else [])
            + self.delegation_cache_files()
        )

    def computer_cache_files(self):
        if self.has_cache_file("machines"):
            return ["machines"]
        return self.delegation_cache_files()

    @staticmethod
    def _is_user_record(record):
        classes = record.get("objectClass", [])
        if isinstance(classes, str):
            classes = [classes]
        classes = {str(value).casefold() for value in classes}
        managed_service_account = classes & {
            "msds-groupmanagedserviceaccount",
            "msds-managedserviceaccount",
        }
        return ("user" in classes or "msds-managedserviceaccount" in classes) and (
            "computer" not in classes or managed_service_account
        )

    @staticmethod
    def _is_computer_record(record):
        classes = record.get("objectClass", [])
        if isinstance(classes, str):
            classes = [classes]
        classes = {str(value).casefold() for value in classes}
        return (
            "computer" in classes
            and "msds-groupmanagedserviceaccount" not in classes
            and "msds-managedserviceaccount" not in classes
        )

    def USER_ALL_FILTER(self):
        return {
            "files": self.user_cache_files(),
            "filter": self._is_user_record,
        }

    def COMPUTERS_FILTER(self, name):
        return {
            "files": self.computer_cache_files(),
            "filter": lambda record: self._is_computer_record(record)
            and (name == "*" or eq(record["cn"], name)),
        }

    class CacheActiveDirectoryException(Exception):
        pass

    class CacheActiveDirectoryDirNotFoundException(Exception):
        pass

    class CacheActiveDirectoryFileNotFoundException(Exception):
        pass

    def __init__(self, cache_dir=".", prefix="ldeep_"):
        """
        CacheActiveDirectoryView constructor.
        Initialize the cache state with the provided directory and file prefixes.

        @cache_dir: directory containing ldeep files
        @prefix: prefix of the files
        """
        if not path.exists(cache_dir):
            raise self.CacheActiveDirectoryDirNotFoundException(
                f"{cache_dir} doesn't exist."
            )
        self.path = cache_dir
        self.prefix = prefix
        self.fqdn, self.base_dn, self.forest_base_dn = self.__get_domain_info()
        self.attributes = ALL
        self.throttle = 0
        self.page_size = 0

    def set_all_attributes(self, attributes=ALL):
        self.attributes = attributes

    def all_attributes(self):
        return self.attributes

    def set_controls(self, controls):
        pass

    def query(self, cachefilter, attributes=[], base=None, scope=None, **filter_args):
        """
        Perform a query to cache files.

        @cachefilter: a dict containing the following fields: fmt (optional), files and filter (optional).
        @attributes: only use to deduce the file formats to use (`lst` or `json`).
        @base: Not implemented.
        @scope: Not implemented.

        @return a list of records.
        """

        def scrub_json_from_key(obj, func):
            if isinstance(obj, dict):
                for key in list(obj.keys()):
                    if func(key):
                        del obj[key]
                    else:
                        scrub_json_from_key(obj[key], func)
            elif isinstance(obj, list):
                for k in reversed(range(len(obj))):
                    if func(obj[k]):
                        del obj[k]
                    else:
                        scrub_json_from_key(obj[k], func)

        # Process unimplemented queries
        if cachefilter is None:
            raise self.CacheActiveDirectoryException("Cache query not supported.")

        if base is not None:
            if "filter" in cachefilter:
                oldFilter = cachefilter["filter"]
                cachefilter["filter"] = lambda elt: (
                    oldFilter(elt)
                    and ("dn" not in elt or elt["dn"].endswith("," + base))
                )
            else:
                cachefilter["filter"] = lambda elt: (
                    "dn" not in elt or elt["dn"].endswith("," + base)
                )

        # Get format of cache files to use: either `lst` or `json`
        if "fmt" in cachefilter:
            fmt = cachefilter["fmt"]
        elif ALL_ATTRIBUTES in attributes:
            fmt = "json"
        else:
            fmt = "lst"

        data = []
        # For each file, retrieve result based on an optional filter
        for fil in cachefilter["files"]:
            filename = f"{self.prefix}_{fil}.{fmt}"
            # In case the JSON file exists, parse it unless specified by the query engine
            if (
                path.exists(path.join(self.path, filename[:-3] + "json"))
                and not "fmt" in cachefilter
            ):
                fmt = "json"
                filename = f"{self.prefix}_{fil}.{fmt}"

            replacement = cachefilter.get("replacement", None)
            cache_path = path.join(self.path, filename)
            if not path.exists(cache_path) and replacement is None:
                if cache_path not in warned_missing_files:
                    error(f"{cache_path} required but not found")
                    warned_missing_files.add(cache_path)
                continue
            if not path.exists(cache_path) and replacement:
                cachefilter["files"] = cachefilter["replacement"]["files"]
                cachefilter["filter"] = cachefilter["replacement"]["filter"]
                del cachefilter["replacement"]
                return self.query(cachefilter, attributes, base, scope)

            # Two cases
            # all attributes are required thus we parse the JSON file
            if fmt == "json":
                if path.join(self.path, filename) in FILE_CONTENT_DICT:
                    json = FILE_CONTENT_DICT[path.join(self.path, filename)]
                else:
                    fp = open(cache_path)
                    json = json_load(fp)
                    if "ntSecurityDescriptor" not in self.attributes:
                        scrub_json_from_key(json, lambda x: x == "nTSecurityDescriptor")
                    FILE_CONTENT_DICT[path.join(self.path, filename)] = json

                if "filter" in cachefilter:
                    for record in json:
                        if cachefilter["filter"](record):
                            data.append(record)
                else:
                    data += json

            # we use the lst file
            else:
                if path.join(self.path, filename) in FILE_CONTENT_DICT:
                    fp = FILE_CONTENT_DICT[path.join(self.path, filename)]
                else:
                    fp = open(cache_path)
                    FILE_CONTENT_DICT[path.join(self.path, filename)] = fp
                if "filter" in cachefilter:
                    for line in fp:
                        x = {"sAMAccountName": line.strip()}  # a little hacky :)
                        if cachefilter["filter"](x):
                            data += [line.strip()]
                else:
                    data += map(lambda x: x.strip(), fp.readlines())
        return data

    def query_server_info(self):
        return self.query(
            {
                "fmt": "json",
                "files": ["server_info"],
            }
        )

    def resolve_sid(self, sid):
        """
        Two cases:
            * the SID is a WELL KNOWN SID and a local SID, the name of the corresponding account is returned;
            * else, the SID is search through the cache and the corresponding record is returned.

        @sid: the sid to search for.

        @throw ActiveDirectoryInvalidSID if the SID is not a valid SID.
        @return the record corresponding to the SID queried.
        """
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        elif validate_sid(sid):
            results = self.query(
                {
                    "fmt": "json",
                    "files": ["users_all", "groups", "machines"],
                    "filter": lambda x: x["objectSid"] == sid,
                }
            )
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
            results = self.query(
                {
                    "fmt": "json",
                    "files": ["users_all", "groups", "machines"],
                    "filter": lambda x: x["objectGUID"] == guid,
                }
            )
            if results:
                return results
        raise self.ActiveDirectoryInvalidGUID(f"GUID: {guid}")

    def get_sddl(self, *kwargs):
        raise NotImplementedError

    def __get_domain_info(self):
        """
        Private functions to retrieve the cache domain name.
        """
        filename = f"{self.prefix}_server_info.json"
        if path.exists(path.join(self.path, filename)):
            with open(path.join(self.path, filename)) as fp:
                info = json_load(fp)
                base = info[0]["raw"]["defaultNamingContext"][0]
                forest_base = info[0]["raw"]["rootDomainNamingContext"][0]
                domain = base.replace("DC=", ".")[1:].replace(",", "")
                return domain, base, forest_base

        # A BloodHound conversion is useful with a deliberately partial ldeep
        # cache (for example only users and computers).  server_info is not
        # needed to read those JSON records, so derive a conservative naming
        # context from the first distinguished name available instead of
        # refusing to open the cache.
        for cache_file in (
            "users_all",
            "users_enabled",
            "users_disabled",
            "users_locked",
            "users_nopasswordexpire",
            "users_passwordexpired",
            "users_passwordnotrequired",
            "users_nokrbpreauth",
            "users_reversible",
            "users_spn",
            "smsa",
            "delegations_all",
            "delegations_unconstrained",
            "delegations_constrained",
            "delegations_rbcd",
            "fsp",
            "shadow_principals",
            "groups",
            "machines",
            "domain_policy",
            "gmsa",
            "ou",
            "gpo",
            "pkis",
            "conf",
        ):
            candidate = path.join(self.path, f"{self.prefix}_{cache_file}.json")
            if not path.exists(candidate):
                continue
            try:
                with open(candidate) as fp:
                    records = json_load(fp)
            except (OSError, ValueError):
                continue
            for record in records if isinstance(records, list) else []:
                dn = record.get("distinguishedName") or record.get("dn")
                if not isinstance(dn, str):
                    continue
                components = [
                    component.split("=", 1)[1].strip()
                    for component in dn.split(",")
                    if component.split("=", 1)[0].strip().lower() == "dc"
                    and "=" in component
                ]
                if components:
                    base = ",".join(f"DC={component}" for component in components)
                    return ".".join(components), base, base

        raise self.CacheActiveDirectoryFileNotFoundException(
            f"{filename} not found and no domain DN was found in the cache"
        )
