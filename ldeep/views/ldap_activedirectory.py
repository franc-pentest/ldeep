from sys import exit, _getframe
from struct import unpack
from socket import inet_ntoa
from ssl import CERT_NONE
from uuid import UUID

from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD4, SHA1
from Cryptodome.Protocol.KDF import PBKDF2

from ldap3 import (
    Server,
    Connection,
    SASL,
    KERBEROS,
    NTLM,
    SUBTREE,
    ALL as LDAP3_ALL,
    BASE,
    DEREF_NEVER,
    TLS_CHANNEL_BINDING,
    ENCRYPT,
    MODIFY_REPLACE,
)
from ldap3 import SIMPLE
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.core.exceptions import (
    LDAPOperationResult,
    LDAPSocketOpenError,
    LDAPAttributeError,
    LDAPSocketSendError,
)
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
from ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups as addUsersInGroups,
)
from ldap3.extend.microsoft.removeMembersFromGroups import (
    ad_remove_members_from_groups as removeUsersInGroups,
)

import ldap3

from ldeep.views.activedirectory import (
    ActiveDirectoryView,
    ALL,
    validate_sid,
    validate_guid,
)
from ldeep.views.constants import (
    USER_ACCOUNT_CONTROL,
    DNS_TYPES,
    SAM_ACCOUNT_TYPE,
    PWD_PROPERTIES,
    TRUSTS_INFOS,
    WELL_KNOWN_SIDS,
    LOGON_SAM_LOGON_RESPONSE_EX,
    GMSA_ENCRYPTION_CONSTANTS,
)
from ldeep.utils.sddl import parse_ntSecurityDescriptor
from ldeep.utils.structure import Structure
from ldeep.views.structures import MSDS_MANAGEDPASSWORD_BLOB


# define an ldap3-compliant formatters
def format_userAccountControl(raw_value):
    try:
        val = int(raw_value)
        result = []
        for k, v in USER_ACCOUNT_CONTROL.items():
            if v & val:
                result.append(k)
        return " | ".join(result)
    except (TypeError, ValueError):  # expected exceptions↲
        pass
    except (
        Exception
    ):  # any other exception should be investigated, anyway the formatters return the raw_value
        pass
    return raw_value


# define an ldap3-compliant formatters
def format_samAccountType(raw_value):
    try:
        val = int(raw_value)
        result = []
        for k, v in SAM_ACCOUNT_TYPE.items():
            if v & val:
                result.append(k)
        return " | ".join(result)
    except (TypeError, ValueError):  # expected exceptions↲
        pass
    except (
        Exception
    ):  # any other exception should be investigated, anyway the formatter returns the raw_value
        pass
    return raw_value


# define an ldap3-compliant formatters
def format_pwdProperties(raw_value):
    try:
        val = int(raw_value)
        result = []
        for k, v in PWD_PROPERTIES.items():
            if v & val:
                result.append(k)
        return " | ".join(result)
    except (TypeError, ValueError):  # expected exceptions↲
        pass
    except (
        Exception
    ):  # any other exception should be investigated, anyway the formatter returns the raw_value
        pass
    return raw_value


# define an ldap3-compliant formatters
def format_trustsInfos(raw_value):
    try:
        val = int(raw_value)
        result = []
        for k, v in TRUSTS_INFOS.items():
            if v & val:
                result.append(k)
        return " | ".join(result)
    except (TypeError, ValueError):  # expected exceptions↲
        pass
    except (
        Exception
    ):  # any other exception should be investigated, anyway the formatter returns the raw_value
        pass
    return raw_value


# define an ldap3-compliant formatters
def format_dnsrecord(raw_value):
    databytes = raw_value[0:4]
    datalen, datatype = unpack("HH", databytes)
    data = raw_value[24 : 24 + datalen]
    for recordname, recordvalue in DNS_TYPES.items():
        if recordvalue == datatype:
            if recordname == "A":
                target = inet_ntoa(data)
            else:
                # how, ugly
                data = data.decode("unicode-escape", errors="replace")
                target = "".join([c for c in data if ord(c) > 31 or ord(c) == 9])
            return "%s %s" % (recordname, target)


def format_ad_timedelta(raw_value):
    """
    Convert a negative filetime value to an integer timedelta.
    """
    if isinstance(raw_value, bytes):
        raw_value = int(raw_value)
    return raw_value


# from http://www.kouti.com/tables/baseattributes.htm
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.8"] = (
    format_userAccountControl,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.302"] = (
    format_samAccountType,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.382"] = (
    format_dnsrecord,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.121"] = (
    format_sid,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.93"] = (
    format_pwdProperties,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.382"] = (
    format_dnsrecord,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.60"] = (
    format_ad_timedelta,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.74"] = (
    format_ad_timedelta,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.78"] = (
    format_ad_timedelta,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.470"] = (
    format_trustsInfos,
    None,
)
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.2.281"] = (
    parse_ntSecurityDescriptor,
    None,
)


class LdapActiveDirectoryView(ActiveDirectoryView):
    """
    Manage a LDAP connection to a LDAP Active Directory.
    """

    # Constant functions
    USER_LOCKED_FILTER = (
        lambda _: "(&(objectCategory=Person)(objectClass=user)(lockoutTime:1.2.840.113556.1.4.804:=4294967295))"
    )
    GROUPS_FILTER = lambda _: "(objectClass=group)"
    ZONES_FILTER = lambda _: "(&(objectClass=dnsZone)(!(dc=RootDNSServers)))"
    ZONE_FILTER = lambda _: "(objectClass=dnsNode)"
    SITES_FILTER = lambda _: "(objectClass=site)"
    SUBNET_FILTER = lambda _, s: f"(SiteObject={s})"
    PKI_FILTER = lambda _: "(objectClass=pKIEnrollmentService)"
    TEMPLATE_FILTER = lambda _: "(objectClass=pKICertificateTemplate)"
    PRIMARY_SCCM_FILTER = lambda _: "(cn=System Management)"
    DP_SCCM_FILTER = lambda _: "(objectClass=mssmsmanagementpoint)"
    USER_ALL_FILTER = lambda _: "(&(objectCategory=Person)(objectClass=user))"
    USER_SPN_FILTER = (
        lambda _: "(&(objectCategory=Person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
    )
    USER_ACCOUNT_CONTROL_FILTER = (
        lambda _, n: f"(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={n}))"
    )
    USER_ACCOUNT_CONTROL_FILTER_NEG = (
        lambda _, n: f"(&(objectCategory=Person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:={n})))"
    )
    ANR = lambda _, u: f"(anr={u})"
    DISTINGUISHED_NAME = lambda _, n: f"(distinguishedName={n})"
    COMPUTERS_FILTER = lambda _: "(objectClass=computer)"
    DC_FILTER = lambda _: "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
    GROUP_DN_FILTER = lambda _, g: f"(&(objectClass=group)(sAMAccountName={g}))"
    USER_DN_FILTER = (
        lambda _, u: f"(&(objectClass=user)(objectCategory=Person)(sAMAccountName={u}))"
    )
    ACCOUNTS_IN_GROUP_FILTER = lambda _, p, g: f"(|(primaryGroupID={p})(memberOf={g}))"
    ACCOUNT_IN_GROUPS_FILTER = lambda _, u: f"(sAMAccountName={u})"
    PRIMARY_GROUP_ID = lambda s, i: f"(objectSid={s.get_domain_sid()}-{i})"
    DOMAIN_INFO_FILTER = lambda _: "(objectClass=domain)"
    GPO_INFO_FILTER = lambda _: "(objectCategory=groupPolicyContainer)"
    PSO_INFO_FILTER = lambda _: "(objectClass=msDS-PasswordSettings)"
    TRUSTS_INFO_FILTER = lambda _: "(objectCategory=trustedDomain)"
    OU_FILTER = lambda _: "(|(objectClass=OrganizationalUnit)(objectClass=domain))"
    ENUM_USER_FILTER = (
        lambda _, n: f"(&(NtVer=\x06\x00\x00\x00)(AAC=\x10\x00\x00\x00)(User={n}))"
    )
    ALL_FILTER = lambda _: "(objectClass=*)"
    AUTH_POLICIES_FILTER = lambda _: "(objectClass=msDS-AuthNPolicy)"
    SILOS_FILTER = lambda _: "(objectClass=msDS-AuthNPolicySilo)"
    SILO_FILTER = lambda _, s: f"(&(objectClass=msDS-AuthNPolicySilo)(cn={s}))"
    LAPS_FILTER = (
        lambda _, s: f"(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*)(cn={s}))"
    )
    LAPS2_FILTER = (
        lambda _, s: f"(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*)(cn={s}))"
    )
    GMSA_FILTER = (
        lambda _, s: f"(&(ObjectClass=msDS-GroupManagedServiceAccount)(sAMAccountName={s}))"
    )
    SMSA_FILTER = lambda _: "(ObjectClass=msDS-ManagedServiceAccount)"
    BITLOCKERKEY_FILTER = lambda _: "(objectClass=msFVE-RecoveryInformation)"
    FSMO_DOMAIN_NAMING_FILTER = (
        lambda _: "(&(objectClass=crossRefContainer)(fSMORoleOwner=*))"
    )
    FSMO_SCHEMA_FILTER = lambda _: "(&(objectClass=dMD)(fSMORoleOwner=*))"
    FSMO_DOMAIN_FILTER = lambda _: "(fSMORoleOwner=*)"
    SHADOW_PRINCIPALS_FILTER = lambda _: "(objectClass=msDS-ShadowPrincipal)"
    UNCONSTRAINED_DELEGATION_FILTER = (
        lambda _: f"(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    )
    CONSTRAINED_DELEGATION_FILTER = lambda _: f"(msDS-AllowedToDelegateTo=*)"
    RESOURCE_BASED_CONSTRAINED_DELEGATION_FILTER = (
        lambda _: f"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    )
    ALL_DELEGATIONS_FILTER = (
        lambda _: f"(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
    )

    class ActiveDirectoryLdapException(Exception):
        pass

    def __init__(
        self,
        server,
        domain="",
        base="",
        username="",
        password="",
        ntlm="",
        pfx_file="",
        pfx_pass="",
        cert_pem="",
        key_pem="",
        method="NTLM",
        no_encryption=False,
        throttle=0,
        page_size=1000,
    ):
        """
        LdapActiveDirectoryView constructor.
        Initialize the connection with the LDAP server.

        Three authentication modes:
            * Kerberos (ldap3 will automatically retrieve the $KRB5CCNAME env variable)
            * NTLM (username + NTLM hash/password)
            * SIMPLE (username + password)

        @server: Server to connect and perform LDAP query to.
        @domain: Fully qualified domain name of the Active Directory domain.
        @base: Base for the LDAP queries.
        @username: Username to use for the authentication
        @password: Password to use for the authentication (for SIMPLE authentication)
        @ntlm: NTLM hash to use for the authentication (for NTLM authentication)
        @method: Either to use NTLM, SIMPLE, Kerberos or anonymous authentication.
        @no_encryption: Either the communication is encrypted or not.

        @throw ActiveDirectoryLdapException when the connection or the bind does not work.
        """
        self.username = username
        self.password = password
        self.ntlm = ntlm
        self.pfx_file = pfx_file
        self.pfx_pass = pfx_pass
        self.cert = cert_pem
        self.key = key_pem
        self.no_encryption = no_encryption
        self.server = server
        self.domain = domain
        self.hostnames = []
        self.throttle = throttle
        self.page_size = page_size

        self.set_controls()
        self.set_all_attributes()

        if method == "Certificate":
            if not self.server.startswith("ldaps"):
                # TODO start tls if ldap
                print(
                    "At this moment ldeep needs to use ldaps (use ldaps:// before the server parameter)"
                )
                exit(1)
            else:
                if self.pfx_file:
                    from cryptography.hazmat.primitives.serialization import pkcs12
                    from cryptography.hazmat.primitives import serialization

                    with open(pfx_file, "rb") as f:
                        pfxdata = f.read()
                    if self.pfx_pass:
                        from oscrypto.keys import (
                            parse_pkcs12,
                            parse_certificate,
                            parse_private,
                        )
                        from oscrypto.asymmetric import (
                            rsa_pkcs1v15_sign,
                            load_private_key,
                            dump_openssl_private_key,
                            dump_certificate,
                        )

                        if isinstance(self.pfx_pass, str):
                            pfxpass = self.pfx_pass.encode()
                        privkeyinfo, certinfo, _ = parse_pkcs12(
                            pfxdata, password=pfxpass
                        )
                        key = dump_openssl_private_key(privkeyinfo, self.pfx_pass)
                        cert = dump_certificate(certinfo, encoding="pem")
                    else:
                        privkey, cert, extra_certs = pkcs12.load_key_and_certificates(
                            pfxdata, None
                        )
                        key = privkey.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption(),
                        )
                        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
                    try:
                        from tempfile import gettempdir

                        key_path = f"{gettempdir()}/ldeep_key"
                        cert_path = f"{gettempdir()}/ldeep_cert"
                        with open(key_path, "wb") as f1, open(cert_path, "wb") as f2:
                            f1.write(key)
                            f2.write(cert)
                    except PermissionError:
                        print("Can't write key and cert to disk")
                        exit(1)
                    tls = ldap3.Tls(
                        local_private_key_file=key_path,
                        local_certificate_file=cert_path,
                        validate=CERT_NONE,
                    )
                else:
                    tls = ldap3.Tls(
                        local_private_key_file=self.key,
                        local_certificate_file=self.cert,
                        validate=CERT_NONE,
                    )
        else:
            tls = ldap3.Tls(validate=CERT_NONE)

        if self.server.startswith("ldaps"):
            server = Server(
                self.server,
                port=636,
                use_ssl=True,
                allowed_referral_hosts=[("*", True)],
                get_info=LDAP3_ALL,
                tls=tls,
            )
        else:
            server = Server(self.server, get_info=LDAP3_ALL)

        if method == "Kerberos":
            if self.server.startswith("ldaps"):
                self.ldap = Connection(
                    server, authentication=SASL, sasl_mechanism=KERBEROS
                )
            else:
                if self.no_encryption:
                    self.ldap = Connection(
                        server,
                        authentication=SASL,
                        sasl_mechanism=KERBEROS,
                    )
                else:
                    self.ldap = Connection(
                        server,
                        authentication=SASL,
                        sasl_mechanism=KERBEROS,
                        session_security=ENCRYPT,
                    )
        elif method == "Certificate":
            self.ldap = Connection(server)
        elif method == "anonymous":
            self.ldap = Connection(server)
        elif method == "NTLM":
            if password is not None:
                ntlm = password
            else:
                try:
                    lm, nt = ntlm.split(":")
                    lm = "aad3b435b51404eeaad3b435b51404ee" if not lm else lm
                    ntlm = f"{lm}:{nt}"
                except Exception as e:
                    print(e)
                    print("Incorrect hash, format is LMHASH:NTHASH")
                    exit(1)
            if self.server.startswith("ldaps"):
                if self.no_encryption:
                    self.ldap = Connection(
                        server,
                        user=f"{domain}\\{username}",
                        password=ntlm,
                        authentication=NTLM,
                        check_names=True,
                    )
                else:
                    self.ldap = Connection(
                        server,
                        user=f"{domain}\\{username}",
                        password=ntlm,
                        authentication=NTLM,
                        channel_binding=TLS_CHANNEL_BINDING,
                        check_names=True,
                    )
            else:
                if self.no_encryption:
                    self.ldap = Connection(
                        server,
                        user=f"{domain}\\{username}",
                        password=ntlm,
                        authentication=NTLM,
                        check_names=True,
                    )
                else:
                    self.ldap = Connection(
                        server,
                        user=f"{domain}\\{username}",
                        password=ntlm,
                        authentication=NTLM,
                        session_security=ENCRYPT,
                        check_names=True,
                    )
        elif method == "SIMPLE":
            if "." in domain:
                domain, _, _ = domain.partition(".")
            if not password:
                print("Password is required with simple bind (-p)")
                exit(1)
            self.ldap = Connection(
                server,
                user=f"{domain}\\{username}",
                password=password,
                authentication=SIMPLE,
                check_names=True,
            )

        try:
            if method == "Certificate":
                import os

                try:
                    self.ldap.open()
                    if self.pfx_file:
                        os.remove(key_path)
                        os.remove(cert_path)
                except LDAPSocketOpenError:
                    print(
                        "Cannot get private key data, corrupted key or wrong passphrase ?"
                    )
                    if self.pfx_file:
                        os.remove(key_path)
                        os.remove(cert_path)
                    exit(1)
                except Exception as e:
                    print(f"Unhandled Exception: {e}")
                    import traceback

                    traceback.print_exc()
                    exit(1)
            else:
                if not self.ldap.bind():
                    raise self.ActiveDirectoryLdapException(
                        f"Unable to bind to the LDAP server: {self.ldap.result['description']} ({self.ldap.result['message']})"
                    )
                if method == "anonymous":
                    anon_base = self.ldap.request["base"].split(",")
                    for i, item in enumerate(anon_base):
                        if item.startswith("DC="):
                            anon_base = ",".join(anon_base[i:])
                            break
                    self.ldap.search(
                        search_base=anon_base,
                        search_filter="(&(objectClass=domain))",
                        search_scope="SUBTREE",
                        attributes="*",
                    )

                    if len(self.ldap.entries) == 0:
                        raise self.ActiveDirectoryLdapException(
                            "Unable to retrieve information with anonymous bind"
                        )
        except LDAPSocketOpenError:
            raise self.ActiveDirectoryLdapException(
                f"Unable to open connection with {self.server}"
            )
        except LDAPSocketSendError:
            raise self.ActiveDirectoryLdapException(
                f"Unable to open connection with {self.server}, maybe LDAPS is not enabled ?"
            )

        self.base_dn = base or server.info.other["defaultNamingContext"][0]
        self.fqdn = ".".join(
            map(
                lambda x: x.replace("DC=", ""),
                filter(lambda x: x.startswith("DC="), self.base_dn.split(",")),
            )
        )
        self.search_scope = SUBTREE

    def set_controls(self, controls=[]):
        self.controls = controls

    def set_all_attributes(self, attributes=ALL):
        self.attributes = attributes

    def all_attributes(self):
        return self.attributes

    # Not used anymore
    def __query(self, ldapfilter, attributes=[], base=None, scope=None):
        """
        Perform a query to the LDAP server and return the results.

        @ldapfilter: The LDAP filter to query (see RFC 2254).
        @attributes: List of attributes to retrieved with the query.
        @base: Base to use during the request.
        @scope: Scope to use during the request.

        @return a list of records.
        """
        attributes = self.attributes if attributes == [] else attributes
        result_set = []
        try:
            entry_generator = self.ldap.extend.standard.paged_search(
                search_base=base or self.base_dn,
                search_filter=ldapfilter,
                search_scope=scope or self.search_scope,
                attributes=attributes,
                controls=self.controls,
                paged_size=self.page_size,
                generator=True,
            )

            for entry in entry_generator:
                if "dn" in entry:
                    d = entry["attributes"]
                    d["dn"] = entry["dn"]
                    result_set.append(d)

        except LDAPOperationResult as e:
            raise self.ActiveDirectoryLdapException(e)
        except LDAPAttributeError as e:
            if not _getframe().f_back.f_code.co_name == "get_laps":
                raise self.ActiveDirectoryLdapException(e)

        return result_set

    def query(self, ldapfilter, attributes=[], base=None, scope=None):
        """
        Perform a query to the LDAP server and return the results as a generator.

        @ldapfilter: The LDAP filter to query (see RFC 2254).
        @attributes: List of attributes to retrieved with the query.
        @base: Base to use during the request.
        @scope: Scope to use during the request.

        @return a generator yielding records.
        """
        attributes = self.attributes if attributes == [] else attributes
        # result_set = []
        try:
            entry_generator = self.ldap.extend.standard.paged_search(
                search_base=base or self.base_dn,
                search_filter=ldapfilter,
                search_scope=scope or self.search_scope,
                attributes=attributes,
                controls=self.controls,
                paged_size=self.page_size,
                generator=True,
            )

        except LDAPOperationResult as e:
            raise self.ActiveDirectoryLdapException(e)
        except LDAPAttributeError as e:
            if not _getframe().f_back.f_code.co_name == "get_laps":
                raise self.ActiveDirectoryLdapException(e)

        def result(x):
            if "dn" in x:
                d = x["attributes"]
                d["dn"] = x["dn"]
                return dict(d)

        return filter(lambda x: x is not None, map(result, entry_generator))

    def create_objecttype_guid_map(self):
        self.objecttype_guid_map = dict()
        sresult = self.ldap.extend.standard.paged_search(
            self.ldap.server.info.other["schemaNamingContext"][0],
            "(objectClass=*)",
            attributes=["name", "schemaidguid"],
        )
        for res in sresult:
            if res["attributes"]["schemaIDGUID"]:
                guid = str(UUID(bytes_le=res["attributes"]["schemaIDGUID"]))
                self.objecttype_guid_map[res["attributes"]["name"].lower()] = guid

    def get_domain_sid(self):
        """
        Return the current domain SID by issuing a LDAP request.

        @return the domain sid or None if a problem occurred.
        """
        results = list(self.query(self.DOMAIN_INFO_FILTER(), ["ObjectSid"]))

        if results:
            return results[0]["objectSid"]

        return None

    def resolve_sid(self, sid):
        """
        Two cases:
            * the SID is a WELL KNOWN SID and a local SID, the name of the corresponding account is returned;
            * else, the SID is search through the LDAP and the corresponding record is returned.

        @sid: the sid to search for.

        @throw ActiveDirectoryInvalidSID if the SID is not a valid SID.
        @return the record corresponding to the SID queried.
        """
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        elif validate_sid(sid):
            results = self.query(f"(&(ObjectSid={sid}))")
            if results:
                return results
        raise self.ActiveDirectoryInvalidSID(f"SID: {sid}")

    def resolve_guid(self, guid):
        """
        Return the LDAP record with the provided GUID.

        @guid: the guid to search for.

        @throw ActiveDirectoryInvalidGUID if the GUID is not a valid GUID.
        @return the record corresponding to the guid queried.
        """
        if validate_guid(guid):
            results = self.query(f"(&(ObjectGUID={guid}))")
            # Normally only one result should have been retrieved:
            if results:
                return results
        raise self.ActiveDirectoryInvalidGUID(f"GUID: {guid}")

    def get_sddl(self, ldapfilter, base=None, scope=None):
        """
        Perform a query to the LDAP server and return the results.

        @ldapfiler: The LDAP filter to query (see RFC 2254).
        @attributes: List of attributes to retrieved with the query.
        @base: Base to use during the request.
        @scope: Scope to use during the request.

        @return a list of records.
        """
        result_set = []
        try:
            result = self.ldap.search(
                search_base=base or self.base_dn,
                search_filter=ldapfilter,
                search_scope=scope or self.search_scope,
                attributes=["ntSecurityDescriptor"],
                controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],
            )

            if not result:
                raise self.ActiveDirectoryLdapException()
            else:
                for entry in self.ldap.response:
                    if "dn" in entry:
                        d = entry["attributes"]
                        d["dn"] = entry["dn"]
                        result_set.append(dict(d))

        except LDAPOperationResult as e:
            raise self.ActiveDirectoryLdapException(e)

        return result_set

    def get_gmsa(self, attributes, target):
        entries = list(self.query(self.GMSA_FILTER(target), attributes))

        constants = GMSA_ENCRYPTION_CONSTANTS
        iv = b"\x00" * 16

        for entry in entries:
            sam = entry["sAMAccountName"]
            data = entry["msDS-ManagedPassword"]
            try:
                readers = entry["msDS-GroupMSAMembership"]
            except Exception:
                readers = []
            # Find principals who can read the password
            if readers:
                try:
                    readers_sd = parse_ntSecurityDescriptor(readers)
                    entry["readers"] = []
                    for ace in readers_sd["DACL"]["ACEs"]:
                        try:
                            reader_object = list(self.resolve_sid(ace["SID"]))
                            if reader_object:
                                name = reader_object[0]["sAMAccountName"]
                                if "group" in reader_object[0]["objectClass"]:
                                    name += " (group)"
                                entry["readers"].append(name)
                            else:
                                entry["readers"].append(ace["SID"])
                        except Exception:
                            pass
                except Exception:
                    pass
            blob = MSDS_MANAGEDPASSWORD_BLOB()
            try:
                blob.fromString(data)
            except (TypeError, KeyError):
                continue

            password = blob["CurrentPassword"][:-2]

            # Compute NT hash
            hash = MD4.new()
            hash.update(password)
            nthash = hash.hexdigest()

            # Quick and dirty way to get the FQDN of the account's domain
            dc_list = []
            for s in entry["dn"].split(","):
                if s.startswith("DC="):
                    dc_list.append(s[3:])

            domain_fqdn = ".".join(dc_list)
            salt = f"{domain_fqdn.upper()}host{sam[:-1].lower()}.{domain_fqdn.lower()}"
            encryption_key = PBKDF2(
                password.decode("utf-16-le", "replace").encode(),
                salt.encode(),
                32,
                count=4096,
                hmac_hash_module=SHA1,
            )

            # Compute AES keys
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            first_part = cipher.encrypt(constants)
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            second_part = cipher.encrypt(first_part)
            aes256_key = first_part[:16] + second_part[:16]

            cipher = AES.new(encryption_key[:16], AES.MODE_CBC, iv)
            aes128_key = cipher.encrypt(constants[:16])

            entry["nthash"] = f"{nthash}"
            entry["aes128-cts-hmac-sha1-96"] = f"{aes128_key.hex()}"
            entry["aes256-cts-hmac-sha1-96"] = f"{aes256_key.hex()}"

        return entries

    def unlock(self, username):
        """
        Unlock an account.

        @username: the username associated to the account to unlock.

        @throw ActiveDirectoryLdapException if the account does not exist or the query returns more than one result.
        @return True if the account was successfully unlock or False otherwise.
        """
        results = list(self.query(self.USER_DN_FILTER(username)))
        if len(results) != 1:
            raise self.ActiveDirectoryLdapException("Zero or non uniq result")
        else:
            user = results[0]
            unlock = ad_unlock_account(self.ldap, user["dn"])
            # goddamn, return value is either True or str...
            return isinstance(unlock, bool)

    def modify_password(self, username, oldpassword, newpassword):
        """
        Change the password of `username`.

        @username: the username associated to the account to modify its password.
        @newpassword: the new password to apply.
        @oldpassword: the old password.

        @throw ActiveDirectoryLdapException if the account does not exist or the query returns more than one result.
        @return True if the account was successfully unlock or False otherwise.
        """
        results = list(self.query(self.USER_DN_FILTER(username)))
        if len(results) != 1:
            raise self.ActiveDirectoryLdapException("Zero or non uniq result")
        else:
            user = results[0]
            res = ad_modify_password(
                self.ldap, user["dn"], newpassword, old_password=oldpassword
            )
            if res == False:
                res = ad_modify_password(
                    self.ldap, user["dn"], newpassword, old_password=None
                )
            return res

    def add_user_to_group(self, user_dn, group_dn):
        """
        Add user to a group.

        @username: the username that will be added to the group. DN format: "CN=username,CN=Users,DC=CORP,DC=LOCAL"
        @group: the target group. DN format: "CN=group,CN=Users,DC=CORP,DC=LOCAL"

        @return True if the account was successfully added or False otherwise.
        """
        try:
            return addUsersInGroups(self.ldap, user_dn, group_dn)
        except ldap3.core.exceptions.LDAPInvalidDnError as e:
            print(f"Unhandled exception: {e}")
            # catch invalid group dn
            return False

    def remove_user_from_group(self, user_dn, group_dn):
        """
        Remove user from a group.

        @username: the username that will be removed from the group. dn format: "CN=username,CN=Users,DC=CORP,DC=LOCAL"
        @group: the target group. dn format: "CN=group,CN=Users,DC=CORP,DC=LOCAL"

        @return True if the account was successfully removed or if the account doesn't exist or False otherwise.
        """
        try:
            return removeUsersInGroups(self.ldap, user_dn, group_dn, fix=True)
        except ldap3.core.exceptions.LDAPInvalidDnError as e:
            print(f"Unhandled exception: {e}")
            # catch invalid group dn
            return False

    def change_uac(self, user_dn, uac):
        """
        Change userAccountControl.

        @username: the target user of UAC change
        @uac: the integer value for the userAccountControl. Ex: 512 for NORMAL_ACCOUNT

        @return True if the UAC was successfully changed or False otherwise.
        """
        try:
            return self.ldap.modify(
                user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]}
            )
        except ldap3.core.exceptions.LDAPInvalidDnError as e:
            print(f"Unhandled exception: {e}")
            # catch invalid group dn
            return False

    def user_exists(self, username):
        """
        Perform an LDAP ping to determine if the specified user exists.

        @username: the username to test.

        @return True if the user exists, False otherwise.
        """
        try:
            result = self.ldap.search(
                "",
                search_filter=self.ENUM_USER_FILTER(username),
                search_scope=BASE,
                attributes=["NetLogon"],
                dereference_aliases=DEREF_NEVER,
            )

            if not result:
                raise self.ActiveDirectoryLdapException()
            else:
                for entry in self.ldap.response:
                    attr = entry.get("raw_attributes")
                    if attr:
                        netlogon = attr.get("netlogon")
                        if (
                            netlogon
                            and len(netlogon[0]) > 1
                            and netlogon[0][:2] == LOGON_SAM_LOGON_RESPONSE_EX
                        ):
                            return True

        except LDAPOperationResult as e:
            raise self.ActiveDirectoryLdapException(e)

        return False

    def create_computer(self, computer, password):
        """
        Create a computer account on the domain.

        @computer: the name of the create computer.
        @password: the password of the computer to create.

        @return the result code on the add action
        """
        computer_dn = f"CN={computer},CN=Computers,{self.base_dn}"
        # Default computer SPNs
        spns = [
            f"HOST/{computer}",
            f"HOST/{computer}.{self.domain}",
            f"RestrictedKrbHost/{computer}",
            f"RestrictedKrbHost/{computer}.{self.domain}",
        ]

        ucd = {
            "dnsHostName": "%s.%s" % (computer, self.domain),
            "userAccountControl": 0x1000,  # WORKSTATION_TRUST_ACCOUNT
            "servicePrincipalName": spns,
            "sAMAccountName": computer,
            "unicodePwd": ('"%s"' % password).encode("utf-16-le"),
        }
        try:
            result = self.ldap.add(
                computer_dn,
                ["top", "person", "organizationalPerson", "user", "computer"],
                ucd,
            )
        except Exception as e:
            raise self.ActiveDirectoryLdapException(e)
        return result

    def create_user(self, user, password):
        """
        Create a user account on the domain.

        @user: the name of the create user.
        @password: the password of the user to create.

        @return the result code on the add action
        """
        user_dn = f"CN={user},CN=Users,{self.base_dn}"

        ucd = {
            "objectCategory": "CN=Person,CN=Schema,CN=Configuration,%s" % self.base_dn,
            "distinguishedName": user_dn,
            "cn": user,
            "sn": user,
            "givenName": user,
            "displayName": user,
            "name": user,
            "userAccountControl": 0x200,  # NORMAL_ACCOUNT (decimal value: 512)
            "accountExpires": 0,
            "sAMAccountName": user,
            "unicodePwd": ('"%s"' % password).encode("utf-16-le"),
        }
        try:
            result = self.ldap.add(
                user_dn, ["top", "person", "organizationalPerson", "user"], ucd
            )
        except Exception as e:
            raise self.ActiveDirectoryLdapException(e)
        return result
