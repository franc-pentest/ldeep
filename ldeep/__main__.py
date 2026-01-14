#!/usr/bin/env python3

import sys
from argparse import ArgumentParser
from base64 import b64encode
from datetime import date, datetime, timedelta
from json import dump as json_dump
from math import fabs
from re import compile as re_compile
from time import sleep
from uuid import UUID

from Cryptodome.Cipher import AES
from Cryptodome.Hash import MD4, SHA1
from Cryptodome.Protocol.KDF import PBKDF2

from commandparse import Command
from ldap3.core import results as coreResults
from ldap3.core.exceptions import LDAPAttributeError, LDAPObjectClassError
from ldap3.protocol.formatters.formatters import format_sid
from pyasn1.error import PyAsn1UnicodeDecodeError

from ldeep._version import __version__
from ldeep.utils import Logger, error, info
from ldeep.utils import resolve as utils_resolve
from ldeep.utils.sddl import parse_ntSecurityDescriptor
from ldeep.views.activedirectory import (
    ALL,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
    ActiveDirectoryView,
)
from ldeep.views.cache_activedirectory import CacheActiveDirectoryView
from ldeep.views.constants import (
    FILETIME_TIMESTAMP_FIELDS,
    FOREST_LEVELS,
    LDAP_SERVER_SD_FLAGS_OID_SEC_DESC,
    USER_ACCOUNT_CONTROL,
    GMSA_ENCRYPTION_CONSTANTS,
)
from ldeep.views.structures import MSDS_MANAGEDPASSWORD_BLOB
from ldeep.views.ldap_activedirectory import LdapActiveDirectoryView
from ldeep.utils.protections import checkProtections
from ldeep.utils import get_key_for_value


class Ldeep(Command):
    def __init__(self, query_engine, format="json"):
        self.engine = query_engine
        if format == "json":
            self.__display = self.__display_json

    def display(self, records, verbose=False, specify_group=True, extra_records=None):
        def default(o):
            if isinstance(o, date) or isinstance(o, datetime):
                return o.isoformat()
            elif isinstance(o, bytes):
                return b64encode(o).decode("ascii")

        if verbose:
            self.__display(records, default)
        else:
            k = 0
            for record in records:
                k += 1
                if "objectClass" not in record:
                    print(record)
                elif "group" in record["objectClass"]:
                    print(
                        record["sAMAccountName"] + (" (group)" if specify_group else "")
                    )
                elif "user" in record["objectClass"]:
                    print(record["sAMAccountName"])
                elif (
                    "organizationalUnit" in record["objectClass"]
                    or "domain" in record["objectClass"]
                    and extra_records
                ):
                    print(record["dn"])
                    if "gPLink" in record.keys():
                        if record["gPLink"]:
                            guids = re_compile("{[^}]+}")
                            gpo_guids = guids.findall(record["gPLink"])
                            if len(gpo_guids) > 0:
                                print("  [gPLink]:")
                                print(
                                    "    * {}".format(
                                        "\n    * ".join(
                                            [
                                                (
                                                    extra_records[g]
                                                    if g in extra_records
                                                    else g
                                                )
                                                for g in gpo_guids
                                            ]
                                        )
                                    )
                                )
                elif "groupPolicyContainer" in record["objectClass"]:
                    print(f"{record['cn']}: {record['displayName']}")
                elif "dnsNode" in record["objectClass"]:
                    if record["dc"] != "@":
                        for sub_record in record["dnsRecord"]:
                            print("{dc} {rec}".format(dc=record["dc"], rec=sub_record))
                    else:  # TODO: @ seem to be a special record, as well as DomainDnsZones, they seem to have the NS and A of domain controllers
                        for sub_record in record["dnsRecord"]:
                            print("{dc} {rec}".format(dc=record["dc"], rec=sub_record))
                elif "dnsZone" in record["objectClass"]:
                    print(record["dc"])
                elif (
                    "domainDNS" in record["objectClass"]
                    and "fSMORoleOwner" in record.keys()
                ):
                    try:
                        dc_name = record["fSMORoleOwner"].split(",")[1].split("=")[1]
                        domain_fqdn = ".".join(
                            record["fSMORoleOwner"].split(",")[-2:]
                        ).replace("DC=", "")
                    except:
                        print(f"Can't parse fSMORoleOwner {record['fSMORoleOwner']}")
                    print(f"PDC                      {dc_name}.{domain_fqdn}")
                elif "domainDNS" in record["objectClass"]:
                    for field, value in record.items():
                        if field == "objectClass":
                            continue
                        if field == "lockOutObservationWindow" and isinstance(
                            value, timedelta
                        ):
                            value = int(value.total_seconds()) / 60
                        elif (
                            field in FILETIME_TIMESTAMP_FIELDS.keys()
                            and type(value) == int
                        ):
                            value = int(
                                (fabs(float(value)) / 10**7)
                                / FILETIME_TIMESTAMP_FIELDS[field][0]
                            )
                        if field in FILETIME_TIMESTAMP_FIELDS.keys():
                            value = f"{value} {FILETIME_TIMESTAMP_FIELDS[field][1]}"
                        if field == "msDS-Behavior-Version" and isinstance(value, int):
                            value = FOREST_LEVELS[record[field]]
                        print(f"{field}: {value}")
                elif "domain" in record["objectClass"]:
                    print(record["dn"])
                elif (
                    "msDS-AuthNPolicy" in record["objectClass"]
                    or "msDS-AuthNPolicySilo" in record["objectClass"]
                ):
                    print(record["cn"])
                elif "msFVE-RecoveryInformation" in record["objectClass"]:
                    recovery_key = (
                        record["msFVE-RecoveryPassword"]
                        if record["msFVE-RecoveryPassword"]
                        else ""
                    )
                    if "," in record["dn"]:
                        if record["dn"].split(",")[1].upper().startswith("CN="):
                            computer_name = record["dn"].split(",")[1].split("=", 1)[1]
                    print(f"Machine: {computer_name} | Key: {recovery_key}")
                elif "crossRefContainer" in record["objectClass"]:
                    try:
                        dc_name = record["fSMORoleOwner"].split(",")[1].split("=")[1]
                        domain_fqdn = ".".join(
                            record["fSMORoleOwner"].split(",")[-2:]
                        ).replace("DC=", "")
                    except:
                        print(f"Can't parse fSMORoleOwner {record['fSMORoleOwner']}")
                    print(f"Domain naming master     {dc_name}.{domain_fqdn}")
                elif "dMD" in record["objectClass"]:
                    try:
                        dc_name = record["fSMORoleOwner"].split(",")[1].split("=")[1]
                        domain_fqdn = ".".join(
                            record["fSMORoleOwner"].split(",")[-2:]
                        ).replace("DC=", "")
                    except:
                        print(f"Can't parse fSMORoleOwner {record['fSMORoleOwner']}")
                    print(f"Schema master            {dc_name}.{domain_fqdn}")
                elif "rIDManager" in record["objectClass"]:
                    try:
                        dc_name = record["fSMORoleOwner"].split(",")[1].split("=")[1]
                        domain_fqdn = ".".join(
                            record["fSMORoleOwner"].split(",")[-2:]
                        ).replace("DC=", "")
                    except:
                        print(f"Can't parse fSMORoleOwner {record['fSMORoleOwner']}")
                    print(f"RID pool manager         {dc_name}.{domain_fqdn}")
                elif "infrastructureUpdate" in record["objectClass"]:
                    try:
                        dc_name = record["fSMORoleOwner"].split(",")[1].split("=")[1]
                        domain_fqdn = ".".join(
                            record["fSMORoleOwner"].split(",")[-2:]
                        ).replace("DC=", "")
                    except:
                        print(f"Can't parse fSMORoleOwner {record['fSMORoleOwner']}")
                    print(f"Infrastructure master    {dc_name}.{domain_fqdn}")
                # sccm primary and secondary sites
                elif (
                    "container" in record["objectClass"]
                    and "nTSecurityDescriptor" in record.keys()
                ):
                    for ace in record["nTSecurityDescriptor"]["DACL"]["ACEs"]:
                        # going for domain SID
                        if ace["SID"].startswith("S-1-5-21") and not ace[
                            "SID"
                        ].endswith(("-512", "-519")):
                            # looking for GenericAll ACE
                            if (
                                ace["Access Required"]["Write DAC"] == True
                                and ace["Access Required"]["Write Owner"] == True
                            ):
                                # resolve SID
                                try:
                                    sid = ace.get("SID")
                                    if not sid:
                                        continue
                                    res = next(self.engine.resolve_sid(sid))
                                    if "group" in res["objectClass"]:
                                        name = f"{res['sAMAccountName']} (group)"
                                    else:
                                        name = res["dNSHostName"]
                                    print(f"Primary/Secondary Site: {name}")
                                except:
                                    print(f"Primary/Secondary Site: {sid}")
                # sccm management points
                elif (
                    "mSSMSManagementPoint" in record["objectClass"]
                    and "connectionPoint" in record["objectClass"]
                ):
                    print(f"Management point: {record['dNSHostName']}")
                    print(f"  Default MP: {record['mSSMSDefaultMP']}")
                    print(f"  Site code: {record['mSSMSSiteCode']}")
                # potential sccm distribution points
                elif "connectionPoint" in record["objectClass"]:
                    print(
                        f"Potential distribution point: {','.join(record['distinguishedName'].split(',')[1:])}"
                    )

                if self.engine.page_size > 0 and k % self.engine.page_size == 0:
                    sleep(self.engine.throttle)

    def __display_json(self, records, default):
        need_comma_sep = False
        k = 0

        sys.stdout.write("[")
        for record in records:
            k += 1
            if need_comma_sep:
                sys.stdout.write(",\n")
            else:
                need_comma_sep = True

            json_dump(
                record,
                sys.stdout,
                ensure_ascii=False,
                default=default,
                sort_keys=True,
                indent=2,
            )

            if self.engine.page_size > 0 and k % self.engine.page_size == 0:
                sleep(self.engine.throttle)

        sys.stdout.write("]\n")
        sys.stdout.flush()

    # LISTERS #

    def list_server_info(self, kwargs):
        """
        List server info.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        info = self.engine.query_server_info()
        if verbose:
            self.display(info, True)
        else:
            for key, value in info[0]["raw"].items():
                print(key, value)

    def list_users(self, kwargs):
        """
        List users according to a filter.

        Arguments:
            @verbose:bool
                Results will contain full information
            @filter:string = ["all", "spn", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired", "passwordnotrequired", "nokrbpreauth", "reversible"]
        """
        verbose = kwargs.get("verbose", False)
        filter_ = kwargs.get("filter", "all")

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["sAMAccountName", "objectClass"]

        if filter_ == "all":
            results = self.engine.query(self.engine.USER_ALL_FILTER(), attributes)
        elif filter_ == "spn":
            results = self.engine.query(self.engine.USER_SPN_FILTER(), attributes)
        elif filter_ == "enabled":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER_NEG(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "ACCOUNTDISABLE")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "ACCOUNTDISABLE"
                ),
                attributes,
            )
        elif filter_ == "disabled":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "ACCOUNTDISABLE")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "ACCOUNTDISABLE"
                ),
                attributes,
            )
        elif filter_ == "locked":
            results = self.engine.query(self.engine.USER_LOCKED_FILTER(), attributes)
        elif filter_ == "nopasswordexpire":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "DONT_EXPIRE_PASSWORD")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "DONT_EXPIRE_PASSWORD"
                ),
                attributes,
            )
        elif filter_ == "passwordexpired":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "PASSWORD_EXPIRED")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "PASSWORD_EXPIRED"
                ),
                attributes,
            )
        elif filter_ == "passwordnotrequired":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "PASSWD_NOTREQD")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "PASSWD_NOTREQD"
                ),
                attributes,
            )
        elif filter_ == "nokrbpreauth":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(USER_ACCOUNT_CONTROL, "DONT_REQ_PREAUTH")
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "DONT_REQ_PREAUTH"
                ),
                attributes,
            )
        elif filter_ == "reversible":
            results = self.engine.query(
                self.engine.USER_ACCOUNT_CONTROL_FILTER(
                    get_key_for_value(
                        USER_ACCOUNT_CONTROL, "ENCRYPTED_TEXT_PWD_ALLOWED"
                    )
                    if isinstance(self.engine, LdapActiveDirectoryView)
                    else "ENCRYPTED_TEXT_PWD_ALLOWED"
                ),
                attributes,
            )
        else:
            return None

        self.display(results, verbose)

    def list_groups(self, kwargs):
        """
        List the groups.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["sAMAccountName", "objectClass"]

        self.display(
            self.engine.query(self.engine.GROUPS_FILTER(), attributes),
            verbose,
            specify_group=False,
        )

    def list_machines(self, kwargs):
        """
        List the machine accounts.

        Arguments:
            @verbose:bool
                Results will contain full information
            #machine:string = '*'
                Target machine
        """
        verbose = kwargs.get("verbose", False)
        machine = kwargs.get("machine", "*")

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["sAMAccountName", "objectClass"]

        self.display(
            self.engine.query(self.engine.COMPUTERS_FILTER(machine), attributes),
            verbose,
            specify_group=False,
        )

    def list_computers(self, kwargs):
        """
        List the computer hostnames and resolve them if --resolve is specify.

        Arguments:
            @resolve:bool
                A resolution on all computer names will be performed
            @dns:string
                An optional DNS server to use for the resolution
            @dc:bool
                List only domain controllers
        """
        resolve = "resolve" in kwargs and kwargs["resolve"]
        dns = kwargs.get("dns", "")
        dc = kwargs.get("dc", False)

        hostnames = []
        if not dc:
            results = self.engine.query(self.engine.COMPUTERS_FILTER("*"), ["name"])
        else:
            results = self.engine.query(self.engine.DC_FILTER(), ["name"])
        for result in results:
            if "name" in result:  # ugly
                computer_name = result["name"]
            else:
                computer_name = result[:-1]  # removing trailing $ sign

            hostnames.append(f"{computer_name}.{self.engine.fqdn}")
            # print only if resolution was not mandated
            if not resolve:
                print(f"{computer_name}.{self.engine.fqdn}")
        # do the resolution
        if resolve:
            for computer in utils_resolve(hostnames, dns):
                print(
                    "{addr:20} {name}".format(
                        addr=computer["address"], name=computer["hostname"]
                    )
                )

    def list_gmsa(self, kwargs):
        """
        List the gmsa accounts and retrieve secrets(NT + kerberos keys) if possible.

        Arguments:
            @verbose:bool
                Results will contain full information
            @target:string
                Retrieve only the information regarding the specified target account
        """
        verbose = kwargs.get("verbose", False)
        target = kwargs.get("target", "*")
        hidden_attributes = ["msDS-ManagedPassword"]

        if verbose:
            attributes = ALL + hidden_attributes
        else:
            attributes = [
                "sAMAccountName",
                "msDS-GroupMSAMembership",
                "objectClass",
            ] + hidden_attributes

        try:
            entries = list(
                self.engine.query(self.engine.GMSA_FILTER(target), attributes)
            )
        except LDAPAttributeError as e:
            error(f"{e}. The domain's functional level may be too old")
            entries = []

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
                            reader_object = list(self.engine.resolve_sid(ace["SID"]))
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

        if verbose:
            self.display(entries, verbose)
        else:
            for entry in entries:
                printed = False
                sam = entry["sAMAccountName"]
                for hash_format in (
                    "nthash",
                    "aes128-cts-hmac-sha1-96",
                    "aes256-cts-hmac-sha1-96",
                ):
                    hash = entry.get(hash_format)
                    if hash:
                        print(f"{sam}:{hash_format}:{hash}")
                        printed = True

                readers = entry.get("readers")
                if readers:
                    for reader in readers:
                        print(f"{sam}:reader:{reader}")
                        printed = True

                if not printed:
                    print(sam)

    def list_domain_policy(self, kwargs):
        """
        Return the domain policy.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = [
                "objectClass",
                "dc",
                "distinguishedName",
                "lockOutObservationWindow",
                "lockoutDuration",
                "lockoutThreshold",
                "maxPwdAge",
                "minPwdAge",
                "minPwdLength",
                "pwdHistoryLength",
                "pwdProperties",
                "ms-DS-MachineAccountQuota",
                "msDS-Behavior-Version",
            ]

        self.display(
            self.engine.query(self.engine.DOMAIN_INFO_FILTER(), attributes), verbose
        )

    def list_ou(self, kwargs):
        """
        Return the list of organizational units with linked GPO.

        Arguments:
            @verbose:bool
                Results will contain full information
            #ou:string = '*'
                Target ou
        """
        verbose = kwargs.get("verbose", False)
        ou = kwargs.get("ou", "*")

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["objectClass", "gPLink"]

        ous = self.engine.query(self.engine.OU_FILTER(ou), attributes)
        results = self.engine.query(
            self.engine.GPO_INFO_FILTER("*"), ["cn", "displayName"]
        )

        gpos = {}
        for gpo in results:
            gpos[gpo["cn"]] = gpo["displayName"]
        self.display(ous, verbose, extra_records=gpos)

    def list_gpo(self, kwargs):
        """
        Return the list of Group policy objects.

        Arguments:
            @verbose:bool
                Results will contain full information
            #gpo:string = '*'
                Target gpo
        """
        verbose = kwargs.get("verbose", False)
        gpo = kwargs.get("gpo", "*")

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["objectClass", "cn", "displayName"]

        self.display(
            self.engine.query(self.engine.GPO_INFO_FILTER(gpo), attributes), verbose
        )

    def list_pso(self, _):
        """
        List the Password Settings Objects.
        """
        FILETIME_TIMESTAMP_FIELDS = {
            "msDS-LockoutObservationWindow": (60, "mins"),
            "msDS-MinimumPasswordAge": (86400, "days"),
            "msDS-MaximumPasswordAge": (86400, "days"),
            "msDS-LockoutDuration": (60, "mins"),
        }

        FIELDS_TO_PRINT = [
            "cn",
            "msDS-PasswordReversibleEncryptionEnabled",
            "msDS-PasswordSettingsPrecedence",
            "msDS-MinimumPasswordLength",
            "msDS-PasswordHistoryLength",
            "msDS-PasswordComplexityEnabled",
            "msDS-LockoutObservationWindow",
            "msDS-LockoutDuration",
            "msDS-LockoutThreshold",
            "msDS-MinimumPasswordAge",
            "msDS-MaximumPasswordAge",
            "msDS-PSOAppliesTo",
        ]

        psos = self.engine.query(self.engine.PSO_INFO_FILTER())
        for policy in psos:
            for field in FIELDS_TO_PRINT:
                val = policy.get(field, None)
                if val is None:
                    continue
                if isinstance(val, list):
                    targets = []
                    for target in val:
                        targets.append(target)
                    val = " | ".join(targets)
                else:
                    val = policy[field]

                if field in FILETIME_TIMESTAMP_FIELDS.keys():
                    val = int(
                        (fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0]
                    )
                    val = "{val} {typ}".format(
                        val=val, typ=FILETIME_TIMESTAMP_FIELDS[field][1]
                    )
                print("{field}: {val}".format(field=field, val=val))

        # enum principals affected by PSO if unpriv
        results = []
        # users
        attributes = ["objectClass", "cn", "sAMAccountName", "msDS-PSOApplied"]
        entries = self.engine.query(self.engine.USER_ALL_FILTER(), attributes)
        for entry in entries:
            psos = entry.get("msDS-PSOApplied")
            if psos:
                for pso in psos:
                    pso = next(
                        map(
                            lambda x: x.replace("CN=", ""),
                            filter(lambda x: x.startswith("CN="), pso.split(",")),
                        )
                    )
                    name = entry.get("sAMAccountName")
                    results.append(f"{name}:{pso}")

        # groups
        entries = self.engine.query(self.engine.GROUPS_FILTER(), attributes)
        for entry in entries:
            psos = entry.get("msDS-PSOApplied")
            if psos:
                for pso in psos:
                    pso = next(
                        map(
                            lambda x: x.replace("CN=", ""),
                            filter(lambda x: x.startswith("CN="), pso.split(",")),
                        )
                    )
                    name = entry.get("sAMAccountName")
                    results.append(f"{name}:{pso}")

        if results:
            print("Unprivileged enumeration:")
            print("principal:pso_name")
            print(*results, sep="\n")

    def list_trusts(self, kwargs):
        """
        List the domain's trust relationships.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if verbose:
            attributes = self.engine.all_attributes()

        results = self.engine.query(self.engine.TRUSTS_INFO_FILTER())

        if verbose:
            self.display(results, verbose)
            return

        ATTRIBUTE_TRANSLATION = {
            "trustDirection": {
                0x00000003: "bidirectional",
                0x00000002: "outbound",
                0x00000001: "inbound",
                0x00000000: "disabled",
            },
            "trustType": {
                0x00000001: "Non running Windows domain",
                0x00000002: "Windows domain running Active Directory",
                0x00000003: "Non Windows domain",
            },
        }

        trusts = []
        for result in results:
            for key in ATTRIBUTE_TRANSLATION:
                if key in result:
                    result[key] = ATTRIBUTE_TRANSLATION[key][int(result[key])]
            trusts.append(result)

        FIELDS_TO_PRINT = [
            "dn",
            "cn",
            "securityIdentifier",
            "name",
            "trustDirection",
            "trustPartner",
            "trustType",
            "trustAttributes",
            "flatName",
        ]

        for result in trusts:
            for field in FIELDS_TO_PRINT:
                if field in result:
                    val = result[field]
                    print("{field}: {val}".format(field=field, val=val))
            print("")

    def list_zones(self, kwargs):
        """
        List the DNS zones configured in the Active Directory.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if not verbose:
            attributes = ["dc", "objectClass"]
        else:
            attributes = ALL

        first = True
        displayed = []
        for name, basePre, baseSuf in (
            ("Domain", "CN=MicrosoftDNS,DC=DomainDnsZones", self.engine.base_dn),
            ("Forest", "CN=MicrosoftDNS,DC=ForestDnsZones", self.engine.forest_base_dn),
            ("Legacy", "CN=MicrosoftDNS,CN=System", self.engine.base_dn),
        ):
            try:
                zones = list(
                    self.engine.query(
                        self.engine.ZONES_FILTER(),
                        attributes,
                        base=f"{basePre},{baseSuf}",
                    )
                )

                if len(zones) > 0:
                    if verbose:
                        displayed.extend(zones)
                    else:
                        if first:
                            first = False
                        else:
                            print()
                        info(f"{name} zones:")
                        self.display(zones)
            except:
                error(f"Can't list {name.lower()} zones", close_array=verbose)

        if verbose:
            self.display(displayed, True)
        elif first:
            info("No zones found")

    def list_dns_records(self, kwargs):
        """
        List the DNS records configured in the Active Directory.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if not verbose:
            attributes = ["dc", "dnsRecord", "objectClass"]
        else:
            attributes = ALL

        first = True
        displayed = []
        for name, basePre, baseSuf in (
            ("Domain", "CN=MicrosoftDNS,DC=DomainDnsZones", self.engine.base_dn),
            ("Forest", "CN=MicrosoftDNS,DC=ForestDnsZones", self.engine.forest_base_dn),
            ("Legacy", "CN=MicrosoftDNS,CN=System", self.engine.base_dn),
        ):
            try:
                results = list(
                    self.engine.query(
                        self.engine.ZONE_FILTER(),
                        attributes,
                        base=f"{basePre},{baseSuf}",
                    )
                )

            except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
                error(f"Can't list {name.lower()} records", close_array=verbose)
            else:
                filteredResults = []
                for result in results:
                    result["dnsRecord"] = list(
                        filter(lambda rec: rec != "", result["dnsRecord"])
                    )
                    if len(result["dnsRecord"]) > 0:
                        filteredResults.append(result)

                if len(filteredResults) > 0:
                    if verbose:
                        displayed.extend(filteredResults)
                    else:
                        if first:
                            first = False
                        else:
                            print()
                        info(f"{name} records:")
                        self.display(filteredResults, verbose)

        if verbose:
            self.display(displayed, True)
        elif first:
            info("No records found")

    def list_pkis(self, kwargs):
        """
        List pkis.
        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = [
                "cACertificateDN",
                "certificateTemplates",
                "dNSHostName",
                "name",
            ]

        ca_info = self.engine.query(
            self.engine.PKI_FILTER(),
            attributes,
            base=(
                None
                if isinstance(self.engine, CacheActiveDirectoryView)
                else ",".join(
                    [
                        "CN=Enrollment Services,CN=Public Key Services,CN=Services",
                        self.engine.ldap.server.info.other[
                            "configurationNamingContext"
                        ][0],
                    ]
                )
            ),
        )
        ca_info = list(ca_info)
        if verbose:
            self.display(ca_info, verbose)
            return
        elif isinstance(ca_info, filter) or isinstance(ca_info[0], dict):
            ca_number = 1
            print("Certificate Authorities")
            for ca in ca_info:
                print(ca_number)
                print(f"{'CA Name':<30}: {ca.get('name')}")
                print(f"{'DNS Name':<30}: {ca.get('dNSHostName')}")
                print(f"{'Certificate Subject':<30}: {ca.get('cACertificateDN')}")
                if ca.get("certificateTemplates"):
                    print(f"{'Associated Templates':<30}")
                    for template in ca.get("certificateTemplates"):
                        print(f"{' ' * 32}{template}")
                ca_number += 1
        else:
            print("\n".join(ca_info))

    def list_sccm(self, kwargs):
        """
        List servers related to SCCM infrastructure (Primary/Secondary Sites and Distribution Points).
        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        # Primary/Secondary Sites
        self.engine.set_controls(LDAP_SERVER_SD_FLAGS_OID_SEC_DESC)
        if verbose:
            attributes = ["*", "+", "ntSecurityDescriptor"]
        else:
            attributes = ["objectClass", "ntSecurityDescriptor"]

        results = self.engine.query(
            self.engine.PRIMARY_SCCM_FILTER(),
            attributes,
        )

        try:
            self.display(results, verbose)
        except Exception as e:
            error(e, close_array=verbose)

        # Management points
        self.engine.set_controls()
        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = [
                "objectClass",
                "dNSHostName",
                "mSSMSDefaultMP",
                "mSSMSSiteCode",
            ]

        results = self.engine.query(
            self.engine.MP_SCCM_FILTER(),
            attributes,
        )

        try:
            self.display(results, verbose)
        except Exception as e:
            error(f"{e}. Can't find SCCM management points", close_array=verbose)

        # Distribution points
        if verbose:
            attributes = self.engine.all_attributes()
        else:
            attributes = ["objectClass", "distinguishedName"]

        results = self.engine.query(
            self.engine.DP_SCCM_FILTER(),
            attributes,
        )

        try:
            self.display(results, verbose)
        except Exception as e:
            error(f"{e}. Can't find SCCM distribution points", close_array=verbose)

    def list_subnets(self, kwargs):
        """
        List sites and associated subnets.
        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)

        if not verbose:
            attributes = ["distinguishedName", "name", "description"]
        else:
            attributes = ALL

        if verbose:
            self.display(
                self.engine.query(
                    self.engine.SITES_FILTER(),
                    attributes,
                    base=",".join(["CN=Configuration", self.engine.base_dn]),
                ),
                verbose,
            )
        else:
            entries = self.engine.query(
                self.engine.SITES_FILTER(),
                attributes,
                base=",".join(["CN=Configuration", self.engine.base_dn]),
            )

            site_dn = ""
            site_name = ""
            site_description = ""
            subnet_name = ""
            subnet_description = ""
            for entry in entries:
                site_dn = (
                    entry["distinguishedName"] if entry["distinguishedName"] else ""
                )
                site_name = entry["name"] if entry["name"] else ""
                site_description = (
                    entry["description"][0] if entry["description"] else ""
                )
                subnet_entries = self.engine.query(
                    self.engine.SUBNET_FILTER(site_dn),
                    attributes,
                    base=",".join(["CN=Sites,CN=Configuration", self.engine.base_dn]),
                )
                for subnet in subnet_entries:
                    subnet_name = subnet["name"] if subnet["name"] else ""
                    subnet_description = (
                        subnet["description"][0] if subnet["description"] else ""
                    )
                    servers = self.engine.query(
                        "(objectClass=server)", ["cn"], base=site_dn
                    )
                    servers_list = [d["cn"] for d in servers]

                    output = "Site: {}".format(site_name)
                    output += " | Subnet: {}".format(subnet_name) if subnet_name else ""
                    output += (
                        " | Site description: {}".format(site_description)
                        if site_description
                        else ""
                    )
                    output += (
                        " | Subnet description: {}".format(subnet_description)
                        if subnet_description
                        else ""
                    )
                    output += (
                        " | Servers: {}".format(", ".join(servers_list))
                        if servers_list
                        else ""
                    )
                    print(output)

    def list_conf(self, kwargs):
        """
        Dump the configuration partition of the Active Directory.
        """
        self.display(
            self.engine.query(
                self.engine.ALL_FILTER(),
                ALL,
                base=",".join(["CN=Configuration", self.engine.base_dn]),
            ),
            True,
        )

    def list_schema(self, kwargs):
        """
        Dump the schema partition of the Active Directory.
        """
        self.display(
            self.engine.query(
                self.engine.ALL_FILTER(),
                ALL,
                base=",".join(["CN=Schema,CN=Configuration", self.engine.base_dn]),
            ),
            True,
        )

    def list_auth_policies(self, kwargs):
        """
        List the authentication policies configured in the Active Directory.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)
        attributes = ALL if verbose else ["cn", "objectClass"]

        try:
            self.display(
                self.engine.query(
                    self.engine.AUTH_POLICIES_FILTER(),
                    attributes,
                    base=",".join(
                        [
                            "CN=AuthN Policy Configuration,CN=Services,CN=Configuration",
                            self.engine.base_dn,
                        ]
                    ),
                ),
                verbose,
            )
        except LDAPObjectClassError as e:
            error(
                f"{e}. The domain's functional level may be too old",
                close_array=verbose,
            )

    def list_silos(self, kwargs):
        """
        List the silos configured in the Active Directory.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)
        attributes = ALL if verbose else ["cn", "objectClass"]

        try:
            self.display(
                self.engine.query(
                    self.engine.SILOS_FILTER(),
                    attributes,
                    base=",".join(
                        [
                            "CN=AuthN Policy Configuration,CN=Services,CN=Configuration",
                            self.engine.base_dn,
                        ]
                    ),
                ),
                verbose,
            )
        except LDAPObjectClassError as e:
            error(
                f"{e}. The domain's functional level may be too old",
                close_array=verbose,
            )

    def list_smsa(self, kwargs):
        """
        List the smsa accounts and the machines they are associated with.

        Arguments:
            @verbose:bool
                Results will contain full information
        """

        verbose = kwargs.get("verbose", False)
        attributes = ALL if verbose else ["sAMAccountName", "msDS-HostServiceAccountBL"]
        entries = self.engine.query(self.engine.SMSA_FILTER(), attributes)

        try:
            if verbose:
                self.display(entries, verbose)
            else:
                for entry in entries:
                    sam = entry["sAMAccountName"]
                    for host in entry["msDS-HostServiceAccountBL"]:
                        print(f"{sam}:{host}")
        except LDAPObjectClassError as e:
            error(
                f"{e}. The domain's functional level may be too old",
                close_array=verbose,
            )

    def list_shadow_principals(self, kwargs):
        """
        List the shadow principals and the groups associated with.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        try:
            verbose = kwargs.get("verbose", False)
            attributes = ALL if verbose else ["member", "msDS-ShadowPrincipalSid"]
            base = ",".join(
                [
                    "CN=Shadow Principal Configuration,CN=Services,CN=Configuration",
                    self.engine.base_dn,
                ]
            )
            entries = self.engine.query(
                self.engine.SHADOW_PRINCIPALS_FILTER(),
                attributes,
                base=(
                    None if isinstance(self.engine, CacheActiveDirectoryView) else base
                ),
            )

            if verbose:
                self.display(entries, verbose)
            else:
                for entry in entries:
                    for user in entry.get("member", []):
                        print(
                            f"User {entry['member'][0]} added to Group {format_sid(entry['msDS-ShadowPrincipalSid'])}"
                        )
        except (LDAPAttributeError, LDAPObjectClassError) as e:
            error(
                f"{e}. The domain's functional level may be too old",
                close_array=verbose,
            )

    def list_fsmo(self, kwargs):
        """
        List FSMO roles.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)
        if verbose:
            attributes = ALL
        else:
            attributes = ["objectClass", "fSMORoleOwner"]

        results = self.engine.query(
            self.engine.FSMO_DOMAIN_NAMING_FILTER(),
            attributes,
            base=",".join(["CN=Partitions,CN=Configuration", self.engine.base_dn]),
        )

        try:
            self.display(results, verbose)
        except Exception as e:
            error(f"{e}", close_array=verbose)

        results = self.engine.query(
            self.engine.FSMO_SCHEMA_FILTER(),
            attributes,
            base=",".join(["CN=Schema,CN=Configuration", self.engine.base_dn]),
        )

        try:
            self.display(results, verbose)
        except Exception as e:
            error(f"{e}", close_array=verbose)

        results = self.engine.query(self.engine.FSMO_DOMAIN_FILTER(), attributes)

        try:
            self.display(results, verbose)
        except Exception as e:
            error(f"{e}", close_array=verbose)

    def list_delegations(self, kwargs):
        """
        List accounts configured for any kind of delegation.

        Arguments:
            @verbose:bool
                Results will contain full information
            @filter:string = ["all", "unconstrained", "constrained", "rbcd"]
        """
        verbose = kwargs.get("verbose", False)
        filter_ = kwargs.get("filter", "all")

        attributes = ALL if verbose else ["sAMAccountName", "userAccountControl"]

        try:
            if filter_ == "all":
                if not verbose:
                    attributes.extend(
                        [
                            "msDS-AllowedToDelegateTo",
                            "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        ]
                    )
                entries = self.engine.query(
                    self.engine.ALL_DELEGATIONS_FILTER(), attributes
                )
            elif filter_ == "unconstrained":
                entries = self.engine.query(
                    self.engine.UNCONSTRAINED_DELEGATION_FILTER(), attributes
                )
            elif filter_ == "constrained":
                if not verbose:
                    attributes.append("msDS-AllowedToDelegateTo")
                entries = self.engine.query(
                    self.engine.CONSTRAINED_DELEGATION_FILTER(), attributes
                )
            elif filter_ == "rbcd":
                if not verbose:
                    attributes.append("msDS-AllowedToActOnBehalfOfOtherIdentity")
                entries = self.engine.query(
                    self.engine.RESOURCE_BASED_CONSTRAINED_DELEGATION_FILTER(),
                    attributes,
                )
            else:
                return None

            # Force the actual LDAP request to be done there, to catch potential LDAPAttributeError errors related
            # to an old domain functional level. We don't want to miss the other delegation types because of RBCD
            entries = list(entries)
        except LDAPAttributeError as e:
            if filter_ == "rbcd":
                error(f"{e}. The domain's functional level may be too old")
                return

            # If "delegations all" was used, redo the request without RBCD
            if "msDS-AllowedToActOnBehalfOfOtherIdentity" in attributes:
                attributes = list(
                    filter(
                        lambda a: a != "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        attributes,
                    )
                )
                entries = self.engine.query(
                    self.engine.ALL_DELEGATIONS_FILTER(), attributes
                )

        if verbose:
            self.display(entries, verbose)
        else:
            for entry in entries:
                try:
                    uac = entry["userAccountControl"]
                    sam = entry["sAMAccountName"]
                    delegate = entry.get("msDS-AllowedToDelegateTo")
                    allowed_to_act = entry.get(
                        "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    )
                    if (
                        filter_ == "unconstrained" or filter_ == "all"
                    ) and "TRUSTED_FOR_DELEGATION" in uac:
                        print(f"{sam}:unconstrained:")
                    if (filter_ == "constrained" or filter_ == "all") and delegate:
                        transition = (
                            "with"
                            if "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac
                            else "without"
                        )
                        for a in delegate:
                            print(
                                f"{sam}:constrained {transition} protocol transition:{a}"
                            )
                    if (filter_ == "rbcd" or filter_ == "all") and allowed_to_act:
                        sd = parse_ntSecurityDescriptor(allowed_to_act)
                        for ace in sd["DACL"]["ACEs"]:
                            try:
                                sid = ace.get("SID")
                                if not sid:
                                    continue
                                res = self.engine.resolve_sid(sid)
                                name = next(res)["sAMAccountName"]
                                print(f"{name}:rbcd:{sam}")
                            except Exception:
                                print(f"{sid}:rbcd:{sam}")
                except Exception:
                    continue

    def list_bitlockerkeys(self, kwargs):
        """
        Extract the bitlocker recovery keys.

        Arguments:
            @verbose:bool
                Results will contain full information
        """
        verbose = kwargs.get("verbose", False)
        if verbose:
            attributes = ALL
        else:
            attributes = ["objectClass", "msFVE-RecoveryPassword"]

        try:
            self.display(
                self.engine.query(self.engine.BITLOCKERKEY_FILTER(), attributes),
                verbose,
            )
        except LDAPObjectClassError as e:
            error(
                f"{e}. The domain's functional level may be too old",
                close_array=verbose,
            )

    # GETTERS #

    def get_zone(self, kwargs):
        """
        Return the records of a DNS zone.

        Arguments:
            #dns_zone:string
                DNS zone to retrieve records
        """
        dns_zone = kwargs["dns_zone"]

        first = True
        for name, basePre, baseSuf in (
            ("Domain", "CN=MicrosoftDNS,DC=DomainDnsZones", self.engine.base_dn),
            ("Forest", "CN=MicrosoftDNS,DC=ForestDnsZones", self.engine.forest_base_dn),
            ("Legacy", "CN=MicrosoftDNS,CN=System", self.engine.base_dn),
        ):
            try:
                results = list(
                    self.engine.query(
                        self.engine.ZONE_FILTER(),
                        base=f"DC={dns_zone},{basePre},{baseSuf}",
                    )
                )
            except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
                error(e)
            else:
                filteredResults = []
                for result in results:
                    result["dnsRecord"] = list(
                        filter(lambda rec: rec != "", result["dnsRecord"])
                    )
                    if len(result["dnsRecord"]) > 0:
                        filteredResults.append(result)

                if len(filteredResults) > 0:
                    if first:
                        first = False
                    else:
                        print()
                    info(f"{name} records:")
                    self.display(filteredResults)

        if first:
            info("No records found")

    def get_membersof(self, kwargs):
        """
        List the members of `group`.

        Arguments:
            @verbose:bool
                Results will contain full information
            @recursive:bool
                List recursively the members of `group`
            #group:string
                Group to list members
        """
        user_prefix = "[USER] "
        group_prefix = "[GROUP] "

        group = kwargs["group"]
        verbose = kwargs.get("verbose", False)
        recursive = kwargs.get("recursive", False)

        already_printed = set()

        # Recursive function in case the recursive flag is set
        def lookup_members(dn, primary_group_id, leading_sp, already_treated: set):
            # Check if the current group is already processed
            if dn in already_treated:
                return already_treated

            # Mark the current group as processed
            already_treated.add(dn)

            # Query for members of the group
            results = self.engine.query(
                self.engine.ACCOUNTS_IN_GROUP_FILTER(primary_group_id, dn)
            )

            if results:
                for result in results:
                    member_dn = result["distinguishedName"]
                    object_class = result["objectClass"]
                    member_primary_group_id = result["objectSid"].split("-")[-1]

                    if any(
                        cls in object_class
                        for cls in [
                            "user",
                            "computer",
                            "msDS-ManagedServiceAccount",
                            "msDS-GroupManagedServiceAccount",
                        ]
                    ):
                        print(
                            "{g:>{width}}".format(
                                g=user_prefix + member_dn,
                                width=leading_sp + len(user_prefix + member_dn),
                            )
                        )
                    elif "group" in object_class:
                        print(
                            "{g:>{width}}".format(
                                g=group_prefix + member_dn,
                                width=leading_sp + len(group_prefix + member_dn),
                            )
                        )
                        # Recurse into nested groups
                        lookup_members(
                            member_dn,
                            member_primary_group_id,
                            leading_sp + 4,
                            already_treated,
                        )

            return already_treated

        # Getting the group DN and primary ID
        results = list(
            self.engine.query(
                self.engine.GROUP_DN_FILTER(group), ["distinguishedName", "objectSid"]
            )
        )

        # Checking first that the length of the results is > 0 (at least one entry)
        if len(list(results)) != 0:
            group_dn = results[0]["distinguishedName"]
            primary_group_id = results[0]["objectSid"].split("-")[-1]

            # As there is a result, we get the users within the group
            results = self.engine.query(
                self.engine.ACCOUNTS_IN_GROUP_FILTER(primary_group_id, group_dn)
            )

            # Iterating over each user / group belonging to the group
            for result in results:
                # Getting DN and ObjectClass attributes of the user / group
                dn = result["distinguishedName"]
                object_class = result["objectClass"]

                if any(
                    cls in object_class
                    for cls in [
                        "user",
                        "computer",
                        "msDS-ManagedServiceAccount",
                        "msDS-GroupManagedServiceAccount",
                    ]
                ):
                    print(user_prefix + dn)
                elif "group" in object_class:
                    print(group_prefix + dn)
                    if recursive:
                        primary_group_id = result["objectSid"].split("-")[-1]
                        s = lookup_members(dn, primary_group_id, 4, already_printed)
                        already_printed.union(s)

            self.display(results, verbose)

        # If the list's length == 0 it means no entry were found and therefore the group does not exist
        else:
            error("Group '{group}' does not exist".format(group=group))

    def get_memberships(self, kwargs):
        """
        List the group for which `account` belongs to.

        Arguments:
            #account:string
                User to list memberships
            @recursive:bool
                List recursively the groups
        """
        account = kwargs["account"]
        recursive = kwargs.get("recursive", False)

        already_printed = set()

        def lookup_groups(dn, leading_sp, already_treated):
            results = self.engine.query(
                self.engine.DISTINGUISHED_NAME(dn), ["memberOf", "primaryGroupID"]
            )
            for result in results:
                if "memberOf" in result:
                    for group_dn in result["memberOf"]:
                        if group_dn not in already_treated:
                            print(
                                "{g:>{width}}".format(
                                    g=group_dn, width=leading_sp + len(group_dn)
                                )
                            )
                            already_treated.add(group_dn)
                            lookup_groups(group_dn, leading_sp + 4, already_treated)

                if "primaryGroupID" in result and result["primaryGroupID"]:
                    pid = result["primaryGroupID"]
                    results = list(self.engine.query(self.engine.PRIMARY_GROUP_ID(pid)))
                    if results:
                        already_treated.add(results[0]["dn"])

            return already_treated

        results = self.engine.query(
            self.engine.ACCOUNT_IN_GROUPS_FILTER(account),
            ["memberOf", "primaryGroupID"],
        )
        for result in results:
            if "memberOf" in result:
                for group_dn in result["memberOf"]:
                    print(group_dn)
                    if recursive:
                        already_printed.add(group_dn)
                        s = lookup_groups(group_dn, 4, already_printed)
                        already_printed.union(s)

            # for some reason, when we request an attribute which is not set on an object,
            # ldap3 returns an empty list as the value of this attribute
            if "primaryGroupID" in result and result["primaryGroupID"] != []:
                pid = result["primaryGroupID"]
                results = list(self.engine.query(self.engine.PRIMARY_GROUP_ID(pid)))
                if results:
                    dn = results[0]["dn"]
                    print(dn)
                    if recursive:
                        already_printed.add(dn)
                        s = lookup_groups(dn, 4, already_printed)
                        already_printed.union(s)

        if len(list(results)) == 0:
            error("User {account} does not exists".format(account=account))

    def get_from_sid(self, kwargs):
        """
        Return the object associated with the given `sid`.

        Arguments:
            @verbose:bool
                Results will contain full information
            #sid:string
                SID to search for
        """
        sid = kwargs["sid"]
        verbose = kwargs.get("verbose", False)

        try:
            result = self.engine.resolve_sid(sid)
            if isinstance(result, str):
                print(result)
            else:
                self.display(result, verbose)
        except ActiveDirectoryView.ActiveDirectoryInvalidSID:
            error("Invalid SID")

    def get_from_guid(self, kwargs):
        """
        Return the object associated with the given `guid`.

        Arguments:
            @verbose:bool
                Results will contain full information
            #guid:string
                GUID to search for
        """
        guid = kwargs["guid"]
        verbose = kwargs.get("verbose", False)

        try:
            self.display(self.engine.resolve_guid(guid), verbose)
        except ActiveDirectoryView.ActiveDirectoryLdapInvalidGUID:
            error("Invalid GUID")

    def get_laps(self, kwargs):
        """
        Return the LAPS passwords. If a target is specified, only retrieve the LAPS password for this one.

        Arguments:
            @verbose:bool
                Results will contain full information
            @computer:string
                Target computer where LAPS is set
        """
        computer = kwargs.get("computer", "*")
        verbose = kwargs.get("verbose", False)

        guid_map = {}
        if isinstance(self.engine, LdapActiveDirectoryView):
            schema_entries = self.engine.ldap.extend.standard.paged_search(
                self.engine.ldap.server.info.other["schemaNamingContext"][0],
                "(objectClass=*)",
                attributes=["name", "schemaidguid"],
            )
            for entry in schema_entries:
                name = entry["attributes"]["name"].lower()
                if (
                    name in ("ms-laps-encryptedpassword", "ms-laps-password")
                    and entry["attributes"]["schemaIDGUID"]
                ):
                    guid = str(UUID(bytes_le=entry["attributes"]["schemaIDGUID"]))
                    guid_map[name] = guid

        attributes = (
            ALL
            if verbose
            else ["dNSHostName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"]
        )

        try:
            # LAPSv1
            entries = self.engine.query(self.engine.LAPS_FILTER(computer), attributes)
            if not verbose:
                for entry in entries:
                    cn = entry["dNSHostName"]
                    password = entry.get("ms-Mcs-AdmPwd", None)
                    if password is None:
                        continue
                    try:
                        epoch = (
                            int(str(entry["ms-Mcs-AdmPwdExpirationTime"])) / 10000000
                        ) - 11644473600
                        expiration_date = datetime.fromtimestamp(epoch).strftime(
                            "%m-%d-%Y"
                        )
                    except Exception:
                        expiration_date = entry["ms-Mcs-AdmPwdExpirationTime"]
                    print(f"{cn} {password} {expiration_date}")
            else:
                self.display(entries, verbose)
        except LDAPAttributeError:
            try:
                # LAPSv2
                attributes = (
                    ALL
                    if verbose
                    else [
                        "dNSHostName",
                        "msLAPS-EncryptedPassword",
                        "msLAPS-PasswordExpirationTime",
                        "nTSecurityDescriptor",
                    ]
                )
                entries = self.engine.query(
                    self.engine.LAPS2_FILTER(computer), attributes
                )
                computers = list(entries)
                computer_count = len(computers)
                if computer_count > 0:
                    print("LAPSv2 detected, password decryption is not implemented")
                    if not verbose:
                        for c in computers:
                            if c["msLAPS-EncryptedPassword"]:
                                print(
                                    f"{c['dNSHostName']}:::{b64encode(c['msLAPS-EncryptedPassword'])}"
                                )
                            else:
                                print(f"{c['dNSHostName']}")

                            readers = set()
                            for ace in c["nTSecurityDescriptor"]["DACL"]["ACEs"]:
                                if "GUID" in ace.keys():
                                    guid = ace["GUID"].strip("{}")
                                    if (
                                        guid == guid_map["ms-laps-encryptedpassword"]
                                        or guid == guid_map["ms-laps-password"]
                                    ):
                                        if ace["SID"] not in readers:
                                            if ace["SID"] == "S-1-5-10":
                                                name = "S-1-5-10 (self)"
                                            else:
                                                try:
                                                    res = next(
                                                        self.engine.resolve_sid(
                                                            ace["SID"]
                                                        )
                                                    )
                                                    if "group" in res["objectClass"]:
                                                        name = f"{res['sAMAccountName']} (group)"
                                                    else:
                                                        name = res["sAMAccountName"]
                                                except StopIteration:
                                                    name = ace["SID"]
                                            print(f"{c['dNSHostName']}:reader:{name}")
                                            readers.add(ace["SID"])
            except Exception as e:
                print(e)
                error("No LAPS related attribute has been detected")
        except Exception as e:
            error(f"{e}. No LAPS attribute or not enough permission to read it.")

    def get_object(self, kwargs):
        """
        Return the records containing `object` in a CN.

        Arguments:
            @verbose:bool
                Results will contain full information
            #object:string
                Pattern to look for in CNs
        """
        anr = kwargs["object"]
        verbose = kwargs.get("verbose", False)

        if verbose:
            attributes = ALL
        else:
            attributes = ["sAMAccountName", "objectClass"]
        results = self.engine.query(self.engine.ANR(anr), attributes)
        self.display(results, verbose)

    def get_sddl(self, kwargs):
        """
        Returns the SDDL of an object given it's CN.

        Arguments:
            #object:string
                CN of object.
        """
        anr = kwargs["object"]

        results = self.engine.get_sddl(f"(anr={anr})")

        self.display(results, True, False)

    def get_silo(self, kwargs):
        """
        Get information about a specific `silo`.

        Arguments:
            #silo:string
                Silo to query
            @information:string = ["all", "members", "auth_policies"]
                Information to query
        """
        silo = kwargs["silo"]
        info = kwargs["information"]

        if info == "all":
            attributes = ALL
        elif info == "members":
            attributes = ["msDS-AuthNPolicySiloMembers"]
        elif info == "auth_policies":
            attributes = [
                "msDS-ComputerAuthNPolicy",
                "msDS-ServiceAuthNPolicy",
                "msDS-UserAuthNPolicy",
            ]
        else:
            return None

        try:
            results = list(
                self.engine.query(
                    self.engine.SILO_FILTER(silo),
                    attributes,
                    base=",".join(
                        [
                            "CN=AuthN Policy Configuration,CN=Services,CN=Configuration",
                            self.engine.base_dn,
                        ]
                    ),
                )
            )
        except LDAPObjectClassError as e:
            print(f"Error: {e}. The domain's functional level may be too old")
            return

        if not results:
            error(f"Silo {silo} does not exists")

        if info == "all":
            self.display(results, True)
        elif info == "members":
            members = results[0]["msDS-AuthNPolicySiloMembers"]
            print(*members, sep="\n")
        elif info == "auth_policies":
            print(f"msDS-ComputerAuthNPolicy: {results[0]['msDS-ComputerAuthNPolicy']}")
            print(f"msDS-ServiceAuthNPolicy: {results[0]['msDS-ServiceAuthNPolicy']}")
            print(f"msDS-UserAuthNPolicy: {results[0]['msDS-UserAuthNPolicy']}")

    # MISC #

    def misc_search(self, kwargs):
        """
        Query the LDAP with `filter` and retrieve ALL or `attributes` if specified.

        Arguments:
            #filter:string
                LDAP filter to search for
            #attributes:string = 'ALL'
                Comma separated list of attributes to display, ALL for every possible attribute
        """
        attr = kwargs["attributes"]
        filter_ = kwargs["filter"]

        try:
            if attr and attr != "ALL":
                results = self.engine.query(filter_, attr.split(","))
            else:
                results = self.engine.query(filter_)
            self.display(results, True)
        except PyAsn1UnicodeDecodeError as e:
            error(f"Decoding error with the filter: {e}")
        except Exception as e:
            if e.__str__() == "":
                error("An exception occurred with the provided filter")
            else:
                error(e)

    def misc_all(self, kwargs):
        """
        Collect and store computers, domain_policy, zones, gpo, groups, ou, users, trusts, pso information

        Arguments:
            #output:string
                File prefix for the files that will be created during the execution
        """
        output = kwargs["output"]
        kwargs["verbose"] = False

        for command, method in self.get_commands(prefix="list_"):
            info("Retrieving {command} output".format(command=command))
            if self.has_option(method, "filter"):
                filter_ = self.retrieve_default_val_for_arg(method, "filter")
                for f in filter_:
                    sys.stdout = Logger(
                        "{output}_{command}_{filter}.lst".format(
                            output=output, command=command, filter=f
                        ),
                        quiet=True,
                    )
                    kwargs["filter"] = f
                    getattr(self, method)(kwargs)

                    if self.has_option(method, "verbose"):
                        info(
                            "Retrieving {command} verbose output".format(
                                command=command
                            )
                        )
                        sys.stdout = Logger(
                            "{output}_{command}_{filter}.json".format(
                                output=output, command=command, filter=f
                            ),
                            quiet=True,
                        )
                        kwargs["verbose"] = True
                        getattr(self, method)(kwargs)
                        kwargs["verbose"] = False
                kwargs["filter"] = None
            else:
                sys.stdout = Logger(
                    "{output}_{command}.lst".format(output=output, command=command),
                    quiet=True,
                )
                getattr(self, method)(kwargs)

                if self.has_option(method, "verbose"):
                    info("Retrieving {command} verbose output".format(command=command))
                    sys.stdout = Logger(
                        "{output}_{command}.json".format(
                            output=output, command=command
                        ),
                        quiet=True,
                    )
                    kwargs["verbose"] = True
                    getattr(self, method)(kwargs)
                    kwargs["verbose"] = False

    def misc_enum_users(self, kwargs):
        """
        Anonymously enumerate enabled users with LDAP pings.

        Arguments:
            #file:string
                File containing a list of usernames to try.
            @delay:int = 0
                Delay in milliseconds between each try.
        """

        # LDAP pings can only be used with an anonymous bind
        if self.engine.ldap.authentication != "ANONYMOUS":
            error(
                "The enum_users feature can only be used with an anonymous bind (-a option)"
            )

        file = kwargs["file"]
        delay = kwargs["delay"]
        try:
            with open(file, "r") as f:
                while True:
                    line = f.readline()[:-1]
                    if not line:
                        break
                    if self.engine.user_exists(line):
                        print(line)
                    sleep(delay / 1000)
        except FileNotFoundError:
            error(f"Can't find file {file}")

    def misc_whoami(self, kwargs):
        """
        Return user identity.
        """
        user = self.engine.ldap.extend.standard.who_am_i()
        if user == None:
            error("Can't retrieve user identiy")
        else:
            print(user[2:])

    # ACTION #

    def action_unlock(self, kwargs):
        """
        Unlock `user`.

        Arguments:
            #user:string
                User to unlock
        """
        user = kwargs["user"]

        if self.engine.unlock(user):
            info(
                "User {username} unlocked (or was already unlocked)".format(
                    username=user
                )
            )
        else:
            error("Unable to unlock {username}, check privileges".format(username=user))

    def action_modify_password(self, kwargs):
        """
        Change `user`'s password.

        Arguments:
            #user:string
                Target user
            #newpassword:string
                New password
            @currpassword:string = None
                Current password (might be optional according to privileges)
        """
        user = kwargs["user"]
        new = kwargs["newpassword"]
        curr = kwargs.get("currpassword", None)
        if curr == "None":
            curr = None

        try:
            if self.engine.modify_password(user, curr, new):
                info("Password of {username} changed".format(username=user))
            else:
                error(
                    f"Unable to change {user}'s password, check domain password policy or privileges"
                )
        except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
            error(f"{e}, check sAMAccountName")

    def action_add_to_group(self, kwargs):
        """
        Add `user` to `group`.

        Arguments:
            #user:string
                Target user (dn or SID format). Ex: "CN=bob,CN=Users,DC=CORP,DC=LOCAL" or S-1-5-21-2808000538-3973481384-2586621659-1116. SID format will be used for foreign security principal.
            #group:string
                Target group (dn format). Ex: "CN=Domain Admins,CN=Users,DC=CORP,DC=LOCAL". If the target is using the SID format, group scope must be Domain Local or Universal.
        """
        user = kwargs["user"]
        group = kwargs["group"]

        if self.engine.add_user_to_group(user, group):
            info(f"User {user} successfully added to {group}")
        else:
            error(f"Unable to add {user} to {group}, check privileges or dn")

    def action_remove_from_group(self, kwargs):
        """
        Remove `user` from `group`.

        Arguments:
            #user:string
                Target user (dn format). Ex: "CN=bob,CN=Users,DC=CORP,DC=LOCAL"
            #group:string
                Target group (dn format). Ex: "CN=Domain Admins,CN=Users,DC=CORP,DC=LOCAL"
        """
        user = kwargs["user"]
        group = kwargs["group"]

        if self.engine.remove_user_from_group(user, group):
            info(f"User {user} successfully removed from {group}")
        else:
            error(f"Unable to remove {user} from {group}, check privileges or dn")

    def action_change_uac(self, kwargs):
        """
        Change user account control

        Arguments:
            #user:string
                Target user (dn format). Ex: "CN=bob,CN=Users,DC=CORP,DC=LOCAL"
            #uac:string
                UAC integer value. Ex: 512 for NORMAL_ACCOUNT
        """
        user = kwargs["user"]
        uac = kwargs["uac"]

        if self.engine.change_uac(user, uac):
            info(f"UAC successfully changed for {user}")
        else:
            error(f"Unable to change UAC for {user}, check privileges or dn")

    def action_create_computer(self, kwargs):
        """
        Create a computer account

        Arguments:
            #computer_name:string
                Name of computer to add (no '$' needed).
            #computer_pass:string
                Password set to computer account
        """
        computer = kwargs["computer_name"]
        password = kwargs["computer_pass"]

        if self.engine.create_computer(computer, password):
            info(f"Computer {computer} successfully created with password {password}")
        else:
            if (
                self.engine.ldap.result["result"]
                == coreResults.RESULT_UNWILLING_TO_PERFORM
            ):
                error_code = int(
                    self.engine.ldap.result["message"].split(":")[0].strip(), 16
                )
                if error_code == 0x216D:
                    print(f"Machine quota exceeded with account {self.engine.username}")
                else:
                    print(str(self.engine.ldap.result))
            elif (
                self.engine.ldap.result["result"]
                == coreResults.RESULT_INSUFFICIENT_ACCESS_RIGHTS
            ):
                print(
                    f"User {self.engine.username} doesn't have right to create a machine account!"
                )
            elif (
                self.engine.ldap.result["result"]
                == list(coreResults.RESULT_CODES.keys())[36]
            ):
                print(f"Computer {computer} already exists")
            elif self.engine.ldap.result["message"].startswith("00000523"):
                error("KB5008102 seems applied, add an ending '$' to the computer name")
            else:
                error_message = self.engine.ldap.result["message"]
                error(f"ERROR: {error_message}")

    def action_create_user(self, kwargs):
        """
        Create a user account

        Arguments:
            #user_name:string
                Name of user to add.
            #user_pass:string
                Password set to user account
        """
        user = kwargs["user_name"]
        password = kwargs["user_pass"]

        if self.engine.create_user(user, password):
            info(f"User {user} successfully created with password {password}")
        else:
            if (
                self.engine.ldap.result["result"]
                == coreResults.RESULT_UNWILLING_TO_PERFORM
            ):
                error_code = int(
                    self.engine.ldap.result["message"].split(":")[0].strip(), 16
                )
                print(f"ERROR: error_code = {error_code}")
                if error_code == 0x216D:
                    print(f"Machine quota exceeded with account {self.engine.username}")
                else:
                    print(str(self.engine.ldap.result))
            elif (
                self.engine.ldap.result["result"]
                == coreResults.RESULT_INSUFFICIENT_ACCESS_RIGHTS
            ):
                print(
                    f"User {self.engine.username} doesn't have right to create a user account!"
                )
            elif (
                self.engine.ldap.result["result"]
                == list(coreResults.RESULT_CODES.keys())[36]
            ):
                print(f"User {user} already exists")
            else:
                error_message = self.engine.ldap.result["message"]
                print(f"ERROR: {error_message}")


def main():
    parser = ArgumentParser(f"ldeep - {__version__}")
    parser.add_argument(
        "-o", "--outfile", default="", help="Store the results in a file"
    )
    parser.add_argument(
        "--security_desc",
        action="store_true",
        help="Enable the retrieval of security descriptors in ldeep results",
    )

    sub = parser.add_subparsers(
        title="Mode",
        dest="mode",
        description="Available modes",
        help="Backend engine to retrieve data",
    )
    sub.required = True

    ldap = sub.add_parser("ldap", description="LDAP mode")
    cache = sub.add_parser("cache", description="Cache mode")
    protections = sub.add_parser("protections", description="Protections mode")
    protections.add_argument(
        "-d", "--domain", required=True, help="The domain as NetBIOS or FQDN"
    )
    protections.add_argument(
        "-s",
        "--ldapserver",
        required=True,
        help="The LDAP server (IP or FQDN for Kerberos)",
    )
    protections.add_argument("-u", "--username", help="The username")
    protections.add_argument(
        "-p", "--password", help="The password used for the authentication"
    )
    protections.add_argument(
        "-H", "--ntlm", help="NTLM hashes, format is LMHASH:NTHASH"
    )
    protections.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable",
    )

    ldap.add_argument(
        "-d", "--domain", required=True, help="The domain as NetBIOS or FQDN"
    )
    ldap.add_argument(
        "-s",
        "--ldapserver",
        required=True,
        help="The LDAP path (ex : ldap://corp.contoso.com:389)",
    )
    ldap.add_argument(
        "-b",
        "--base",
        default="",
        help="LDAP base for query (by default, this value is pulled from remote Ldap)",
    )
    ldap.add_argument(
        "-f",
        "--forest-base",
        default="",
        help="LDAP forest base for query (by default, this value is pulled from remote Ldap)",
    )
    ldap.add_argument(
        "-t",
        "--type",
        default="ntlm",
        choices=["ntlm", "simple"],
        help="Authentication type: ntlm (default) or simple. Simple bind will always be in cleartext with ldap (not ldaps)",
    )
    ldap.add_argument(
        "--throttle",
        default=0,
        type=float,
        help="Add a throttle between queries to sneak under detection thresholds (in seconds between queries: argument to the sleep function)",
    )
    ldap.add_argument(
        "--page_size",
        default=1000,
        type=int,
        help="Configure the page size used by the engine to query the LDAP server (default: 1000)",
    )
    ldap.add_argument(
        "-n",
        "--no-encryption",
        default=False,
        action="store_true",
        help="Encrypt the communication or not (default: encrypted, except with simple bind and ldap)",
    )

    cache.add_argument(
        "-d",
        "--dir",
        default=".",
        type=str,
        help="Use saved JSON files in specified directory as cache",
    )
    cache.add_argument(
        "-p", "--prefix", required=True, type=str, help="Prefix of ldeep saved files"
    )

    ntlm = ldap.add_argument_group("NTLM authentication")
    ntlm.add_argument("-u", "--username", help="The username")
    ntlm.add_argument(
        "-p", "--password", help="The password used for the authentication"
    )
    ntlm.add_argument("-H", "--ntlm", help="NTLM hashes, format is LMHASH:NTHASH")

    kerberos = ldap.add_argument_group("Kerberos authentication")
    kerberos.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable",
    )

    certificate = ldap.add_argument_group("Certificate authentication")
    certificate.add_argument("--pfx-file", help="PFX file")
    certificate.add_argument("--pfx-pass", help="PFX password")
    certificate.add_argument("--cert-pem", help="User certificate")
    certificate.add_argument("--key-pem", help="User private key")

    anonymous = ldap.add_argument_group("Anonymous authentication")
    anonymous.add_argument(
        "-a", "--anonymous", action="store_true", help="Perform anonymous binds"
    )

    Ldeep.add_subparsers(
        ldap,
        "ldap",
        ["list_", "get_", "misc_", "action_"],
        title="commands",
        description="available commands",
    )
    Ldeep.add_subparsers(
        cache,
        "cache",
        ["list_", "get_"],
        title="commands",
        description="available commands",
    )

    args = parser.parse_args()

    # Output
    if args.outfile:
        sys.stdout = Logger(args.outfile, quiet=False)

    cache = "prefix" in args  # figuring out whether we use the cache or not

    # main
    if cache:
        try:
            query_engine = CacheActiveDirectoryView(args.dir, args.prefix)
        except (
            CacheActiveDirectoryView.CacheActiveDirectoryDirNotFoundException,
            CacheActiveDirectoryView.CacheActiveDirectoryFileNotFoundException,
        ) as e:
            error(e)
            sys.exit(1)

    elif args.mode == "protections":
        # Check protections (LDAP Signing & LDAPS Channel Binding)
        checkProtections(
            args.ldapserver,
            args.username,
            args.password,
            args.ntlm,
            args.domain,
            args.kerberos,
        )
        exit()

    else:
        try:
            # Authentication
            method = "NTLM"
            if args.kerberos:
                method = "Kerberos"
            elif args.cert_pem or args.pfx_file:
                method = "Certificate"
            elif args.anonymous or args.command_ldap == "enum_users":
                method = "anonymous"
            elif args.type == "ntlm":
                method = "NTLM"
            elif args.type == "simple":
                method = "SIMPLE"
            else:
                error(
                    "Lack of authentication options: either Kerberos, Certificate, Username with Password (can be a NTLM hash) or Anonymous."
                )
                sys.exit(1)

            query_engine = LdapActiveDirectoryView(
                args.ldapserver,
                args.domain,
                args.base,
                args.forest_base,
                args.username,
                args.password,
                args.ntlm,
                args.pfx_file,
                args.pfx_pass,
                args.cert_pem,
                args.key_pem,
                method,
                args.no_encryption,
                args.throttle,
                args.page_size,
            )

        except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
            error(e)
            sys.exit(1)

    # If `security_desc` are requested, enable LDAP Security Descriptor flags and modify the default attributes
    # In cache mode, the security_desc corresponding JSON field will be kept
    if args.security_desc:
        query_engine.set_controls(LDAP_SERVER_SD_FLAGS_OID_SEC_DESC)
        query_engine.set_all_attributes(
            [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, "ntSecurityDescriptor"]
        )

    ldeep = Ldeep(query_engine)

    try:
        ldeep.dispatch_command(args)
    except (
        CacheActiveDirectoryView.CacheActiveDirectoryException,
        CacheActiveDirectoryView.CacheActiveDirectoryFileNotFoundException,
    ) as e:
        error(e)
    except NotImplementedError:
        error("Feature not yet available")


if __name__ == "__main__":
    main()
