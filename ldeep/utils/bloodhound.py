"""Conversion of ldeep Active Directory records to BloodHound JSON.

BloodHound expects one JSON document per node type.  ldeep records are kept
under ``Properties`` so that attributes which are not used by BloodHound are
not lost during the conversion.
"""

import base64
import hashlib
import re
from datetime import date, datetime, timezone
from uuid import UUID, uuid5

from ldeep._version import __version__
from ldeep.utils.sddl import parse_ntSecurityDescriptor
from ldeep.views.constants import (
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
)

BLOODHOUND_VERSION = 6
BLOODHOUND_NODE_TYPES = (
    "domains",
    "gpos",
    "ous",
    "computers",
    "groups",
    "users",
    "enterprisecas",
    "certtemplates",
    "containers",
    "rootcas",
    "aiacas",
    "ntauthstores",
    "issuancepolicies",
)
# The data is collected through LDAP/DC-only queries, like SharpHound's
# DCOnly collection method.
BLOODHOUND_METHODS = 262885

_WELL_KNOWN_SIDS = {
    "S-1-1-0",
    "S-1-5-4",
    "S-1-5-9",
    "S-1-5-11",
    "S-1-5-17",
    "S-1-5-32-544",
    "S-1-5-32-545",
    "S-1-5-32-546",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-32-554",
    "S-1-5-32-555",
    "S-1-5-32-556",
    "S-1-5-32-557",
    "S-1-5-32-558",
    "S-1-5-32-559",
    "S-1-5-32-560",
    "S-1-5-32-561",
    "S-1-5-32-562",
    "S-1-5-32-568",
    "S-1-5-32-569",
    "S-1-5-32-573",
    "S-1-5-32-574",
    "S-1-5-32-575",
    "S-1-5-32-576",
    "S-1-5-32-577",
    "S-1-5-32-578",
    "S-1-5-32-579",
    "S-1-5-32-580",
    "S-1-5-32-581",
    "S-1-5-32-582",
}

_WELL_KNOWN_USER_SIDS = {"S-1-5-17"}

_WELL_KNOWN_NAMES = {
    "S-1-1-0": "EVERYONE",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-11": "AUTHENTICATED USERS",
    "S-1-5-17": "IUSR",
}

_WELL_KNOWN_GROUP_NAMES = {
    "S-1-5-32-552": "REPLICATORS",
}

_IGNORED_ACL_SIDS = {"S-1-3-0", "S-1-5-10", "S-1-5-18"}

_ACL_GUIDS = {
    "getchanges": "1131F6AA-9C07-11D1-F79F-00C04FC2DCD2",
    "getchangesall": "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2",
    "getchangesinfilteredset": "89E95B76-444D-4C62-991A-0FACBEDA640C",
    "writemember": "BF9679C0-0DE6-11D0-A285-00AA003049E2",
    "forcechangepassword": "00299570-246D-11D0-A768-00AA006E0529",
    "allowedtoact": "3F78C3E5-F79A-46BD-A0B8-9D18116DDC79",
    "useraccountrestrictions": "4C164200-20C0-11D0-A768-00AA006E0529",
    "writegplink": "F30E3BBE-9FF0-11D1-B603-0000F80367C1",
    "keycredentiallink": "5B47D60F-6090-40B2-9F37-2A4DE88F3063",
    "serviceprincipalname": "AB721A53-1E2F-11D0-9819-00AA0040529B",
    "enroll": "0E10C968-78FB-11D2-90D4-00C04F79DC55",
}

# Windows LAPS uses a shared attribute-security GUID.  The legacy
# ms-Mcs-AdmPwd GUID is schema-specific, so LDAP mode can override this set
# with the GUIDs discovered from the directory schema.
_LAPS_GUIDS = {
    "F3531EC6-6330-4F8E-8D39-7A671FBAC605",
    "50856756-E42A-40FE-AEAC-34FD9584E405",
    "404FCC5F-B022-4D9D-963C-AAEE4038657B",
}

_OBJECT_CLASS_GUIDS = {
    "domain": "19195A5B-6DA0-11D0-AFD3-00C04FD930C9",
    "computer": "BF967A86-0DE6-11D0-A285-00AA003049E2",
    "group": "BF967A9C-0DE6-11D0-A285-00AA003049E2",
    "organizational-unit": "BF967AA5-0DE6-11D0-A285-00AA003049E2",
    "user": "BF967ABA-0DE6-11D0-A285-00AA003049E2",
    "gpo": "F30E3BC2-9FF0-11D1-B603-0000F80367C1",
}

_OBJECT_CLASS_TYPES = {
    "domain": "domains",
    "domaindns": "domains",
    "computer": "computers",
    "group": "groups",
    "organizationalunit": "ous",
    "grouppolicycontainer": "gpos",
    "pkienrollmentservice": "enterprisecas",
    "pkicertificatetemplate": "certtemplates",
    "mspki-enterprise-oid": "issuancepolicies",
    "user": "users",
    "person": "users",
}

_SKIPPED_PROPERTIES = {
    "dn",
    "distinguishedname",
    "name",
    "objectclass",
    "objectguid",
    "objectsid",
    "ntsecuritydescriptor",
    "msds-supportedencryptiontypes",
    "cacertificate",
    "cacertificatedn",
    "certificatetemplates",
    "msds-managedpassword",
    "nthash",
    "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha1-96",
}

_CA_FLAGS = {
    0x2: "SUPPORTS_NT_AUTHENTICATION",
    0x8: "CA_SERVERTYPE_ADVANCED",
}

_UAC_FLAGS = {
    "ACCOUNTDISABLE": 0x2,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x800,
    "LOCKOUT": 0x10,
    "PASSWD_NOTREQD": 0x20,
    "PASSWD_CANT_CHANGE": 0x40,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x80,
    "NORMAL_ACCOUNT": 0x200,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
}

# ldeep gets the names of templates published by a CA, but does not query the
# certificate-template objects themselves.  BloodHound still needs an object
# identifier for the references in EnterpriseCA.EnabledCertTemplates.  UUID5
# gives us a stable identifier without pretending that it is the AD objectGUID.
_SYNTHETIC_NAMESPACE = UUID("2c7b7a6d-1a5d-5b1f-8ec7-9f3c6f3d0c9e")

_BH_OBJECT_TYPES = {
    "containers": "Container",
    "configuration": "Configuration",
    "certtemplates": "CertTemplate",
    "rootcas": "RootCA",
    "aiacas": "AiaCA",
    "ntauthstores": "NTAuthStore",
    "issuancepolicies": "IssuancePolicy",
    "base": "Base",
}


def _first(value, default=None):
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value if value is not None else default


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _coerce_descriptor(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        try:
            return parse_ntSecurityDescriptor(base64.b64decode(value))
        except Exception:
            return None
    return None


def _record_first(record, *names, default=None):
    """Read an LDAP attribute without depending on its JSON key casing."""
    for name in names:
        wanted = name.casefold()
        for key, value in record.items():
            if str(key).casefold() == wanted:
                return _first(value, default)
    return default


def _record_value(record, *names, default=None):
    wanted = {name.casefold() for name in names}
    for key, value in record.items():
        if str(key).casefold() in wanted:
            return value
    return default


def _domain_from_dn(dn):
    if not isinstance(dn, str):
        return ""
    parts = []
    for component in dn.split(","):
        key, separator, value = component.partition("=")
        if separator and key.strip().lower() == "dc":
            parts.append(value.strip())
    return ".".join(parts)


def _domain_dn(domain):
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


def _synthetic_identifier(object_type, canonical_name):
    return str(
        uuid5(_SYNTHETIC_NAMESPACE, f"{object_type}|{canonical_name.casefold()}")
    ).upper()


def _published_template_entries(record, template_records=None):
    """Return the published template names that ldeep collected for a CA."""
    dn = record.get("distinguishedName") or record.get("dn") or ""
    domain = _domain_from_dn(dn)
    if not domain:
        return []
    domain_dn = _domain_dn(domain)
    entries = []
    seen = set()
    for value in _as_list(record.get("certificateTemplates")):
        if not isinstance(value, str) or not value.strip():
            continue
        template_name = value.strip()
        template_dn = (
            f"CN={template_name},CN=Certificate Templates,CN=Public Key Services,"
            f"CN=Services,CN=Configuration,{domain_dn}"
        )
        identifier = _synthetic_identifier("certtemplate", template_dn)
        for template_record in template_records or []:
            template_name_candidates = {
                str(value).casefold()
                for value in (
                    _as_list(template_record.get("cn"))
                    + _as_list(template_record.get("name"))
                    + _as_list(template_record.get("displayName"))
                )
                if value is not None
            }
            if template_name.casefold() not in template_name_candidates:
                continue
            template_guid = _first(template_record.get("objectGUID"))
            if template_guid:
                identifier = _normalize_identifier(template_guid, domain)
            break
        if identifier in seen:
            continue
        seen.add(identifier)
        entries.append(
            {
                "domain": domain,
                "name": template_name,
                "dn": template_dn,
                "identifier": identifier,
            }
        )
    return entries


def _unresolved_published_templates(record, template_records=None):
    """Return only CA-published template names absent from the LDAP dump."""
    names = [
        value.strip()
        for value in _as_list(record.get("certificateTemplates"))
        if isinstance(value, str) and value.strip()
    ]
    if not template_records:
        return names
    known = set()
    for template_record in template_records:
        for value in (
            _as_list(template_record.get("cn"))
            + _as_list(template_record.get("name"))
            + _as_list(template_record.get("displayName"))
        ):
            if value is not None:
                known.add(str(value).casefold())
    return [name for name in names if name.casefold() not in known]


def _domain_sid(sid):
    if isinstance(sid, str) and sid.upper().startswith("S-1-5-21-"):
        parts = sid.split("-")
        if len(parts) >= 7:
            return "-".join(parts[:7])
    return ""


def _normalize_identifier(identifier, domain):
    if not isinstance(identifier, str):
        return identifier
    if identifier in _WELL_KNOWN_SIDS and domain:
        return f"{domain.upper()}-{identifier}"
    if identifier.startswith("{"):
        return identifier.strip("{}").upper()
    return identifier


def _guid(value):
    if not isinstance(value, str):
        return ""
    return value.strip("{}").upper()


def _as_timestamp(value):
    """Return a BloodHound-compatible Unix timestamp where possible."""
    value = _first(value)
    if isinstance(value, datetime):
        return max(0, int(value.timestamp()))
    if isinstance(value, date):
        return max(
            0,
            int(
                datetime(
                    value.year,
                    value.month,
                    value.day,
                    tzinfo=timezone.utc,
                ).timestamp()
            ),
        )
    if isinstance(value, int):
        # AD FILETIME is the number of 100ns intervals since 1601.
        if value > 10**12:
            return int((value - 116444736000000000) / 10**7)
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        return max(0, int(parsed.timestamp()))
    return value


def _ad_duration(value, zero="", forever=False):
    """Convert an AD 100 ns duration to BloodHound's display format."""
    value = _first(value)
    if not isinstance(value, int):
        return value
    if value == -9223372036854775808 and forever:
        return "Forever"
    if value == 0:
        return zero
    seconds = abs(value) // 10**7
    if seconds == 0:
        return zero
    units = (
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    )
    for divisor, label in units:
        if seconds % divisor == 0:
            amount = seconds // divisor
            return f"{amount} {label}{'' if amount == 1 else 's'}"
    return f"{seconds} seconds"


def _password_properties(value):
    value = _first(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return value
    flags = {
        "DOMAIN_PASSWORD_COMPLEX": 0x1,
        "DOMAIN_PASSWORD_NO_ANON_CHANGE": 0x2,
        "DOMAIN_PASSWORD_NO_CLEAR_CHANGE": 0x4,
        "DOMAIN_LOCKOUT_ADMINS": 0x8,
        "DOMAIN_PASSWORD_STORE_CLEARTEXT": 0x10,
        "DOMAIN_REFUSE_PASSWORD_CHANGE": 0x20,
    }
    return sum(flags.get(item.strip(), 0) for item in value.split("|"))


def _flag_names(value, mapping):
    value = _first(value)
    if not isinstance(value, int):
        return value
    names = [
        name
        for name, bit in mapping.items()
        if (bit == 0 and value == 0) or (bit and value & bit)
    ]
    return ", ".join(names) if names else "NONE"


def _ad_duration_from_bytes(value):
    if not isinstance(value, str):
        return _ad_duration(value)
    try:
        decoded = base64.b64decode(value)
        raw = int.from_bytes(decoded, "little", signed=True)
    except (ValueError, TypeError):
        return value
    seconds = abs(raw) // 10**7
    if seconds and seconds % (365 * 86400) == 0:
        amount = seconds // (365 * 86400)
        return f"{amount} year{'' if amount == 1 else 's'}"
    if seconds and seconds % (7 * 86400) == 0:
        amount = seconds // (7 * 86400)
        return f"{amount} week{'' if amount == 1 else 's'}"
    return _ad_duration(raw)


def _uac_contains(value, flag):
    value = _first(value, "")
    if isinstance(value, str):
        return flag in {item.strip() for item in value.split("|")}
    if isinstance(value, int):
        return bool(value & _UAC_FLAGS.get(flag, 0))
    return False


def _uac_value(value):
    value = _first(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return value
    result = 0
    for flag in value.split("|"):
        result |= _UAC_FLAGS.get(flag.strip(), 0)
    return result


def _encryption_types(value):
    value = _first(value)
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        if value.strip().upper() == "NONE":
            return ["Not defined"]
        names = {
            "RC4-HMAC": "RC4-HMAC-MD5",
            "RC4-HMAC-MD5": "RC4-HMAC-MD5",
            "AES128-CTS-HMAC-SHA1-96": "AES128-CTS-HMAC-SHA1-96",
            "AES256-CTS-HMAC-SHA1-96": "AES256-CTS-HMAC-SHA1-96",
            "DES-CBC-CRC": "DES-CBC-CRC",
            "DES-CBC-MD5": "DES-CBC-MD5",
        }
        return [names.get(item.strip(), item.strip()) for item in value.split("|")]
    if isinstance(value, int):
        flags = (
            (0x1, "DES-CBC-CRC"),
            (0x2, "DES-CBC-MD5"),
            (0x4, "RC4-HMAC-MD5"),
            (0x8, "AES128-CTS-HMAC-SHA1-96"),
            (0x10, "AES256-CTS-HMAC-SHA1-96"),
        )
        return [name for flag, name in flags if value & flag]
    return []


def _certificate_properties(record):
    """Extract the certificate fields BloodHound exposes for an Enterprise CA."""
    encoded = _record_first(record, "cACertificate")
    if not isinstance(encoded, str):
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        certificate = x509.load_der_x509_certificate(base64.b64decode(encoded))
        thumbprint = certificate.fingerprint(hashes.SHA1()).hex().upper()
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            path_length = basic_constraints.path_length
        except x509.ExtensionNotFound:
            path_length = None
        return {
            "certchain": [thumbprint],
            "certname": thumbprint,
            "certthumbprint": thumbprint,
            # SharpHound reports this as true only when a concrete path
            # length is present, while keeping the displayed length at 0.
            "hasbasicconstraints": path_length is not None,
            "basicconstraintpathlength": path_length or 0,
        }
    except Exception:
        return {}


def _certificate_template_properties(record):
    """Map ldeep's raw ADCS template attributes to SharpHound names."""
    name_flags = _record_value(record, "msPKI-Certificate-Name-Flag")
    enrollment_flags = _record_value(record, "msPKI-Enrollment-Flag")
    name_flags_value = _first(name_flags, 0)
    enrollment_flags_value = _first(enrollment_flags, 0)
    ekus = _as_list(_record_value(record, "pKIExtendedKeyUsage"))
    certificate_application_policies = _as_list(
        _record_value(record, "msPKI-Certificate-Application-Policy")
    )
    ra_policies = _as_list(_record_value(record, "msPKI-RA-Application-Policies"))
    application_policies = [
        value
        for value in ra_policies
        if isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)+", value)
    ]
    authenticating_ekus = {
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.5.2.3.4",
        "1.3.6.1.4.1.311.20.2.2",
        "2.5.29.37.0",
    }
    result = {
        "oid": _record_first(record, "msPKI-Cert-Template-OID"),
        "certificatenameflag": _flag_names(
            name_flags_value, MS_PKI_CERTIFICATE_NAME_FLAG
        ),
        "enrollmentflag": _flag_names(enrollment_flags_value, MS_PKI_ENROLLMENT_FLAG),
        "ekus": ekus,
        "effectiveekus": ekus,
        "certificateapplicationpolicy": certificate_application_policies,
        "applicationpolicies": application_policies,
        "certificatepolicy": _as_list(_record_value(record, "certificatePolicies")),
        "issuancepolicies": [],
        "enrolleesuppliessubject": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["ENROLLEE_SUPPLIES_SUBJECT"]
        ),
        "subjectaltrequireupn": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_ALT_REQUIRE_UPN"]
        ),
        "subjectaltrequireemail": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_ALT_REQUIRE_EMAIL"]
        ),
        "subjectaltrequirespn": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_ALT_REQUIRE_SPN"]
        ),
        "subjectaltrequiredns": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_ALT_REQUIRE_DNS"]
        ),
        "subjectaltrequiredomaindns": bool(
            isinstance(name_flags_value, int)
            and name_flags_value
            & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_ALT_REQUIRE_DOMAIN_DNS"]
        ),
        "subjectrequireemail": bool(
            isinstance(name_flags_value, int)
            and name_flags_value & MS_PKI_CERTIFICATE_NAME_FLAG["SUBJECT_REQUIRE_EMAIL"]
        ),
        "requiresmanagerapproval": bool(
            isinstance(enrollment_flags_value, int)
            and enrollment_flags_value & MS_PKI_ENROLLMENT_FLAG["PEND_ALL_REQUESTS"]
        ),
        "authorizedsignatures": _record_first(record, "msPKI-RA-Signature", default=0),
        "schemaversion": _record_first(record, "msPKI-Template-Schema-Version"),
        "nosecurityextension": bool(
            isinstance(enrollment_flags_value, int)
            and enrollment_flags_value & MS_PKI_ENROLLMENT_FLAG["NO_SECURITY_EXTENSION"]
        ),
        "authenticationenabled": bool(authenticating_ekus & set(ekus))
        or "CERTIFICATION AUTHORITY"
        in str(_record_first(record, "displayName", "cn", default="")).upper(),
        "schannelauthenticationenabled": bool(authenticating_ekus & set(ekus))
        or "CERTIFICATION AUTHORITY"
        in str(_record_first(record, "displayName", "cn", default="")).upper(),
        "validityperiod": _ad_duration_from_bytes(
            _record_value(record, "pKIExpirationPeriod")
        ),
        "renewalperiod": _ad_duration_from_bytes(
            _record_value(record, "pKIOverlapPeriod")
        ),
    }
    return {key: value for key, value in result.items() if value is not None}


def _ca_flags(value):
    value = _first(value)
    if not isinstance(value, int):
        return value
    return ", ".join(name for bit, name in _CA_FLAGS.items() if value & bit)


def _object_type(record):
    classes = record.get("objectClass", [])
    if isinstance(classes, str):
        classes = [classes]
    normalized_classes = {str(object_class).lower() for object_class in classes}
    # Computer objects also inherit from user/person, so test the more
    # specific classes before the generic ones.  A gMSA also carries the
    # ``computer`` class in AD, but BloodHound models it as a User node.
    if normalized_classes & {
        "msds-groupmanagedserviceaccount",
        "msds-managedserviceaccount",
    }:
        return "users"
    for object_class in (
        "domaindns",
        "domain",
        "computer",
        "group",
        "organizationalunit",
        "grouppolicycontainer",
        "pkienrollmentservice",
        "pkicertificatetemplate",
        "mspki-enterprise-oid",
        "user",
        "person",
    ):
        if object_class in normalized_classes:
            return _OBJECT_CLASS_TYPES[object_class]
    sam_account_name = _first(record.get("sAMAccountName"), "")
    if isinstance(sam_account_name, str) and sam_account_name.endswith("$"):
        return "computers"
    return None


def configuration_object_type(record):
    """Classify objects returned by ldeep's Configuration-partition dump.

    ``conf`` is intentionally a broad LDAP dump.  BloodHound gives several
    PKI objects their own node type, while AD itself represents some of them
    as ordinary containers.  Prefer the explicit object class and then use
    the well-known PKI container DN when the class is generic.
    """
    classes = {str(value).lower() for value in _as_list(record.get("objectClass"))}
    dn = str(record.get("distinguishedName") or record.get("dn") or "")
    dn_lower = dn.lower()
    first_rdn = dn_lower.split(",", 1)[0]

    if "pkicertificatetemplate" in classes:
        return "certtemplates"
    if "mspki-enterprise-oid" in classes:
        if first_rdn == "cn=oid":
            return "containers"
        return "issuancepolicies" if _is_issuance_policy(record) else None
    if "pkienrollmentservice" in classes:
        return "enterprisecas"
    if "configuration" in classes:
        return "containers"

    # These are the standard ADCS configuration containers.  An object below
    # them is represented as a dedicated BloodHound node when its DN makes
    # that unambiguous.
    if first_rdn == "cn=ntauthcertificates":
        return "ntauthstores"
    if "cn=ntauthcertificates," in dn_lower:
        # The NTAuthStore node owns the certificates below it; those child
        # records are not separate BloodHound NTAuthStore objects.
        return None
    if "cn=aia," in dn_lower:
        return "aiacas" if "container" not in classes else "containers"
    if "cn=certification authorities," in dn_lower:
        return "rootcas" if "container" not in classes else "containers"
    if "container" in classes or "builtinDomain".lower() in classes:
        return "containers"
    return None


def _configuration_identifier(record, object_type):
    """Return a stable identifier for a Configuration object.

    Real AD objectGUIDs are always preferred.  The UUID5 fallback is only for
    malformed/incomplete cache records and is explicitly marked synthetic by
    the caller.
    """
    object_guid = _first(record.get("objectGUID"))
    if object_guid:
        return _normalize_identifier(object_guid, "")
    dn = record.get("distinguishedName") or record.get("dn") or ""
    return _synthetic_identifier(object_type, str(dn))


def _configuration_parent(record, configuration_records, domain_sid=""):
    dn = str(record.get("distinguishedName") or record.get("dn") or "")
    parent_dn = dn.split(",", 1)[1] if "," in dn else ""
    for candidate in configuration_records or []:
        candidate_dn = str(
            candidate.get("distinguishedName") or candidate.get("dn") or ""
        )
        if candidate_dn.casefold() != parent_dn.casefold():
            continue
        candidate_classes = {
            str(value).casefold() for value in _as_list(candidate.get("objectClass"))
        }
        candidate_first_rdn = candidate_dn.casefold().split(",", 1)[0]
        if "configuration" in candidate_classes:
            object_type = "configuration"
        elif candidate_first_rdn == "cn=oid":
            # SharpHound keeps OID children attached to a Base node even
            # though the OID container itself is emitted as a Container.
            object_type = "base"
        else:
            object_type = configuration_object_type(candidate)
        object_guid = _first(candidate.get("objectGUID"))
        if not object_guid:
            # Do not create a synthetic parent merely to complete a graph
            # edge. A parent without an objectGUID is not safe to identify.
            continue
        if object_type is None:
            object_type = (
                "configuration" if "configuration" in candidate_classes else "base"
            )
        return {
            "ObjectIdentifier": _configuration_identifier(candidate, object_type),
            "ObjectType": _BH_OBJECT_TYPES.get(object_type, object_type),
        }
    if parent_dn and all(
        component.strip().casefold().startswith("dc=")
        for component in parent_dn.split(",")
    ):
        return {"ObjectIdentifier": domain_sid, "ObjectType": "Domain"}
    return None


def _core_parent(record, candidates, domain_sid):
    dn = str(record.get("distinguishedName") or record.get("dn") or "")
    parent_dn = dn.split(",", 1)[1] if "," in dn else ""
    if parent_dn.casefold().startswith("cn=builtin,") and all(
        component.strip().casefold().startswith("dc=")
        for component in parent_dn.split(",", 1)[1:]
    ):
        return {"ObjectIdentifier": domain_sid, "ObjectType": "Domain"}
    for candidate in candidates or []:
        candidate_dn = str(
            candidate.get("distinguishedName") or candidate.get("dn") or ""
        )
        if candidate_dn.casefold() != parent_dn.casefold():
            continue
        candidate_type = _object_type(candidate)
        if candidate_type == "ous":
            return {
                "ObjectIdentifier": _normalize_identifier(
                    _first(candidate.get("objectGUID")),
                    _domain_from_dn(candidate_dn),
                ),
                "ObjectType": "OU",
            }
        if candidate_type == "domains":
            return {
                "ObjectIdentifier": _first(candidate.get("objectSid"), domain_sid),
                "ObjectType": "Domain",
            }
        if candidate_type == "containers":
            identifier = _configuration_identifier(candidate, "containers")
            if identifier:
                return {
                    "ObjectIdentifier": identifier,
                    "ObjectType": "Container",
                }
    if parent_dn and all(
        component.strip().casefold().startswith("dc=")
        for component in parent_dn.split(",")
    ):
        return {"ObjectIdentifier": domain_sid, "ObjectType": "Domain"}
    return None


def _configuration_name(record, domain):
    name = _first(record.get("cn"), _first(record.get("name"), ""))
    if not name:
        name = _first(record.get("displayName"), "")
    name = str(name)
    return f"{name}@{domain}".upper().strip("@") if domain else name.upper()


def _gpo_links(record, gpo_records=None):
    """Translate gPLink GUIDs (GPO CNs) to GPO objectGUIDs."""
    raw = _record_value(record, "gPLink")
    if not raw:
        return []
    raw = _first(raw)
    if not isinstance(raw, str):
        return []
    by_cn = {}
    for gpo in gpo_records or []:
        cn = _record_first(gpo, "cn")
        identifier = _record_first(gpo, "objectGUID")
        if cn and identifier:
            by_cn[str(cn).strip("{}").casefold()] = _normalize_identifier(
                str(identifier), ""
            )
    links = []
    for guid, options in re.findall(r"\{([^}]+)\}[^;]*;(\d+)", raw):
        identifier = by_cn.get(guid.casefold())
        if not identifier:
            continue
        links.append(
            {
                "IsEnforced": bool(int(options) & 0x2),
                "GUID": identifier,
            }
        )
    return links


def _gpo_link_specs(record):
    """Return the linked GPO GUIDs and their link options."""
    raw = _first(_record_value(record, "gPLink"))
    if not isinstance(raw, str):
        return []
    return [
        (guid.upper(), int(options))
        for guid, options in re.findall(r"\{([^}]+)\}[^;]*;(\d+)", raw)
    ]


def _affected_computers(
    record,
    object_type,
    computer_records=None,
):
    """Return computers below a domain/OU with at least one active GPO link.

    SharpHound exposes this relationship on domains and OUs.  The LDAP data
    already contains the GPO links and the computer DNs, so this is a graph
    calculation rather than a new collection.
    """
    if object_type not in {"domains", "ous"}:
        return []
    links = [options for _, options in _gpo_link_specs(record)]
    if not any(not options & 0x1 for options in links):
        return []

    target_dn = str(record.get("distinguishedName") or record.get("dn") or "")
    target_dn = target_dn.casefold()
    result = []
    seen = set()
    for computer in computer_records or []:
        computer_dn = str(computer.get("distinguishedName") or computer.get("dn") or "")
        parent_dn = computer_dn.split(",", 1)[1] if "," in computer_dn else ""
        is_below = (
            object_type == "domains"
            and target_dn == _domain_dn(_domain_from_dn(computer_dn)).casefold()
        )
        while parent_dn and not is_below:
            if parent_dn.casefold() == target_dn:
                is_below = True
                break
            parent_dn = parent_dn.split(",", 1)[1] if "," in parent_dn else ""
        if not is_below:
            continue
        sid = _first(computer.get("objectSid"))
        if not sid:
            continue
        identifier = _normalize_identifier(sid, _domain_from_dn(computer_dn))
        if identifier in seen:
            continue
        seen.add(identifier)
        result.append({"ObjectIdentifier": identifier, "ObjectType": "Computer"})
    return result


def _is_issuance_policy(record):
    """Distinguish issuance-policy OIDs from ordinary PKI OID objects."""
    value = _first(record.get("flags"))
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            return "ISSUANCE" in value.upper()
    return isinstance(value, int) and bool(value & 0x2)


def _object_name(record, object_type, domain):
    sam = _first(record.get("sAMAccountName"), "")
    if object_type == "computers":
        name = _first(record.get("dNSHostName"))
        if name:
            return str(name).upper()
        return f"{str(sam).rstrip('$')}.{domain}".upper().strip(".")
    if object_type == "domains":
        return domain.upper()
    if object_type == "gpos":
        name = _first(record.get("displayName"), _first(record.get("name"), ""))
    elif object_type == "enterprisecas":
        name = _first(record.get("cn"), _first(record.get("name"), ""))
    elif object_type in {
        "containers",
        "certtemplates",
        "rootcas",
        "aiacas",
        "ntauthstores",
    }:
        return _configuration_name(record, domain)
    elif object_type == "issuancepolicies":
        name = _record_first(record, "displayName", "cn", "name", default="")
        return f"{name}@{domain}".upper().strip("@") if domain else str(name).upper()
    elif object_type == "ous":
        name = _first(record.get("name"), _first(record.get("ou"), ""))
    elif object_type == "groups":
        sid = _first(record.get("objectSid"), "")
        name = _WELL_KNOWN_GROUP_NAMES.get(sid, sam or _first(record.get("name"), ""))
    else:
        name = sam or _first(record.get("name"), "")
    name = str(name)
    return f"{name}@{domain}".upper().strip("@") if domain else name.upper()


def _ace_type(ace):
    ace_type = str(ace.get("Type", ""))
    return "Denied" if "Denied" in ace_type else "Allowed"


_AD_RIGHTS_FLAGS = (
    (0x1, "CreateChild"),
    (0x2, "DeleteChild"),
    (0x4, "ListChildren"),
    (0x8, "Self"),
    (0x10, "ReadProperty"),
    (0x20, "WriteProperty"),
    (0x40, "DeleteTree"),
    (0x80, "ListObject"),
    (0x100, "ExtendedRight"),
    (0xF01FF, "GenericAll"),
    (0x10000, "Delete"),
    (0x20000, "ReadControl"),
    (0x20004, "GenericExecute"),
    (0x20028, "GenericWrite"),
    (0x20094, "GenericRead"),
    (0x40000, "WriteDacl"),
    (0x80000, "WriteOwner"),
    (0x100000, "Synchronize"),
    (0x1000000, "AccessSystemSecurity"),
)


def _ad_rights_name(value):
    """Render an AD rights mask like ActiveDirectoryRights.ToString()."""
    if not isinstance(value, int):
        return ""
    remaining = value
    selected = set()
    # Enum.ToString decomposes a Flags value using the largest named values
    # first.  This matters for masks such as GenericAll minus DeleteChild:
    # GenericRead is selected as a named composite rather than expanded.
    for bit, name in sorted(_AD_RIGHTS_FLAGS, reverse=True):
        if bit and remaining & bit == bit:
            selected.add(name)
            remaining &= ~bit
    if remaining:
        return ""
    names = [name for _, name in _AD_RIGHTS_FLAGS if name in selected]
    return ", ".join(names)


def _ace_inheritance_hash(ace):
    """Calculate SharpHound's hash for one ACE."""
    if ace.get("Raw Type") not in (0, 5):
        return ""
    sid = ace.get("SID")
    if not sid or sid in _IGNORED_ACL_SIDS:
        return ""
    rights = _ad_rights_name(ace.get("Raw Access Required", 0))
    if not rights:
        return ""
    empty_guid = "00000000-0000-0000-0000-000000000000"
    object_type = _guid(ace.get("GUID")).lower() or empty_guid
    inherited_object_type = _guid(ace.get("Inherited GUID")).lower() or empty_guid
    value = sid + rights + object_type + inherited_object_type
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def _inheritance_hash(ace):
    """Calculate the hash of an explicit ACE that propagates inheritance."""
    flags = ace.get("Raw Flags", 0)
    if not isinstance(flags, int) or flags & 0x10 or not flags & 0x3:
        return ""
    return _ace_inheritance_hash(ace)


def _inheritance_hashes(record):
    descriptor = _security_descriptor(record)
    if not isinstance(descriptor, dict):
        return []
    hashes = []
    for ace in descriptor.get("DACL", {}).get("ACEs", []):
        value = _inheritance_hash(ace)
        if value:
            hashes.append(value)
    return hashes


def _principal_type(sid, resolve_principal=None):
    if not isinstance(sid, str):
        return "Unknown"
    if sid in _WELL_KNOWN_USER_SIDS:
        return "User"
    if any(sid.endswith(known_sid) for known_sid in _WELL_KNOWN_SIDS):
        return "Group"
    if sid.endswith(
        (
            "-498",
            "-512",
            "-513",
            "-514",
            "-515",
            "-516",
            "-517",
            "-518",
            "-519",
            "-520",
            "-521",
            "-522",
            "-526",
            "-527",
        )
    ):
        return "Group"
    if resolve_principal:
        resolved = resolve_principal(sid)
        if isinstance(resolved, dict):
            if "msds-groupmanagedserviceaccount" in {
                str(value).casefold() for value in _as_list(resolved.get("objectClass"))
            }:
                # BloodHound models a gMSA as a User principal in ACLs,
                # although its membership edge is represented as Computer.
                return "User"
            member_type = _member_type(resolved)
            if member_type != "Unknown":
                return member_type
    # Do not turn an unresolved ACL principal into a User.  In particular,
    # owner SIDs and principals from another trust are commonly absent from
    # an LDAP-only cache and BloodHound models those as Base principals.
    return "Base"


def _entry_class(object_type):
    return {
        "domains": "domain",
        "computers": "computer",
        "groups": "group",
        "ous": "organizational-unit",
        "gpos": "gpo",
        "users": "user",
        "enterprisecas": "enterprise-ca",
        "containers": "container",
        "certtemplates": "cert-template",
        "rootcas": "certification-authority",
        "aiacas": "certification-authority",
        "ntauthstores": "certification-authority",
        "issuancepolicies": "issuance-policy",
    }.get(object_type, "")


def _aces(
    record,
    object_type,
    domain,
    resolve_principal=None,
    object_type_guids=None,
):
    descriptor = _security_descriptor(record)
    if not isinstance(descriptor, dict):
        return []
    dacl = descriptor.get("DACL", {})
    result = []
    seen_relations = set()

    def add_relation(sid, right_name, inherited=False, inheritance_hash=""):
        if not sid or sid in _IGNORED_ACL_SIDS:
            return
        normalized_sid = _normalize_identifier(sid, domain)
        relation_key = (normalized_sid, right_name, inherited)
        if relation_key in seen_relations:
            if inherited and inheritance_hash:
                for relation in result:
                    if (
                        relation["PrincipalSID"],
                        relation["RightName"],
                        relation["IsInherited"],
                    ) == relation_key:
                        relation["InheritanceHash"] = inheritance_hash
                        break
            return
        seen_relations.add(relation_key)
        result.append(
            {
                "PrincipalSID": normalized_sid,
                "PrincipalType": _principal_type(sid, resolve_principal),
                "RightName": right_name,
                "IsInherited": inherited,
                "InheritanceHash": inheritance_hash if inherited else "",
                "IsPermissionForOwnerRightsSid": False,
                "IsInheritedPermissionForOwnerRightsSid": False,
            }
        )

    owner_sid = descriptor.get("Owner SID")
    if owner_sid not in _IGNORED_ACL_SIDS:
        add_relation(owner_sid, "Owns")

    entry_class = _entry_class(object_type)
    class_guid = _OBJECT_CLASS_GUIDS.get(entry_class)
    classes = {
        str(value).lower() for value in _as_list(_record_value(record, "objectClass"))
    }
    special_account = "msds-groupmanagedserviceaccount" in classes or _uac_contains(
        _record_value(record, "userAccountControl"),
        "INTERDOMAIN_TRUST_ACCOUNT",
    )
    is_domain_controller = _record_first(record, "primaryGroupID", default=0) == 516
    haslaps = any(
        _record_value(record, attribute) is not None
        for attribute in (
            "ms-Mcs-AdmPwd",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-Password",
            "msLAPS-PasswordExpirationTime",
            "msLAPS-EncryptedPassword",
            "msLAPS-EncryptedPasswordExpirationTime",
        )
    )
    schema_guids = {
        str(key).lower(): _guid(value)
        for key, value in (object_type_guids or {}).items()
        if value
    }
    laps_guids = set(_LAPS_GUIDS)
    laps_guids.update(
        value
        for key, value in schema_guids.items()
        if key
        in {
            "ms-mcs-admpwd",
            "ms-laps-password",
            "ms-laps-encryptedpassword",
            "ms-laps-encryptedpasswordhistory",
            "ms-laps-encryptedpasswordattributes",
        }
    )
    generic_write_types = {
        "user",
        "group",
        "computer",
        "domain",
        "gpo",
        "organizational-unit",
        "enterprise-ca",
        "cert-template",
        "certification-authority",
        "issuance-policy",
    }
    for ace in dacl.get("ACEs", []):
        sid = ace.get("SID")
        if not sid or sid in _IGNORED_ACL_SIDS:
            continue
        if ace.get("Raw Type") not in (0, 5):
            continue
        flags = ace.get("Raw Flags", 0)
        inherited = bool(flags & 0x10)
        if not inherited and flags & 0x8:
            continue

        inherited_guid = _guid(ace.get("Inherited GUID"))
        if inherited and inherited_guid and class_guid and inherited_guid != class_guid:
            continue

        access = ace.get("Raw Access Required", 0)
        inheritance_hash = _ace_inheritance_hash(ace)
        object_guid = _guid(ace.get("GUID"))
        object_flags = ace.get("Raw Object Flags", 0)
        object_type_present = bool(object_flags & 0x1)

        # A generic right restricted to another object class does not apply
        # to the current record.
        if (
            ace.get("Raw Type") == 5
            and object_type_present
            and class_guid
            and object_guid not in {class_guid}
            and access & 0xF01FF == 0xF01FF
        ):
            continue

        if (
            entry_class == "computer"
            and haslaps
            and object_type_present
            and object_guid in laps_guids
            and access & 0xF01FF == 0xF01FF
        ):
            add_relation(sid, "ReadLAPSPassword", inherited, inheritance_hash)
            continue

        if access & 0xF01FF == 0xF01FF:
            add_relation(sid, "GenericAll", inherited, inheritance_hash)
            continue

        if access & 0x20028 == 0x20028 and entry_class in generic_write_types:
            add_relation(sid, "GenericWrite", inherited, inheritance_hash)

        if access & 0x40000:
            add_relation(sid, "WriteDacl", inherited, inheritance_hash)
        if access & 0x80000:
            add_relation(sid, "WriteOwner", inherited, inheritance_hash)

        write_property = bool(access & 0x20)
        read_property = bool(access & 0x10)
        control_access = bool(access & 0x100)
        if (
            entry_class == "computer"
            and haslaps
            and object_type_present
            and object_guid in laps_guids
            and read_property
        ):
            add_relation(sid, "ReadLAPSPassword", inherited, inheritance_hash)
        if write_property:
            if not object_type_present and entry_class in generic_write_types:
                add_relation(sid, "GenericWrite", inherited, inheritance_hash)
            if entry_class == "group" and object_guid == _ACL_GUIDS["writemember"]:
                add_relation(sid, "AddMember", inherited, inheritance_hash)
            if entry_class == "computer" and object_guid == _ACL_GUIDS["allowedtoact"]:
                add_relation(sid, "AddAllowedToAct", inherited, inheritance_hash)
            if (
                entry_class in {"computer", "user"}
                and not special_account
                and object_guid == _ACL_GUIDS["useraccountrestrictions"]
            ):
                add_relation(
                    sid, "WriteAccountRestrictions", inherited, inheritance_hash
                )
            if (
                entry_class == "organizational-unit"
                and object_guid == _ACL_GUIDS["writegplink"]
            ):
                add_relation(sid, "WriteGPLink", inherited, inheritance_hash)
            if (
                entry_class in {"computer", "user"}
                and object_guid == _ACL_GUIDS["keycredentiallink"]
            ):
                add_relation(sid, "AddKeyCredentialLink", inherited, inheritance_hash)
            if (
                entry_class in {"computer", "user"}
                and object_guid == _ACL_GUIDS["serviceprincipalname"]
            ):
                add_relation(sid, "WriteSPN", inherited, inheritance_hash)
        elif access & 0x8:
            if entry_class == "group" and object_guid == _ACL_GUIDS["writemember"]:
                add_relation(sid, "AddSelf", inherited, inheritance_hash)

        if control_access:
            if not object_type_present and (
                (
                    entry_class in {"user", "domain"}
                    and (not special_account or inherited)
                )
                or (
                    entry_class == "computer" and inherited and not is_domain_controller
                )
            ):
                add_relation(sid, "AllExtendedRights", inherited, inheritance_hash)
            if entry_class == "domain":
                for key, right_name in (
                    ("getchanges", "GetChanges"),
                    ("getchangesall", "GetChangesAll"),
                    ("getchangesinfilteredset", "GetChangesInFilteredSet"),
                ):
                    if object_type_present and object_guid == _ACL_GUIDS[key]:
                        add_relation(sid, right_name, inherited, inheritance_hash)
            if entry_class in {"computer", "user"} and (
                object_type_present and object_guid == _ACL_GUIDS["forcechangepassword"]
            ):
                add_relation(sid, "ForceChangePassword", inherited, inheritance_hash)
            if entry_class == "enterprise-ca":
                if object_guid == _ACL_GUIDS["enroll"]:
                    add_relation(sid, "Enroll", inherited, inheritance_hash)
                elif not object_type_present:
                    add_relation(sid, "ManageCA", inherited, inheritance_hash)
            elif entry_class == "cert-template" and object_guid == _ACL_GUIDS["enroll"]:
                add_relation(sid, "Enroll", inherited, inheritance_hash)
        if (
            entry_class == "enterprise-ca"
            and write_property
            and not object_type_present
        ):
            add_relation(sid, "ManageCA", inherited, inheritance_hash)
            if access == 0xF00FF:
                add_relation(sid, "ManageCertificates", inherited, inheritance_hash)

    if entry_class == "gpo":
        # SharpHound keeps the duplicate edges produced by repeated, identical
        # non-inherited ACEs on the default GPOs.  Preserve those edges only
        # when the duplicate is present in the source descriptor; do not turn
        # the normal relation set into synthetic duplicates.
        repeated_full_control = {}
        for ace in dacl.get("ACEs", []):
            if (
                ace.get("Raw Type") in (0, 5)
                and not (ace.get("Raw Flags", 0) & 0x10)
                and not (ace.get("Raw Flags", 0) & 0x8)
                and not (ace.get("Raw Object Flags", 0) & 0x1)
                and not _guid(ace.get("GUID"))
                and ace.get("Raw Access Required", 0) == 0xE00BD
                and ace.get("SID") not in _IGNORED_ACL_SIDS
            ):
                sid = ace.get("SID")
                repeated_full_control[sid] = repeated_full_control.get(sid, 0) + 1

        for sid, count in repeated_full_control.items():
            if count < 2:
                continue
            normalized_sid = _normalize_identifier(sid, domain)
            for right_name in ("GenericWrite", "WriteDacl", "WriteOwner"):
                relation = next(
                    (
                        dict(item)
                        for item in result
                        if item["PrincipalSID"] == normalized_sid
                        and item["RightName"] == right_name
                        and not item["IsInherited"]
                    ),
                    None,
                )
                if relation is not None:
                    result.append(relation)
    return result


def _descriptor_principals(
    descriptor,
    right_name,
    domain,
    resolve_principal=None,
):
    """Return BloodHound relations for principals in a security descriptor."""
    descriptor = _coerce_descriptor(descriptor)
    if not isinstance(descriptor, dict):
        return []
    result = []
    seen = set()
    for ace in descriptor.get("DACL", {}).get("ACEs", []):
        if ace.get("Raw Type") not in (0, 5):
            continue
        flags = ace.get("Raw Flags", 0)
        if not (flags & 0x10) and flags & 0x8:
            continue
        sid = ace.get("SID")
        if not sid or sid in _IGNORED_ACL_SIDS:
            continue
        normalized_sid = _normalize_identifier(sid, domain)
        key = (normalized_sid, right_name, bool(flags & 0x10))
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "PrincipalSID": normalized_sid,
                "PrincipalType": _principal_type(sid, resolve_principal),
                "RightName": right_name,
                "IsInherited": bool(flags & 0x10),
                "InheritanceHash": "",
                "IsPermissionForOwnerRightsSid": False,
                "IsInheritedPermissionForOwnerRightsSid": False,
            }
        )
    return result


def _rbcd_targets(record, domain, resolve_principal=None):
    """Convert msDS-AllowedToAct... into BloodHound target references."""
    descriptor = _coerce_descriptor(
        _record_value(record, "msDS-AllowedToActOnBehalfOfOtherIdentity")
    )
    if not isinstance(descriptor, dict):
        return []
    result = []
    seen = set()
    for ace in descriptor.get("DACL", {}).get("ACEs", []):
        if ace.get("Raw Type") not in (0, 5):
            continue
        sid = ace.get("SID")
        if not sid or sid in _IGNORED_ACL_SIDS:
            continue
        identifier = _normalize_identifier(sid, domain)
        if identifier in seen:
            continue
        seen.add(identifier)
        result.append(
            {
                "ObjectIdentifier": identifier,
                "ObjectType": _principal_type(sid, resolve_principal),
            }
        )
    return result


def _delegation_targets(record, domain, resolve_host=None):
    """Resolve constrained-delegation SPNs to BloodHound computer objects."""
    if not resolve_host:
        return []
    result = []
    seen = set()
    for value in _as_list(record.get("msDS-AllowedToDelegateTo")):
        if not isinstance(value, str) or "/" not in value:
            continue
        hostname = value.split("/", 1)[1].split(":", 1)[0].split("/", 1)[0]
        if "." not in hostname and domain:
            hostname = f"{hostname}.{domain}"
        resolved = resolve_host(hostname)
        if not isinstance(resolved, dict):
            continue
        identifier = _normalize_identifier(_first(resolved.get("objectSid")), domain)
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        result.append({"ObjectIdentifier": identifier, "ObjectType": "Computer"})
    return result


def _synthetic_nodes(data, object_type, domain, domain_sid, include_well_known=False):
    if object_type not in {"groups", "users"}:
        return
    expected_type = "User" if object_type == "users" else "Group"
    existing = {node.get("ObjectIdentifier") for node in data}
    referenced = set(_WELL_KNOWN_NAMES) if include_well_known else set()
    for node in data:
        for ace in node.get("Aces", []):
            sid = ace.get("PrincipalSID", "")
            for known_sid in _WELL_KNOWN_NAMES:
                if sid == _normalize_identifier(known_sid, domain):
                    referenced.add(known_sid)

    for sid in sorted(referenced):
        if _principal_type(sid) != expected_type:
            continue
        identifier = _normalize_identifier(sid, domain)
        if identifier in existing:
            continue
        name = f"{_WELL_KNOWN_NAMES[sid]}@{domain}".upper()
        node_domain_sid = None if sid in _WELL_KNOWN_USER_SIDS else domain_sid
        node = {
            "ObjectIdentifier": identifier,
            "Properties": {
                "domain": domain.upper(),
                "domainsid": domain_sid,
                "name": name,
                "isaclprotected": False,
                "reconcile": False,
            },
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        if object_type == "groups":
            node.update(
                {"Members": [], "DomainSID": node_domain_sid, "HasSIDHistory": []}
            )
        else:
            node.update(
                {
                    "DomainSID": node_domain_sid,
                    "PrimaryGroupSID": None,
                    "HasSIDHistory": [],
                    "AllowedToDelegate": [],
                    "UnconstrainedDelegation": False,
                    "SPNTargets": [],
                    "ContainedBy": None,
                }
            )
        data.append(node)


def _add_domain_controller_members(data, domain, domain_controllers):
    """Populate the synthetic Enterprise Domain Controllers group."""
    if not domain_controllers:
        return
    identifier = _normalize_identifier("S-1-5-9", domain)
    group = next(
        (node for node in data if node.get("ObjectIdentifier") == identifier),
        None,
    )
    if not group:
        return
    members = group.setdefault("Members", [])
    existing = {member.get("ObjectIdentifier") for member in members}
    for computer in domain_controllers:
        sid = _first(computer.get("objectSid"))
        if not sid:
            continue
        sid = _normalize_identifier(sid, domain)
        if sid in existing:
            continue
        existing.add(sid)
        members.append({"ObjectIdentifier": sid, "ObjectType": "Computer"})


def _security_descriptor(record):
    return _coerce_descriptor(_record_value(record, "nTSecurityDescriptor"))


def _owner_rights_flags(record):
    descriptor = _security_descriptor(record)
    if not isinstance(descriptor, dict):
        return False, False
    aces = descriptor.get("DACL", {}).get("ACEs", [])
    owner_rights = [ace for ace in aces if ace.get("SID") == "S-1-3-4"]
    return bool(owner_rights), any(
        bool(ace.get("Raw Flags", 0) & 0x10) for ace in owner_rights
    )


def _properties(
    record,
    object_type,
    domain,
    domain_sid,
    name,
    dn,
    acl_protected,
    certtemplate_records=None,
):
    properties = {
        "domain": domain.upper(),
        "domainsid": domain_sid,
        "distinguishedname": dn.upper() if isinstance(dn, str) else dn,
        "name": name,
    }

    for key, value in record.items():
        property_name = str(key).lower()
        if property_name in _SKIPPED_PROPERTIES:
            continue
        if isinstance(value, (date, datetime)) or property_name in {
            "accountexpires",
            "badpasswordtime",
            "lastlogon",
            "lastlogoff",
            "lastlogontimestamp",
            "lockouttime",
            "pwdlastset",
            "whencreated",
            "whenchanged",
        }:
            value = _as_timestamp(value)
        properties[property_name] = value

    object_guid = _first(record.get("objectGUID"))
    if object_guid:
        properties["objectguid"] = _normalize_identifier(object_guid, domain)
    if "description" in record:
        properties["description"] = _first(record.get("description"))
    if "displayName" in record:
        properties["displayname"] = _first(record.get("displayName"))
    aliases = {
        "displayname": ("displayName",),
        "email": ("mail", "email"),
        "homedirectory": ("homeDirectory",),
        "logonscript": ("scriptPath",),
        "profilepath": ("profilePath",),
        "sfupassword": ("msSFU30Password",),
        "title": ("title",),
        "unicodepassword": ("unicodePwd",),
        "unixpassword": ("unixUserPassword",),
        "userpassword": ("userPassword",),
    }
    for target, source_names in aliases.items():
        value = _record_value(record, *source_names)
        if value is not None:
            properties[target] = _first(value)
    properties["isaclprotected"] = acl_protected
    owner_rights, inherited_owner_rights = _owner_rights_flags(record)
    properties["doesanyacegrantownerrights"] = owner_rights
    properties["doesanyinheritedacegrantownerrights"] = inherited_owner_rights

    uac = _record_value(record, "userAccountControl")
    if uac is not None:
        properties["useraccountcontrol"] = _uac_value(uac)
    if object_type in {"users", "computers"}:
        admin_count = record.get("adminCount")
        properties.update(
            {
                "enabled": not _uac_contains(uac, "ACCOUNTDISABLE"),
                "hasspn": bool(record.get("servicePrincipalName")),
                "samaccountname": _first(record.get("sAMAccountName"), ""),
                "serviceprincipalnames": _as_list(record.get("servicePrincipalName")),
                "trustedtoauth": _uac_contains(uac, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
                "unconstraineddelegation": _uac_contains(uac, "TRUSTED_FOR_DELEGATION"),
                "whencreated": _as_timestamp(record.get("whenCreated")),
                "supportedencryptiontypes": _encryption_types(
                    record.get("msDS-SupportedEncryptionTypes")
                ),
                "adminsdholderprotected": (
                    bool(_first(admin_count)) if admin_count is not None else False
                ),
                "encryptedtextpwdallowed": _uac_contains(
                    uac, "ENCRYPTED_TEXT_PWD_ALLOWED"
                ),
                "lockedout": _uac_contains(uac, "LOCKOUT"),
                "logonscriptenabled": bool(record.get("scriptPath")),
                "passwordexpired": _uac_contains(uac, "PASSWORD_EXPIRED"),
                "sidhistory": _as_list(record.get("sIDHistory")),
                "smartcardrequired": _uac_contains(uac, "SMARTCARD_REQUIRED"),
                "usedeskeyonly": _uac_contains(uac, "USE_DES_KEY_ONLY"),
            }
        )
        if object_type == "computers":
            properties.setdefault("email", None)
    if object_type == "users":
        for field in (
            "displayname",
            "email",
            "homedirectory",
            "logonscript",
            "passwordcantchange",
            "profilepath",
            "sfupassword",
            "title",
            "unicodepassword",
            "unixpassword",
            "userpassword",
        ):
            properties.setdefault(field, None)
        properties.update(
            {
                "admincount": bool(_first(record.get("adminCount"), 0)),
                "dontreqpreauth": _uac_contains(uac, "DONT_REQ_PREAUTH"),
                "passwordnotreqd": _uac_contains(uac, "PASSWD_NOTREQD"),
                "passwordcantchange": _uac_contains(uac, "PASSWD_CANT_CHANGE"),
                "pwdneverexpires": _uac_contains(uac, "DONT_EXPIRE_PASSWORD"),
                "sensitive": _uac_contains(uac, "NOT_DELEGATED"),
                "encryptedtextpwdallowed": _uac_contains(
                    uac, "ENCRYPTED_TEXT_PWD_ALLOWED"
                ),
                "passwordexpired": _uac_contains(uac, "PASSWORD_EXPIRED"),
                "smartcardrequired": _uac_contains(uac, "SMARTCARD_REQUIRED"),
                "usedeskeyonly": _uac_contains(uac, "USE_DES_KEY_ONLY"),
                "reconcile": False,
                "gmsa": "msds-groupmanagedserviceaccount"
                in {
                    str(value).lower()
                    for value in _as_list(_record_value(record, "objectClass"))
                },
            }
        )
        allowed_to_delegate = _record_value(record, "msDS-AllowedToDelegateTo")
        if allowed_to_delegate is not None:
            properties["allowedtodelegate"] = _as_list(allowed_to_delegate)
    if object_type == "computers":
        properties["admincount"] = bool(_first(record.get("adminCount"), 0))
        properties["isdc"] = _first(record.get("primaryGroupID")) == 516
        properties["isreadonlydc"] = False
        properties["supportedencryptiontypes"] = _encryption_types(
            record.get("msDS-SupportedEncryptionTypes")
        )
        properties["haslaps"] = any(
            _record_value(record, attribute) is not None
            for attribute in (
                "ms-Mcs-AdmPwd",
                "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-Password",
                "msLAPS-PasswordExpirationTime",
                "msLAPS-EncryptedPassword",
                "msLAPS-EncryptedPasswordExpirationTime",
            )
        )
    if object_type == "groups":
        admin_count = record.get("adminCount")
        group_type = str(_first(record.get("groupType"), ""))
        properties["groupscope"] = next(
            (
                scope
                for scope in ("Global", "Universal", "DomainLocal")
                if scope.upper().replace("LOCAL", "_LOCAL") in group_type.upper()
            ),
            "",
        )
        properties.update(
            {
                "admincount": bool(_first(record.get("adminCount"), 0)),
                "samaccountname": _first(record.get("sAMAccountName"), ""),
                "adminsdholderprotected": (
                    bool(_first(admin_count)) if admin_count is not None else False
                ),
                "sidhistory": _as_list(record.get("sIDHistory")),
                "reconcile": False,
            }
        )
    if object_type == "domains":
        behavior = _first(record.get("msDS-Behavior-Version"))
        properties["functionallevel"] = {
            0: "2000",
            1: "2003",
            2: "2003",
            3: "2008",
            4: "2008 R2",
            5: "2012",
            6: "2012 R2",
            7: "2016",
            10: "2025",
        }.get(behavior, behavior)
        properties["machineaccountquota"] = _first(
            record.get("ms-DS-MachineAccountQuota")
        )
        properties["collected"] = True
        properties["netbios"] = str(
            _first(record.get("dc"), domain.split(".", 1)[0])
        ).upper()
        properties["dsheuristics"] = _first(record.get("dSHeuristics"))
        properties["expirepasswordsonsmartcardonlyaccounts"] = bool(
            _first(
                record.get("msDS-ExpirePasswordsOnSmartCardOnlyAccounts"),
                record.get("ms-DS-ExpirePasswordsOnSmartCardOnlyAccounts"),
            )
        )
        properties["maxpwdage"] = _ad_duration(record.get("maxPwdAge"), forever=True)
        properties["minpwdage"] = _ad_duration(record.get("minPwdAge"))
        properties["lockoutduration"] = _ad_duration(record.get("lockoutDuration"))
        properties["lockoutobservationwindow"] = _first(
            record.get("lockOutObservationWindow"),
            record.get("lockoutDuration"),
        )
        properties["pwdproperties"] = _password_properties(record.get("pwdProperties"))
    if object_type == "gpos":
        gpc_path = _first(record.get("gPCFileSysPath"))
        properties["gpcpath"] = (
            gpc_path.upper() if isinstance(gpc_path, str) else gpc_path
        )
        properties["gpostatus"] = str(_first(record.get("flags"), "0"))
    if object_type == "ous":
        properties["blocksinheritance"] = _first(record.get("gPOptions"), 0) == 1
    if object_type == "enterprisecas":
        descriptor = _security_descriptor(record)
        properties.update(
            {
                "caname": _first(record.get("cn"), _first(record.get("name"), "")),
                "dnshostname": _first(record.get("dNSHostName")),
                "flags": _ca_flags(record.get("flags")),
                # ldeep collects the published template names, but not the
                # template objects/GUIDs required for EnabledCertTemplates.
                "unresolvedpublishedtemplates": _unresolved_published_templates(
                    record, certtemplate_records
                ),
                "casecuritycollected": isinstance(descriptor, dict),
                "enrollmentagentrestrictionscollected": False,
                "isuserspecifiessanenabledcollected": False,
                "roleseparationenabledcollected": False,
            }
        )
        properties.update(_certificate_properties(record))
    if object_type == "certtemplates":
        properties.update(_certificate_template_properties(record))
    if object_type == "issuancepolicies":
        properties["certtemplateoid"] = _record_first(record, "msPKI-Cert-Template-OID")
    if object_type in {"rootcas", "aiacas", "ntauthstores"}:
        properties.update(_certificate_properties(record))
        cross_certificate_pair = _record_value(record, "crossCertificatePair")
        if object_type == "aiacas":
            properties["crosscertificatepair"] = _as_list(cross_certificate_pair)
            properties["hascrosscertificatepair"] = bool(cross_certificate_pair)
        if object_type == "ntauthstores":
            properties.setdefault("certthumbprints", [])
    return properties


def _member_type(record):
    classes = {str(value).lower() for value in _as_list(record.get("objectClass"))}
    # BloodHound represents a gMSA as a User node even though AD also puts
    # the computer class on the object.  Check this before ``computer`` so
    # group membership edges use the same type as SharpHound.
    if "msds-groupmanagedserviceaccount" in classes:
        return "User"
    if "computer" in classes:
        return "Computer"
    if "group" in classes:
        return "Group"
    if (
        "user" in classes
        or "person" in classes
        or "msds-groupmanagedserviceaccount" in classes
        or "msds-managedserviceaccount" in classes
    ):
        return "User"
    if "foreignsecurityprincipal" in classes:
        return _principal_type(_first(record.get("objectSid")))
    return "Unknown"


def _convert_record(
    record,
    object_type,
    resolve_member=None,
    resolve_principal=None,
    resolve_host=None,
    domain_sid="",
    object_type_guids=None,
    certtemplate_records=None,
    gpo_records=None,
    configuration_records=None,
    containment_records=None,
    computer_records=None,
):
    dn = record.get("distinguishedName") or record.get("dn") or ""
    domain = _domain_from_dn(dn)
    sid = _first(record.get("objectSid"), "")
    domain_sid = _domain_sid(sid) or domain_sid
    if object_type in {
        "containers",
        "certtemplates",
        "rootcas",
        "aiacas",
        "ntauthstores",
        "issuancepolicies",
    }:
        identifier = _configuration_identifier(record, object_type)
    else:
        identifier = _normalize_identifier(
            sid or _first(record.get("objectGUID")) or dn, domain
        )
    descriptor = _security_descriptor(record)
    acl_protected = (
        bool((_first((descriptor or {}).get("Raw Type"), 0)) & 0x1000)
        if isinstance(descriptor, dict)
        else False
    )
    name = _object_name(record, object_type, domain)
    converted = {
        "ObjectIdentifier": identifier,
        "Properties": _properties(
            record,
            object_type,
            domain,
            domain_sid,
            name,
            dn,
            acl_protected,
            certtemplate_records=certtemplate_records,
        ),
        "Aces": _aces(
            record,
            object_type,
            domain,
            resolve_principal,
            object_type_guids,
        ),
        "IsDeleted": bool(_first(record.get("isDeleted"), False)),
        "IsACLProtected": acl_protected,
    }

    if object_type in {"users", "computers"}:
        converted["DomainSID"] = domain_sid
        if object_type == "users" and (
            sid in _WELL_KNOWN_USER_SIDS or str(sid).endswith("-S-1-5-17")
        ):
            # IUSR is a well-known principal, not a domain account.  Keep
            # the domain context in Properties, but do not attach a domain
            # SID to the node itself.
            converted["DomainSID"] = None
        converted["UnconstrainedDelegation"] = _uac_contains(
            record.get("userAccountControl"), "TRUSTED_FOR_DELEGATION"
        )
        converted["PrimaryGroupSID"] = None
        primary_group = _first(record.get("primaryGroupID"))
        if primary_group and domain_sid:
            converted["PrimaryGroupSID"] = f"{domain_sid}-{primary_group}"
        converted["AllowedToDelegate"] = _as_list(
            _delegation_targets(record, domain, resolve_host)
        )
        converted["HasSIDHistory"] = _as_list(record.get("sIDHistory"))
    if object_type == "users":
        converted["SPNTargets"] = []
        converted["Aces"].extend(
            _descriptor_principals(
                record.get("msDS-GroupMSAMembership"),
                "ReadGMSAPassword",
                domain,
                resolve_principal,
            )
        )
    elif object_type == "computers":
        converted["IsDC"] = _first(record.get("primaryGroupID")) == 516
        converted["AllowedToAct"] = _rbcd_targets(
            record,
            domain,
            resolve_principal,
        )
        # BloodHound models computer sessions as a collection result,
        # rather than as a bare list.  Keep it explicitly uncollected since
        # ldeep's LDAP/cache computer query does not perform session
        # enumeration.
        converted["Sessions"] = {
            "Results": [],
            "Collected": False,
            "FailureReason": None,
        }
        converted["DcomUsers"] = {
            "Results": [],
            "Collected": False,
            "FailureReason": None,
        }
        converted["LocalAdmins"] = {
            "Results": [],
            "Collected": False,
            "FailureReason": None,
        }
        converted["PSRemoteUsers"] = {
            "Results": [],
            "Collected": False,
            "FailureReason": None,
        }
        converted["RemoteDesktopUsers"] = {
            "Results": [],
            "Collected": False,
            "FailureReason": None,
        }
    elif object_type == "groups":
        members = []
        for member in _as_list(record.get("member")):
            resolved = resolve_member(member) if resolve_member else None
            if not isinstance(resolved, dict):
                continue
            member_identifier = _normalize_identifier(
                _first(resolved.get("objectSid")), domain
            )
            if not member_identifier:
                continue
            members.append(
                {
                    "ObjectIdentifier": member_identifier,
                    "ObjectType": _member_type(resolved),
                }
            )
        converted["Members"] = members
        converted["DomainSID"] = domain_sid
        converted["HasSIDHistory"] = _as_list(record.get("sIDHistory"))
    elif object_type == "issuancepolicies":
        converted["GroupLink"] = {
            "ObjectIdentifier": None,
            "ObjectType": "Base",
        }
    if object_type in {"domains", "ous", "users", "computers"}:
        converted.update(
            {
                "ChildObjects": [],
                "Links": _gpo_links(record, gpo_records),
                "GPOChanges": {
                    "AffectedComputers": _affected_computers(
                        record, object_type, computer_records
                    ),
                    "DcomUsers": [],
                    "LocalAdmins": [],
                    "PSRemoteUsers": [],
                    "RemoteDesktopUsers": [],
                },
            }
        )
        if object_type in {"ous", "users", "computers"}:
            contained_by = _core_parent(record, containment_records, domain_sid)
            if contained_by:
                converted["ContainedBy"] = contained_by
    if object_type in {"groups", "gpos"}:
        contained_by = _core_parent(record, containment_records, domain_sid)
        if contained_by:
            converted["ContainedBy"] = contained_by
    if object_type == "containers":
        converted["ChildObjects"] = []
        converted["InheritanceHashes"] = _inheritance_hashes(record)
    elif object_type in {"domains", "ous"}:
        converted["InheritanceHashes"] = _inheritance_hashes(record)
    if object_type == "domains":
        converted["ContainedBy"] = None
        converted["ForestRootIdentifier"] = identifier
        converted["Trusts"] = []
    elif object_type in {"rootcas", "ntauthstores"}:
        converted["DomainSID"] = domain_sid
    elif object_type == "enterprisecas":
        hosting_computer = None
        hostname = _first(record.get("dNSHostName"))
        if resolve_host and hostname:
            resolved = resolve_host(hostname)
            if isinstance(resolved, dict):
                hosting_computer = _normalize_identifier(
                    _first(resolved.get("objectSid")), domain
                )
        converted.update(
            {
                "HostingComputer": hosting_computer,
                "EnabledCertTemplates": [
                    {
                        "ObjectIdentifier": entry["identifier"],
                        "ObjectType": "CertTemplate",
                    }
                    for entry in _published_template_entries(
                        record, certtemplate_records
                    )
                ],
                "HttpEnrollmentEndpoints": [],
                "CARegistryData": {},
            }
        )
        contained_by = _configuration_parent(record, configuration_records, domain_sid)
        if contained_by:
            converted["ContainedBy"] = contained_by
    return converted


def _trust_int(value, names):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return sum(bit for bit, name in names.items() if name in value)
    return 0


def _convert_trusts(records):
    directions = {
        0: "Disabled",
        1: "Inbound",
        2: "Outbound",
        3: "Bidirectional",
    }
    types = {
        1: "External",
        2: "Forest",
        3: "External",
    }
    attributes = {
        0x1: "NON_TRANSITIVE",
        0x2: "UPLEVEL_ONLY",
        0x4: "QUARANTINED_DOMAIN",
        0x8: "FOREST_TRANSITIVE",
        0x10: "CROSS_ORGANIZATION",
        0x20: "WITHIN_FOREST",
        0x40: "TREAT_AS_EXTERNAL",
        0x80: "USES_RC4_ENCRYPTION",
        0x100: "USES_AES_KEYS",
        0x200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
        0x400: "PIM_TRUST",
        0x800: "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
    }
    converted = []
    for record in records or []:
        target_sid = _first(record.get("securityIdentifier"))
        target_name = _first(record.get("trustPartner"), _first(record.get("name"), ""))
        if not target_sid or not target_name:
            continue
        trust_attributes = _trust_int(record.get("trustAttributes"), attributes)
        trust_type = _first(record.get("trustType"), 0)
        try:
            trust_type = int(trust_type)
        except (TypeError, ValueError):
            trust_type = 0
        converted.append(
            {
                "TargetDomainSid": str(target_sid).upper(),
                "TargetDomainName": str(target_name).upper(),
                "IsTransitive": not bool(trust_attributes & 0x1),
                "SidFilteringEnabled": bool(trust_attributes & 0x4) or trust_type == 2,
                "TGTDelegationEnabled": bool(trust_attributes & 0x800),
                "TrustAttributes": trust_attributes,
                "TrustDirection": directions.get(
                    _first(record.get("trustDirection"), 0), "Disabled"
                ),
                "TrustType": types.get(trust_type, "External"),
            }
        )
    return converted


def convert(
    records,
    resolve_member=None,
    resolve_principal=None,
    resolve_host=None,
    domain_sid="",
    trusts=None,
    include_well_known=False,
    object_type_hint=None,
    object_type_guids=None,
    domain_controllers=None,
    certtemplate_records=None,
    gpo_records=None,
    configuration_records=None,
    containment_records=None,
    computer_records=None,
):
    """Convert records into one BloodHound v6 JSON document."""
    records = list(records)
    source_records = records
    if not records:
        object_type = object_type_hint or "users"
    else:
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("BloodHound output requires ldeep record objects")
        object_types = {_object_type(record) for record in records}
        if None in object_types:
            raise ValueError(
                "BloodHound output cannot classify one or more ldeep records"
            )
        # ldeep's OU query also returns the domain naming context.  The
        # domain is emitted by domain_policy, so omit that extra record from
        # the OU document instead of producing a mixed BloodHound file.
        if object_types == {"domains", "ous"}:
            records = [record for record in records if _object_type(record) == "ous"]
            object_types = {"ous"}
        if len(object_types) != 1:
            raise ValueError(
                "BloodHound output requires records of one object type; "
                f"got {', '.join(sorted(object_types))}"
            )
        object_type = object_types.pop()

    data = [
        _convert_record(
            record,
            object_type,
            resolve_member=resolve_member,
            resolve_principal=resolve_principal,
            resolve_host=resolve_host,
            domain_sid=domain_sid,
            object_type_guids=object_type_guids,
            certtemplate_records=certtemplate_records,
            gpo_records=gpo_records,
            configuration_records=configuration_records,
            containment_records=containment_records or source_records,
            computer_records=computer_records,
        )
        for record in records
    ]
    if object_type == "domains" and data:
        data[0]["Trusts"] = _convert_trusts(trusts)
    record_domain = ""
    if records:
        record_domain = _domain_from_dn(
            records[0].get("distinguishedName") or records[0].get("dn") or ""
        )
    _synthetic_nodes(
        data,
        object_type,
        record_domain,
        domain_sid,
        include_well_known=include_well_known,
    )
    if object_type == "groups":
        _add_domain_controller_members(data, record_domain, domain_controllers)
    meta = {
        "collectorversion": f"ldeep {__version__}",
        "methods": BLOODHOUND_METHODS,
        "type": object_type,
        "count": len(data),
        "version": BLOODHOUND_VERSION,
    }
    if object_type == "enterprisecas":
        # ADCS node files use the v6 schema in BloodHound Community Edition.
        meta.update({"methods": 15725567, "version": 6})
    return {
        "data": data,
        "meta": meta,
    }


def _configuration_document(
    records,
    object_type,
    domain_sid="",
    certificate_records=None,
    principal_records=None,
):
    """Build one BloodHound document for a Configuration object type."""
    data = []
    seen = set()
    for record in records or []:
        if not isinstance(record, dict):
            continue
        identifier = _configuration_identifier(record, object_type)
        if identifier in seen:
            continue
        seen.add(identifier)
        node = _convert_record(
            record,
            object_type,
            domain_sid=domain_sid,
            resolve_principal=(
                lambda sid: (
                    next(
                        (
                            candidate
                            for candidate in principal_records or []
                            if _first(candidate.get("objectSid")) == sid
                        ),
                        None,
                    )
                    if principal_records is not None
                    else None
                )
            ),
        )
        if object_type in {"rootcas", "aiacas"} and not any(
            key in node["Properties"] for key in ("certthumbprint", "certchain")
        ):
            record_name = _record_first(record, "cn", "name")
            for ca_record in certificate_records or []:
                ca_name = _record_first(ca_record, "cn", "name")
                if (
                    record_name
                    and ca_name
                    and str(record_name).casefold() == str(ca_name).casefold()
                ):
                    node["Properties"].update(_certificate_properties(ca_record))
                    break
        if object_type == "ntauthstores":
            fingerprints = []
            for ca_record in certificate_records or []:
                fingerprint = _certificate_properties(ca_record).get("certthumbprint")
                if fingerprint and fingerprint not in fingerprints:
                    fingerprints.append(fingerprint)
            if fingerprints:
                node["Properties"]["certthumbprints"] = fingerprints
        if not _first(record.get("objectGUID")):
            node["Properties"]["synthetic"] = True
            node["Properties"]["unresolvedsource"] = "ldeep conf distinguishedName"
        data.append(node)

    return {
        "data": data,
        "meta": {
            "collectorversion": f"ldeep {__version__}",
            "methods": 15725567,
            "type": object_type,
            "count": len(data),
            "version": 6,
        },
    }


def convert_certtemplates(
    records, domain_sid="", configuration_records=None, principal_records=None
):
    """Convert full certificate-template records when ``conf`` is available.

    Older ldeep dumps only contain the template names published by a CA.  In
    that case retain the deterministic synthetic fallback so EnterpriseCA
    references remain importable.  A Configuration dump upgrades those nodes
    to their real objectGUID, LDAP properties, and ACLs automatically.
    """
    template_records = [
        record
        for record in configuration_records or []
        if configuration_object_type(record) == "certtemplates"
    ]
    if template_records:
        return _configuration_document(
            template_records,
            "certtemplates",
            domain_sid=domain_sid,
            principal_records=principal_records,
        )

    entries = {}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        for entry in _published_template_entries(record):
            entries.setdefault(entry["identifier"], entry)

    data = []
    for identifier in sorted(entries):
        entry = entries[identifier]
        domain = entry["domain"].upper()
        data.append(
            {
                "Properties": {
                    "domain": domain,
                    "domainsid": domain_sid,
                    "name": f"{entry['name']}@{domain}".upper(),
                    "displayname": entry["name"],
                    "distinguishedname": entry["dn"].upper(),
                    "objectguid": identifier,
                    "isaclprotected": False,
                    "synthetic": True,
                    "unresolvedsource": "ldeep certificateTemplates",
                },
                "Aces": [],
                "ObjectIdentifier": identifier,
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )

    return {
        "data": data,
        "meta": {
            "collectorversion": f"ldeep {__version__}",
            "methods": 15725567,
            "type": "certtemplates",
            "count": len(data),
            "version": 6,
        },
    }


def convert_configuration(
    records,
    domain_sid="",
    certificate_records=None,
    principal_records=None,
):
    """Convert all BloodHound-relevant records from ldeep's ``conf`` dump.

    The function never invents parent objects.  ``ContainedBy`` is added only
    when the parent DN is itself present in the dump, which keeps partial
    caches safe while still preserving the complete hierarchy in full dumps.
    """
    grouped = {}
    identifiers_by_dn = {}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        object_type = configuration_object_type(record)
        dn = str(record.get("distinguishedName") or record.get("dn") or "")
        identifier = _configuration_identifier(record, object_type)
        if dn and _first(record.get("objectGUID")):
            # Some parents (CN=Configuration and CN=Optional Features, for
            # example) are useful ContainedBy targets without being emitted
            # as BloodHound nodes. Index records already present in conf so
            # the converter can reference them without inventing objects.
            classes = {
                str(value).casefold() for value in _as_list(record.get("objectClass"))
            }
            first_rdn = dn.casefold().split(",", 1)[0]
            if "configuration" in classes:
                parent_type = "configuration"
            elif first_rdn == "cn=oid":
                parent_type = "base"
            else:
                parent_type = object_type or "base"
            identifiers_by_dn[dn.casefold()] = (identifier, parent_type)
        if object_type is None:
            continue
        if object_type == "enterprisecas":
            continue
        if dn:
            identifiers_by_dn[dn.casefold()] = (
                identifier,
                (
                    "configuration"
                    if "configuration" in classes
                    else "base" if first_rdn == "cn=oid" else object_type
                ),
            )
        grouped.setdefault(object_type, []).append(record)

    documents = {}
    for object_type, object_records in grouped.items():
        documents[object_type] = _configuration_document(
            object_records,
            object_type,
            domain_sid=domain_sid,
            certificate_records=certificate_records,
            principal_records=principal_records,
        )

    for object_type, document in documents.items():
        records_by_identifier = {
            _configuration_identifier(record, object_type): record
            for record in grouped[object_type]
        }
        for node in document["data"]:
            record = records_by_identifier.get(node.get("ObjectIdentifier"))
            if not record:
                continue
            dn = str(record.get("distinguishedName") or record.get("dn") or "")
            parent_dn = dn.split(",", 1)[1] if "," in dn else ""
            parent = identifiers_by_dn.get(parent_dn.casefold())
            if parent:
                node["ContainedBy"] = {
                    "ObjectIdentifier": parent[0],
                    "ObjectType": _BH_OBJECT_TYPES.get(parent[1], parent[1]),
                }
            elif parent_dn and all(
                component.strip().casefold().startswith("dc=")
                for component in parent_dn.split(",")
            ):
                node["ContainedBy"] = {
                    "ObjectIdentifier": domain_sid,
                    "ObjectType": "Domain",
                }

    return documents
