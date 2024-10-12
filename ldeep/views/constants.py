from enum import Enum

DNS_TYPES = {
    "ZERO": 0x0000,
    "A": 0x0001,
    "NS": 0x0002,
    "MD": 0x0003,
    "MF": 0x0004,
    "CNAME": 0x0005,
    "SOA": 0x0006,
    "MB": 0x0007,
    "MG": 0x0008,
    "MR": 0x0009,
    "NULL": 0x000A,
    "WKS": 0x000B,
    "PTR": 0x000C,
    "HINFO": 0x000D,
    "MINFO": 0x000E,
    "MX": 0x000F,
    "TXT": 0x0010,
    "RP": 0x0011,
    "AFSDB": 0x0012,
    "X25": 0x0013,
    "ISDN": 0x0014,
    "RT": 0x0015,
    "SIG": 0x0018,
    "KEY": 0x0019,
    "AAAA": 0x001C,
    "LOC": 0x001D,
    "NXT": 0x001E,
    "SRV": 0x0021,
    "ATMA": 0x0022,
    "NAPTR": 0x0023,
    "DNAME": 0x0027,
    "DS": 0x002B,
    "RRSIG": 0x002E,
    "NSEC": 0x002F,
    "DNSKEY": 0x0030,
    "DHCID": 0x0031,
    "NSEC3": 0x0032,
    "NSEC3PARAM": 0x0033,
    "TLSA": 0x0034,
    "ALL": 0x00FF,
    "WINS": 0xFF01,
    "WINSR": 0xFF02,
}

USER_ACCOUNT_CONTROL = {
    "SCRIPT": 0x0001,
    "ACCOUNTDISABLE": 0x0002,
    "HOMEDIR_REQUIRED": 0x0008,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "PASSWD_CANT_CHANGE": 0x0040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
    "TEMP_DUPLICATE_ACCOUNT": 0x0100,
    "NORMAL_ACCOUNT": 0x0200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
    "WORKSTATION_TRUST_ACCOUNT": 0x1000,
    "SERVER_TRUST_ACCOUNT": 0x2000,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "MNS_LOGON_ACCOUNT": 0x20000,
    "SMARTCARD_REQUIRED": 0x40000,
    "TRUSTED_FOR_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "USE_DES_KEY_ONLY": 0x200000,
    "DONT_REQ_PREAUTH": 0x400000,
    "PASSWORD_EXPIRED": 0x800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}

SAM_ACCOUNT_TYPE = {
    "SAM_DOMAIN_OBJECT": 0x0,
    "SAM_GROUP_OBJECT": 0x10000000,
    "SAM_NON_SECURITY_GROUP_OBJECT": 0x10000001,
    "SAM_ALIAS_OBJECT": 0x20000000,
    "SAM_NON_SECURITY_ALIAS_OBJECT": 0x20000001,
    "SAM_USER_OBJECT": 0x30000000,
    "SAM_NORMAL_USER_ACCOUNT": 0x30000000,
    "SAM_MACHINE_ACCOUNT": 0x30000001,
    "SAM_TRUST_ACCOUNT": 0x30000002,
    "SAM_APP_BASIC_GROUP": 0x40000000,
    "SAM_APP_QUERY_GROUP": 0x40000001,
    "SAM_ACCOUNT_TYPE_MAX": 0x7FFFFFFF,
}

PWD_PROPERTIES = {
    "DOMAIN_PASSWORD_COMPLEX": 0x1,
    "DOMAIN_PASSWORD_NO_ANON_CHANGE": 0x2,
    "DOMAIN_PASSWORD_NO_CLEAR_CHANGE": 0x4,
    "DOMAIN_LOCKOUT_ADMINS": 0x8,
    "DOMAIN_PASSWORD_STORE_CLEARTEXT": 0x10,
    "DOMAIN_REFUSE_PASSWORD_CHANGE": 0x20,
}

TRUSTS_INFOS = {
    "NON_TRANSITIVE": 0x1,
    "UPLEVEL_ONLY": 0x2,
    "QUARANTINED_DOMAIN": 0x4,
    "FOREST_TRANSITIVE": 0x8,
    "CROSS_ORGANIZATION": 0x10,
    "WITHIN_FOREST": 0x20,
    "TREAT_AS_EXTERNAL": 0x40,
    "USES_RC4_ENCRYPTION": 0x80,
    "USES_AES_KEYS": 0x100,
    "CROSS_ORGANIZATION_NO_TGT_DELEGATION": 0x200,
    "PIM_TRUST": 0x400,
    "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION": 0x800,
}

FOREST_LEVELS = {
    7: "Windows Server 2016",
    6: "Windows Server 2012 R2",
    5: "Windows Server 2012",
    4: "Windows Server 2008 R2",
    3: "Windows Server 2008",
    2: "Windows Server 2003",
    1: "Windows Server 2003 operating system through Windows Server 2016",
    0: "Windows 2000 Server operating system through Windows Server 2008 operating system",
}

FUNCTIONAL_LEVELS = {
    0: "2000 Mixed/Native",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
}


WELL_KNOWN_SIDS = {
    "S-1-5-11": r"BUILTIN\Authenticated Users",
    "S-1-5-32-544": r"BUILTIN\Administrators",
    "S-1-5-32-545": r"BUILTIN\Users",
    "S-1-5-32-546": r"BUILTIN\Guests",
    "S-1-5-32-547": r"BUILTIN\Power Users",
    "S-1-5-32-548": r"BUILTIN\Account Operators",
    "S-1-5-32-549": r"BUILTIN\Server Operators",
    "S-1-5-32-550": r"BUILTIN\Print Operators",
    "S-1-5-32-551": r"BUILTIN\Backup Operators",
    "S-1-5-32-552": r"BUILTIN\Replicators",
    "S-1-5-64-10": r"BUILTIN\NTLM Authentication",
    "S-1-5-64-14": r"BUILTIN\SChannel Authentication",
    "S-1-5-64-21": r"BUILTIN\Digest Authentication",
    "S-1-16-4096": r"BUILTIN\Low Mandatory Level",
    "S-1-16-8192": r"BUILTIN\Medium Mandatory Level",
    "S-1-16-8448": r"BUILTIN\Medium Plus Mandatory Level",
    "S-1-16-12288": r"BUILTIN\High Mandatory Level",
    "S-1-16-16384": r"BUILTIN\System Mandatory Level",
    "S-1-16-20480": r"BUILTIN\Protected Process Mandatory Level",
    "S-1-16-28672": r"BUILTIN\Secure Process Mandatory Level",
    "S-1-5-32-554": r"BUILTIN\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": r"BUILTIN\Remote Desktop Users",
    "S-1-5-32-556": r"BUILTIN\Network Configuration Operators",
    "S-1-5-32-557": r"BUILTIN\Incoming Forest Trust Builders",
    "S-1-5-32-558": r"BUILTIN\Performance Monitor Users",
    "S-1-5-32-559": r"BUILTIN\Performance Log Users",
    "S-1-5-32-560": r"BUILTIN\Windows Authorization Access Group",
    "S-1-5-32-561": r"BUILTIN\Terminal Server License Servers",
    "S-1-5-32-562": r"BUILTIN\Distributed COM Users",
    "S-1-5-32-569": r"BUILTIN\Cryptographic Operators",
    "S-1-5-32-573": r"BUILTIN\Event Log Readers",
    "S-1-5-32-574": r"BUILTIN\Certificate Service DCOM Access",
    "S-1-5-32-575": r"BUILTIN\RDS Remote Access Servers",
    "S-1-5-32-576": r"BUILTIN\RDS Endpoint Servers",
    "S-1-5-32-577": r"BUILTIN\RDS Management Servers",
    "S-1-5-32-578": r"BUILTIN\Hyper-V Administrators",
    "S-1-5-32-579": r"BUILTIN\Access Control Assistance Operators",
    "S-1-5-32-580": r"BUILTIN\Remote Management Users",
}

WELLKNOWN_SIDS = {
    "S-1-0": ("Null Authority", "USER"),
    "S-1-0-0": ("Nobody", "USER"),
    "S-1-1": ("World Authority", "USER"),
    "S-1-1-0": ("Everyone", "GROUP"),
    "S-1-2": ("Local Authority", "USER"),
    "S-1-2-0": ("Local", "GROUP"),
    "S-1-2-1": ("Console Logon", "GROUP"),
    "S-1-3": ("Creator Authority", "USER"),
    "S-1-3-0": ("Creator Owner", "USER"),
    "S-1-3-1": ("Creator Group", "GROUP"),
    "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
    "S-1-3-3": ("Creator Group Server", "COMPUTER"),
    "S-1-3-4": ("Owner Rights", "GROUP"),
    "S-1-4": ("Non-unique Authority", "USER"),
    "S-1-5": ("NT Authority", "USER"),
    "S-1-5-1": ("Dialup", "GROUP"),
    "S-1-5-2": ("Network", "GROUP"),
    "S-1-5-3": ("Batch", "GROUP"),
    "S-1-5-4": ("Interactive", "GROUP"),
    "S-1-5-6": ("Service", "GROUP"),
    "S-1-5-7": ("Anonymous", "GROUP"),
    "S-1-5-8": ("Proxy", "GROUP"),
    "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
    "S-1-5-10": ("Principal Self", "USER"),
    "S-1-5-11": ("Authenticated Users", "GROUP"),
    "S-1-5-12": ("Restricted Code", "GROUP"),
    "S-1-5-13": ("Terminal Server Users", "GROUP"),
    "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
    "S-1-5-15": ("This Organization", "GROUP"),
    "S-1-5-17": ("IUSR", "USER"),
    "S-1-5-18": ("Local System", "USER"),
    "S-1-5-19": ("NT Authority", "USER"),
    "S-1-5-20": ("Network Service", "USER"),
    "S-1-5-80-0": ("All Services ", "GROUP"),
    "S-1-5-32-544": ("Administrators", "GROUP"),
    "S-1-5-32-545": ("Users", "GROUP"),
    "S-1-5-32-546": ("Guests", "GROUP"),
    "S-1-5-32-547": ("Power Users", "GROUP"),
    "S-1-5-32-548": ("Account Operators", "GROUP"),
    "S-1-5-32-549": ("Server Operators", "GROUP"),
    "S-1-5-32-550": ("Print Operators", "GROUP"),
    "S-1-5-32-551": ("Backup Operators", "GROUP"),
    "S-1-5-32-552": ("Replicators", "GROUP"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
    "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
    "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
    "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
    "S-1-5-32-559": ("Performance Log Users", "GROUP"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
    "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
    "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
    "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
    "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
    "S-1-5-32-573": ("Event Log Readers", "GROUP"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
    "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
    "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-581": ("System Managed Accounts Group", "GROUP"),
    "S-1-5-32-582": ("Storage Replica Administrators", "GROUP"),
}

FILETIME_FIELDS = [
    "badPasswordTime",
    "lastLogon",
    "lastLogoff",
    "lastLogonTimestamp",
    "pwdLastSet",
    "accountExpires",
    "lockoutTime",
]

DATETIME_FIELDS = ["dSCorePropagationData", "whenChanged", "whenCreated"]

FILETIME_TIMESTAMP_FIELDS = {
    "lockOutObservationWindow": (60, "mins"),
    "lockoutDuration": (60, "mins"),
    "maxPwdAge": (86400, "days"),
    "minPwdAge": (86400, "days"),
    "forceLogoff": (60, "mins"),
}

LDAP_SERVER_SD_FLAGS_OID_SEC_DESC = [
    ("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")
]

LOGON_SAM_LOGON_RESPONSE_EX = b"\x17\x00"

GMSA_ENCRYPTION_CONSTANTS = b"\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93\x5c\x9b\xdc\xda\xd9\x5c\x98\x99\xc4\xca\xe4\xde\xe6\xd6\xca\xe4"


class ObjectType(Enum):
    BASE = "base"
    USER = "user"
    COMPUTER = "computer"
    GROUP = "group"
    LOCALGROUP = "localgroup"
    LOCALUSER = "localuser"
    GPO = "gpo"
    DOMAIN = "domain"
    OU = "organizational-unit"
    CONTAINER = "container"
    CONFIGURATION = "configuration"
    CERTTEMPLATE = "cert-template"
    ROOTCA = "root-ca"
    AIACA = "aia-ca"
    ENTERPRISECA = "enterprise-ca"
    NTAUTHSTORE = "ntauthstore"
    ISSUANCEPOLICY = "issuancepolicy"


class EdgeNames(Enum):
    GenericWrite = "GenericWrite"
    Owns = "Owns"
    GenericAll = "GenericAll"
    WriteDacl = "WriteDacl"
    WriteOwner = "WriteOwner"
    AddSelf = "AddSelf"
    GetChanges = "GetChanges"
    GetChangesAll = "GetChangesAll"
    GetChangesInFilteredSet = "GetChangesInFilteredSet"
    AllExtendedRights = "AllExtendedRights"
    ForceChangePassword = "ForceChangePassword"
    AddAllowedToAct = "AddAllowedToAct"
    ReadLAPSPassword = "ReadLAPSPassword"
    ReadGMSAPassword = "ReadGMSAPassword"
    AddMember = "AddMember"
    WriteSPN = "WriteSPN"
    AddKeyCredentialLink = "AddKeyCredentialLink"
    SQLAdmin = "SQLAdmin"
    WriteAccountRestrictions = "WriteAccountRestrictions"
    WritePKIEnrollmentFlag = "WritePKIEnrollmentFlag"
    WritePKINameFlag = "WritePKINameFlag"
    ManageCA = "ManageCA"
    ManageCertificates = "ManageCertificates"
    Enroll = "Enroll"
    WriteGPLink = "WriteGPLink"


class ACE(Enum):
    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERIT_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x04


class ACEGuids(Enum):
    DSReplicationGetChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    DSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    DSReplicationGetChangesInFilteredSet = "89e95b76-444d-4c62-991a-0facbeda640c"
    UserForceChangePassword = "00299570-246d-11d0-a768-00aa006e0529"
    AllGuid = "00000000-0000-0000-0000-000000000000"
    WriteMember = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    WriteAllowedToAct = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
    WriteSPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
    AddKeyPrincipal = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
    UserAccountRestrictions = "4c164200-20c0-11d0-a768-00aa006e0529"
    PKINameFlag = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"
    PKIEnrollmentFlag = "d15ef7d8-f226-46db-ae79-b34e560bd12c"
    Enroll = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
    AutoEnroll = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
    WriteGPLink = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"


ADRights = {
    "GenericRead": 0x00020094,
    "GenericWrite": 0x00020028,
    "GenericExecute": 0x00020004,
    "GenericAll": 0x000F01FF,
    "Synchronize": 0x00100000,
    "WriteOwner": 0x00080000,
    "WriteDacl": 0x00040000,
    "ReadControl": 0x00020000,
    "Delete": 0x00010000,
    "ExtendedRight": 0x00000100,
    "CreateChild": 0x00000001,
    "DeleteChild": 0x00000002,
    "ReadProperty": 0x00000010,
    "WriteProperty": 0x00000020,
    "Self": 0x00000008,
}

EXTENDED_RIGHTS_MAP = {
    "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Serve",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
    "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
    "e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Maste",
    "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Maste",
    "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
    "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
    "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
    "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Maste",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    "4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Lette",
    "4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Lette",
    "4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
    "4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
    "06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
    "06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
    "06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
    "06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
    "b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connecto",
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Maste",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
    "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
    "91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
    "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
    "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
    "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
    "ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
    "5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Serve",
    "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect-Admin-Groups-Task",
    "7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controlle",
    "d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
    "80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
    "4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owne",
    "88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Compute",
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights",
}

EXTENDED_RIGHTS_NAME_MAP = {k: v for v, k in EXTENDED_RIGHTS_MAP.items()}

OID_TO_STR_MAP = {
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.23.133.8.2": "Platform Certificate",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

AUTHENTICATING_EKUS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose",
}

MS_PKI_CERTIFICATE_NAME_FLAG = {
    "NONE": 0x00000000,
    "ENROLLEE_SUPPLIES_SUBJECT": 0x00000001,
    "ADD_EMAIL": 0x00000002,
    "ADD_OBJ_GUID": 0x00000004,
    "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME": 0x00000008,
    "ADD_DIRECTORY_PATH": 0x00000100,
    "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME": 0x00010000,
    "SUBJECT_ALT_REQUIRE_DOMAIN_DNS": 0x00400000,
    "SUBJECT_ALT_REQUIRE_SPN": 0x00800000,
    "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID": 0x01000000,
    "SUBJECT_ALT_REQUIRE_UPN": 0x02000000,
    "SUBJECT_ALT_REQUIRE_EMAIL": 0x04000000,
    "SUBJECT_ALT_REQUIRE_DNS": 0x08000000,
    "SUBJECT_REQUIRE_DNS_AS_CN": 0x10000000,
    "SUBJECT_REQUIRE_EMAIL": 0x20000000,
    "SUBJECT_REQUIRE_COMMON_NAME": 0x40000000,
    "SUBJECT_REQUIRE_DIRECTORY_PATH": 0x80000000,
}

MS_PKI_ENROLLMENT_FLAG = {
    "NONE": 0x00000000,
    "INCLUDE_SYMMETRIC_ALGORITHMS": 0x00000001,
    "PEND_ALL_REQUESTS": 0x00000002,
    "PUBLISH_TO_KRA_CONTAINER": 0x00000004,
    "PUBLISH_TO_DS": 0x00000008,
    "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE": 0x00000010,
    "AUTO_ENROLLMENT": 0x00000020,
    "CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED": 0x80,
    "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT": 0x00000040,
    "USER_INTERACTION_REQUIRED": 0x00000100,
    "ADD_TEMPLATE_NAME": 0x200,
    "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE": 0x00000400,
    "ALLOW_ENROLL_ON_BEHALF_OF": 0x00000800,
    "ADD_OCSP_NOCHECK": 0x00001000,
    "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL": 0x00002000,
    "NOREVOCATIONINFOINISSUEDCERTS": 0x00004000,
    "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS": 0x00008000,
    "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT": 0x00010000,
    "ISSUANCE_POLICIES_FROM_REQUEST": 0x00020000,
    "SKIP_AUTO_RENEWAL": 0x00040000,
    "NO_SECURITY_EXTENSION": 0x0008000,
}
