
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
	"SAM_ACCOUNT_TYPE_MAX": 0x7fffffff,
}

PWD_PROPERTIES = {
	"DOMAIN_PASSWORD_COMPLEX": 0x1,
	"DOMAIN_PASSWORD_NO_ANON_CHANGE": 0x2,
	"DOMAIN_PASSWORD_NO_CLEAR_CHANGE": 0x4,
	"DOMAIN_LOCKOUT_ADMINS": 0x8,
	"DOMAIN_PASSWORD_STORE_CLEARTEXT": 0x10,
	"DOMAIN_REFUSE_PASSWORD_CHANGE": 0x20
}

USER_LOCKED_FILTER = "(&(objectCategory=Person)(objectClass=user)(lockoutTime:1.2.840.113556.1.4.804:=4294967295))"
GROUPS_FILTER = "(objectClass=group)"
ZONES_FILTER = "(&(objectClass=dnsZone)(!(dc=RootDNSServers)))"
ZONE_FILTER = "(objectClass=dnsNode)"
USER_ALL_FILTER = "(&(objectCategory=Person)(objectClass=user))"
USER_SPN_FILTER = "(&(objectCategory=Person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"
USER_ACCOUNT_CONTROL_FILTER = "(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={intval}))"
USER_ACCOUNT_CONTROL_FILTER_NEG = "(&(objectCategory=Person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:={intval})))"
COMPUTERS_FILTER = "(objectClass=computer)"
GROUP_DN_FILTER = "(&(objectClass=group)(sAMAccountName={group}))"
USER_DN_FILTER = "(&(objectClass=user)(objectCategory=Person)(sAMAccountName={username}))"
USERS_IN_GROUP_FILTER = "(&(|(objectCategory=user)(objectCategory=group))(|(primaryGroupID={primary_group_id})(memberOf={group})))"
USER_IN_GROUPS_FILTER = "(sAMAccountName={username})"
DOMAIN_INFO_FILTER = "(objectClass=domain)"
GPO_INFO_FILTER = "(objectCategory=groupPolicyContainer)"
PSO_INFO_FILTER = "(objectClass=msDS-PasswordSettings)"
TRUSTS_INFO_FILTER = "(objectCategory=trustedDomain)"
OU_FILTER = "(|(objectClass=OrganizationalUnit)(objectClass=domain))"

WELL_KNOWN_SIDs = {
	"S-1-5-32-544"	: r"BUILTIN\Administrators",
	"S-1-5-32-545"	: r"BUILTIN\Users",
	"S-1-5-32-546"	: r"BUILTIN\Guests",
	"S-1-5-32-547"	: r"BUILTIN\Power Users",
	"S-1-5-32-548"	: r"BUILTIN\Account Operators",
	"S-1-5-32-549"	: r"BUILTIN\Server Operators",
	"S-1-5-32-550"	: r"BUILTIN\Print Operators",
	"S-1-5-32-551"	: r"BUILTIN\Backup Operators",
	"S-1-5-32-552"	: r"BUILTIN\Replicators",
	"S-1-5-64-10"	: r"BUILTIN\NTLM Authentication",
	"S-1-5-64-14"	: r"BUILTIN\SChannel Authentication",
	"S-1-5-64-21"	: r"BUILTIN\Digest Authentication",
	"S-1-16-4096"	: r"BUILTIN\Low Mandatory Level",
	"S-1-16-8192"	: r"BUILTIN\Medium Mandatory Level",
	"S-1-16-8448"	: r"BUILTIN\Medium Plus Mandatory Level",
	"S-1-16-12288"	: r"BUILTIN\High Mandatory Level",
	"S-1-16-16384"	: r"BUILTIN\System Mandatory Level",
	"S-1-16-20480"	: r"BUILTIN\Protected Process Mandatory Level",
	"S-1-16-28672"	: r"BUILTIN\Secure Process Mandatory Level",
	"S-1-5-32-554"	: r"BUILTIN\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555"	: r"BUILTIN\Remote Desktop Users",
	"S-1-5-32-556"	: r"BUILTIN\Network Configuration Operators",
	"S-1-5-32-557"	: r"BUILTIN\Incoming Forest Trust Builders",
	"S-1-5-32-558"	: r"BUILTIN\Performance Monitor Users",
	"S-1-5-32-559"	: r"BUILTIN\Performance Log Users",
	"S-1-5-32-560"	: r"BUILTIN\Windows Authorization Access Group",
	"S-1-5-32-561"	: r"BUILTIN\Terminal Server License Servers",
	"S-1-5-32-562"	: r"BUILTIN\Distributed COM Users",
	"S-1-5-32-569"	: r"BUILTIN\Cryptographic Operators",
	"S-1-5-32-573"	: r"BUILTIN\Event Log Readers",
	"S-1-5-32-574"	: r"BUILTIN\Certificate Service DCOM Access",
	"S-1-5-32-575"	: r"BUILTIN\RDS Remote Access Servers",
	"S-1-5-32-576"	: r"BUILTIN\RDS Endpoint Servers",
	"S-1-5-32-577"	: r"BUILTIN\RDS Management Servers",
	"S-1-5-32-578"	: r"BUILTIN\Hyper-V Administrators",
	"S-1-5-32-579"	: r"BUILTIN\Access Control Assistance Operators",
	"S-1-5-32-580"	: r"BUILTIN\Remote Management Users",
}

FILETIME_FIELDS = [
	"badPasswordTime",
	"lastLogon",
	"lastLogoff",
	"lastLogonTimestamp",
	"pwdLastSet",
	"accountExpires",
	"lockoutTime"
]

DATETIME_FIELDS = [
	"dSCorePropagationData",
	"whenChanged",
	"whenCreated"
]

