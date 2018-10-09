#!/usr/bin/env python3

from sys import exit
import sys
from struct import unpack
import socket
import json
from argparse import ArgumentParser
from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, Server, Connection, SASL, KERBEROS, NTLM, SUBTREE, ALL
from ldap3.protocol.formatters.formatters import format_sid, format_uuid, format_ad_timestamp
from ldap3.protocol.formatters.validators import validate_sid, validate_guid
from ldap3.core.exceptions import LDAPNoSuchObjectResult
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from binascii import hexlify, unhexlify
from math import fabs
import dns.resolver
from multiprocessing.dummy import Pool as ThreadPool
from termcolor import colored
from tqdm import tqdm
from pprint import pprint
from re import compile as re_compile, findall
import datetime
from base64 import b64encode, b64decode
import ldap3


# define an ldap3-compliant formatter
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
	except Exception:  # any other exception should be investigated, anyway the formatter return the raw_value
		pass
	return raw_value


# add formater to standard ones
ldap3.protocol.formatters.standard.standard_formatter["1.2.840.113556.1.4.8"] = (format_userAccountControl, None)

# All stuff below will soon go to constants.py
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

USER_LOCKED_FILTER = "(&(objectCategory=Person)(objectClass=user)(lockoutTime:1.2.840.113556.1.4.804:=4294967295))"
GROUPS_FILTER = "(objectClass=group)"
ZONES_FILTER = "(&(objectClass=dnsZone)(!(dc=RootDNSServers)))"
ZONE_FILTER = "(objectClass=dnsNode)"
USER_ALL_FILTER = "(&(objectCategory=Person)(objectClass=user))"
USER_ACCOUNT_CONTROL_FILTER = "(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={intval}))"
USER_ACCOUNT_CONTROL_FILTER_NEG = "(&(objectCategory=Person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:={intval})))"
COMPUTERS_FILTER = "(objectClass=computer)"
GROUP_DN_FILTER = "(&(objectClass=group)(sAMAccountName={group}))"
USER_DN_FILTER = "(&(objectClass=user)(objectCategory=Person)(sAMAccountName={username}))"
USERS_IN_GROUP_FILTER = "(&(|(objectCategory=user)(objectCategory=group))(memberOf={group}))"
USER_IN_GROUPS_FILTER = "(sAMAccountName={username})"
DOMAIN_INFO_FILTER = "(objectClass=domain)"
GPO_INFO_FILTER = "(objectCategory=groupPolicyContainer)"
PSO_INFO_FILTER = "(objectClass=msDS-PasswordSettings)"
TRUSTS_INFO_FILTER = "(objectCategory=trustedDomain)"
OU_FILTER = "(objectClass=OrganizationalUnit)"

PAGESIZE = 1000

DOMAIN_PASSWORD_COMPLEX = 1
DOMAIN_PASSWORD_NO_ANON_CHANGE = 2
DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 4
DOMAIN_LOCKOUT_ADMINS = 8
DOMAIN_PASSWORD_STORE_CLEARTEXT = 16
DOMAIN_REFUSE_PASSWORD_CHANGE = 32

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


class Logger(object):

	def __init__(self, outfile=None, quiet=False):
		self.quiet = quiet
		self.terminal = sys.__stdout__
		self.log = open(outfile, 'w') if outfile else None

	def write(self, message):
		if not self.quiet:
			self.terminal.write(message)
		if self.log:
			self.log.write(message)

	def flush(self):
		if self.log:
			self.log.flush()
		pass


# This will go to utils.py
def info(content):
	sys.__stderr__.write("%s\n" % colored("[+] " + content, "blue", attrs=["bold"]))

def error(content):
	sys.__stderr__.write("%s\n" % colored("[!] " + content, "red", attrs=["bold"]))
	sys.exit(1)

# this will go somewhere
class ResolverThread(object):

	def __init__(self, dns_server):
		self.dns_server = dns_server
		self.resolutions = []

	def resolve(self, hostname):
		if self.dns_server:
			resolver = dns.resolver.Resolver()
			resolver.nameservers = [self.dns_server]
		else:
			resolver = dns.resolver
		try:
			answers = resolver.query(hostname, 'A', tcp=True)
			for rdata in answers:
				if rdata.address:
					self.resolutions.append({
						"hostname": hostname,
						"address": rdata.address
					})
					break
			else:
				pass
		except Exception:
			pass


class ActiveDirectoryView(object):

	def __init__(self, username, password, server, fqdn, base, method="NTLM", verbose=False):
		self.username = username
		self.password = password
		self.server = server
		self.fqdn = fqdn
		self.hostnames = []
		self.verbose = verbose

		if method == "Kerberos":
			server = Server(self.server)
			self.ldap = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
		elif method == "NTLM":
			server = Server(self.server, get_info=ALL)
			self.ldap = Connection(server, user="%s\\%s" % (fqdn, username), password=password, authentication=NTLM, check_names=True)

		if not self.ldap.bind():
			error("Unable to bind with provided information")

		self.base_dn = base or ','.join(["dc=%s" % x for x in fqdn.split(".")])
		self.search_scope = SUBTREE

	def query(self, ldapfilter, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], base=None, scope=None):
		entry_generator = self.ldap.extend.standard.paged_search(
			search_base=base or self.base_dn,
			search_filter=ldapfilter,
			search_scope=scope or self.search_scope,
			attributes=attributes,
			paged_size=PAGESIZE,
			generator=True
		)

		result_set = []
		for entry in entry_generator:
			if "dn" in entry:
				d = entry["attributes"]
				d["dn"] = entry["dn"]
				result_set.append(d)

		return result_set

	def get_object(self, ldap_object):
		results = self.query("(&(cn=*{ldap_object}*))".format(ldap_object=ldap_object))
		for result in results:
			self.display(result)

	def list_computers(self, resolve, dns_server):
		self.hostnames = []
		results = self.query(COMPUTERS_FILTER, ["name"])
		for result in results:
			computer_name = result["name"]
			self.hostnames.append("%s.%s" % (computer_name, self.fqdn))
			# print only if resolution was not mandated
			if not resolve:
				print("%s.%s" % (computer_name, self.fqdn))
		# do the resolution
		if resolve:
			self.resolve(dns_server)

	def list_domain_policy(self):
		FILETIME_TIMESTAMP_FIELDS = {
			"lockOutObservationWindow": (60, "mins"),
			"lockoutDuration": (60, "mins"),
			"maxPwdAge": (86400, "days"),
			"minPwdAge": (86400, "days"),
			"forceLogoff": (60, "mins")
		}
		FIELDS_TO_PRINT = ["dc", "distinguishedName", "lockOutObservationWindow", "lockoutDuration", "lockoutThreshold", "maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength", "pwdProperties"]
		policy = self.query(DOMAIN_INFO_FILTER)
		if policy:
			policy = policy[0]
			for field in FIELDS_TO_PRINT:
				val = policy[field]

				if field in FILETIME_TIMESTAMP_FIELDS.keys():
					val = int((fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0])
					val = "%d %s" % (val, FILETIME_TIMESTAMP_FIELDS[field][1])
				elif field == "pwdProperties":
					if int(val) == 1:
						val = "complexity enabled"
					elif int(val) == 2:
						val = "complexity disabled"

				print("%s: %s" % (field, val))


	def resolve_sid(self, sid):
		# Local SID
		if sid in WELL_KNOWN_SIDs:
			print(WELL_KNOWN_SIDs[sid])
		elif validate_sid(sid):
			results = self.query("(&(ObjectSid={sid}))".format(sid=sid))
			if results and len(results) > 0:
				self.display(results[0])
		else:
			error("Invalid SID")

	def resolve_guid(self, guid):
		if validate_guid(guid):
			results = self.query("(&(ObjectGUID={guid}))".format(guid=guid))
			if results and len(results) > 0:
				self.display(results[0])
		else:
			error("Invalid GUID")

	def get_gpo(self):
		results = self.query(GPO_INFO_FILTER)
		gpos = {}
		for result in results:
			gpos[result["cn"]] = result["displayName"]
		return gpos

	def list_gpo(self):
		gpos = self.get_gpo()
		for k, v in gpos.items():
			print("%s: %s" % (k, v))

	def list_ou(self):
		results = self.query(OU_FILTER)
		cn_re = re_compile("{[^}]+}")
		gpos = self.get_gpo()
		for result in results:
			print(result["distinguishedName"])
			if "gPLink" in result:
				guids = cn_re.findall(result["gPLink"])
				if len(guids) > 0:
					print("[gPLink]")
					print("* {}".format("\n* ".join([gpos[g] if g in gpos else g for g in guids])))

	def unlock(self, username):
		results = self.query(USER_DN_FILTER.format(username=username))
		if len(results) != 1:
			error("No or more than 1 users found, exiting")
		else:
			user = results[0]
			info("Found user %s at DN %s" % (username, user["dn"]))
			unlock = ad_unlock_account(self.ldap, user["dn"])
			# goddamn, return value is either True or str...
			if isinstance(unlock, bool):
				info("User %s unlocked" % username)
			else:
				error("Unable to unlock %s, check privileges" % username)

	def list_zones(self):
		if not self.verbose:
			attributes = ["dc", "objectClass"]
		else:
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
		results = self.query(ZONES_FILTER, attributes, base=','.join(["CN=MicrosoftDNS,DC=DomainDNSZones", self.base_dn]))
		for result in results:
			print(result["dc"])

	def list_zone(self, zone):
		try:
			results = self.query(ZONE_FILTER, base=','.join(["DC=%s" % zone, "CN=MicrosoftDNS,DC=DomainDNSZones", self.base_dn]))
			for result in results:
				dnsrecord = result["dnsrecord"][0]
				databytes = dnsrecord[0:4]
				datalen, datatype = unpack("HH", databytes)
				data = dnsrecord[24:24 + datalen]
				for recordname, recordvalue in DNS_TYPES.items():
					if recordvalue == datatype:
						if recordname == "A":
							target = socket.inet_ntoa(data)
						else:
							# how, ugly
							data = data.decode('unicode-escape')
							target = ''.join([c for c in data if ord(c) > 31 or ord(c) == 9])
						print("%s IN %s %s" % (result["dc"], recordname, target))
		except LDAPNoSuchObjectResult:
			error("Zone %s does not exists" % zone)

	def list_pso(self):
		FILETIME_TIMESTAMP_FIELDS = {
			"msDS-LockoutObservationWindow": (60, "mins"),
			"msDS-MinimumPasswordAge": (86400, "days"),
			"msDS-MaximumPasswordAge": (86400, "days"),
			"msDS-LockoutDuration": (60, "mins")
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
		]
		psos = self.query(PSO_INFO_FILTER)
		for policy in psos:
			for field in FIELDS_TO_PRINT:
				if isinstance(policy[field], list):
					val = policy[field][0]

				if field in FILETIME_TIMESTAMP_FIELDS.keys():
					val = int((fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0])
					val = "%d %s" % (val, FILETIME_TIMESTAMP_FIELDS[field][1])
			print("%s: %s" % (field, val))

	def list_trusts(self):
		# python3: no tested
		results = self.query(TRUSTS_INFO_FILTER)
		FIELDS_TO_PRINT = ["dn", "cn", "name", "trustDirection", "trustPartner", "trustType", "trustAttributes", "flatName"]
		for result in results:
			for field in FIELDS_TO_PRINT:
				if field in result:
					val = result[field]
					if field == "trustDirection":
						if int(val) == 0x00000003:
							val = "bidirectional"
						elif int(val) == 0x00000002:
							val = "outbound"
						elif int(val) == 0x00000001:
							val = "inbound"
						elif int(val) == 0x00000000:
							val = "disabled"
					elif field == "trustType":
						if int(val) == 0x00000001:
							val = "Non running Windows domain"
						elif int(val) == 0x00000002:
							val = "Windows domain running Active Directory"
						elif int(val) == 0x00000003:
							val = "Non Windows domain"
					print("%s: %s" % (field, val))
			print("")

	def list_groups(self):
		if not self.verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

		results = self.query(GROUPS_FILTER, attributes)
		for result in results:
			self.display(result)

	def list_users(self, filter_):
		if not self.verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

		if filter_ == "all":
			results = self.query(USER_ALL_FILTER)
		elif filter_ == "enabled":
			results = self.query(USER_ACCOUNT_CONTROL_FILTER_NEG.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]))
		elif filter_ == "disabled":
			results = self.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]))
		elif filter_ == "locked":
			results = self.query(USER_LOCKED_FILTER)
		elif filter_ == "nopasswordexpire":
			results = self.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["DONT_EXPIRE_PASSWORD"]))
		elif filter_ == "passwordexpired":
			results = self.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["PASSWORD_EXPIRED"]))

		for result in results:
			self.display(result)

	def list_membersof(self, group):
		# retrieve group DN
		results = self.query(GROUP_DN_FILTER.format(group=group), ["distinguishedName"])
		if results:
			group_dn = results[0]["distinguishedName"]
		else:
			error("Group %s does not exists" % group)
			exit(0)
		results = self.query(USERS_IN_GROUP_FILTER.format(group=group_dn))
		for result in results:
			self.display(result)

	def list_membership(self, user):
		# retrieve group DN
		results = self.query(USER_IN_GROUPS_FILTER.format(username=user), ["memberOf"])
		for result in results:
			if "memberOf" in result:
				for group_dn in result["memberOf"]:
					print(group_dn)
			else:
				error("No groups for user %s" % user)

	def search(self, filter_, attr):
		# custom search is custom, verbose on for printing
		# all attributes
		self.verbose = True
		try:
			if attr:
				results = self.query(filter_, [attr])
			else:
				results = self.query(filter_)
			for result in results:
				self.display(result)
		except Exception as e:
			# shit will be printed
			error(e)

	def resolve(self, dns_server):
		pool = ThreadPool(20)
		resolver_thread = ResolverThread(dns_server)
		with tqdm(total=len(self.hostnames)) as pbar:
			for _ in pool.imap_unordered(resolver_thread.resolve, tqdm(self.hostnames, desc="Resolution", bar_format="{desc} {n_fmt}/{total_fmt} hostnames")):
				pbar.update()
		pool.close()
		pool.join()
		for computer in resolver_thread.resolutions:
			print("%s %s" % (computer["address"].ljust(20, " "), computer["hostname"]))

	def display(self, record):
		def default(o):
			if type(o) is datetime.date or type(o) is datetime.datetime:
				return o.isoformat()

		if self.verbose:
			print(json.dumps(dict(record), ensure_ascii=False, default=default, sort_keys=True, indent=2))
		else:
			if "group" in record["objectClass"]:
				print(record["sAMAccountName"] + " (group)")
			if "user" in record["objectClass"]:
				print(record["sAMAccountName"])


if __name__ == "__main__":
	parser = ArgumentParser("LDEEP - Deep LDAP inspection")
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")
	parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Results will contain full information")
	parser.add_argument("--dns", help="An optional DNS server to use", default=False)

	authentication = parser.add_argument_group("Authentication")
	authentication.add_argument("-u", "--username", help="The username")
	authentication.add_argument("-p", "--password", help="The password or the corresponding NTLM hash")
	authentication.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by KRB5NAME env variable")

	action = parser.add_argument_group("Action (exclusive)")
	xgroup = action.add_mutually_exclusive_group(required=True)
	xgroup.add_argument("--all", metavar="OUTFILE", help="Lists all things to OUTFILE_thing.lst")
	xgroup.add_argument("--groups", action="store_true", help="Lists all available groups")
	xgroup.add_argument("--users", nargs='?', const="all", action="store", choices=["all", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired"], help="Lists all available users")
	xgroup.add_argument("--zones", action="store_true", help="Return configured DNS zones")
	xgroup.add_argument("--zone", help="Return zone records")
	xgroup.add_argument("--object", metavar="OBJECT", help="Return information on an object (group, computer, user, etc.)")
	xgroup.add_argument("--computers", action="store_true", help="Lists all computers")
	xgroup.add_argument("--sid", metavar="SID", help="Return the record associated to the SID")
	xgroup.add_argument("--unlock", metavar="USER", help="Unlock the given user")
	xgroup.add_argument("--guid", metavar="GUID", help="Return the record associated to the GUID")
	xgroup.add_argument("--domain_policy", action="store_true", help="Print the domain policy")
	xgroup.add_argument("--gpo", action="store_true", help="List GPO GUID and their name")
	xgroup.add_argument("--ou", action="store_true", help="List OU and resolve linked GPO")
	xgroup.add_argument("--pso", action="store_true", help="Dump Password Setting Object (PSO) containers")
	xgroup.add_argument("--trusts", action="store_true", help="List domain trusts")
	xgroup.add_argument("--members", metavar="GROUP", help="Returns users in a specific group")
	xgroup.add_argument("--membership", metavar="USER", help="Returns all groups the users in member of")
	xgroup.add_argument("--search", help="Custom LDAP filter")

	parser.add_argument("--resolve", action="store_true", required=False, help="Performs a resolution on all computer names, should be used with --computers")
	parser.add_argument("--attr", required=False, help="Filters output of --search")
	parser.add_argument("-o", "--output", required=False, help="File for saving results", default=None)

	args = parser.parse_args()

	method = "NTLM"
	if args.kerberos:
		method = "Kerberos"
	elif args.username and args.password:
		method = "NTLM"
	else:
		error("Lack of authentication options: either Kerberos or Username with Password (can be a NTLM hash).")

	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn, args.base, method, args.verbose)
	if args.all:
		info("Getting all users")
		sys.stdout = Logger("%s_all_users.lst" % args.all, quiet=True)
		ad.list_users("all")
		info("Getting enabled users")
		sys.stdout = Logger("%s_enabled_users.lst" % args.all, quiet=True)
		ad.list_users("enabled")
		info("Getting disabled users")
		sys.stdout = Logger("%s_disabled_users.lst" % args.all, quiet=True)
		ad.list_users("disabled")
		info("Getting locked users")
		sys.stdout = Logger("%s_locked_users.lst" % args.all, quiet=True)
		ad.list_users("locked")
		info("Getting users with no password expiry")
		sys.stdout = Logger("%s_nopasswordexpire_users.lst" % args.all, quiet=True)
		ad.list_users("nopasswordexpire")
		info("Getting users with password expired")
		sys.stdout = Logger("%s_passwordexpired_users.lst" % args.all, quiet=True)
		ad.list_users("passwordexpired")
		info("Getting groups")
		sys.stdout = Logger("%s_groups.lst" % args.all, quiet=True)
		ad.list_groups()
		info("Getting computers")
		sys.stdout = Logger("%s_computers.lst" % args.all, quiet=True)
		ad.list_computers(args.resolve, args.dns)
		info("Getting organizational units")
		sys.stdout = Logger("%s_ou.lst" % args.all, quiet=True)
		ad.list_ou()
		info("Getting Group Policy Objects")
		sys.stdout = Logger("%s_gpo.lst" % args.all, quiet=True)
		ad.list_gpo()
		info("Getting Password Security Objects")
		sys.stdout = Logger("%s_pso.lst" % args.all, quiet=True)
		ad.list_pso()
		info("Getting domain trusts")
		sys.stdout = Logger("%s_trusts.lst" % args.all, quiet=True)
		ad.list_trusts()
		info("Getting domain policy")
		sys.stdout = Logger("%s_domain_policy.lst" % args.all, quiet=True)
		ad.list_domain_policy()
		sys.exit(0)

	sys.stdout = Logger(args.output)
	if args.groups:
		ad.list_groups()
	elif args.users:
		ad.list_users(args.users)
	elif args.members:
		ad.list_membersof(args.members)
	elif args.sid:
		ad.resolve_sid(args.sid)
	elif args.guid:
		ad.resolve_guid(args.guid)
	elif args.object:
		ad.get_object(args.object)
	elif args.membership:
		ad.list_membership(args.membership)
	elif args.computers:
		ad.list_computers(args.resolve, args.dns)
	elif args.domain_policy:
		ad.list_domain_policy()
	elif args.gpo:
		ad.list_gpo()
	elif args.zones:
		ad.list_zones()
	elif args.zone:
		ad.list_zone(args.zone)
	elif args.ou:
		ad.list_ou()
	elif args.pso:
		ad.list_pso()
	elif args.trusts:
		ad.list_trusts()
	elif args.search:
		ad.search(args.search, args.attr)
	elif args.unlock:
		ad.unlock(args.unlock)
