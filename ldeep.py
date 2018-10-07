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
from binascii import hexlify, unhexlify
from math import fabs
import dns.resolver
from multiprocessing.dummy import Pool as ThreadPool
from distutils.version import LooseVersion
from tqdm import tqdm
from pprint import pprint
from re import compile as re_compile, findall
from datetime import timedelta, datetime
from base64 import b64encode, b64decode


# DNS record types
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

LOCKED_USERS = "(&(objectCategory=Person)(objectClass=User)(lockoutTime>=1))"


GROUPS_FILTER = "(&(objectClass=group))"
ZONES_FILTER = "(&(objectClass=dnsZone)(!(dc=RootDNSServers)))"
ZONE_FILTER = "(&(objectClass=dnsNode))"
USER_ALL_FILTER = "(&(objectCategory=Person)(objectClass=user))"
USER_ENABLED_FILTER = "(&(objectCategory=Person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
USER_DISABLED_FILTER = "(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
USER_DONT_EXPIRE_FILTER = "(&(objectCategory=Person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
COMPUTERS_FILTER = "(&(objectClass=computer))"
GROUP_DN_FILTER = "(&(objectClass=group)(sAMAccountName=%s))"
USERS_IN_GROUP_FILTER = "(&(|(objectCategory=user)(objectCategory=group))(memberOf=%s))"
USER_IN_GROUPS_FILTER = "(&(sAMAccountName=%s))"
DOMAIN_INFO_FILTER = "(&(objectClass=domain))"
GPO_INFO_FILTER = "(&(objectCategory=groupPolicyContainer))"
GPO_INFO_FILTER_BY_GUID = "(&(objectCategory=groupPolicyContainer){})"
PSO_INFO_FILTER = "(&(objectClass=msDS-PasswordSettings))"
TRUSTS_INFO_FILTER = "(&(objectCategory=trustedDomain))"
OU_FILTER = "(&(objectClass=OrganizationalUnit))"

PAGESIZE = 1000

DOMAIN_PASSWORD_COMPLEX = 1
DOMAIN_PASSWORD_NO_ANON_CHANGE = 2
DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 4
DOMAIN_LOCKOUT_ADMINS = 8
DOMAIN_PASSWORD_STORE_CLEARTEXT = 16
DOMAIN_REFUSE_PASSWORD_CHANGE = 32


# UTILS


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
	"accountExpires"
]

DATETIME_FIELDS = [
	"dSCorePropagationData",
	"whenChanged",
	"whenCreated"
]

class Logger(object):

	def __init__(self, outfile=None):
		self.terminal = sys.stdout
		self.log = open(outfile, 'w') if outfile else None

	def write(self, message):
		self.terminal.write(message)
		if self.log:
			self.log.write(message)

	def flush(self):
		pass



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

	def __init__(self, username, password, server, fqdn, dpaged, base, method="NTLM", verbose=False):
		self.username = username
		self.password = password
		self.server = server
		self.fqdn = fqdn
		self.dpaged = dpaged
		self.hostnames = []
		self.verbose = verbose

		if method == "Kerberos":
			server = Server(self.server)
			self.ldap = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS)
		elif method == "NTLM":
			server = Server(self.server, get_info=ALL)
			domain, _, _ = fqdn.partition(".")
			self.ldap = Connection(server, user="%s\\%s" % (domain, username), password=password, authentication=NTLM)

		if not self.ldap.bind():
			print("[!] Unable to bind with provided information")
			exit(1)

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
			print("[!] Invalid SID")

	def resolve_guid(self, guid):
		if validate_guid(guid):
			results = self.query("(&(ObjectGUID={guid}))".format(guid=guid))
			if results and len(results) > 0:
				self.display(results[0])
		else:
			print("[!] Invalid GUID")

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
			print("Zone %s does not exists" % zone)

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
			results = self.query(USER_ENABLED_FILTER)
		elif filter_ == "disabled":
			results = self.query(USER_DISABLED_FILTER)
		elif filter_ == "noexpire":
			results = self.query(USER_DONT_EXPIRE_FILTER)

		for result in results:
			self.display(result)

	def list_membersof(self, group):
		# retrieve group DN
		results = self.query(GROUP_DN_FILTER % group, ["distinguishedName"])
		if results:
			group_dn = results[0]["distinguishedName"]
		else:
			print("[!] Group %s does not exists" % group)
			exit(0)
		results = self.query(USERS_IN_GROUP_FILTER % group_dn)
		for result in results:
			self.display(result)

	def list_membership(self, user):
		# retrieve group DN
		results = self.query(USER_IN_GROUPS_FILTER % user, ["memberOf"])
		for result in results:
			if "memberOf" in result:
				for group_dn in result["memberOf"]:
					print(group_dn)
			else:
				print("[-] No groups for user %s" % user)

	def search(self, filter_, attr):
		try:
			if attr:
				results = self.query(filter_, [attr])
			else:
				results = self.query(filter_)
			print(json.dumps(results, ensure_ascii=False, indent=2))
		except Exception as e:
			print(e)

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
		if self.verbose:
			for field, values in record.items():
				if isinstance(values, list):
					for idx, value in enumerate(values):
						if field in FILETIME_FIELDS and value != '0':
							record[field] = str(format_ad_timestamp(value))
						elif field in DATETIME_FIELDS and value != '0':
							record[field][idx] = str(format_ad_timestamp(value))
						elif isinstance(value, bytes):
							record[field] = b64encode(value).decode("utf-8")

					if len(values) == 1:
						record[field] = values[0]

				else:
					value = values
					if field in FILETIME_FIELDS and value != '0':
						record[field] = str(format_ad_timestamp(value))
					elif field in DATETIME_FIELDS and value != '0':
						record[field] = str(format_ad_timestamp(value))
					elif isinstance(value, bytes):
						record[field] = b64encode(value).decode("utf-8")

			print(json.dumps(dict(record), ensure_ascii=False, indent=2))
		else:
			if "group" in record["objectClass"]:
				print(record["sAMAccountName"] + " (group)")
			if "user" in record["objectClass"]:
				print(record["sAMAccountName"])


if __name__ == "__main__":
	parser = ArgumentParser("LDEEP - Bangalore")
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")
	parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Results will contain full information")
	parser.add_argument("--dns", help="An optional DNS server to use", default=False)
	parser.add_argument("--dpaged", action="store_true", help="Disable paged search (in case of unwanted behavior)")

	authentication = parser.add_argument_group("Authentication")
	authentication.add_argument("-u", "--username", help="The username")
	authentication.add_argument("-p", "--password", help="The password or the corresponding NTLM hash")
	authentication.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by KRB5NAME env variable")

	action = parser.add_argument_group("Action (exclusive)")
	xgroup = action.add_mutually_exclusive_group(required=True)
	xgroup.add_argument("--groups", action="store_true", help="Lists all available groups")
	xgroup.add_argument("--users", nargs='?', const="all", action="store", choices=["all", "enabled", "noexpire", "disabled", "locked"], help="Lists all available users")
	xgroup.add_argument("--zones", action="store_true", help="Return configured DNS zones")
	xgroup.add_argument("--zone", help="Return zone records")
	xgroup.add_argument("--object", metavar="OBJECT", help="Return information on an object (group, computer, user, etc.)")
	xgroup.add_argument("--computers", action="store_true", help="Lists all computers")
	xgroup.add_argument("--sid", metavar="SID", help="Return the record associated to the SID")
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
		print("[!] Lack of authentication options: either Kerberos or Username with Password (can be a NTLM hash).")
		exit(1)

	sys.stdout = Logger(args.output)
	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn, args.dpaged, args.base, method, args.verbose)
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

