#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json
import argparse
import ldap
from binascii import hexlify, unhexlify
from math import fabs
import dns.resolver
from multiprocessing.dummy import Pool as ThreadPool
from distutils.version import LooseVersion
from tqdm import tqdm
from ldap.controls import SimplePagedResultsControl
from pprint import pprint
from re import compile as re_compile, findall
from datetime import timedelta, datetime
from base64 import b64encode
from struct import unpack

# userAccountControl flags

LOCKED_USERS = "(&(objectCategory=Person)(objectClass=User)(lockoutTime>=1))"


GROUPS_FILTER = "(&(objectClass=group))"
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

# Check if we're using the Python "ldap" 2.4 or greater API
LDAP24API = LooseVersion(ldap.__version__) >= LooseVersion('2.4')


def create_controls(pagesize):
	"""Create an LDAP control with a page size of "pagesize"."""
	# Initialize the LDAP controls for paging. Note that we pass ''
	# for the cookie because on first iteration, it starts out empty.
	if LDAP24API:
		return SimplePagedResultsControl(True, size=pagesize, cookie='')
	else:
		return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True, (pagesize, ''))


def get_pctrls(serverctrls):
	"""Lookup an LDAP paged control object from the returned controls."""
	# Look through the returned controls and find the page controls.
	# This will also have our returned cookie which we need to make
	# the next search request.
	if LDAP24API:
		return [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
	else:
		return [c for c in serverctrls if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]


def set_cookie(lc_object, pctrls, pagesize):
	"""Push latest cookie back into the page control."""
	if LDAP24API:
		cookie = pctrls[0].cookie
		lc_object.cookie = cookie
		return cookie
	else:
		est, cookie = pctrls[0].controlValue
		lc_object.controlValue = (pagesize, cookie)
		return cookie


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
	'badPasswordTime',
	'lastLogon',
	'lastLogoff',
	'lastLogonTimestamp',
	'pwdLastSet',
	'accountExpires'
]

DATETIME_FIELDS = [
	'whenChanged',
	'whenCreated',
	'dSCorePropagationData'
]


def binary_to_text_GUID(blob):
	guid = list(hexlify(blob))
	guid.insert(20, '-')
	guid.insert(16, '-')
	guid.insert(12, '-')
	guid.insert(8, '-')
	return ''.join(guid)


def text_to_binary_GUID(text):
	guid = text.replace('-', '')
	return unhexlify(guid)


def text_to_binary_SID(text):
	return "".join(['\\{:02X}'.format(ord(x)) for x in text])


def binary_to_text_SID(blob):
	offset = 0
	text = "S"
	text += "-" + str(unpack("B", blob[offset:offset + 1])[0])
	no = unpack("B", blob[offset + 1:offset + 2])[0]
	text += "-" + str(unpack(">L", blob[offset + 2:offset + 6])[0] + unpack(">H", blob[offset + 6:offset + 8])[0])
	mem_offset = offset + 8
	for j in range(no):
		text += "-" + str(unpack("<L", blob[mem_offset:mem_offset + 4])[0])
		mem_offset += 4
	return text


EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time


def filetime_to_human(ft):
	ft = int(ft)
	if ft == 9223372036854775807:
		return "Never"
	else:
		us = (ft - EPOCH_AS_FILETIME) // 10
		return (datetime(1970, 1, 1) + timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M:%S")


def datetime_to_human(dt):
	if int(dt[0:4]) < 1900:
		return "Never"
	else:
		return datetime.strptime(dt, "%Y%m%d%H%M%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")


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

	def __init__(self, username, password, server, fqdn, dpaged, base, verbose):
		self.username = username
		self.password = password
		self.server = server
		self.fqdn = fqdn
		self.dpaged = dpaged
		self.hostnames = []
		self.verbose = verbose

		try:
			self.ldap = ldap.initialize(self.server)
			self.ldap.simple_bind_s("{username}@{fqdn}".format(**self.__dict__), self.password)
		except ldap.LDAPError as e:
			print('[!] %s' % e)
			sys.exit(0)

		self.ldap.set_option(ldap.OPT_REFERRALS, 0)
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

		if base:
			self.base_dn = base
		else:
			self.base_dn = ','.join(["dc=%s" % x for x in fqdn.split(".")])
		self.search_scope = ldap.SCOPE_SUBTREE

	def query(self, ldapfilter, attributes=[]):
		result_set = []
		if not self.dpaged:
			lc = create_controls(PAGESIZE)

			while True:
				try:
					msgid = self.ldap.search_ext(self.base_dn, ldap.SCOPE_SUBTREE, ldapfilter, attributes, serverctrls=[lc])
				except ldap.LDAPError as e:
					sys.exit("LDAP search failed: %s" % e)

				try:
					rtype, rdata, rmsgid, serverctrls = self.ldap.result3(msgid)
				except ldap.LDAPError as e:
					sys.exit("Could not pull LDAP results: %s" % e)

				for dn, attrs in rdata:
					if dn:
						result_set.append(attrs)

				# Get cookie for next request
				pctrls = get_pctrls(serverctrls)
				if not pctrls:
					print >> sys.stderr, 'Warning: Server ignores RFC 2696 control.'
					break

				# Ok, we did find the page control, yank the cookie from it and
				# insert it into the control for our next search. If however there
				# is no cookie, we are done!
				cookie = set_cookie(lc, pctrls, PAGESIZE)
				if not cookie:
					break
			return result_set
		else:
			try:
				ldap_result_id = self.ldap.search(self.base_dn, self.search_scope, ldapfilter, attributes)
				result_set = []
				while 1:
					result_type, result_data = self.ldap.result(ldap_result_id, 0)
					if (result_data == []):
						break
					else:
						if result_type == ldap.RES_SEARCH_ENTRY:
							result_set.extend(result_data)
				return result_set
			except ldap.LDAPError, e:
				print("[!] %s" % e)
				sys.exit(0)

	def get_object(self, ldap_object):
		results = self.query("cn=*{ldap_object}*".format(ldap_object=ldap_object))
		for result in results:
			self.display(result)

	def list_computers(self, resolve, dns_server):
		self.hostnames = []
		results = self.query(COMPUTERS_FILTER, ["name"])
		for result in results:
			self.hostnames.append("%s.%s" % (result["name"][0], self.fqdn))
			# print only if resolution was not mandated
			if not resolve:
				print("%s.%s" % (result["name"][0], self.fqdn))
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
				if isinstance(policy[field], list):
					val = policy[field][0]

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
		else:
			results = self.query("ObjectSid={sid}".format(sid=text_to_binary_SID(sid)))
			if results and len(results) > 0:
				self.display(results[0])

	def resolve_guid(self, guid):
		results = self.query("ObjectGUID={guid}".format(guid=text_to_binary_GUID(guid)))
		if results and len(results) > 0:
			self.display(results[0])

	def get_gpo(self):
		results = self.query(GPO_INFO_FILTER)
		gpos = {}
		for result in results:
			gpos[result["cn"][0]] = result["displayName"][0]
		return gpos

	def list_gpo(self):
		gpos = self.get_gpo()
		for k, v in gpos.items():
			print("%s: %s" % (k, v))

	def list_ou(self):
		results = self.query(OU_FILTER)
		cn_re = re_compile("{[^}]+}")
		gpos = self.get_gpo()
		# print(json.dumps(results, ensure_ascii=False, indent=2))
		for result in results:
			print(result["distinguishedName"][0])
			if "gPLink" in result:
				guids = cn_re.findall(result["gPLink"][0])
				if len(guids) > 0:
					print("[gPLink]")
					print("* {}".format("\n* ".join([gpos[g] if g in gpos else g for g in guids])))

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
		results = self.query(TRUSTS_INFO_FILTER)
		FIELDS_TO_PRINT = ["dn", "cn", "name", "trustDirection", "trustPartner", "trustType", "trustAttributes", "flatName"]
		for result in results:
			for field in FIELDS_TO_PRINT:
				if field in result:
					val = result[field][0]
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
		results = self.query(GROUPS_FILTER)
		# print(json.dumps(results, ensure_ascii=False, indent=2))
		for result in results:
			print(result["sAMAccountName"][0])

	def list_users(self, filter_):
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
		# print(json.dumps(results, ensure_ascii=False, indent=2))

	def list_membersof(self, group):
		# retrieve group DN
		results = self.query(GROUP_DN_FILTER % group, ["distinguishedName"])
		if results:
			group_dn = results[0]["distinguishedName"][0]
		else:
			print("[!] Group %s does not exists" % group)
			sys.exit(0)
		results = self.query(USERS_IN_GROUP_FILTER % group_dn)
		for result in results:
			if "group" in result["objectClass"]:
				print(result["sAMAccountName"][0] + " (group)")
			else:
				print(result["sAMAccountName"][0])

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
# 			for result in results:
# 				if attr in result and attr:
# 					print "\n".join(result[attr])
# 				else:
# 					pprint.pprint(result)
		except Exception, e:
			print e

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
			# pprint(ldap_object)
			for field, values in record.items():
				for idx, value in enumerate(values):
					if field == "objectSid":
						record[field][idx] = binary_to_text_SID(value)
					elif field in FILETIME_FIELDS and value != '0':
						record[field][idx] = filetime_to_human(value)
					elif field in DATETIME_FIELDS and value != '0':
						record[field][idx] = datetime_to_human(value)
					elif field == 'objectGUID':
						record[field][idx] = binary_to_text_GUID(value)
					# test if it could correctly displayed otherwise encode in base64
					try:
						value.encode("utf-8")
					except UnicodeError:
						record[field][idx] = b64encode(value)

				if len(values) == 1:
					record[field] = values[0]
			print(json.dumps(record, ensure_ascii=False, indent=2))
		else:
			if "group" in record["objectClass"]:
				print(record["sAMAccountName"][0] + " (group)")
			if "user" in record["objectClass"]:
				print(record["sAMAccountName"][0])


if __name__ == "__main__":
	parser = argparse.ArgumentParser("LDEEP - Bangalore")
	parser.add_argument("-u", "--username", help="The username", required=True)
	parser.add_argument("-p", "--password", help="The password", required=True)
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")
	parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Results will contain full information")
	parser.add_argument("--dns", help="An optional DNS server to use", default=False)
	parser.add_argument("--dpaged", action="store_true", help="Disable paged search (in case of unwanted behavior)")

	action = parser.add_mutually_exclusive_group(required=True)
	action.add_argument("--groups", action="store_true", help="Lists all available groups")
	action.add_argument("--users", nargs='?', const="all", action="store", choices=["all", "enabled", "noexpire", "disabled", "locked"], help="Lists all available users")
	action.add_argument("--object", metavar="OBJECT", help="Return information on an object (group, computer, user, etc.)")
	action.add_argument("--computers", action="store_true", help="Lists all computers")
	action.add_argument("--sid", metavar="SID", help="Return the record associated to the SID")
	action.add_argument("--guid", metavar="GUID", help="Return the record associated to the GUID")
	action.add_argument("--domain_policy", action="store_true", help="Print the domain policy")
	action.add_argument("--gpo", action="store_true", help="List GPO GUID and their name")
	action.add_argument("--ou", action="store_true", help="List OU and resolve linked GPO")
	action.add_argument("--pso", action="store_true", help="Dump Password Setting Object (PSO) containers")
	action.add_argument("--trusts", action="store_true", help="List domain trusts")
	action.add_argument("--members", metavar="GROUP", help="Returns users in a specific group")
	action.add_argument("--membership", metavar="USER", help="Returns all groups the users in member of")
	action.add_argument("--search", help="Custom LDAP filter")

	parser.add_argument("--resolve", action="store_true", required=False, help="Performs a resolution on all computer names, should be used with --computers")
	parser.add_argument("--attr", required=False, help="Filters output of --search")

	args = parser.parse_args()

	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn, args.dpaged, args.base, args.verbose)
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
	elif args.ou:
		ad.list_ou()
	elif args.pso:
		ad.list_pso()
	elif args.trusts:
		ad.list_trusts()
	elif args.search:
		ad.search(args.search, args.attr)

