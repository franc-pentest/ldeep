#!/usr/bin/env python

import sys
import json
import argparse
from math import fabs
from multiprocessing.dummy import Pool as ThreadPool
from distutils.version import LooseVersion
from tqdm import tqdm
import ldap
from ldap.controls import SimplePagedResultsControl
import dns.resolver
from pprint import pprint

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
PSO_INFO_FILTER = "(&(objectClass=msDS-PasswordSettings))"
TRUSTS_INFO_FILTER = "(&(objectCategory=trustedDomain))"

PAGESIZE = 1000

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


def display(ldap_object):

	if "group" in ldap_object["objectClass"]:
		print(ldap_object["sAMAccountName"][0] + " (group)")
	if "user" in ldap_object["objectClass"]:
		print(ldap_object["sAMAccountName"][0])


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

	def __init__(self, username, password, server, fqdn, dpaged):
		self.username = username
		self.password = password
		self.server = server
		self.fqdn = fqdn
		self.dpaged = dpaged
		self.hostnames = []
		try:
			self.ldap = ldap.open(self.server)
			self.ldap.simple_bind_s("{username}@{fqdn}".format(**self.__dict__), self.password)
		except ldap.LDAPError, e:
			print('[!] %s' % e)
			sys.exit(0)

		self.ldap.set_option(ldap.OPT_REFERRALS, 0)
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

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
				print("%s: %s" % (field, val))

	def list_gpo(self):
		results = self.query(GPO_INFO_FILTER)
		for result in results:
			print("%s: %s" % (result["cn"][0], result["displayName"][0]))

	def list_pso(self):
		results = self.query(PSO_INFO_FILTER)
		for result in results:
			print(result)
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
			display(result)

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


if __name__ == "__main__":
	parser = argparse.ArgumentParser("LDEEP - Bangalore")
	parser.add_argument("-u", "--username", help="The username", required=True)
	parser.add_argument("-p", "--password", help="The password", required=True)
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("--dns", help="An optional DNS server to use", default=False)
	parser.add_argument("--dpaged", action="store_true", help="Disable paged search (in case of unwanted behavior)")

	action = parser.add_mutually_exclusive_group(required=True)
	action.add_argument("--groups", action="store_true", help="Lists all available groups")
	action.add_argument("--users", nargs='?', const="all", action="store", choices=["all", "enabled", "noexpire", "disabled", "locked"], help="Lists all available users")
	action.add_argument("--computers", action="store_true", help="Lists all computers")
	action.add_argument("--domain_policy", action="store_true", help="Print the domain policy")
	action.add_argument("--gpo", action="store_true", help="List GPO GUID and their name")
	action.add_argument("--pso", action="store_true", help="Dump Password Setting Object (PSO) containers")
	action.add_argument("--trusts", action="store_true", help="List domain trusts")
	action.add_argument("--members", metavar="GROUP", help="Returns users in a specific group")
	action.add_argument("--membership", metavar="USER", help="Returns all groups the users in member of")
	action.add_argument("--search", help="Custom LDAP filter")

	parser.add_argument("--resolve", action="store_true", required=False, help="Performs a resolution on all computer names, should be used with --computers")
	parser.add_argument("--attr", required=False, help="Filters output of --search")

	args = parser.parse_args()
	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn, args.dpaged)
	if args.groups:
		ad.list_groups()
	elif args.users:
		ad.list_users(args.users)
	elif args.members:
		ad.list_membersof(args.members)
	elif args.membership:
		ad.list_membership(args.membership)
	elif args.computers:
		ad.list_computers(args.resolve, args.dns)
	elif args.domain_policy:
		ad.list_domain_policy()
	elif args.gpo:
		ad.list_gpo()
	elif args.pso:
		ad.list_pso()
	elif args.trusts:
		ad.list_trusts()
	elif args.search:
		ad.search(args.search, args.attr)

