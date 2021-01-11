#!/usr/bin/env python3

from sys import exit
from os import path
from argparse import ArgumentParser
from json import dump as json_dump, load as json_load
import base64
from math import fabs
from re import compile as re_compile
from datetime import date, datetime, timedelta
from commandparse import Command

from pyasn1.error import PyAsn1UnicodeDecodeError

from ldeep.views.activedirectory import ActiveDirectoryView, ALL, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldeep.views.constants import USER_ACCOUNT_CONTROL, LDAP_SERVER_SD_FLAGS_OID_SEC_DESC
from ldeep.views.ldap_activedirectory import LdapActiveDirectoryView
from ldeep.views.cache_activedirectory import CacheActiveDirectoryView

from ldeep.utils import error, info, Logger, resolve as utils_resolve

import sys


class Ldeep(Command):

	def __init__(self, query_engine, format="json"):
		self.engine = query_engine
		if format == "json":
			self.__display = self.__display_json

	def display(self, records, verbose=False, specify_group=True):
		def default(o):
			if isinstance(o, date) or isinstance(o, datetime):
				return o.isoformat()
			elif isinstance(o, bytes):
				return base64.b64encode(o).decode('ascii')

		if verbose:
			self.__display(list(map(dict, records)), default)
		else:
			for record in records:
				if "objectClass" not in record:
					print(record)
				elif "group" in record["objectClass"]:
					print(record["sAMAccountName"] + (" (group)" if specify_group else ""))
				elif "user" in record["objectClass"]:
					print(record["sAMAccountName"])
				elif "dnsNode" in record["objectClass"]:
					print("{dc} {rec}".format(dc=record["dc"], rec=" ".join(record["dnsRecord"])))
				elif "dnsZone" in record["objectClass"]:
					print(record["dc"])
				elif "domain" in record["objectClass"]:
					print(record["dn"])

	def __display_json(self, records, default):
		json_dump(records, sys.stdout, ensure_ascii=False, default=default, sort_keys=True, indent=2)

	# LISTERS #

	def list_users(self, kwargs):
		"""
		List users according to a filter.

		Arguments:
			@verbose:bool
				Results will contain full information
			@filter:string = ["all", "spn", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired", "nokrbpreauth", "reversible"]
		"""
		verbose	 = kwargs.get("verbose", False)
		filter_	 = kwargs.get("filter", "all")

		if verbose:
			attributes = self.engine.all_attributes()
		else:
			attributes = ["samAccountName", "objectClass"]

		if filter_ == "all":
			results = self.engine.query(self.engine.USER_ALL_FILTER(), attributes)
		elif filter_ == "spn":
			results = self.engine.query(self.engine.USER_SPN_FILTER(), attributes)
		elif filter_ == "enabled":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER_NEG(USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes)
		elif filter_ == "disabled":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER(USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes)
		elif filter_ == "locked":
			results = self.engine.query(self.engine.USER_LOCKED_FILTER(), attributes)
		elif filter_ == "nopasswordexpire":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER(USER_ACCOUNT_CONTROL["DONT_EXPIRE_PASSWORD"]), attributes)
		elif filter_ == "passwordexpired":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER(USER_ACCOUNT_CONTROL["PASSWORD_EXPIRED"]), attributes)
		elif filter_ == "nokrbpreauth":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER(USER_ACCOUNT_CONTROL["DONT_REQ_PREAUTH"]), attributes)
		elif filter_ == "reversible":
			results = self.engine.query(self.engine.USER_ACCOUNT_CONTROL_FILTER(USER_ACCOUNT_CONTROL["ENCRYPTED_TEXT_PWD_ALLOWED"]), attributes)
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
		verbose	 = kwargs.get("verbose", False)

		if verbose:
			attributes = self.engine.all_attributes()
		else:
			attributes = ["samAccountName", "objectClass"]			

		self.display(self.engine.query(self.engine.GROUPS_FILTER(), attributes), verbose, specify_group=False)

	def list_machines(self, kwargs):
		"""
		List the machine accounts.

		Arguments:
			@verbose:bool
				Results will contain full information
		"""
		verbose  = kwargs.get("verbose", False)

		if verbose:
			attributes = self.engine.all_attributes()
		else:
			attributes = ["samAccountName", "objectClass"]

		self.display(self.engine.query(self.engine.COMPUTERS_FILTER(), attributes), verbose, specify_group=False)

	def list_computers(self, kwargs):
		"""
		List the computer hostnames and resolve them if --resolve is specify.

		Arguments:
			@resolve:bool
				A resolution on all computer names will be performed
			@dns:string
				An optional DNS server to use for the resolution
		"""
		resolve = "resolve" in kwargs and kwargs["resolve"]
		dns = kwargs.get("dns", "")

		hostnames = []
		results = self.engine.query(self.engine.COMPUTERS_FILTER(), ["name"])
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
				print("{addr:20} {name}".format(addr=computer["address"], name=computer["hostname"]))

	def list_domain_policy(self, kwargs):
		"""
		Return the domain policy.
		"""
		FILETIME_TIMESTAMP_FIELDS = {
			"lockOutObservationWindow": (60, "mins"),
			"lockoutDuration": (60, "mins"),
			"maxPwdAge": (86400, "days"),
			"minPwdAge": (86400, "days"),
			"forceLogoff": (60, "mins")
		}
		FIELDS_TO_PRINT = ["dc", "distinguishedName", "lockOutObservationWindow", "lockoutDuration", "lockoutThreshold", "maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength", "pwdProperties"]
		policy = self.engine.query(self.engine.DOMAIN_INFO_FILTER())
		if policy:
			policy = policy[0]
			for field in FIELDS_TO_PRINT:
				val = policy[field]

				if field == "lockOutObservationWindow" and isinstance(val, timedelta):
					val = int(val.total_seconds()) / 60
				elif field in FILETIME_TIMESTAMP_FIELDS.keys() and type(val) == int:
					val = int((fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0])
				if field in FILETIME_TIMESTAMP_FIELDS.keys():
					val = "%d %s" % (val, FILETIME_TIMESTAMP_FIELDS[field][1])

				print("%s: %s" % (field, val))

	def list_ou(self, kwargs):
		"""
		Return the list of organizational units with linked GPO.
		"""
		cn_re = re_compile("{[^}]+}")
		results = self.engine.query(self.engine.GPO_INFO_FILTER(), ["cn", "displayName"])
		gpos = {}
		for gpo in results:
			gpos[gpo["cn"]] = gpo["displayName"]

		results = self.engine.query(self.engine.OU_FILTER())
		for result in results:
			print(result["distinguishedName"])
			if "gPLink" in result:
				guids = cn_re.findall(result["gPLink"])
				if len(guids) > 0:
					print("[gPLink]")
					print("* {}".format("\n* ".join([gpos[g] if g in gpos else g for g in guids])))

	def list_gpo(self, kwargs):
		"""
		Return the list of Group policy objects.
		"""
		results = self.engine.query(self.engine.GPO_INFO_FILTER(), ["cn", "displayName"])
		for gpo in results:
			print("{cn}: {name}".format(cn=gpo["cn"], name=gpo["displayName"]))

	def list_pso(self, kwargs):
		"""
		List the Password Settings Objects.
		"""
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
		psos = self.engine.query(self.engine.PSO_INFO_FILTER())
		for policy in psos:
			for field in FIELDS_TO_PRINT:
				if isinstance(policy[field], list):
					val = policy[field][0]
				else:
					val = policy[field]

				if field in FILETIME_TIMESTAMP_FIELDS.keys():
					val = int((fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0])
					val = "{val} {typ}".format(val=val, typ=FILETIME_TIMESTAMP_FIELDS[field][1])
				print("{field}: {val}".format(field=field, val=val))

	def list_trusts(self, kwargs):
		"""
		List the domain's trust relationships.
		"""
		results = self.engine.query(self.engine.TRUSTS_INFO_FILTER())
		FIELDS_TO_PRINT = ["dn", "cn", "securityIdentifier", "name", "trustDirection", "trustPartner", "trustType", "trustAttributes", "flatName"]
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

		self.display(
			self.engine.query(
				self.engine.ZONES_FILTER(),
				attributes, base=','.join(["CN=MicrosoftDNS,DC=DomainDNSZones", self.engine.base_dn])
			),
			verbose
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
		try:
			results = self.engine.query(
				self.engine.ZONE_FILTER(),
				base=','.join([f"DC={dns_zone}", "CN=MicrosoftDNS,DC=DomainDNSZones", self.engine.base_dn])
			)
		except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
			error(e)
		else:
			self.display(results)

	def get_membersof(self, kwargs):
		"""
		List the members of `group`.

		Arguments:
			@verbose:bool
				Results will contain full information
			#group:string
				Group to list members
		"""
		group = kwargs["group"]
		verbose = kwargs.get("verbose", False)

		results = self.engine.query(self.engine.GROUP_DN_FILTER(group), ["distinguishedName", "objectSid"])
		if results:
			group_dn = results[0]["distinguishedName"]
		else:
			error("Group {group} does not exists".format(group=group))

		primary_group_id = results[0]["objectSid"].split('-')[-1]
		results = self.engine.query(self.engine.USERS_IN_GROUP_FILTER(primary_group_id, group_dn))
		self.display(results, verbose)

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
			groups = []
			results = self.engine.query(self.engine.DISTINGUISHED_NAME(dn), ["memberOf", "primaryGroupID"])
			for result in results:
				if "memberOf" in result:
					for group_dn in result["memberOf"]:
						if group_dn not in already_treated:
							print("{g:>{width}}".format(g=group_dn, width=leading_sp + len(group_dn)))
							already_treated.add(group_dn)
							lookup_groups(group_dn, leading_sp + 4, already_treated)
							
				if "primaryGroupID" in result:
					pid = result["primaryGroupID"]
					results = self.engine.query(self.engine.PRIMARY_GROUP_ID(pid))
					already_treated.add(results[0]["dn"])

			return already_treated

		results = self.engine.query(self.engine.USER_IN_GROUPS_FILTER(account), ["memberOf", "primaryGroupID"])
		for result in results:
			if "memberOf" in result:
				for group_dn in result["memberOf"]:
					print(group_dn)
					if recursive:
						already_printed.add(group_dn)
						s = lookup_groups(group_dn, 4, already_printed)
						already_printed.union(s)

			if "primaryGroupID" in result:
				pid = result["primaryGroupID"]
				results = self.engine.query(self.engine.PRIMARY_GROUP_ID(pid))
				if results:
					print(results[0]["dn"])

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
			error("Decoding error with the filter")
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
					sys.stdout = Logger("{output}_{command}_{filter}.lst".format(output=output, command=command, filter=f), quiet=True)
					kwargs["filter"] = f
					getattr(self, method)(kwargs)

					if self.has_option(method, "verbose"):
						info("Retrieving {command} verbose output".format(command=command))
						sys.stdout = Logger("{output}_{command}_{filter}.json".format(output=output, command=command, filter=f), quiet=True)
						kwargs["verbose"] = True
						getattr(self, method)(kwargs)
						kwargs["verbose"] = False
				kwargs["filter"] = None
			else:
				sys.stdout = Logger("{output}_{command}.lst".format(output=output, command=command), quiet=True)
				getattr(self, method)(kwargs)

				if self.has_option(method, "verbose"):
					info("Retrieving {command} verbose output".format(command=command))
					sys.stdout = Logger("{output}_{command}.json".format(output=output, command=command), quiet=True)
					kwargs["verbose"] = True
					getattr(self, method)(kwargs)
					kwargs["verbose"] = False

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
			info("User {username} unlocked (or was already unlocked)".format(username=user))
		else:
			error("Unable to unlock {username}, check privileges".format(username=user))

	def action_modify_password(self, kwargs):
		"""
		Change `user`'s password.

		Arguments:
			#user:string
				User to unlock
			#newpassword:string
				New password
			#currpassword:string = None
				Current password
		"""
		user = kwargs["user"]
		new = kwargs["newpassword"]
		curr = kwargs.get("currpassword", None)
		if curr == "None":
			curr = None

		if self.engine.modify_password(user, curr, new):
			info("Password of {username} changed".format(username=user))
		else:
			error("Unable to change {username}'s password, check privileges or try with ldaps://".format(username=user))



def main():
	parser = ArgumentParser()
	parser.add_argument("-o", "--outfile", default="", help="Store the results in a file")
	parser.add_argument("--security_desc", action="store_true", help="Enable the retrieval of security descriptors in ldeep results")
	
	sub = parser.add_subparsers(title="Mode", dest="mode", description="Available modes", help="Backend engine to retrieve data")
	sub.required = True

	ldap = sub.add_parser("ldap", description="LDAP mode")
	cache = sub.add_parser("cache", description="Cache mode")
	
	ldap.add_argument("-d", "--domain", required=True, help="The domain as NetBIOS or FQDN")
	ldap.add_argument("-s", "--ldapserver", required=True, help="The LDAP path (ex : ldap://corp.contoso.com:389)")
	ldap.add_argument("-b", "--base", default="", help="LDAP base for query (by default, this value is pulled from remote Ldap)")
	
	cache.add_argument("-d", "--dir", default=".", type=str, help="Use saved JSON files in specified directory as cache")
	cache.add_argument("-p", "--prefix", required=True, type=str, help="Prefix of ldeep saved files")

	ntlm = ldap.add_argument_group("NTLM authentication")
	ntlm.add_argument("-u", "--username", help="The username")
	ntlm.add_argument("-p", "--password", help="The password used for the authentication")
	ntlm.add_argument("-H", "--ntlm", help="The NTLM hash used for authentication, ex: aad3b435b51404eeaad3b435b51404ee:a2d4623d306be8e06dbc4e2e8b78353a")

	kerberos = ldap.add_argument_group("Kerberos authentication")
	kerberos.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable")

	anonymous = ldap.add_argument_group("Anonymous authentication")
	anonymous.add_argument("-a", "--anonymous", action="store_true", help="Perform anonymous binds")

	Ldeep.add_subparsers(ldap, "ldap", ["list_", "get_", "misc_", "action_"], title="commands", description="available commands")
	Ldeep.add_subparsers(cache, "cache", ["list_", "get_"], title="commands", description="available commands")
	
	args = parser.parse_args()

	# Output
	if args.outfile:
		sys.stdout = Logger(args.outfile, quiet=False)

	cache = "prefix" in args  # figuring out whether we use the cache or not

	# main
	if cache:
		try:
			query_engine = CacheActiveDirectoryView(args.dir, args.prefix)
		except CacheActiveDirectoryView.CacheActiveDirectoryDirNotFoundException as e:
			error(e)

	else:
		try:
			# Authentication
			method = "NTLM"
			if args.kerberos:
				method = "Kerberos"
			elif args.username:
				if args.password:
					method = "SIMPLE"
				else:
					method = "NTLM"
			elif args.anonymous:
				method = "anonymous"
			else:
				error("Lack of authentication options: either Kerberos, Username with Password (can be a NTLM hash) or Anonymous.")

			query_engine = LdapActiveDirectoryView(args.ldapserver, args.domain, args.base, args.username, args.password, args.ntlm, method)

			
		except LdapActiveDirectoryView.ActiveDirectoryLdapException as e:
			error(e)

	# If `security_desc` are requested, enable LDAP Security Descriptor flags and modify the default attributes
	# In cache mode, the security_desc corresponding JSON field will be kept
	if args.security_desc:
		query_engine.set_controls(LDAP_SERVER_SD_FLAGS_OID_SEC_DESC)
		query_engine.set_all_attributes([ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, "ntSecurityDescriptor"])

	ldeep = Ldeep(query_engine)

	try:
		ldeep.dispatch_command(args)
	except CacheActiveDirectoryView.CacheActiveDirectoryException as e:
		error(e)
	except NotImplementedError:
		error("Feature not yet available")

if __name__ == "__main__":
	main()
