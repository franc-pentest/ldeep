#!/usr/bin/env python3

from sys import exit
from argparse import ArgumentParser
from json import dump as json_dump
import base64
from math import fabs
from re import compile as re_compile
from datetime import date, datetime, timedelta
from commandparse import Command

from ldeep.ldap.activedirectory import ActiveDirectoryView, ALL
from ldeep.ldap.constants import *

from ldeep.utils import error, info, Logger, resolve as utils_resolve

import sys


class Ldeep(Command):

	def __init__(self, ldap_connection, format="json"):
		try:
			self.ldap = ldap_connection
		except ActiveDirectoryView.ActiveDirectoryLdapException as e:
			error(e)

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
				if "group" in record["objectClass"]:
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
			@security:bool
				Results will contain full information + security descriptors on objects
			@filter:string = ["all", "spn", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired", "nokrbpreauth", "reversible"]
		"""
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)
		filter_ = kwargs.get("filter", "all")

		if verbose:
			attributes = ALL
		else:
			attributes = ["samAccountName", "objectClass"]

		if security:
			attributes = attributes + ['ntSecurityDescriptor']
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		if filter_ == "all":
			results = self.ldap.query(USER_ALL_FILTER, attributes, controls=controls)
		elif filter_ == "spn":
			results = self.ldap.query(USER_SPN_FILTER, attributes, controls=controls)
		elif filter_ == "enabled":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER_NEG.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes, controls=controls)
		elif filter_ == "disabled":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes, controls=controls)
		elif filter_ == "locked":
			results = self.ldap.query(USER_LOCKED_FILTER, attributes, controls=controls)
		elif filter_ == "nopasswordexpire":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["DONT_EXPIRE_PASSWORD"]), attributes, controls=controls)
		elif filter_ == "passwordexpired":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["PASSWORD_EXPIRED"]), attributes, controls=controls)
		elif filter_ == "nokrbpreauth":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["DONT_REQ_PREAUTH"]), attributes, controls=controls)
		elif filter_ == "reversible":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["ENCRYPTED_TEXT_PWD_ALLOWED"]), attributes, controls=controls)
		else:
			return None

		self.display(results, verbose)

	def list_groups(self, kwargs):
		"""
		List the groups.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
		"""
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if not verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = ALL

		if security:
			attributes = attributes + ['ntSecurityDescriptor']
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		self.display(self.ldap.query(GROUPS_FILTER, attributes, controls=controls), verbose, specify_group=False)

	def list_machines(self, kwargs):
		"""
		List the machine accounts.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
		"""
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if not verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = ALL

		if security:
			attributes = attributes + ['ntSecurityDescriptor']
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		self.display(self.ldap.query(COMPUTERS_FILTER, attributes, controls=controls), verbose, specify_group=False)

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
		results = self.ldap.query(COMPUTERS_FILTER, ["name"])
		for result in results:
			computer_name = result["name"]
			hostnames.append("{hostname}.{fqdn}".format(hostname=computer_name, fqdn=self.ldap.fqdn))
			# print only if resolution was not mandated
			if not resolve:
				print("{hostname}.{fqdn}".format(hostname=computer_name, fqdn=self.ldap.fqdn))
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
		policy = self.ldap.query(DOMAIN_INFO_FILTER)
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
		results = self.ldap.query(GPO_INFO_FILTER, ["cn", "displayName"])
		gpos = {}
		for gpo in results:
			gpos[gpo["cn"]] = gpo["displayName"]

		results = self.ldap.query(OU_FILTER)
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
		results = self.ldap.query(GPO_INFO_FILTER, ["cn", "displayName"])
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
		psos = self.ldap.query(PSO_INFO_FILTER)
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
		results = self.ldap.query(TRUSTS_INFO_FILTER)
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
			@security:bool
				Results will contain full information + security descriptors on objects
		"""
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if not verbose:
			attributes = ["dc", "objectClass"]
		else:
			attributes = ALL

		if security:
			attributes = attributes + ['ntSecurityDescriptor']
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		self.display(
			self.ldap.query(
				ZONES_FILTER,
				attributes,
				controls=controls,
				base=','.join(["CN=MicrosoftDNS,DC=DomainDNSZones", self.ldap.base_dn])
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
			results = self.ldap.query(
				ZONE_FILTER,
				base=','.join(["DC={}".format(dns_zone), "CN=MicrosoftDNS,DC=DomainDNSZones", self.ldap.base_dn])
			)
		except ActiveDirectoryView.ActiveDirectoryLdapException as e:
			error(e)
		else:
			self.display(results)

	def get_membersof(self, kwargs):
		"""
		List the members of `group`.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
			#group:string
				Group to list members
		"""
		group = kwargs["group"]
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		attributes = ["distinguishedName", "objectSid"]

		if security:
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		results = self.ldap.query(GROUP_DN_FILTER.format(group=group), attributes)
		if results:
			group_dn = results[0]["distinguishedName"]
		else:
			error("Group {group} does not exists".format(group=group))

		primary_group_id = results[0]["objectSid"].split('-')[-1]
		results = self.ldap.query(USERS_IN_GROUP_FILTER.format(group=group_dn, primary_group_id=primary_group_id), controls=controls)
		self.display(results, verbose)

	def get_memberships(self, kwargs):
		"""
		List the group for which `users` belongs to.

		Arguments:
			#user:string
				User to list memberships
			@recursive:bool
				List recursively the groups
		"""
		user = kwargs["user"]
		recursive = kwargs.get("recursive", False)

		already_printed = set()

		def lookup_groups(dn, leading_sp, already_treated):
			groups = []
			results = self.ldap.query("(distinguishedName={})".format(dn), ["memberOf"])
			for result in results:
				if "memberOf" in result:
					for group_dn in result["memberOf"]:
						if group_dn not in already_treated:
							print("{g:>{width}}".format(g=group_dn, width=leading_sp + len(group_dn)))
							already_treated.add(group_dn)
							lookup_groups(group_dn, leading_sp + 4, already_treated)

			return already_treated

		results = self.ldap.query(USER_IN_GROUPS_FILTER.format(username=user), ["memberOf"])
		for result in results:
			if "memberOf" in result:
				for group_dn in result["memberOf"]:
					print(group_dn)
					if recursive:
						already_printed.add(group_dn)
						s = lookup_groups(group_dn, 4, already_printed)
						already_printed.union(s)
			else:
				error("No groups for user {}".format(user))

	def get_from_sid(self, kwargs):
		"""
		Return the object associated with the given `sid`.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
			#sid:string
				SID to search for
		"""
		sid = kwargs["sid"]
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if security:
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		try:
			result = self.ldap.resolve_sid(sid, controls=controls)
			if isinstance(result, str):
				print(result)
			else:
				self.display(result, verbose)
		except ActiveDirectoryView.ActiveDirectoryLdapInvalidSID:
			error("Invalid SID")

	def get_from_guid(self, kwargs):
		"""
		Return the object associated with the given `guid`.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
			#guid:string
				GUID to search for
		"""
		guid = kwargs["guid"]
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if security:
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		try:
			self.display(self.ldap.resolve_guid(guid, controls=controls), verbose)
		except ActiveDirectoryView.ActiveDirectoryLdapInvalidGUID:
			error("Invalid GUID")

	def get_object(self, kwargs):
		"""
		Return the records containing `object` in a CN.

		Arguments:
			@verbose:bool
				Results will contain full information
			@security:bool
				Results will contain full information + security descriptors on objects
			#object:string
				Pattern to look for in CNs
		"""
		anr = kwargs["object"]
		verbose = kwargs.get("verbose", False)
		security = kwargs.get("security", False)

		if security:
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		results = self.ldap.query("(&(anr={ldap_object}))".format(ldap_object=anr), controls=controls)
		self.display(results, verbose)

	def get_sddl(self, kwargs):
		"""
		Returns the SDDL of an object given it's CN.

		Arguments:
			#object:string
				CN of object.
		"""
		anr = kwargs["object"]

		results = self.ldap.get_sddl("(anr={ldap_object})".format(ldap_object=anr))

		self.display(results, True, False)

	# MISC #

	def misc_search(self, kwargs):
		"""
		Query the LDAP with `filter` and retrieve ALL or `attributes` if specified.

		Arguments:
			@security:bool
				Results will contain full information + security descriptors on objects
			#filter:string
				LDAP filter to search for
			#attributes:string = 'ALL'
				Comma separated list of attributes to display, ALL for every possible attribute
		"""
		attr = kwargs["attributes"]
		filter_ = kwargs["filter"]
		security = kwargs.get("security", False)

		if security:
			controls = [('1.2.840.113556.1.4.801', True, b'\x30\x03\x02\x01\x07')]
		else:
			controls = []

		try:
			if attr and attr != "ALL":
				results = self.ldap.query(filter_, attr.split(","), controls=controls)
			else:
				results = self.ldap.query(filter_, controls=controls)
			self.display(results, True)
		except Exception as e:
			error(e)

	def misc_all(self, kwargs):
		"""
		Collect and store computers, domain_policy, zones, gpo, groups, ou, users, trusts, pso information

		Arguments:
			@security:bool
				Results will contain full information + security descriptors on objects
			#output:string
				File prefix for the files that will be created during the execution
		"""
		output = kwargs["output"]
		security = kwargs.get("security", False)
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
						if security:
							kwargs["security"] = True
						info("Retrieving {command} verbose output".format(command=command))
						sys.stdout = Logger("{output}_{command}_{filter}.json".format(output=output, command=command, filter=f), quiet=True)
						kwargs["verbose"] = True
						getattr(self, method)(kwargs)
						kwargs["verbose"] = False
						kwargs["security"] = False
				kwargs["filter"] = None
			else:
				sys.stdout = Logger("{output}_{command}.lst".format(output=output, command=command), quiet=True)
				getattr(self, method)(kwargs)

				if self.has_option(method, "verbose"):
					if security:
						kwargs["security"] = True
					info("Retrieving {command} verbose output".format(command=command))
					sys.stdout = Logger("{output}_{command}.json".format(output=output, command=command), quiet=True)
					kwargs["verbose"] = True
					getattr(self, method)(kwargs)
					kwargs["verbose"] = False
					kwargs["security"] = False

	# ACTION #

	def action_unlock(self, kwargs):
		"""
		Unlock `user`.

		Arguments:
			#user:string
				User to unlock
		"""
		user = kwargs["user"]

		if self.ldap.unlock(user):
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

		if self.ldap.modify_password(user, curr, new):
			info("Password of {username} changed".format(username=user))
		else:
			error("Unable to change {username}'s password, check privileges or try with ldaps://".format(username=user))


def main():
	parser = ArgumentParser()
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")
	parser.add_argument("-o", "--outfile", default="", help="Store the results in a file")

	ntlm = parser.add_argument_group("NTLM authentication")
	ntlm.add_argument("-u", "--username", help="The username")
	ntlm.add_argument("-p", "--password", help="The password or the corresponding NTLM hash")

	kerberos = parser.add_argument_group("Kerberos authentication")
	kerberos.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable")

	anonymous = parser.add_argument_group("Anonymous authentication")
	anonymous.add_argument("-a", "--anonymous", action="store_true", help="Perform anonymous binds")

	Ldeep.add_subparsers(parser, ["list_", "get_", "misc_", "action_"], title="commands", description="available commands")
	args = parser.parse_args()

	# Authentication
	method = "NTLM"
	if args.kerberos:
		method = "Kerberos"
	elif args.username:
		method = "NTLM"
	elif args.anonymous:
		method = "anonymous"
	else:
		error("Lack of authentication options: either Kerberos or Username with Password (can be a NTLM hash).")

	# Output
	if args.outfile:
		sys.stdout = Logger(args.outfile, quiet=False)

	# main
	try:
		ldap_connection = ActiveDirectoryView(args.ldapserver, args.fqdn, args.base, args.username, args.password, method)
	except ActiveDirectoryView.ActiveDirectoryLdapException as e:
		error(e)

	ldeep = Ldeep(ldap_connection)
	ldeep.dispatch_command(args)


if __name__ == "__main__":
	main()
