#!/usr/bin/env python3

from sys import exit, stdout
from argparse import ArgumentParser
from json import dump as json_dump
from math import fabs

from datetime import date, datetime

from ldirectory import ActiveDirectoryView, ALL
from utils import error, info, Logger
from ldap_utils import *

from command import Command


class Ldeep(Command):

	def __init__(self, ldap_connection, format="json"):
		try:
			self.ldap = ldap_connection
		except ActiveDirectoryLdapException as e:
			error(e)
			exit(1)

		if format == "json":
			self.__display = self.__display_json

	def display(self, records, verbose, specify_group=True):
		def default(o):
			if isinstance(o, date) or isinstance(o, datetime):
				return o.isoformat()

		if verbose:
			self.__display(list(map(dict, records)), default)
		else:
			for record in records:
				if "group" in record["objectClass"]:
					print(record["sAMAccountName"] + (" (group)" if specify_group else ""))
				elif "user" in record["objectClass"]:
					print(record["sAMAccountName"])
				elif "dnsNode" in record["objectClass"]:
					print("%s %s" % (record["dc"], " ".join(record["dnsRecord"])))
				elif "dnsZone" in record["objectClass"]:
					print(record["dc"])

	def __display_json(self, records, default):
		json_dump(records, stdout, ensure_ascii=False, default=default, sort_keys=True, indent=2)

	def list_users(self, kwargs):
		"""
		List users according to a filter.

		Arguments:
			@verbose:bool
				Results will contain full information
			@filter:list = ["all", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired"]
		"""
		verbose = "verbose" in kwargs and kwargs["verbose"]
		if "filter" not in kwargs:
			raise Exception("No filter")

		filter_ = kwargs["filter"]

		if verbose:
			attributes = ALL
		else:
			attributes = ["samAccountName", "objectClass"]

		if filter_ == "all":
			results = self.ldap.query(USER_ALL_FILTER, attributes)
		elif filter_ == "enabled":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER_NEG.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes)
		elif filter_ == "disabled":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["ACCOUNTDISABLE"]), attributes)
		elif filter_ == "locked":
			results = self.ldap.query(USER_LOCKED_FILTER, attributes)
		elif filter_ == "nopasswordexpire":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["DONT_EXPIRE_PASSWORD"]), attributes)
		elif filter_ == "passwordexpired":
			results = self.ldap.query(USER_ACCOUNT_CONTROL_FILTER.format(intval=USER_ACCOUNT_CONTROL["PASSWORD_EXPIRED"]), attributes)

		self.display(results, verbose)

	def list_groups(self, kwargs):
		"""
		List the groups.

		Arguments:
			@verbose:bool
				Results will contain full information
		"""
		verbose = "verbose" in kwargs and kwargs["verbose"]

		if not verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = ALL

		self.display(self.ldap.query(GROUPS_FILTER, attributes), verbose, specify_group=False)

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
		dns = kwargs["dns"] if "dns" in kwargs else ""

		self.hostnames = []
		results = self.ldap.query(COMPUTERS_FILTER, ["name"])
		for result in results:
			computer_name = result["name"]
			self.hostnames.append("{hostname}.{fqdn}".format(hostname=computer_name, fqdn=self.ldap.fqdn))
			# print only if resolution was not mandated
			if not resolve:
				print("{hostname}.{fqdn}".format(hostname=computer_name, fqdn=self.ldap.fqdn))
		# do the resolution
		# if resolve:
		# 	self.resolve(dns_server)

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

				if field in FILETIME_TIMESTAMP_FIELDS.keys():
					val = int((fabs(float(val)) / 10**7) / FILETIME_TIMESTAMP_FIELDS[field][0])
					val = "%d %s" % (val, FILETIME_TIMESTAMP_FIELDS[field][1])
				elif field == "pwdProperties":
					if int(val) == 1:
						val = "complexity enabled"
					elif int(val) == 2:
						val = "complexity disabled"

				print("%s: %s" % (field, val))


if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")

	ntlm = parser.add_argument_group("NTLM authentication")
	ntlm.add_argument("-u", "--username", help="The username")
	ntlm.add_argument("-p", "--password", help="The password or the corresponding NTLM hash")

	kerberos = parser.add_argument_group("Kerberos authentication")
	kerberos.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable")

	sub = parser.add_subparsers(title="commands", dest="command", description="available commands")

	commands = {}
	for command, method in Ldeep.get_commands(prefix="list_"):
		Ldeep.set_subparser_for(command, method, sub)
		commands[command] = method

	args = parser.parse_args()

	method = "NTLM"
	if args.kerberos:
		method = "Kerberos"
	elif args.username and args.password:
		method = "NTLM"
	else:
		error("Lack of authentication options: either Kerberos or Username with Password (can be a NTLM hash).")

	ldap_connection = ActiveDirectoryView(args.ldapserver, args.fqdn, args.base, args.username, args.password, method)
	ldeep = Ldeep(ldap_connection)

	getattr(ldeep, commands[args.command])(vars(args))
