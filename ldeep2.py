#!/usr/bin/env python3

from sys import exit, stdout
from argparse import ArgumentParser
from json import dumps as json_dumps
from inspect import getmembers
from re import compile as re_compile
from ast import literal_eval
from math import fabs

from datetime import date, datetime

from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldirectory import ActiveDirectoryView
from utils import error, info, Logger
from ldap_utils import *


LIST_COMMANDS_REGEX = re_compile("list_(.*)")


def parse_docstring(docstring):
	"""
	Parse a docstring to extract help and argument to generate a subparsers with arguments.
	The expected format is (triple quotes are replaced by { and }):

		{{{
		Help line

		Arguments:
			@argumentName:argumentType
			@argumentName:argumentType = value
		}}}
	"""
	result = {}
	lines = docstring.replace("\t", "").split("\n")
	result["help_line"] = lines[1]
	if len(lines) > 3:  # third line should be empty
		if lines[3] == "Arguments:":
			result["arguments"] = dict()
			for arg in lines[4:]:
				if arg.startswith('@'):
					arg = arg[1:]
					variable, _, values = arg.partition(' = ')
					name, _, typ = variable.partition(':')
					alias = name[0]
					arg_dict = {
						"alias": "-{alias}".format(alias=alias),
						"name": "--{name}".format(name=name),
						"type": typ
					}
					if values and typ in ["list"]:
						arg_dict["values"] = literal_eval(values.strip())
					result["arguments"][name] = arg_dict
	return result


class Ldeep():

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
		print(json_dumps(records, ensure_ascii=False, default=default, sort_keys=True, indent=2))

	def list_users(self, kwargs):
		"""
		List users according to a filter.

		Arguments:
			@verbose:bool
			@filter:list = ["all", "enabled", "disabled", "locked", "nopasswordexpire", "passwordexpired"]
		"""
		verbose = "verbose" in kwargs and kwargs["verbose"]
		if "filter" not in kwargs:
			raise Exception("No filter")

		filter_ = kwargs["filter"]

		if verbose:
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
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
		"""
		verbose = "verbose" in kwargs and kwargs["verbose"]

		if not verbose:
			attributes = ["samAccountName", "objectClass"]
		else:
			attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

		self.display(self.ldap.query(GROUPS_FILTER, attributes), verbose, specify_group=False)

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

	parser = ArgumentParser("LDEEP - Deep LDAP inspection")
	parser.add_argument("-d", "--fqdn", help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument("-s", "--ldapserver", help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument("-b", "--base", default="", help="LDAP base for query")
	parser.add_argument("--dns", help="An optional DNS server to use", default=False)

	ntlm = parser.add_argument_group("NTLM authentication")
	ntlm.add_argument("-u", "--username", help="The username")
	ntlm.add_argument("-p", "--password", help="The password or the corresponding NTLM hash")

	kerberos = parser.add_argument_group("Kerberos authentication")
	kerberos.add_argument("-k", "--kerberos", action="store_true", help="For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable")

	sub = parser.add_subparsers(title="commands", dest="command", description="available commands")

	commands = {}
	# Enumeration of list_* and get_* (Not yet implemented) methods
	for name, func in getmembers(Ldeep):
		if name.startswith("list_"):

			command_name = LIST_COMMANDS_REGEX.findall(name)[0]
			commands[command_name] = name
			# Parsing of the docstring to retrieve help line and arguments
			args_info = parse_docstring(func.__doc__)
			c = sub.add_parser(command_name, help=args_info["help_line"])

			if "arguments" in args_info:
				for label, dic in args_info["arguments"].items():
					if dic["type"] == "bool":
						c.add_argument(dic["alias"], dic["name"], action="store_true", default=False)
					elif dic["type"] == "list" and dic["values"]:
						c.add_argument(label, choices=dic["values"], default=dic["values"][0], nargs="?")

		elif name.startswith("get_*"):
			raise NotImplemented

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
