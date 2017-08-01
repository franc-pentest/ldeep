#!/usr/bin/env python

import ldap
import sys
import time
import argparse

GROUPS_FILTER = "(&(objectClass=group))"
GROUP_DN_FILTER = "(&(objectClass=group)(cn=%s))"
USERS_IN_GROUP_FILTER = "(&(objectCategory=user)(memberOf=%s))"
USER_IN_GROUPS_FILTER = "(&(sAMAccountName=%s))"


class ActiveDirectoryView(object):

	def __init__(self, username, password, server, fqdn):
		self.username = username
		self.password = password
		self.server = server
		self.fqdn = fqdn
		try:
			self.ldap = ldap.open(self.server)
			self.ldap.simple_bind_s("{username}@{fqdn}".format(**self.__dict__), self.password)
		except ldap.LDAPError, e:
			print '[!] %s' % e
			sys.exit(0)

		self.ldap.set_option(ldap.OPT_REFERRALS, 0)

		self.base_dn = ",".join(map(lambda x: "dc=%s" % x, fqdn.split('.')))
		self.search_scope = ldap.SCOPE_SUBTREE

	def query(self, ldapfilter, attributes=[]):
		try:
			ldap_result_id = self.ldap.search(self.base_dn, self.search_scope, ldapfilter, attributes)
			result_set = []
			while 1:
				result_type, result_data = self.ldap.result(ldap_result_id, 0)
				if (result_data == []):
					break
				else:
					if result_type == ldap.RES_SEARCH_ENTRY:
						result_set.append(result_data)
			return result_set
		except ldap.LDAPError, e:
			print '[!] %s' % e
			sys.exit(0)

	def list_groups(self):
		results = self.query(GROUPS_FILTER)
		for result in results:
			_, result = result[0]
			print result['sAMAccountName'][0]

	def list_membersof(self, group):
		# retrieve group DN
		results = self.query(GROUP_DN_FILTER % group, ["distinguishedName"])
		for result in results:
			_, result = result[0]
			group_dn = result['distinguishedName'][0]
		results = self.query(USERS_IN_GROUP_FILTER % group_dn)
		for result in results:
			_, result = result[0]
			print result['sAMAccountName'][0]

	def list_membership(self, user):
		# retrieve group DN
		results = self.query(USER_IN_GROUPS_FILTER % user, ["memberOf"])
		for result in results:
			_, result = result[0]
			for group_dn in result['memberOf']:
				print group_dn


if __name__ == "__main__":
	parser = argparse.ArgumentParser('LDEEP - Bangalore')
	parser.add_argument('-u', '--username', help="The username", required=True)
	parser.add_argument('-p', '--password', help="The password", required=True)
	parser.add_argument('-d', '--fqdn', help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument('-s', '--ldapserver', help="The IP address of an LDAP server", required=True)

	action = parser.add_mutually_exclusive_group(required=True)
	action.add_argument('--groups', action="store_true", help='Lists all available groups')
	action.add_argument('--members', metavar="GROUP", help='Returns users in a specific group')
	action.add_argument('--membership', metavar="USER", help='Returns all groups the users in member of')

	args = parser.parse_args()
	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn)

	if args.groups:
		ad.list_groups()
	elif args.members:
		ad.list_membersof(args.members)
	elif args.membership:
		ad.list_membership(args.membership)

