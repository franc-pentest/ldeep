#!/usr/bin/env python

import ldap
import sys
import time
from tqdm import tqdm
import argparse
from ldap.controls import SimplePagedResultsControl
from multiprocessing.dummy import Pool as ThreadPool
from distutils.version import LooseVersion
import dns.resolver


GROUPS_FILTER = "(&(objectClass=group))"
COMPUTERS_FILTER = "(&(objectClass=computer))"
GROUP_DN_FILTER = "(&(objectClass=group)(sAMAccountName=%s))"
USERS_IN_GROUP_FILTER = "(&(objectCategory=user)(memberOf=%s))"
USER_IN_GROUPS_FILTER = "(&(sAMAccountName=%s))"

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
		return SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True,
										 (pagesize, ''))


def get_pctrls(serverctrls):
	"""Lookup an LDAP paged control object from the returned controls."""
	# Look through the returned controls and find the page controls.
	# This will also have our returned cookie which we need to make
	# the next search request.
	if LDAP24API:
		return [c for c in serverctrls
				if c.controlType == SimplePagedResultsControl.controlType]
	else:
		return [c for c in serverctrls
				if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]


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
		try:
			self.ldap = ldap.open(self.server)
			self.ldap.simple_bind_s("{username}@{fqdn}".format(**self.__dict__), self.password)
		except ldap.LDAPError, e:
			print '[!] %s' % e
			sys.exit(0)

		self.ldap.set_option(ldap.OPT_REFERRALS, 0)
		ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

		self.base_dn = ",".join(map(lambda x: "dc=%s" % x, fqdn.split('.')))
		self.search_scope = ldap.SCOPE_SUBTREE

	def query(self, ldapfilter, attributes=[]):
		result_set = []
		if not self.dpaged:
			lc = create_controls(PAGESIZE)

			while True:
				try:
					msgid = self.ldap.search_ext(self.base_dn, ldap.SCOPE_SUBTREE, ldapfilter,
										 attributes, serverctrls=[lc])
				except ldap.LDAPError as e:
					sys.exit('LDAP search failed: %s' % e)

				try:
					rtype, rdata, rmsgid, serverctrls = self.ldap.result3(msgid)
				except ldap.LDAPError as e:
					sys.exit('Could not pull LDAP results: %s' % e)

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
				print '[!] %s' % e
				sys.exit(0)

	def list_computers(self, resolve, dns_server):
		self.hostnames = []
		results = self.query(COMPUTERS_FILTER, ['name'])
		for result in results:
			self.hostnames.append('%s.%s' % (result['name'][0], self.fqdn))
			# print only if resolution was not mandated
			if not resolve:
				print '%s.%s' % (result['name'][0], self.fqdn)
		# do the resolution
		if resolve:
			self.resolve(dns_server)

	def list_groups(self):
		results = self.query(GROUPS_FILTER)
		for result in results:
			print result['sAMAccountName'][0]

	def list_membersof(self, group):
		# retrieve group DN
		results = self.query(GROUP_DN_FILTER % group, ["distinguishedName"])
		if results:
			group_dn = results[0]['distinguishedName'][0]
		else:
			print '[!] Group %s does not exists' % group
			sys.exit(0)
		results = self.query(USERS_IN_GROUP_FILTER % group_dn)
		for result in results:
			print result['sAMAccountName'][0]

	def list_membership(self, user):
		# retrieve group DN
		results = self.query(USER_IN_GROUPS_FILTER % user, ["memberOf"])
		for result in results:
			if 'memberOf' in result:
				for group_dn in result['memberOf']:
					print group_dn
			else:
				print '[-] No groups for user %s' % user

	def search(self, filter_, attr):
		try:
			if attr:
				results = self.query(filter_, [attr])
			else:
				results = self.query(filter_)
			for result in results:
				if attr in result and attr:
					print "\n".join(result[attr])
				else:
					print result
		except Exception, e:
			print e

	def resolve(self, dns_server):
		pool = ThreadPool(20)
		resolver_thread = ResolverThread(dns_server)
		with tqdm(total=len(self.hostnames)) as pbar:
			for _ in pool.imap_unordered(resolver_thread.resolve, tqdm(self.hostnames, desc="Resolution", bar_format='{desc} {n_fmt}/{total_fmt} hostnames')):
				pbar.update()
		pool.close()
		pool.join()
		for computer in resolver_thread.resolutions:
			print '%s %s' % (computer['address'].ljust(20, ' '), computer['hostname'])


if __name__ == "__main__":
	parser = argparse.ArgumentParser('LDEEP - Bangalore')
	parser.add_argument('-u', '--username', help="The username", required=True)
	parser.add_argument('-p', '--password', help="The password", required=True)
	parser.add_argument('-d', '--fqdn', help="The domain FQDN (ex : domain.local)", required=True)
	parser.add_argument('-s', '--ldapserver', help="The LDAP path (ex : ldap://corp.contoso.com:389)", required=True)
	parser.add_argument('--dns', help="An optional DNS server to use", default=False)
	parser.add_argument('--dpaged', action="store_true", help="Disable paged search (in case of unwanted behavior)")

	action = parser.add_mutually_exclusive_group(required=True)
	action.add_argument('--groups', action="store_true", help='Lists all available groups')
	action.add_argument('--computers', action="store_true", help='Lists all computers')
	action.add_argument('--members', metavar="GROUP", help='Returns users in a specific group')
	action.add_argument('--membership', metavar="USER", help='Returns all groups the users in member of')
	action.add_argument('--search', help="Custom LDAP filter")

	parser.add_argument('--resolve', action="store_true", required=False, help="Performs a resolution on all computer names, should be used with --computers")
	parser.add_argument('--attr', required=False, help="Filters output of --search")

	args = parser.parse_args()
	ad = ActiveDirectoryView(args.username, args.password, args.ldapserver, args.fqdn, args.dpaged)

	if args.groups:
		ad.list_groups()
	elif args.members:
		ad.list_membersof(args.members)
	elif args.membership:
		ad.list_membership(args.membership)
	elif args.computers:
		ad.list_computers(args.resolve, args.dns)
	elif args.search:
		ad.search(args.search, args.attr)

