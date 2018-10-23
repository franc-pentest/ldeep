=====
LDEEP
=====

Help is self-explanatory. Let's check it out::

	usage: ldeep.py [-h] -d FQDN -s LDAPSERVER [-b BASE] [-o OUTFILE]
					[-u USERNAME] [-p PASSWORD] [-k]
					{computers,domain_policy,gpo,groups,ou,pso,trusts,users,zones,from_guid,from_sid,memberships,membersof,object,zone,search,all}
					...

	optional arguments:
	  -h, --help            show this help message and exit
	  -d FQDN, --fqdn FQDN  The domain FQDN (ex : domain.local)
	  -s LDAPSERVER, --ldapserver LDAPSERVER
							The LDAP path (ex : ldap://corp.contoso.com:389)
	  -b BASE, --base BASE  LDAP base for query
	  -o OUTFILE, --outfile OUTFILE
							Store the results in a file

	NTLM authentication:
	  -u USERNAME, --username USERNAME
							The username
	  -p PASSWORD, --password PASSWORD
							The password or the corresponding NTLM hash

	Kerberos authentication:
	  -k, --kerberos        For Kerberos authentication, ticket file should be
							pointed by $KRB5NAME env variable

	commands:
	  available commands

	  {computers,domain_policy,gpo,groups,ou,pso,trusts,users,zones,from_guid,from_sid,memberships,membersof,object,zone,search,all}
		computers           List the computer hostnames and resolve them if
							--resolve is specify.
		domain_policy       Return the domain policy.
		gpo                 Return the list of Group policy objects.
		groups              List the groups.
		ou                  Return the list of organizational units with linked
							GPO.
		pso                 List the Password Settings Objects.
		trusts              List the domain's trust relationships.
		users               List users according to a filter.
		zones               List the DNS zones configured in the Active Directory.
		from_guid           Return the object associated with the given `guid`.
		from_sid            Return the object associated with the given `sid`.
		memberships         List the group for which `users` belongs to.
		membersof           List the members of `group`.
		object              Return the records containing `object` in a CN.
		zone                Return the records of a DNS zone.
		search              Query the LDAP with `filter` and retrieve ALL or
							`attributes` if specified.
		all                 Collect and store computers, domain_policy, zones,
							gpo, groups, ou, users, trusts, pso information

=======
INSTALL
=======

``ldeep`` is Python3 only.::

	pip3 install ldeep

====
TODO
====

* Proper DNS zone enumeration
* Project tree
* Any ideas ?
