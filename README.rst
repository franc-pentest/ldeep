==============
Project Status
==============

.. image:: https://github.com/franc-pentest/ldeep/actions/workflows/autorelease.yml/badge.svg
   :target: https://github.com/franc-pentest/ldeep/actions/workflows/autorelease.yml
   :alt: Build status
.. image:: https://badgen.net/pypi/v/ldeep
   :target: https://pypi.org/project/ldeep/
   :alt: PyPi version
.. image:: https://img.shields.io/pypi/dm/ldeep.svg
   :alt: Download rate
   :target: https://pypi.org/project/ldeep/



============
Installation
============

To use Kerberos, `ldeep` needs to build native extensions and some headers could be required:

Debian::

  sudo apt-get install -y libkrb5-dev krb5-config gcc python3-dev

ArchLinux::

  sudo pacman -S krb5


-------------------------------------------
Install from pypi (latest released version)
-------------------------------------------

::

  python -m pip install ldeep


----------------------------------------------------
Install from GitHub (current state of master branch)
----------------------------------------------------

::

  python -m pip install git+https://github.com/franc-pentest/ldeep

===========
Development
===========

Clone the project and install the backend build system `pdm`::

  python -m pip install pdm
  git clone https://github.com/franc-pentest/ldeep && cd ldeep

---------------------------
Install an isolated version
---------------------------

Clone and install dependencies::

  pdm install

Run locally::

  pdm run ldeep

----------------------------------
Install the package in your system
----------------------------------

::

  python -m pip install .

------------------------------------
Build source and wheel distributions
------------------------------------

::

  python -m build

=====
ldeep
=====

Help is self-explanatory. Let's check it out::

  $ ldeep -h
  usage: ldeep [-h] [--version] [-o OUTFILE] [--security_desc] {ldap,cache} ...

  options:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    -o OUTFILE, --outfile OUTFILE
                          Store the results in a file
    --security_desc       Enable the retrieval of security descriptors in ldeep results

  Mode:
    Available modes

    {ldap,cache}          Backend engine to retrieve data


`ldeep` can either run against an Active Directory LDAP server or locally on saved files::

  $ ldeep ldap -u Administrator -p 'password' -d winlab -s ldap://10.0.0.1 all backup/winlab
  [+] Retrieving auth_policies output
  [+] Retrieving auth_policies verbose output
  [+] Retrieving computers output
  [+] Retrieving conf output
  [+] Retrieving delegations output
  [+] Retrieving delegations verbose output
  [+] Retrieving delegations verbose output
  [+] Retrieving delegations verbose output
  [+] Retrieving delegations verbose output
  [+] Retrieving domain_policy output
  [+] Retrieving gmsa output
  [+] Retrieving gpo output
  [+] Retrieving groups output
  [+] Retrieving groups verbose output
  [+] Retrieving machines output
  [+] Retrieving machines verbose output
  [+] Retrieving ou output
  [+] Retrieving pkis output
  [+] Retrieving pkis verbose output
  [+] Retrieving pso output
  [+] Retrieving silos output
  [+] Retrieving silos verbose output
  [+] Retrieving subnets output
  [+] Retrieving subnets verbose output
  [+] Retrieving trusts output
  [+] Retrieving users output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving users verbose output
  [+] Retrieving zones output
  [+] Retrieving zones verbose output

  $ ldeep cache -d backup -p winlab users
  Administrator
  [...]

These two modes have different options:

----
LDAP
----

::

    $ ldeep ldap -h
    usage: ldeep ldap [-h] -d DOMAIN -s LDAPSERVER [-b BASE] [-t {ntlm,simple}] [--throttle THROTTLE] [--page_size PAGE_SIZE]
                      [-u USERNAME] [-p PASSWORD] [-H NTLM] [-k] [--pfx-file PFX_FILE] [--pfx-pass PFX_PASS] [--cert-pem CERT_PEM]
                      [--key-pem KEY_PEM] [-a]
                      {auth_policies,bitlockerkeys,computers,conf,delegations,domain_policy,fsmo,gmsa,gpo,groups,machines,ou,pkis,pso,sccm,shadow_principals,silos,smsa,subnets,trusts,users,zones,from_guid,from_sid,laps,memberships,membersof,object,sddl,silo,zone,all,enum_users,search,whoami,add_to_group,create_computer,create_user,modify_password,remove_from_group,unlock}
                      ...

    LDAP mode

    options:
      -h, --help            show this help message and exit
      -d DOMAIN, --domain DOMAIN
                            The domain as NetBIOS or FQDN
      -s LDAPSERVER, --ldapserver LDAPSERVER
                            The LDAP path (ex : ldap://corp.contoso.com:389)
      -b BASE, --base BASE  LDAP base for query (by default, this value is pulled from remote Ldap)
      -t {ntlm,simple}, --type {ntlm,simple}
                            Authentication type: ntlm (default) or simple
      --throttle THROTTLE   Add a throttle between queries to sneak under detection thresholds (in seconds between queries:
                            argument to the sleep function)
      --page_size PAGE_SIZE
                            Configure the page size used by the engine to query the LDAP server (default: 1000)

    NTLM authentication:
      -u USERNAME, --username USERNAME
                            The username
      -p PASSWORD, --password PASSWORD
                            The password used for the authentication
      -H NTLM, --ntlm NTLM  NTLM hashes, format is LMHASH:NTHASH

    Kerberos authentication:
      -k, --kerberos        For Kerberos authentication, ticket file should be pointed by $KRB5NAME env variable

    Certificate authentication:
      --pfx-file PFX_FILE   PFX file
      --pfx-pass PFX_PASS   PFX password
      --cert-pem CERT_PEM   User certificate
      --key-pem KEY_PEM     User private key

    Anonymous authentication:
      -a, --anonymous       Perform anonymous binds

    commands:
      available commands

      {auth_policies,bitlockerkeys,computers,conf,delegations,domain_policy,fsmo,gmsa,gpo,groups,machines,ou,pkis,pso,sccm,shadow_principals,silos,smsa,subnets,trusts,users,zones,from_guid,from_sid,laps,memberships,membersof,object,sddl,silo,zone,all,enum_users,search,whoami,add_to_group,change_uac,create_computer,create_user,modify_password,remove_from_group,unlock}
        auth_policies       List the authentication policies configured in the Active Directory.
        bitlockerkeys       Extract the bitlocker recovery keys.
        computers           List the computer hostnames and resolve them if --resolve is specify.
        conf                Dump the configuration partition of the Active Directory.
        delegations         List accounts configured for any kind of delegation.
        domain_policy       Return the domain policy.
        fsmo                List FSMO roles.
        gmsa                List the gmsa accounts and retrieve NT hash if possible.
        gpo                 Return the list of Group policy objects.
        groups              List the groups.
        machines            List the machine accounts.
        ou                  Return the list of organizational units with linked GPO.
        pkis                List pkis.
        pso                 List the Password Settings Objects.
        sccm                List servers related to SCCM infrastructure (Primary/Secondary Sites and Distribution Points).
        shadow_principals   List the shadow principals and the groups associated with.
        silos               List the silos configured in the Active Directory.
        smsa                List the smsa accounts and the machines they are associated with.
        subnets             List sites and associated subnets.
        trusts              List the domain's trust relationships.
        users               List users according to a filter.
        zones               List the DNS zones configured in the Active Directory.
        from_guid           Return the object associated with the given `guid`.
        from_sid            Return the object associated with the given `sid`.
        laps                Return the LAPS passwords. If a target is specified, only retrieve the LAPS password for this one.
        memberships         List the group for which `account` belongs to.
        membersof           List the members of `group`.
        object              Return the records containing `object` in a CN.
        sddl                Returns the SDDL of an object given it's CN.
        silo                Get information about a specific `silo`.
        zone                Return the records of a DNS zone.
        all                 Collect and store computers, domain_policy, zones, gpo, groups, ou, users, trusts, pso information
        enum_users          Anonymously enumerate users with LDAP pings.
        search              Query the LDAP with `filter` and retrieve ALL or `attributes` if specified.
        whoami              Return user identity.
        add_to_group        Add `user` to `group`.
        change_uac          Change user account control
        create_computer     Create a computer account
        create_user         Create a user account
        modify_password     Change `user`'s password.
        remove_from_group   Remove `user` from `group`.
        unlock              Unlock `user`.



-----
CACHE
-----

::

    $ ldeep cache -h
    usage: ldeep cache [-h] [-d DIR] -p PREFIX
                       {auth_policies,bitlockerkeys,computers,conf,delegations,domain_policy,fsmo,gmsa,gpo,groups,machines,ou,pkis,pso,sccm,shadow_principals,silos,smsa,subnets,trusts,users,zones,from_guid,from_sid,laps,memberships,membersof,object,sddl,silo,zone}
                       ...

    Cache mode

    options:
      -h, --help            show this help message and exit
      -d DIR, --dir DIR     Use saved JSON files in specified directory as cache
      -p PREFIX, --prefix PREFIX
                            Prefix of ldeep saved files

    commands:
      available commands

      {auth_policies,bitlockerkeys,computers,conf,delegations,domain_policy,fsmo,gmsa,gpo,groups,machines,ou,pkis,pso,sccm,shadow_principals,silos,smsa,subnets,trusts,users,zones,from_guid,from_sid,laps,memberships,membersof,object,sddl,silo,zone}
        auth_policies       List the authentication policies configured in the Active Directory.
        bitlockerkeys       Extract the bitlocker recovery keys.
        computers           List the computer hostnames and resolve them if --resolve is specify.
        conf                Dump the configuration partition of the Active Directory.
        delegations         List accounts configured for any kind of delegation.
        domain_policy       Return the domain policy.
        fsmo                List FSMO roles.
        gmsa                List the gmsa accounts and retrieve NT hash if possible.
        gpo                 Return the list of Group policy objects.
        groups              List the groups.
        machines            List the machine accounts.
        ou                  Return the list of organizational units with linked GPO.
        pkis                List pkis.
        pso                 List the Password Settings Objects.
        sccm                List servers related to SCCM infrastructure (Primary/Secondary Sites and Distribution Points).
        shadow_principals   List the shadow principals and the groups associated with.
        silos               List the silos configured in the Active Directory.
        smsa                List the smsa accounts and the machines they are associated with.
        subnets             List sites and associated subnets.
        trusts              List the domain's trust relationships.
        users               List users according to a filter.
        zones               List the DNS zones configured in the Active Directory.
        from_guid           Return the object associated with the given `guid`.
        from_sid            Return the object associated with the given `sid`.
        laps                Return the LAPS passwords. If a target is specified, only retrieve the LAPS password for this one.
        memberships         List the group for which `account` belongs to.
        membersof           List the members of `group`.
        object              Return the records containing `object` in a CN.
        sddl                Returns the SDDL of an object given it's CN.
        silo                Get information about a specific `silo`.
        zone                Return the records of a DNS zone.




==============
Usage examples
==============

Listing users without verbosity::

	$ ldeep ldap -u Administrator -p 'password' -d winlab.local -s ldap://10.0.0.1 users
	userspn2
	userspn1
	gobobo
	test
	krbtgt
	DefaultAccount
	Guest
	Administrator


Listing users with reversible password encryption enable and with verbosity::

	$ ldeep ldap -u Administrator -p 'password' -d winlab.local -s ldap://10.0.0.1 users reversible -v
	[
	  {
	    "accountExpires": "9999-12-31T23:59:59.999999",
	    "badPasswordTime": "1601-01-01T00:00:00+00:00",
	    "badPwdCount": 0,
	    "cn": "User SPN1",
	    "codePage": 0,
	    "countryCode": 0,
	    "dSCorePropagationData": [
	      "1601-01-01T00:00:00+00:00"
	    ],
	    "displayName": "User SPN1",
	    "distinguishedName": "CN=User SPN1,CN=Users,DC=winlab,DC=local",
	    "dn": "CN=User SPN1,CN=Users,DC=winlab,DC=local",
	    "givenName": "User",
	    "instanceType": 4,
	    "lastLogoff": "1601-01-01T00:00:00+00:00",
	    "lastLogon": "1601-01-01T00:00:00+00:00",
	    "logonCount": 0,
	    "msDS-SupportedEncryptionTypes": 0,
	    "name": "User SPN1",
	    "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=winlab,DC=local",
	    "objectClass": [
	      "top",
	      "person",
	      "organizationalPerson",
	      "user"
	    ],
	    "objectGUID": "{593cb08f-3cc5-431a-b3d7-9fbad4511b1e}",
	    "objectSid": "S-1-5-21-3640577749-2924176383-3866485758-1112",
	    "primaryGroupID": 513,
	    "pwdLastSet": "2018-10-13T12:19:30.099674+00:00",
	    "sAMAccountName": "userspn1",
	    "sAMAccountType": "SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT | SAM_USER_OBJECT | SAM_NORMAL_USER_ACCOUNT | SAM_MACHINE_ACCOUNT | SAM_TRUST_ACCOUNT | SAM_ACCOUNT_TYPE_MAX",
	    "servicePrincipalName": [
	      "HOST/blah"
	    ],
	    "sn": "SPN1",
	    "uSNChanged": 115207,
	    "uSNCreated": 24598,
	    "userAccountControl": "ENCRYPTED_TEXT_PWD_ALLOWED | NORMAL_ACCOUNT | DONT_REQ_PREAUTH",
	    "userPrincipalName": "userspn1@winlab.local",
	    "whenChanged": "2018-10-22T18:04:43+00:00",
	    "whenCreated": "2018-10-13T12:19:30+00:00"
	  }
	]

Listing GPOs::

	$ ldeep -u Administrator -p 'password' -d winlab.local -s ldap://10.0.0.1 gpo
	{6AC1786C-016F-11D2-945F-00C04fB984F9}: Default Domain Controllers Policy
	{31B2F340-016D-11D2-945F-00C04FB984F9}: Default Domain Policy

Getting all things::

	$ ldeep ldap -u Administrator -p 'password' -d winlab.local -s ldap://10.0.0.1 all /tmp/winlab.local_dump
	[+] Retrieving computers output
	[+] Retrieving domain_policy output
	[+] Retrieving gpo output
	[+] Retrieving groups output
	[+] Retrieving groups verbose output
	[+] Retrieving ou output
	[+] Retrieving pso output
	[+] Retrieving trusts output
	[+] Retrieving users output
	[+] Retrieving users verbose output
	[+] Retrieving zones output
	[+] Retrieving zones verbose output

Using this last command line switch, you have persistent output in both verbose and non-verbose mode saved::

	$ ls winlab.local_dump_*
	winlab.local_dump_computers.lst      winlab.local_dump_groups.json  winlab.local_dump_pso.lst     winlab.local_dump_users.lst
	winlab.local_dump_domain_policy.lst  winlab.local_dump_groups.lst   winlab.local_dump_trusts.lst  winlab.local_dump_zones.json
	winlab.local_dump_gpo.lst            winlab.local_dump_ou.lst       winlab.local_dump_users.json  winlab.local_dump_zones.lst

The the cache mode can be used to query some other information.


--------------------------
Usage with Kerberos config
--------------------------

For Kerberos, you will also need to configure the ``/etc/krb5.conf``.::

  [realms]
        CORP.LOCAL = {
                kdc = DC01.CORP.LOCAL
        }

========
Upcoming
========

* Proper DNS zone enumeration
* ADCS enumeration
* Sites and subnets
* Project tree
* Useful Kerberos delegation information
* Any ideas?

================
Related projects
================

* https://github.com/SecureAuthCorp/impacket
* https://github.com/ropnop/windapsearch
* https://github.com/shellster/LDAPPER


