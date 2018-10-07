# LDEEP

Help is self-explanatory. Let's check it out:

```
usage: LDEEP - Deep LDAP inspection [-h] -d FQDN -s LDAPSERVER [-b BASE] [-v]
                                    [--dns DNS] [--dpaged] [-u USERNAME]
                                    [-p PASSWORD] [-k]
                                    (--all OUTFILE | --groups | --users [{all,enabled,disabled,locked,nopasswordexpire,passwordexpired}] | --zones | --zone ZONE | --object OBJECT | --computers | --sid SID | --unlock USER | --guid GUID | --domain_policy | --gpo | --ou | --pso | --trusts | --members GROUP | --membership USER | --search SEARCH)
                                    [--resolve] [--attr ATTR] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -d FQDN, --fqdn FQDN  The domain FQDN (ex : domain.local)
  -s LDAPSERVER, --ldapserver LDAPSERVER
                        The LDAP path (ex : ldap://corp.contoso.com:389)
  -b BASE, --base BASE  LDAP base for query
  -v, --verbose         Results will contain full information
  --dns DNS             An optional DNS server to use
  --dpaged              Disable paged search (in case of unwanted behavior)
  --resolve             Performs a resolution on all computer names, should be
                        used with --computers
  --attr ATTR           Filters output of --search
  -o OUTPUT, --output OUTPUT
                        File for saving results

Authentication:
  -u USERNAME, --username USERNAME
                        The username
  -p PASSWORD, --password PASSWORD
                        The password or the corresponding NTLM hash
  -k, --kerberos        For Kerberos authentication, ticket file should be
                        pointed by KRB5NAME env variable

Action (exclusive):
  --all OUTFILE         Lists all things to OUTFILE_thing.lst
  --groups              Lists all available groups
  --users [{all,enabled,disabled,locked,nopasswordexpire,passwordexpired}]
                        Lists all available users
  --zones               Return configured DNS zones
  --zone ZONE           Return zone records
  --object OBJECT       Return information on an object (group, computer,
                        user, etc.)
  --computers           Lists all computers
  --sid SID             Return the record associated to the SID
  --unlock USER         Unlock the given user
  --guid GUID           Return the record associated to the GUID
  --domain_policy       Print the domain policy
  --gpo                 List GPO GUID and their name
  --ou                  List OU and resolve linked GPO
  --pso                 Dump Password Setting Object (PSO) containers
  --trusts              List domain trusts
  --members GROUP       Returns users in a specific group
  --membership USER     Returns all groups the users in member of
  --search SEARCH       Custom LDAP filter
```
# INSTALL

`ldeep` is Python3 only.

```
pip3 install -r requirements
```

# TODO

* Proper DNS zone enumeration
* Project tree
* Any ideas ?
