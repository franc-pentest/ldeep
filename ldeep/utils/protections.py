#!/usr/bin/env python3

"""
A module used to verify LDAP Signing and LDAPS Channel Binding from Active Directory LDAP.
"""

import sys, socket, ssl
from io import StringIO
from ldap3 import Connection, SASL, KERBEROS, NTLM, Server, ALL


# Check LDAP Signing enforcement
# 1. Bind LDAP
# 2. "stronger" in description -> Bind failed -> Enforced
# 3. "data 52e" or "data 532" in error -> Connection error -> Cannot determined
# 4. No error -> Bind succeed -> Not enforced
def checkLDAPSigning(server, userDN, password, kerberosAuth):
    try:
        if kerberosAuth:
            conn = Connection(
                server,
                userDN,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=False,
            )
        else:
            conn = Connection(
                server, userDN, password, authentication=NTLM, auto_bind=False
            )
    except:
        return None
    originalSTDOUT = sys.stdout
    originalSTDERR = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    _ = conn.bind()
    sys.stdout = originalSTDOUT
    sys.stderr = originalSTDERR
    if "stronger" in conn.result["description"]:
        return True
    elif ("data 52e" or "data 532") in conn.result["message"]:
        return None
    elif "LdapErr" not in conn.result["message"]:
        return False


# Check LDAPS configuration
# 1. Connect to port 636
# 2. Try to wrap socket with SSL/TLS
# 3. If no error or self-signed certificate -> SSL/TLS configured
# 4. Else -> SSL/TLS not configured (By default DCs do not have
#     a certificate setup for LDAPS on port 636 and TLS handshake will hang)
def LDAPSCompleteHandshake(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    ssl_sock = ssl.wrap_socket(
        s,
        cert_reqs=ssl.CERT_OPTIONAL,
        suppress_ragged_eofs=False,
        do_handshake_on_connect=False,
    )
    ssl_sock.connect((target, 636))
    try:
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            ssl_sock.close()
            return True
        if "handshake operation timed out" in str(e):
            ssl_sock.close()
            return False
        else:
            ssl_sock.close()
            return False


# Check Channel Binding (EPA) enforcement
# 1. Bind LDAPS without Channel Binding (EPA)
# 2. "data 80090346" in error -> Bind failed -> Enforced
# 3. "data 52e" in error or no error -> Bind succeed -> Not enforced
# Note: Channel Binding (EPA) enforcement will be returned regardless of
#     a successful LDAPS bind -> Allow checking without authentication
def checkEPA(server, userDN, password, kerberosAuth):
    try:
        if kerberosAuth:
            conn = Connection(
                server,
                userDN,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=False,
            )
        else:
            conn = Connection(
                server, userDN, password, authentication=NTLM, auto_bind=False
            )
    except:
        return None
    originalSTDOUT = sys.stdout
    originalSTDERR = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    _ = conn.bind()
    sys.stdout = originalSTDOUT
    sys.stderr = originalSTDERR
    err = conn.result["message"]
    if "data 80090346" in err:
        return True
    elif "data 52e" in err:
        return False
    elif "LdapErr" not in err:
        return False


def do_ntlm_bind_null_avpair_epa(
    self, controls
):  # Patch dynamically NTLM Bind of LDAP3
    # to enforce miscalculation of Channel Binding (EPA)
    self.last_error = None
    with self.connection_lock:
        if not self.sasl_in_progress:
            self.sasl_in_progress = True
            try:
                from ldap3.utils.ntlm import NtlmClient
                from ldap3.core.connection import bind_operation

                domain_name, user_name = self.user.split("\\", 1)
                self.ntlm_client = NtlmClient(
                    user_name=user_name, domain=domain_name, password=self.password
                )
                if self.session_security == "ENCRYPT":
                    self.ntlm_client.confidentiality = True

                if self.channel_binding == "TLS_CHANNEL_BINDING":
                    self.ntlm_client.tls_channel_binding = True
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        from cryptography.hazmat.primitives import hashes
                    except ImportError:
                        raise "package cryptography missing"

                    peer_certificate = x509.load_der_x509_certificate(
                        self.server.tls.peer_certificate, default_backend()
                    )
                    peer_certificate_hash_algorithm = (
                        peer_certificate.signature_hash_algorithm
                    )
                    rfc5929_hashes_list = (hashes.MD5, hashes.SHA1)
                    if isinstance(peer_certificate_hash_algorithm, rfc5929_hashes_list):
                        digest = hashes.Hash(hashes.SHA256(), default_backend())
                    else:
                        digest = hashes.Hash(
                            peer_certificate_hash_algorithm, default_backend()
                        )
                    digest.update(self.server.tls.peer_certificate)
                    peer_certificate_digest = digest.finalize()

                    channel_binding_struct = bytes()
                    initiator_address = b"\x00" * 8
                    acceptor_address = b"\x00" * 8
                    application_data_raw = (
                        b"tls-server-end-point:" + b"\x00"
                    )  # Should be peer_certificate_digest but enforce miscalculation
                    len_application_data = len(application_data_raw).to_bytes(
                        4, byteorder="little", signed=False
                    )
                    application_data = len_application_data
                    application_data += application_data_raw
                    channel_binding_struct += initiator_address
                    channel_binding_struct += acceptor_address
                    channel_binding_struct += application_data

                    from hashlib import md5

                    self.ntlm_client.client_av_channel_bindings = md5(
                        channel_binding_struct
                    ).digest()

                request = bind_operation(
                    self.version, "SICILY_PACKAGE_DISCOVERY", self.ntlm_client
                )
                response = self.post_send_single_response(
                    self.send("bindRequest", request, controls)
                )
                if not self.strategy.sync:
                    _, result = self.get_response(response)
                else:
                    result = response[0]
                if "server_creds" in result:
                    sicily_packages = result["server_creds"].decode("ascii").split(";")
                    if "NTLM" in sicily_packages:
                        request = bind_operation(
                            self.version, "SICILY_NEGOTIATE_NTLM", self.ntlm_client
                        )
                        response = self.post_send_single_response(
                            self.send("bindRequest", request, controls)
                        )
                        if not self.strategy.sync:
                            _, result = self.get_response(response)
                        else:
                            result = response[0]

                        if result["result"] == 0:
                            request = bind_operation(
                                self.version,
                                "SICILY_RESPONSE_NTLM",
                                self.ntlm_client,
                                result["server_creds"],
                            )
                            response = self.post_send_single_response(
                                self.send("bindRequest", request, controls)
                            )
                            if not self.strategy.sync:
                                _, result = self.get_response(response)
                            else:
                                result = response[0]
                else:
                    result = None
            finally:
                self.sasl_in_progress = False

            return result


# Check Channel Binding (EPA) policy
# 1. Bind LDAPS with Channel Binding (EPA) miscalculated
# 2. If "data 80090346" in err -> EPA verification occured and failed
# 3. "data 52e" in error or no error -> No EPA verification
def checkEPAPolicy(server, userDN, password):
    try:
        # Enforce miscalculation of the "Channel Bindings" AV_PAIR
        # in Type 3 NTLM message
        Connection.do_ntlm_bind = do_ntlm_bind_null_avpair_epa
        conn = Connection(
            server,
            userDN,
            password,
            authentication=NTLM,
            channel_binding="TLS_CHANNEL_BINDING",
            auto_bind=False,
        )
    except Exception as e:
        return None
    originalSTDOUT = sys.stdout
    originalSTDERR = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    _ = conn.bind()
    sys.stdout = originalSTDOUT
    sys.stderr = originalSTDERR
    err = conn.result["message"]
    if "data 80090346" in err:
        return True
    elif "data 52e" in err:
        return False
    elif "LdapErr" not in err:
        return False


def checkProtections(target, username, password, ntlm, domain, kerberosAuth):
    serverLDAPS = Server(target, use_ssl=True, get_info=ALL)
    serverLDAP = Server(target, use_ssl=False, get_info=ALL)

    if kerberosAuth:
        user_dn = f"{username}@{domain.upper()}"
    else:
        if ntlm != None:
            password = ntlm
        user_dn = f"{domain}\\{username}"

    signingRequired = checkLDAPSigning(serverLDAP, user_dn, password, kerberosAuth)
    if signingRequired == None:
        print("LDAP connection failed")
        return
    elif signingRequired:
        print("LDAP Signing required")
    else:
        print("LDAP Signing not required")

    if not LDAPSCompleteHandshake(target):
        print(f"LDAPS connection failed. DC certificate probably not configured")
    else:
        policyEPA = None
        ldapsChannelBindingAlways = checkEPA(
            serverLDAPS, user_dn, password, kerberosAuth
        )
        if ldapsChannelBindingAlways == None:
            print(f"Failed to verify Channel Binding (EPA) enforcement")
        else:
            if ldapsChannelBindingAlways == True:
                policyEPA = "Always"
            else:
                if kerberosAuth:
                    print(
                        "Channel Binding (EPA) policy cannot be verified with Kerberos authentication"
                    )
                else:
                    ldapsChannelBindingWhenSupported = checkEPAPolicy(
                        serverLDAPS, user_dn, password
                    )
                    if ldapsChannelBindingWhenSupported == None:
                        print(f"Failed to verify Channel Binding (EPA) policy")
                    else:
                        if ldapsChannelBindingWhenSupported == True:
                            policyEPA = "When supported"
                        else:
                            policyEPA = "Never"
        if policyEPA != None:
            print(f"LDAPS Channel Binding (EPA) policy = {policyEPA}")
