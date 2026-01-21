"""
WorldPosta Authentication Proxy - LDAP Server
Handles LDAP authentication requests from vCenter and other applications
"""

import logging
import asyncio
from typing import Optional, Dict, Tuple
from functools import partial

from twisted.internet import reactor, protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from ldaptor.protocols.ldap import ldapclient, ldapserver, ldapsyntax
from ldaptor.protocols.ldap.ldaperrors import (
    LDAPInvalidCredentials,
    LDAPUnwillingToPerform,
    LDAPOperationsError
)
from ldaptor.protocols import pureldap

from ..config import LDAPServerConfig, ADClientConfig
from ..auth.engine import AuthEngine, AuthResult
from ..api import WorldPostaClient

logger = logging.getLogger(__name__)


class WorldPostaLDAPServer(ldapserver.LDAPServer):
    """
    LDAP server that intercepts bind requests for 2FA

    Flow:
    1. Client sends LDAP bind request (username + password)
    2. We validate password against real AD
    3. We trigger WorldPosta 2FA (push) - unless exempt
    4. If approved, return bind success
    5. If denied/timeout, return bind failure
    """

    def __init__(self, config: LDAPServerConfig, ad_config: ADClientConfig,
                 api_config, service_name: str = "LDAP Authentication"):
        ldapserver.LDAPServer.__init__(self)
        self.config = config
        self.ad_config = ad_config
        self.api_config = api_config
        self.service_name = service_name
        self._auth_engine: Optional[AuthEngine] = None
        self._first_bind_done = False  # Track first bind for exempt_primary_bind

    def _get_auth_engine(self) -> AuthEngine:
        """Get or create auth engine"""
        if self._auth_engine is None:
            self._auth_engine = AuthEngine(
                ad_config=self.ad_config,
                api_config=self.api_config,
                service_name=self.service_name
            )
        return self._auth_engine

    def _is_exempt_from_2fa(self, dn: str) -> Tuple[bool, str]:
        """
        Check if DN is exempt from 2FA

        Returns:
            Tuple of (is_exempt, reason)
        """
        dn_lower = dn.lower()

        # Check exempt_primary_bind - skip 2FA for first bind in connection
        if self.config.exempt_primary_bind and not self._first_bind_done:
            return True, "exempt_primary_bind (first bind in connection)"

        # Check if DN matches the AD service account (auto-exempt)
        if self.ad_config and self.ad_config.bind_dn:
            service_dn = self.ad_config.bind_dn.lower()
            # Match various formats: DN, UPN (user@domain), DOMAIN\user
            if dn_lower == service_dn:
                return True, f"service account (ad_client bind_dn)"
            # Also check username part for UPN format
            if "@" in dn_lower and "@" in service_dn:
                if dn_lower.split("@")[0] == service_dn.split("@")[0]:
                    return True, f"service account (matching username)"

        # Check explicit exempt_ou list
        for exempt_dn in self.config.exempt_ous:
            exempt_lower = exempt_dn.lower()
            # Exact match
            if dn_lower == exempt_lower:
                return True, f"exempt_ou match: {exempt_dn}"
            # UPN/username match
            if "@" in dn_lower and "@" in exempt_lower:
                if dn_lower.split("@")[0] == exempt_lower.split("@")[0]:
                    return True, f"exempt_ou match (username): {exempt_dn}"
            # Check if DN ends with exempt OU (user is in that OU)
            if dn_lower.endswith("," + exempt_lower):
                return True, f"exempt_ou contains: {exempt_dn}"

        return False, ""

    def _get_bytes_value(self, obj) -> str:
        """Extract string value from ldaptor object or bytes"""
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        if hasattr(obj, 'value'):
            val = obj.value
            if isinstance(val, bytes):
                return val.decode('utf-8')
            return str(val)
        return str(obj)

    def _convert_filter(self, filt) -> str:
        """
        Recursively convert ldaptor filter object to LDAP filter string

        Handles: AND, OR, NOT, present, equalityMatch, substrings, etc.
        """
        from ldaptor.protocols import pureldap

        filt_class = filt.__class__.__name__

        # AND filter: (&(filter1)(filter2)...)
        if filt_class == 'LDAPFilter_and':
            parts = [self._convert_filter(f) for f in filt]
            return "(&" + "".join(parts) + ")"

        # OR filter: (|(filter1)(filter2)...)
        elif filt_class == 'LDAPFilter_or':
            parts = [self._convert_filter(f) for f in filt]
            return "(|" + "".join(parts) + ")"

        # NOT filter: (!(filter))
        elif filt_class == 'LDAPFilter_not':
            inner = self._convert_filter(filt.value)
            return "(!" + inner + ")"

        # Present filter: (attr=*)
        elif filt_class == 'LDAPFilter_present':
            attr = self._get_bytes_value(filt)
            return f"({attr}=*)"

        # Equality match: (attr=value)
        elif filt_class == 'LDAPFilter_equalityMatch':
            attr = self._get_bytes_value(filt.attributeDesc)
            val = self._get_bytes_value(filt.assertionValue)
            return f"({attr}={val})"

        # Substring filter: (attr=*val*)
        elif filt_class == 'LDAPFilter_substrings':
            attr = self._get_bytes_value(filt.type)
            parts = []
            if filt.substrings:
                for sub in filt.substrings:
                    sub_class = sub.__class__.__name__
                    sub_val = self._get_bytes_value(sub)
                    if sub_class == 'LDAPFilter_substrings_initial':
                        parts.append(f"{sub_val}*")
                    elif sub_class == 'LDAPFilter_substrings_any':
                        parts.append(f"*{sub_val}*")
                    elif sub_class == 'LDAPFilter_substrings_final':
                        parts.append(f"*{sub_val}")
            if parts:
                return f"({attr}={''.join(parts)})"
            return f"({attr}=*)"

        # Greater or equal: (attr>=value)
        elif filt_class == 'LDAPFilter_greaterOrEqual':
            attr = self._get_bytes_value(filt.attributeDesc)
            val = self._get_bytes_value(filt.assertionValue)
            return f"({attr}>={val})"

        # Less or equal: (attr<=value)
        elif filt_class == 'LDAPFilter_lessOrEqual':
            attr = self._get_bytes_value(filt.attributeDesc)
            val = self._get_bytes_value(filt.assertionValue)
            return f"({attr}<={val})"

        # Approx match: (attr~=value)
        elif filt_class == 'LDAPFilter_approxMatch':
            attr = self._get_bytes_value(filt.attributeDesc)
            val = self._get_bytes_value(filt.assertionValue)
            return f"({attr}~={val})"

        # Fallback - try to get string representation
        else:
            logger.debug(f"Unknown filter type: {filt_class}")
            return "(objectClass=*)"

    def _extract_username(self, dn: str) -> str:
        """
        Extract username from DN

        Handles formats:
        - CN=username,OU=Users,DC=company,DC=com
        - uid=username,ou=users,dc=company,dc=com
        - username@company.com
        - DOMAIN\\username
        """
        dn_lower = dn.lower()

        # Try CN=
        if dn_lower.startswith("cn="):
            parts = dn.split(",")
            return parts[0][3:]  # Remove "CN="

        # Try uid=
        if dn_lower.startswith("uid="):
            parts = dn.split(",")
            return parts[0][4:]  # Remove "uid="

        # Try email format
        if "@" in dn and "=" not in dn:
            return dn.split("@")[0]

        # Try DOMAIN\username
        if "\\" in dn:
            return dn.split("\\")[-1]

        # Return as-is
        return dn

    def handle_LDAPBindRequest(self, request, controls, reply):
        """
        Handle LDAP bind request with 2FA
        """
        dn = request.dn.decode() if isinstance(request.dn, bytes) else request.dn

        # Handle anonymous bind
        if not dn or request.auth == b'':
            logger.debug("Anonymous bind request - allowing")
            reply(pureldap.LDAPBindResponse(resultCode=0))
            return

        password = request.auth.decode() if isinstance(request.auth, bytes) else request.auth
        username = self._extract_username(dn)

        logger.info(f"LDAP bind request: dn={dn}, username={username}")

        # Get client IP (if available)
        try:
            client_ip = self.transport.getPeer().host
        except:
            client_ip = "unknown"

        # Check if this DN is exempt from 2FA (service account)
        is_exempt, exempt_reason = self._is_exempt_from_2fa(dn)

        if is_exempt:
            logger.info(f"2FA EXEMPT for {username}: {exempt_reason}")
            # Only verify AD password, skip 2FA
            try:
                from ldap3 import Server, Connection, ALL
                server = Server(self.ad_config.host, port=self.ad_config.port, get_info=ALL)
                conn = Connection(server, user=dn, password=password)
                if conn.bind():
                    logger.info(f"LDAP bind successful (exempt) for: {username}")
                    conn.unbind()
                    self._first_bind_done = True
                    reply(pureldap.LDAPBindResponse(resultCode=0))
                else:
                    logger.warning(f"LDAP bind failed (exempt) for {username}: invalid credentials")
                    self._first_bind_done = True
                    reply(pureldap.LDAPBindResponse(resultCode=49, errorMessage=b"Invalid credentials"))
            except Exception as e:
                logger.error(f"Error during exempt LDAP bind for {username}: {e}")
                reply(pureldap.LDAPBindResponse(resultCode=1, errorMessage=str(e).encode()))
            return

        # Not exempt - require 2FA
        try:
            # Run authentication in thread pool (to not block Twisted reactor)
            auth_engine = self._get_auth_engine()

            # Use asyncio from thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result, message = loop.run_until_complete(
                    auth_engine.authenticate(
                        username=username,
                        password=password,
                        device_info=f"LDAP client",
                        ip_address=client_ip,
                        mode="auto"
                    )
                )
                # Close the API client session to avoid "Unclosed client session" error
                if hasattr(auth_engine, 'api_client') and auth_engine.api_client:
                    loop.run_until_complete(auth_engine.api_client.close())
            finally:
                loop.close()

            self._first_bind_done = True

            if result == AuthResult.SUCCESS:
                logger.info(f"LDAP bind successful for: {username}")
                reply(pureldap.LDAPBindResponse(resultCode=0))
            else:
                logger.warning(f"LDAP bind failed for {username}: {message}")
                reply(pureldap.LDAPBindResponse(resultCode=49, errorMessage=message.encode() if isinstance(message, str) else message))

        except Exception as e:
            logger.error(f"Error during LDAP bind for {username}: {e}")
            reply(pureldap.LDAPBindResponse(resultCode=1, errorMessage=str(e).encode()))

    def handle_LDAPSearchRequest(self, request, controls, reply):
        """
        Handle LDAP search request

        Proxy search requests to real AD server so vCenter can find users/groups.
        Only bind requests trigger 2FA.
        """
        try:
            base_object = request.baseObject.decode('utf-8') if isinstance(request.baseObject, bytes) else str(request.baseObject)
        except:
            base_object = "unknown"

        logger.debug(f"LDAP search request: base={base_object}")

        # Proxy search to real AD
        if self.ad_config:
            try:
                from ldap3 import Server, Connection, ALL, SUBTREE

                server = Server(self.ad_config.host, port=self.ad_config.port, get_info=ALL)
                conn = Connection(
                    server,
                    user=self.ad_config.bind_dn,
                    password=self.ad_config.bind_password,
                    auto_bind=True
                )

                # Get search parameters
                search_base = request.baseObject.decode('utf-8') if isinstance(request.baseObject, bytes) else str(request.baseObject)

                # Get search scope from request (0=base, 1=onelevel, 2=subtree)
                from ldap3 import BASE, LEVEL, SUBTREE
                scope_map = {0: BASE, 1: LEVEL, 2: SUBTREE}
                search_scope = scope_map.get(request.scope, SUBTREE)
                logger.debug(f"Search scope: {request.scope} -> {search_scope}")

                # Convert filter to string properly
                search_filter = "(objectClass=*)"  # default
                if request.filter is not None:
                    try:
                        search_filter = self._convert_filter(request.filter)
                        logger.debug(f"Converted filter: {search_filter}")
                    except Exception as filter_err:
                        logger.debug(f"Could not parse filter, using default: {filter_err}")
                        search_filter = "(objectClass=*)"

                logger.debug(f"Proxying search to AD: base={search_base}, filter={search_filter}, scope={search_scope}")

                # Perform search with correct scope
                # Request all user attrs (*) plus operational attrs (+) which includes objectSid, objectGUID
                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=['*', '+']
                )

                logger.debug(f"AD returned {len(conn.entries)} entries")

                # Known binary attributes that must be passed as raw bytes
                binary_attributes = {
                    'objectsid', 'objectguid', 'msexchmailboxguid', 'msexchmailboxsecuritydescriptor',
                    'securityidentifier', 'sid', 'sidhistory', 'usercertificate', 'cacertificate',
                    'logonhours', 'jpegphoto', 'thumbnailphoto', 'usersmimecertificate',
                    'msds-generationid', 'msds-cloudextensionattribute1'
                }

                # Send results back
                for entry in conn.entries:
                    try:
                        # Debug: log if objectSid is present and its type
                        if 'objectSid' in entry.entry_attributes:
                            sid_val = entry['objectSid'].value
                            sid_raw = entry['objectSid'].raw_values[0] if entry['objectSid'].raw_values else None
                            logger.debug(f"objectSid for {entry.entry_dn}: value type={type(sid_val)}, raw type={type(sid_raw) if sid_raw else 'None'}, raw len={len(sid_raw) if sid_raw else 0}")

                        # Build attributes list
                        attrs = []
                        for attr_name in entry.entry_attributes:
                            values = entry[attr_name].values
                            raw_values = entry[attr_name].raw_values if hasattr(entry[attr_name], 'raw_values') else None

                            if values:
                                attr_vals = []
                                is_binary = attr_name.lower() in binary_attributes

                                for i, v in enumerate(values):
                                    if is_binary:
                                        # For binary attributes, use raw_values if available
                                        if raw_values and i < len(raw_values):
                                            raw_v = raw_values[i]
                                            if isinstance(raw_v, bytes):
                                                attr_vals.append(raw_v)
                                            else:
                                                attr_vals.append(bytes(raw_v) if raw_v else b'')
                                        elif isinstance(v, bytes):
                                            attr_vals.append(v)
                                        else:
                                            # Last resort - try to preserve the value
                                            logger.debug(f"Binary attribute {attr_name} has non-bytes value type: {type(v)}")
                                            if hasattr(v, '__bytes__'):
                                                attr_vals.append(bytes(v))
                                            else:
                                                attr_vals.append(str(v).encode('utf-8'))
                                    else:
                                        # Non-binary attributes
                                        if isinstance(v, str):
                                            attr_vals.append(v.encode('utf-8'))
                                        elif isinstance(v, bytes):
                                            attr_vals.append(v)
                                        else:
                                            attr_vals.append(str(v).encode('utf-8'))

                                attrs.append((attr_name.encode('utf-8'), attr_vals))

                        result_entry = pureldap.LDAPSearchResultEntry(
                            objectName=entry.entry_dn.encode('utf-8'),
                            attributes=attrs
                        )
                        reply(result_entry)
                    except Exception as entry_error:
                        logger.debug(f"Error processing entry {entry.entry_dn}: {entry_error}")
                        import traceback
                        logger.debug(traceback.format_exc())

                conn.unbind()

            except Exception as e:
                logger.error(f"Error proxying search to AD: {e}")
                import traceback
                logger.debug(traceback.format_exc())

        # Send search done
        reply(pureldap.LDAPSearchResultDone(resultCode=0))

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        """Handle unbind request"""
        logger.debug("LDAP unbind request")
        # No response needed for unbind

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        """
        Handle LDAP extended operation requests

        vCenter may send extended operations like:
        - 1.3.6.1.4.1.4203.1.11.3 (Who Am I)
        - 1.3.6.1.4.1.1466.20037 (StartTLS)
        """
        try:
            oid = request.requestName.decode() if isinstance(request.requestName, bytes) else str(request.requestName)
        except:
            oid = "unknown"

        logger.debug(f"LDAP extended operation: OID={oid}")

        # Who Am I extended operation
        if oid == "1.3.6.1.4.1.4203.1.11.3":
            # Return empty authzId (anonymous) - vCenter doesn't really need this
            reply(pureldap.LDAPExtendedResponse(
                resultCode=0,
                responseName=b"1.3.6.1.4.1.4203.1.11.3",
                response=b""
            ))
            return

        # StartTLS - we don't support it, return unwilling to perform
        if oid == "1.3.6.1.4.1.1466.20037":
            logger.debug("StartTLS requested but not supported")
            reply(pureldap.LDAPExtendedResponse(
                resultCode=53,  # Unwilling to perform
                errorMessage=b"StartTLS not supported"
            ))
            return

        # For other extended operations, return success with empty response
        logger.debug(f"Unknown extended operation {oid}, returning success")
        reply(pureldap.LDAPExtendedResponse(
            resultCode=0,
            response=b""
        ))

    def handle_LDAPCompareRequest(self, request, controls, reply):
        """Handle LDAP compare request by proxying to AD"""
        try:
            dn = request.entry.decode() if isinstance(request.entry, bytes) else str(request.entry)
            attr = request.ava.attributeDesc.decode() if isinstance(request.ava.attributeDesc, bytes) else str(request.ava.attributeDesc)
            val = request.ava.assertionValue.decode() if isinstance(request.ava.assertionValue, bytes) else str(request.ava.assertionValue)
        except:
            dn, attr, val = "unknown", "unknown", "unknown"

        logger.debug(f"LDAP compare request: dn={dn}, attr={attr}")

        # Proxy compare to real AD
        if self.ad_config:
            try:
                from ldap3 import Server, Connection, ALL

                server = Server(self.ad_config.host, port=self.ad_config.port, get_info=ALL)
                conn = Connection(
                    server,
                    user=self.ad_config.bind_dn,
                    password=self.ad_config.bind_password,
                    auto_bind=True
                )

                result = conn.compare(dn, attr, val)
                conn.unbind()

                if result:
                    reply(pureldap.LDAPCompareResponse(resultCode=6))  # compareTrue
                else:
                    reply(pureldap.LDAPCompareResponse(resultCode=5))  # compareFalse
                return
            except Exception as e:
                logger.error(f"Error proxying compare to AD: {e}")

        # Default: return compareFalse
        reply(pureldap.LDAPCompareResponse(resultCode=5))

    def handle_LDAPAbandonRequest(self, request, controls, reply):
        """Handle abandon request - just log it, no response needed"""
        logger.debug(f"LDAP abandon request for message ID: {request}")
        # No response for abandon

    def handle_LDAPModifyRequest(self, request, controls, reply):
        """Handle modify request - return unwilling to perform"""
        logger.debug("LDAP modify request - not supported")
        reply(pureldap.LDAPModifyResponse(
            resultCode=53,  # Unwilling to perform
            errorMessage=b"Modify operations not supported by proxy"
        ))

    def handle_LDAPAddRequest(self, request, controls, reply):
        """Handle add request - return unwilling to perform"""
        logger.debug("LDAP add request - not supported")
        reply(pureldap.LDAPAddResponse(
            resultCode=53,  # Unwilling to perform
            errorMessage=b"Add operations not supported by proxy"
        ))

    def handle_LDAPDelRequest(self, request, controls, reply):
        """Handle delete request - return unwilling to perform"""
        logger.debug("LDAP delete request - not supported")
        reply(pureldap.LDAPDelResponse(
            resultCode=53,  # Unwilling to perform
            errorMessage=b"Delete operations not supported by proxy"
        ))

    def handle_LDAPModifyDNRequest(self, request, controls, reply):
        """Handle modify DN request - return unwilling to perform"""
        logger.debug("LDAP modify DN request - not supported")
        # ModifyDNResponse uses same structure as other responses
        reply(pureldap.LDAPModifyDNResponse(
            resultCode=53,  # Unwilling to perform
            errorMessage=b"Modify DN operations not supported by proxy"
        ))


class LDAPServerFactory(protocol.ServerFactory):
    """Factory for creating LDAP server instances"""

    def __init__(self, config: LDAPServerConfig, ad_config: ADClientConfig,
                 api_config, service_name: str = "LDAP Authentication"):
        self.config = config
        self.ad_config = ad_config
        self.api_config = api_config
        self.service_name = service_name

    def buildProtocol(self, addr):
        logger.debug(f"New LDAP connection from {addr}")
        proto = WorldPostaLDAPServer(
            config=self.config,
            ad_config=self.ad_config,
            api_config=self.api_config,
            service_name=self.service_name
        )
        return proto


class LDAPServer:
    """
    LDAP server wrapper for async operation
    """

    def __init__(self, config: LDAPServerConfig, ad_config: ADClientConfig,
                 api_config, service_name: str = "LDAP Authentication"):
        self.config = config
        self.ad_config = ad_config
        self.api_config = api_config
        self.service_name = service_name
        self._endpoint = None
        self._port = None

    def start(self):
        """Start the LDAP server (runs in Twisted reactor)"""
        logger.info(f"Starting LDAP server on port {self.config.port}")

        factory = LDAPServerFactory(
            config=self.config,
            ad_config=self.ad_config,
            api_config=self.api_config,
            service_name=self.service_name
        )

        self._endpoint = TCP4ServerEndpoint(reactor, self.config.port)
        d = self._endpoint.listen(factory)
        d.addCallback(self._on_listening)
        d.addErrback(self._on_error)

        return d

    def _on_listening(self, port):
        """Called when server starts listening"""
        self._port = port
        logger.info(f"LDAP server listening on port {self.config.port}")

    def _on_error(self, failure):
        """Called on startup error"""
        logger.error(f"Failed to start LDAP server: {failure}")

    def stop(self):
        """Stop the LDAP server"""
        if self._port:
            logger.info("Stopping LDAP server")
            return self._port.stopListening()
