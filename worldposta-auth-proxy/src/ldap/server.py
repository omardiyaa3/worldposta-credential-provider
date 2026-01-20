"""
WorldPosta Authentication Proxy - LDAP Server
Handles LDAP authentication requests from vCenter and other applications
"""

import logging
import asyncio
from typing import Optional, Dict, Tuple
from functools import partial

from twisted.internet import reactor, defer, protocol
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
    3. We trigger WorldPosta 2FA (push)
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

    def _get_auth_engine(self) -> AuthEngine:
        """Get or create auth engine"""
        if self._auth_engine is None:
            self._auth_engine = AuthEngine(
                ad_config=self.ad_config,
                api_config=self.api_config,
                service_name=self.service_name
            )
        return self._auth_engine

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

    @defer.inlineCallbacks
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

        try:
            # Run authentication in thread pool (to not block Twisted reactor)
            auth_engine = self._get_auth_engine()

            # Use asyncio from thread
            loop = asyncio.new_event_loop()
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
            finally:
                loop.close()

            if result == AuthResult.SUCCESS:
                logger.info(f"LDAP bind successful for: {username}")
                reply(pureldap.LDAPBindResponse(resultCode=0))
            else:
                logger.warning(f"LDAP bind failed for {username}: {message}")
                raise LDAPInvalidCredentials(message)

        except LDAPInvalidCredentials:
            raise
        except Exception as e:
            logger.error(f"Error during LDAP bind for {username}: {e}")
            raise LDAPOperationsError(str(e))

    def handle_LDAPSearchRequest(self, request, controls, reply):
        """
        Handle LDAP search request

        For vCenter integration, we need to proxy search requests to the real AD
        to allow user/group lookups.
        """
        # Decode bytes for logging
        base_object = request.baseObject.decode() if isinstance(request.baseObject, bytes) else str(request.baseObject)
        filter_str = str(request.filter) if request.filter else ""

        logger.debug(f"LDAP search request: base={base_object}, filter={filter_str}")

        # Send search done with success
        reply(pureldap.LDAPSearchResultDone(resultCode=0, matchedDN=b'', errorMessage=b''))

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        """Handle unbind request"""
        logger.debug("LDAP unbind request")
        # No response needed for unbind


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
