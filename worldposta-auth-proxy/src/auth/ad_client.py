"""
WorldPosta Authentication Proxy - Active Directory Client
Handles primary authentication against AD/LDAP
"""

import logging
from typing import Optional, Tuple
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE

from ..config import ADClientConfig

logger = logging.getLogger(__name__)


class ADClient:
    """
    Active Directory / LDAP client for primary authentication
    """

    def __init__(self, config: ADClientConfig):
        self.config = config
        self._server: Optional[Server] = None

    def _get_server(self) -> Server:
        """Get or create LDAP server connection"""
        if self._server is None:
            self._server = Server(
                host=self.config.host,
                port=self.config.port,
                use_ssl=self.config.use_ssl,
                get_info=ALL
            )
        return self._server

    def _get_user_dn(self, username: str) -> Optional[str]:
        """
        Look up user's DN from username

        Args:
            username: Username to look up

        Returns:
            User's DN or None if not found
        """
        server = self._get_server()

        try:
            # Connect with service account
            conn = Connection(
                server,
                user=self.config.bind_dn,
                password=self.config.bind_password,
                authentication=SIMPLE,
                auto_bind=True
            )

            # Build search filter
            search_filter = self.config.search_filter.format(username=username)

            # Search for user
            conn.search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["distinguishedName"]
            )

            if len(conn.entries) == 1:
                user_dn = str(conn.entries[0].distinguishedName)
                conn.unbind()
                return user_dn
            elif len(conn.entries) > 1:
                logger.warning(f"Multiple users found for username: {username}")
            else:
                logger.debug(f"User not found: {username}")

            conn.unbind()
            return None

        except Exception as e:
            logger.error(f"Error looking up user {username}: {e}")
            return None

    def authenticate(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate user against Active Directory

        Performs LDAP bind with user's credentials to verify password.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple of (success, message)
        """
        logger.debug(f"Authenticating user: {username}")

        if not password:
            return False, "Password required"

        # Look up user's DN
        user_dn = self._get_user_dn(username)
        if not user_dn:
            logger.warning(f"User not found in AD: {username}")
            return False, "User not found"

        # Try to bind as the user
        server = self._get_server()

        try:
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )
            conn.unbind()
            logger.info(f"Primary auth successful for user: {username}")
            return True, "Authentication successful"

        except Exception as e:
            error_msg = str(e)
            logger.warning(f"Primary auth failed for user {username}: {error_msg}")

            # Parse common AD errors
            if "invalidCredentials" in error_msg:
                return False, "Invalid password"
            elif "user name is invalid" in error_msg.lower():
                return False, "Invalid username"
            elif "account disabled" in error_msg.lower():
                return False, "Account disabled"
            elif "account expired" in error_msg.lower():
                return False, "Account expired"
            elif "account locked" in error_msg.lower():
                return False, "Account locked"
            else:
                return False, "Authentication failed"

    def test_connection(self) -> bool:
        """
        Test connection to AD server

        Returns:
            True if connection successful
        """
        try:
            server = self._get_server()
            conn = Connection(
                server,
                user=self.config.bind_dn,
                password=self.config.bind_password,
                authentication=SIMPLE,
                auto_bind=True
            )
            conn.unbind()
            logger.info(f"AD connection test successful: {self.config.host}")
            return True
        except Exception as e:
            logger.error(f"AD connection test failed: {e}")
            return False
