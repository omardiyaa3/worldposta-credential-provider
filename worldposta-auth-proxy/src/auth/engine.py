"""
WorldPosta Authentication Proxy - Authentication Engine
Orchestrates primary auth + 2FA
"""

import logging
import asyncio
from typing import Optional, Tuple
from enum import Enum

from .ad_client import ADClient
from ..api import WorldPostaClient
from ..config import ADClientConfig, WorldPostaAPIConfig

logger = logging.getLogger(__name__)


class AuthResult(Enum):
    """Authentication result codes"""
    SUCCESS = "success"
    PRIMARY_FAILED = "primary_failed"
    PUSH_FAILED = "push_failed"
    PUSH_DENIED = "push_denied"
    PUSH_TIMEOUT = "push_timeout"
    OTP_INVALID = "otp_invalid"
    USER_NOT_FOUND = "user_not_found"
    ERROR = "error"


class AuthEngine:
    """
    Authentication engine that combines primary auth with WorldPosta 2FA
    """

    def __init__(
        self,
        ad_config: Optional[ADClientConfig],
        api_config: WorldPostaAPIConfig,
        service_name: str = "Authentication"
    ):
        self.ad_client = ADClient(ad_config) if ad_config else None
        self.api_client = WorldPostaClient(
            endpoint=api_config.endpoint,
            integration_key=api_config.integration_key,
            secret_key=api_config.secret_key,
            timeout=api_config.push_timeout
        )
        self.service_name = service_name

    async def close(self):
        """Close API client session"""
        await self.api_client.close()

    def _parse_password(self, password: str) -> Tuple[str, Optional[str]]:
        """
        Parse password for appended factor

        Handles formats like:
        - "password" -> ("password", None)
        - "password,push" -> ("password", "push")
        - "password,123456" -> ("password", "123456")

        Args:
            password: Password string potentially with appended factor

        Returns:
            Tuple of (real_password, factor)
        """
        if "," in password:
            parts = password.rsplit(",", 1)
            return parts[0], parts[1]
        return password, None

    async def authenticate_primary(
        self,
        username: str,
        password: str
    ) -> Tuple[bool, str]:
        """
        Perform primary authentication

        Args:
            username: Username
            password: Password (without appended factor)

        Returns:
            Tuple of (success, message)
        """
        if self.ad_client:
            return self.ad_client.authenticate(username, password)
        else:
            # No primary auth configured - pass-through mode
            logger.debug("No primary auth configured, skipping")
            return True, "Pass-through"

    async def authenticate_push(
        self,
        username: str,
        device_info: str = "",
        ip_address: str = ""
    ) -> AuthResult:
        """
        Perform push-based 2FA

        Args:
            username: Username
            device_info: Device/hostname info
            ip_address: Client IP address

        Returns:
            AuthResult
        """
        success = await self.api_client.authenticate_push(
            username=username,
            service_name=self.service_name,
            device_info=device_info,
            ip_address=ip_address
        )

        if success:
            return AuthResult.SUCCESS
        else:
            return AuthResult.PUSH_TIMEOUT

    async def authenticate_otp(self, username: str, code: str) -> AuthResult:
        """
        Perform OTP-based 2FA

        Args:
            username: Username
            code: OTP code

        Returns:
            AuthResult
        """
        if await self.api_client.verify_otp(username, code):
            return AuthResult.SUCCESS
        else:
            return AuthResult.OTP_INVALID

    async def authenticate(
        self,
        username: str,
        password: str,
        device_info: str = "",
        ip_address: str = "",
        mode: str = "auto"
    ) -> Tuple[AuthResult, str]:
        """
        Complete authentication flow

        Args:
            username: Username
            password: Password (may have appended factor like "password,push")
            device_info: Device/hostname info
            ip_address: Client IP address
            mode: Auth mode - "auto", "push", "otp"

        Returns:
            Tuple of (AuthResult, message)
        """
        logger.info(f"Starting authentication for user: {username} (mode: {mode})")

        # Parse password for appended factor
        real_password, factor = self._parse_password(password)

        # Primary authentication
        primary_success, primary_msg = await self.authenticate_primary(
            username, real_password
        )

        if not primary_success:
            logger.warning(f"Primary auth failed for {username}: {primary_msg}")
            return AuthResult.PRIMARY_FAILED, primary_msg

        logger.debug(f"Primary auth successful for {username}")

        # Determine 2FA method
        if factor:
            # User specified factor
            if factor.lower() == "push":
                result = await self.authenticate_push(
                    username, device_info, ip_address
                )
            elif factor.isdigit() and len(factor) >= 6:
                # Looks like an OTP code
                result = await self.authenticate_otp(username, factor)
            else:
                logger.warning(f"Unknown factor: {factor}")
                return AuthResult.ERROR, f"Unknown factor: {factor}"
        elif mode == "push":
            result = await self.authenticate_push(
                username, device_info, ip_address
            )
        elif mode == "otp":
            # OTP mode without code - this shouldn't happen
            return AuthResult.ERROR, "OTP code required"
        else:
            # Auto mode - default to push
            result = await self.authenticate_push(
                username, device_info, ip_address
            )

        # Return result
        if result == AuthResult.SUCCESS:
            logger.info(f"Authentication successful for user: {username}")
            return AuthResult.SUCCESS, "Authentication successful"
        else:
            logger.warning(f"2FA failed for {username}: {result.value}")
            return result, f"2FA failed: {result.value}"
