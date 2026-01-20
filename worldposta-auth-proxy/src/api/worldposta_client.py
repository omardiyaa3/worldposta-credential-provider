"""
WorldPosta Authentication Proxy - API Client
Handles communication with WorldPosta cloud API for 2FA
"""

import json
import time
import logging
import asyncio
from typing import Optional, Tuple
from enum import Enum

import aiohttp

from .signing import get_auth_headers

logger = logging.getLogger(__name__)


class PushStatus(Enum):
    """Push notification status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    ERROR = "error"


class WorldPostaClient:
    """
    WorldPosta API client for 2FA operations
    """

    def __init__(
        self,
        endpoint: str,
        integration_key: str,
        secret_key: str,
        timeout: int = 60
    ):
        self.endpoint = endpoint.rstrip("/")
        self.integration_key = integration_key
        self.secret_key = secret_key
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            )
        return self._session

    async def close(self):
        """Close the HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None
    ) -> Tuple[bool, dict]:
        """
        Make authenticated request to WorldPosta API

        Args:
            method: HTTP method (GET, POST)
            path: API path (e.g., /v1/push/send)
            body: Request body dict (for POST)

        Returns:
            Tuple of (success, response_data)
        """
        url = f"{self.endpoint}{path}"
        body_str = json.dumps(body) if body else "{}"
        headers = get_auth_headers(self.integration_key, self.secret_key, body_str)

        try:
            session = await self._get_session()

            if method.upper() == "GET":
                async with session.get(url, headers=headers) as response:
                    data = await response.json()
                    return response.status < 300, data
            else:
                async with session.post(url, headers=headers, data=body_str) as response:
                    data = await response.json()
                    return response.status < 300, data

        except asyncio.TimeoutError:
            logger.error(f"Request timeout: {method} {path}")
            return False, {"error": "timeout"}
        except aiohttp.ClientError as e:
            logger.error(f"Request failed: {method} {path} - {e}")
            return False, {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error: {method} {path} - {e}")
            return False, {"error": str(e)}

    async def verify_otp(self, username: str, code: str) -> bool:
        """
        Verify OTP code for user

        Args:
            username: External user ID
            code: OTP code to verify

        Returns:
            True if OTP is valid
        """
        logger.debug(f"Verifying OTP for user: {username}")

        success, data = await self._request("POST", "/v1/totp/verify", {
            "externalUserId": username,
            "code": code
        })

        if success and data.get("valid"):
            logger.info(f"OTP verified for user: {username}")
            return True

        logger.warning(f"OTP verification failed for user: {username}")
        return False

    async def send_push(
        self,
        username: str,
        service_name: str = "Authentication",
        device_info: str = "",
        ip_address: str = ""
    ) -> Optional[str]:
        """
        Send push notification to user

        Args:
            username: External user ID
            service_name: Name of service requesting auth
            device_info: Device/hostname info
            ip_address: Client IP address

        Returns:
            Request ID if push sent, None on failure
        """
        logger.debug(f"Sending push to user: {username}")

        success, data = await self._request("POST", "/v1/push/send", {
            "externalUserId": username,
            "serviceName": service_name,
            "deviceInfo": device_info,
            "ipAddress": ip_address
        })

        if success and "requestId" in data:
            request_id = data["requestId"]
            logger.info(f"Push sent to user {username}, requestId: {request_id}")
            return request_id

        error = data.get("error", "unknown error")
        logger.warning(f"Failed to send push to user {username}: {error}")
        return None

    async def check_push_status(self, request_id: str) -> PushStatus:
        """
        Check status of a push notification

        Args:
            request_id: Push request ID

        Returns:
            PushStatus enum value
        """
        success, data = await self._request("GET", f"/v1/push/status/{request_id}")

        if not success:
            return PushStatus.ERROR

        status = data.get("status", "").lower()

        if status == "approved":
            return PushStatus.APPROVED
        elif status == "denied":
            return PushStatus.DENIED
        elif status == "expired":
            return PushStatus.EXPIRED
        elif status == "pending":
            return PushStatus.PENDING
        else:
            return PushStatus.ERROR

    async def wait_for_push(
        self,
        request_id: str,
        timeout: Optional[int] = None,
        poll_interval: float = 0.5
    ) -> PushStatus:
        """
        Wait for push notification to be approved/denied

        Args:
            request_id: Push request ID
            timeout: Maximum wait time in seconds (default: self.timeout)
            poll_interval: Time between status checks in seconds

        Returns:
            Final PushStatus
        """
        timeout = timeout or self.timeout
        start_time = time.time()

        logger.debug(f"Waiting for push {request_id} (timeout: {timeout}s)")

        while (time.time() - start_time) < timeout:
            status = await self.check_push_status(request_id)

            if status == PushStatus.APPROVED:
                logger.info(f"Push {request_id} approved")
                return PushStatus.APPROVED
            elif status in (PushStatus.DENIED, PushStatus.EXPIRED):
                logger.info(f"Push {request_id} {status.value}")
                return status
            elif status == PushStatus.ERROR:
                logger.warning(f"Error checking push {request_id}")
                # Continue polling on transient errors
                pass

            await asyncio.sleep(poll_interval)

        logger.warning(f"Push {request_id} timed out after {timeout}s")
        return PushStatus.EXPIRED

    async def authenticate_push(
        self,
        username: str,
        service_name: str = "Authentication",
        device_info: str = "",
        ip_address: str = ""
    ) -> bool:
        """
        Complete push authentication flow

        Sends push and waits for approval.

        Args:
            username: External user ID
            service_name: Name of service
            device_info: Device/hostname info
            ip_address: Client IP address

        Returns:
            True if user approved, False otherwise
        """
        # Send push
        request_id = await self.send_push(
            username=username,
            service_name=service_name,
            device_info=device_info,
            ip_address=ip_address
        )

        if not request_id:
            return False

        # Wait for approval
        status = await self.wait_for_push(request_id)
        return status == PushStatus.APPROVED
