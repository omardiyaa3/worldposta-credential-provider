"""
WorldPosta Authentication Proxy - RADIUS Server
Handles RADIUS authentication requests from VPNs, firewalls, etc.
"""

import logging
import asyncio
import socket
import time
import hashlib
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from pyrad import dictionary, packet, server
from pyrad.packet import AccessRequest, AccessAccept, AccessReject, AccessChallenge

from ..config import RADIUSServerConfig, RADIUSClient
from ..auth.engine import AuthEngine, AuthResult

logger = logging.getLogger(__name__)

# RADIUS dictionary for standard attributes
RADIUS_DICT = """
ATTRIBUTE   User-Name       1   string
ATTRIBUTE   User-Password   2   string  encrypt=1
ATTRIBUTE   NAS-IP-Address  4   ipaddr
ATTRIBUTE   NAS-Port        5   integer
ATTRIBUTE   Service-Type    6   integer
ATTRIBUTE   Reply-Message   18  string
ATTRIBUTE   State           24  octets
ATTRIBUTE   Class           25  octets
ATTRIBUTE   Session-Timeout 27  integer
ATTRIBUTE   Calling-Station-Id  31  string
ATTRIBUTE   NAS-Identifier  32  string
"""


@dataclass
class PendingRequest:
    """Track pending requests for duplicate detection"""
    timestamp: float
    identifier: int
    source: Tuple[str, int]


class RADIUSServer:
    """
    RADIUS authentication server

    Supports modes:
    - auto: User enters password, server triggers push
    - concat: User enters "password,push" or "password,123456"
    - challenge: Two-step with Access-Challenge (not yet implemented)
    """

    def __init__(
        self,
        config: RADIUSServerConfig,
        auth_engine: AuthEngine,
        service_name: str = "VPN Authentication"
    ):
        self.config = config
        self.auth_engine = auth_engine
        self.service_name = service_name

        # Build client lookup table
        self.clients: Dict[str, str] = {}  # IP -> secret
        for client in config.clients:
            self.clients[client.ip] = client.secret

        # Pending requests for duplicate detection
        self.pending: Dict[str, PendingRequest] = {}
        self.pending_lock = asyncio.Lock()

        # Socket
        self.socket: Optional[socket.socket] = None
        self.running = False

        # Load RADIUS dictionary
        self.dict = dictionary.Dictionary()
        for line in RADIUS_DICT.strip().split("\n"):
            parts = line.split()
            if parts[0] == "ATTRIBUTE":
                self.dict.attributes[parts[1]] = (int(parts[2]), parts[3])

    def _get_client_secret(self, client_ip: str) -> Optional[str]:
        """Get shared secret for client IP"""
        return self.clients.get(client_ip)

    def _is_duplicate(self, identifier: int, source: Tuple[str, int]) -> bool:
        """
        Check if this is a duplicate request

        RADIUS clients may retransmit if they don't get a response quickly.
        We need to detect and ignore duplicates during push wait.
        """
        key = f"{source[0]}:{source[1]}:{identifier}"
        return key in self.pending

    async def _mark_pending(self, identifier: int, source: Tuple[str, int]):
        """Mark request as pending"""
        key = f"{source[0]}:{source[1]}:{identifier}"
        async with self.pending_lock:
            self.pending[key] = PendingRequest(
                timestamp=time.time(),
                identifier=identifier,
                source=source
            )

    async def _clear_pending(self, identifier: int, source: Tuple[str, int]):
        """Clear pending request"""
        key = f"{source[0]}:{source[1]}:{identifier}"
        async with self.pending_lock:
            self.pending.pop(key, None)

    async def _cleanup_pending(self):
        """Clean up old pending requests"""
        now = time.time()
        async with self.pending_lock:
            expired = [
                key for key, req in self.pending.items()
                if now - req.timestamp > 120  # 2 minute timeout
            ]
            for key in expired:
                del self.pending[key]

    def _parse_packet(
        self,
        data: bytes,
        source: Tuple[str, int],
        secret: str
    ) -> Optional[packet.Packet]:
        """Parse incoming RADIUS packet"""
        try:
            pkt = packet.Packet(
                packet=data,
                secret=secret.encode(),
                dict=self.dict
            )
            return pkt
        except Exception as e:
            logger.error(f"Failed to parse RADIUS packet from {source}: {e}")
            return None

    def _create_response(
        self,
        request: packet.Packet,
        code: int,
        secret: str,
        attributes: Optional[Dict] = None
    ) -> bytes:
        """Create RADIUS response packet"""
        reply = request.CreateReply(packet=None)
        reply.code = code

        if attributes:
            for key, value in attributes.items():
                reply[key] = value

        return reply.ReplyPacket()

    async def _handle_auth_request(
        self,
        pkt: packet.Packet,
        source: Tuple[str, int],
        secret: str
    ) -> bytes:
        """
        Handle Access-Request packet

        Args:
            pkt: RADIUS packet
            source: (IP, port) of client
            secret: Shared secret

        Returns:
            Response packet bytes
        """
        # Extract attributes
        username = pkt.get("User-Name", [b""])[0]
        if isinstance(username, bytes):
            username = username.decode()

        password = pkt.get("User-Password", [b""])[0]
        if isinstance(password, bytes):
            password = password.decode()

        nas_ip = pkt.get("NAS-IP-Address", [""])[0]
        calling_station = pkt.get("Calling-Station-Id", [b""])[0]
        if isinstance(calling_station, bytes):
            calling_station = calling_station.decode()

        logger.info(f"Access-Request from {source[0]}: user={username}, nas={nas_ip}")

        # Check for duplicate
        if self._is_duplicate(pkt.id, source):
            logger.debug(f"Ignoring duplicate request from {source}")
            return b""  # Don't respond to duplicates during push wait

        # Mark as pending
        await self._mark_pending(pkt.id, source)

        try:
            # Perform authentication
            result, message = await self.auth_engine.authenticate(
                username=username,
                password=password,
                device_info=f"NAS: {nas_ip}",
                ip_address=calling_station or source[0],
                mode=self.config.mode
            )

            if result == AuthResult.SUCCESS:
                logger.info(f"Access-Accept for user: {username}")
                return self._create_response(
                    pkt, AccessAccept, secret,
                    {"Reply-Message": "Authentication successful"}
                )
            else:
                logger.warning(f"Access-Reject for user: {username} - {message}")
                return self._create_response(
                    pkt, AccessReject, secret,
                    {"Reply-Message": message}
                )

        finally:
            await self._clear_pending(pkt.id, source)

    async def _handle_packet(
        self,
        data: bytes,
        source: Tuple[str, int]
    ) -> Optional[bytes]:
        """Handle incoming RADIUS packet"""
        client_ip = source[0]

        # Get shared secret for this client
        secret = self._get_client_secret(client_ip)
        if not secret:
            logger.warning(f"Unknown RADIUS client: {client_ip}")
            return None

        # Parse packet
        pkt = self._parse_packet(data, source, secret)
        if not pkt:
            return None

        # Handle based on packet type
        if pkt.code == AccessRequest:
            return await self._handle_auth_request(pkt, source, secret)
        else:
            logger.warning(f"Unsupported RADIUS packet code: {pkt.code}")
            return None

    async def _receive_loop(self):
        """Main receive loop"""
        loop = asyncio.get_event_loop()

        while self.running:
            try:
                # Receive packet (with timeout for graceful shutdown)
                data, source = await asyncio.wait_for(
                    loop.run_in_executor(None, self.socket.recvfrom, 4096),
                    timeout=1.0
                )

                # Handle packet in background
                asyncio.create_task(self._process_and_respond(data, source))

            except asyncio.TimeoutError:
                # Check if we should keep running
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error in receive loop: {e}")

    async def _process_and_respond(self, data: bytes, source: Tuple[str, int]):
        """Process packet and send response"""
        try:
            response = await self._handle_packet(data, source)
            if response:
                self.socket.sendto(response, source)
        except Exception as e:
            logger.error(f"Error processing packet from {source}: {e}")

    async def start(self):
        """Start the RADIUS server"""
        logger.info(f"Starting RADIUS server on port {self.config.port}")

        # Create UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("0.0.0.0", self.config.port))
        self.socket.setblocking(False)

        self.running = True

        # Log configured clients
        for ip in self.clients.keys():
            logger.info(f"RADIUS client configured: {ip}")

        # Start receive loop
        await self._receive_loop()

    async def stop(self):
        """Stop the RADIUS server"""
        logger.info("Stopping RADIUS server")
        self.running = False
        if self.socket:
            self.socket.close()
