"""
WorldPosta Authentication Proxy - Request Signing
HMAC-SHA256 signature generation for API authentication
"""

import hmac
import hashlib
import secrets
import time


def generate_nonce(length: int = 32) -> str:
    """
    Generate a random nonce for request signing

    Args:
        length: Length of nonce in characters (hex)

    Returns:
        Random hex string
    """
    return secrets.token_hex(length // 2)


def generate_signature(secret_key: str, timestamp: int, nonce: str, body: str) -> str:
    """
    Generate HMAC-SHA256 signature for API request

    The signature is computed as:
        HMAC-SHA256(secret_key, timestamp + nonce + body)

    Args:
        secret_key: Integration secret key
        timestamp: Unix timestamp
        nonce: Random nonce string
        body: Request body (JSON string)

    Returns:
        Hex-encoded signature
    """
    # Build signing string: timestamp + nonce + body
    data_to_sign = f"{timestamp}{nonce}{body}"

    # Compute HMAC-SHA256
    signature = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=data_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    return signature


def get_auth_headers(
    integration_key: str,
    secret_key: str,
    body: str = "{}"
) -> dict:
    """
    Generate authentication headers for WorldPosta API request

    Args:
        integration_key: Integration key
        secret_key: Secret key
        body: Request body (use "{}" for GET requests)

    Returns:
        Dictionary of headers
    """
    timestamp = int(time.time())
    nonce = generate_nonce()
    signature = generate_signature(secret_key, timestamp, nonce, body)

    return {
        "Content-Type": "application/json",
        "X-Integration-Key": integration_key,
        "X-Signature": signature,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
    }
