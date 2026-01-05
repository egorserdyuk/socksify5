"""
Authentication providers for Socksify5.

Provides interfaces and implementations for different authentication methods.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple, Union


class AuthProvider(ABC):
    """Base class for authentication providers."""

    @abstractmethod
    async def authenticate(
        self, *args, **kwargs
    ) -> Union[bool, Tuple[bool, Optional[bytes]]]:
        """Authenticate the user.

        For simple methods like no auth and username/password, returns bool.
        For complex methods like GSSAPI, returns (success: bool, response_token: Optional[bytes]).

        Args:
            *args: Method-specific arguments
            **kwargs: Method-specific keyword arguments

        Returns:
            For simple auth: True if authentication successful, False otherwise
            For token-based auth: (success, response_token) where response_token is sent back to client
        """
        pass

    @property
    @abstractmethod
    def method(self) -> int:
        """Return the SOCKS5 authentication method code."""
        pass


class NoAuthProvider(AuthProvider):
    """No authentication provider."""

    async def authenticate(self, *args, **kwargs) -> bool:
        return True

    @property
    def method(self) -> int:
        return 0x00  # NO AUTHENTICATION REQUIRED


class UsernamePasswordProvider(AuthProvider):
    """Username/password authentication provider."""

    def __init__(self, credentials: dict[str, str]):
        """Initialize with a dict of username -> password."""
        self.credentials = credentials

    async def authenticate(
        self, username: Optional[str] = None, password: Optional[str] = None, **kwargs
    ) -> bool:
        if username is None or password is None:
            return False
        return self.credentials.get(username) == password

    @property
    def method(self) -> int:
        return 0x02  # USERNAME/PASSWORD


class GSSAPIProvider(AuthProvider):
    """GSSAPI authentication provider.

    Implements RFC 1961 GSSAPI authentication for SOCKS5.
    This is a basic implementation that can be extended with real GSSAPI/Kerberos support.
    """

    def __init__(self, service_name: str = "SOCKS5"):
        """Initialize GSSAPI provider.

        Args:
            service_name: The service name for GSSAPI authentication
        """
        self.service_name = service_name
        # In a real implementation, this would initialize GSSAPI context
        self._contexts = {}  # Mock context storage

    async def authenticate(
        self, token: Optional[bytes] = None, **kwargs
    ) -> Tuple[bool, Optional[bytes]]:
        """Perform GSSAPI authentication token exchange.

        Args:
            token: Client GSSAPI token

        Returns:
            (success, response_token) where response_token is sent back to client
        """
        if token is None:
            # Initial client token expected
            return False, None

        try:
            # Parse GSSAPI token (simplified - real implementation would use gssapi library)
            # RFC 1961 token format: [message type][token data]

            if len(token) < 1:
                return False, None

            message_type = token[0]

            if message_type == 0x01:  # GSSAPI_INIT
                # Client initial token
                # In real GSSAPI, we would:
                # 1. Accept security context
                # 2. Process client token
                # 3. Generate response token

                # For this mock implementation, we'll accept any valid-looking token
                if len(token) > 1:
                    # Generate a mock response token
                    # In reality, this would be a proper GSSAPI response
                    response_token = bytes([0x02]) + b"mock_gssapi_response"
                    return True, response_token
                else:
                    return False, None

            # GSSAPI_CONTINUE (not used in basic SOCKS5)
            elif message_type == 0x02:
                return False, None

            elif message_type == 0xFF:  # GSSAPI_ABORT
                return False, None

            else:
                return False, None

        except Exception:
            return False, None

    @property
    def method(self) -> int:
        return 0x01  # GSSAPI
