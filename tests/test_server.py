"""
Tests for Socksify5 server.
"""

import asyncio
import pytest
from socksify5 import Socks5Server, NoAuthProvider, UsernamePasswordProvider


class TestSocks5Server:
    """Test cases for Socks5Server."""

    @pytest.mark.asyncio
    async def test_server_creation(self):
        """Test server can be created."""
        server = Socks5Server()
        assert server is not None
        assert server.bind_address == "0.0.0.0"
        assert server.bind_port == 1080

    @pytest.mark.asyncio
    async def test_no_auth_provider(self):
        """Test no auth provider."""
        provider = NoAuthProvider()
        assert provider.method == 0x00
        assert await provider.authenticate() is True

    @pytest.mark.asyncio
    async def test_username_password_provider(self):
        """Test username/password provider."""
        provider = UsernamePasswordProvider({"user": "pass"})
        assert provider.method == 0x02

        # Valid credentials
        assert await provider.authenticate("user", "pass") is True

        # Invalid credentials
        assert await provider.authenticate("user", "wrong") is False
        assert await provider.authenticate("wrong", "pass") is False
        assert await provider.authenticate(None, None) is False

    @pytest.mark.asyncio
    async def test_server_start_stop(self):
        """Test server start and stop."""
        server = Socks5Server()

        # Start server
        await server.start()
        assert server._running is True

        # Stop server
        await server.stop()
        assert server._running is False

    @pytest.mark.asyncio
    async def test_events(self):
        """Test event system."""
        server = Socks5Server()
        events_received = []

        def test_handler(*args):
            events_received.append(args)

        server.events.on("test_event", test_handler)
        server.events.emit("test_event", "arg1", "arg2")

        # Allow async event to fire
        await asyncio.sleep(0.01)
        assert len(events_received) == 1
        assert events_received[0] == ("arg1", "arg2")
