"""
SOCKS5 server implementation for Socksify5.

Implements RFC 1928 and RFC 1929 compliant SOCKS5 proxy server.
"""

import asyncio
import socket
import struct
import ipaddress
from typing import Callable, Optional, Tuple, List
from .auth import AuthProvider, NoAuthProvider
from .events import EventEmitter


class Socks5Server:
    """SOCKS5 proxy server implementation."""

    def __init__(
        self,
        auth_providers: Optional[List[AuthProvider]] = None,
        filter_func: Optional[Callable[[str, int, str, int], bool]] = None,
        idle_timeout: float = 300.0,
        bind_address: str = "0.0.0.0",
        bind_port: int = 1080,
    ):
        """Initialize the SOCKS5 server.

        Args:
            auth_providers: List of authentication providers to support
            filter_func: Function to filter connections (origin_addr, origin_port, dest_addr, dest_port) -> bool
            idle_timeout: Idle timeout in seconds for connections
            bind_address: Address to bind the server to
            bind_port: Port to bind the server to
        """
        self.auth_providers = auth_providers or [NoAuthProvider()]
        self.filter_func = filter_func
        self.idle_timeout = idle_timeout
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.events = EventEmitter()
        self._server = None
        self._running = False

    async def start(self) -> None:
        """Start the SOCKS5 server."""
        if self._running:
            return

        self._server = await asyncio.start_server(
            self._handle_connection, self.bind_address, self.bind_port
        )
        self._running = True
        print(f"SOCKS5 server listening on {self.bind_address}:{self.bind_port}")

    async def stop(self) -> None:
        """Stop the SOCKS5 server."""
        if not self._running:
            return

        self._server.close()
        await self._server.wait_closed()
        self._running = False
        print("SOCKS5 server stopped")

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        client_addr = writer.get_extra_info("peername")
        if client_addr:
            client_ip, client_port = client_addr[0], client_addr[1]
        else:
            client_ip, client_port = "unknown", 0

        self.events.emit("handshake", client_ip, client_port)

        try:
            # SOCKS5 handshake
            auth_method = await self._negotiate_auth(reader, writer)
            if auth_method is None:
                return  # Failed negotiation

            # Authentication if needed
            if auth_method != 0x00:
                if not await self._authenticate(reader, writer, auth_method):
                    return  # Auth failed

            # Handle CONNECT request
            await self._handle_connect(reader, writer, client_ip, client_port)

        except Exception as e:
            self.events.emit("error", e, client_ip, client_port)
        finally:
            writer.close()
            await writer.wait_closed()
            self.events.emit("disconnect", client_ip, client_port)

    async def _negotiate_auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[int]:
        """Negotiate authentication method."""
        try:
            # Read version, nmethods, methods
            header = await asyncio.wait_for(
                reader.readexactly(2), timeout=self.idle_timeout
            )
            version, nmethods = struct.unpack("!BB", header)
            if version != 5:
                return None

            methods = await asyncio.wait_for(
                reader.readexactly(nmethods), timeout=self.idle_timeout
            )

            # Choose the best method we support
            chosen_method = None
            for method in methods:
                for provider in self.auth_providers:
                    if provider.method == method:
                        chosen_method = method
                        break
                if chosen_method is not None:
                    break

            if chosen_method is None:
                # No acceptable method
                writer.write(struct.pack("!BB", 5, 0xFF))
                await writer.drain()
                return None

            # Send response
            writer.write(struct.pack("!BB", 5, chosen_method))
            await writer.drain()
            return chosen_method

        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    async def _authenticate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: int
    ) -> bool:
        """Perform authentication."""
        provider = None
        for p in self.auth_providers:
            if p.method == method:
                provider = p
                break

        if not provider:
            return False

        if method == 0x02:  # Username/password
            try:
                # Read auth version
                auth_ver = await asyncio.wait_for(
                    reader.readexactly(1), timeout=self.idle_timeout
                )
                if auth_ver[0] != 1:
                    return False

                # Read username
                ulen = await asyncio.wait_for(
                    reader.readexactly(1), timeout=self.idle_timeout
                )
                ulen = ulen[0]
                username = (
                    await asyncio.wait_for(
                        reader.readexactly(ulen), timeout=self.idle_timeout
                    )
                ).decode("utf-8")

                # Read password
                plen = await asyncio.wait_for(
                    reader.readexactly(1), timeout=self.idle_timeout
                )
                plen = plen[0]
                password = (
                    await asyncio.wait_for(
                        reader.readexactly(plen), timeout=self.idle_timeout
                    )
                ).decode("utf-8")

                # Authenticate
                success = await provider.authenticate(username, password)
                if success:
                    self.events.emit("authenticate", username)
                else:
                    self.events.emit("authenticate_error", username)

                # Send response
                writer.write(struct.pack("!BB", 1, 0 if success else 1))
                await writer.drain()
                return success

            except asyncio.TimeoutError:
                return False
            except Exception:
                return False

        elif method == 0x01:  # GSSAPI
            try:
                # GSSAPI token exchange (RFC 1961)
                # Read initial token from client
                token_len_bytes = await asyncio.wait_for(
                    reader.readexactly(2), timeout=self.idle_timeout
                )
                token_len = struct.unpack("!H", token_len_bytes)[0]

                if token_len > 0:
                    token = await asyncio.wait_for(
                        reader.readexactly(token_len), timeout=self.idle_timeout
                    )
                else:
                    token = b""

                # Authenticate with token
                result = await provider.authenticate(token=token)
                if isinstance(result, tuple):
                    success, response_token = result
                else:
                    success, response_token = result, None

                if success:
                    self.events.emit("authenticate", "GSSAPI")
                else:
                    self.events.emit("authenticate_error", "GSSAPI")

                # Send response
                if response_token:
                    response_len = len(response_token)
                    writer.write(struct.pack("!H", response_len) + response_token)
                else:
                    writer.write(struct.pack("!H", 0))
                await writer.drain()

                return success

            except asyncio.TimeoutError:
                return False
            except Exception:
                return False

        return False

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int,
    ) -> None:
        """Handle CONNECT command."""
        try:
            # Read request: ver, cmd, rsv, atyp
            header = await asyncio.wait_for(
                reader.readexactly(4), timeout=self.idle_timeout
            )
            ver, cmd, rsv, atyp = struct.unpack("!BBBB", header)
            if ver != 5 or cmd != 1:  # Only CONNECT supported
                await self._send_reply(writer, 0x07)  # Command not supported
                return

            # Read address
            dest_addr, dest_port = await self._read_address(reader, atyp)
            if dest_addr is None:
                # Address type not supported
                await self._send_reply(writer, 0x08)
                return

            # Check filter
            if self.filter_func and not self.filter_func(
                client_ip, client_port, dest_addr, dest_port
            ):
                await self._send_reply(writer, 0x02)  # Connection not allowed
                return

            # Connect to destination
            try:
                dest_reader, dest_writer = await asyncio.wait_for(
                    asyncio.open_connection(dest_addr, dest_port),
                    timeout=10.0,  # Connection timeout
                )
            except Exception:
                await self._send_reply(writer, 0x04)  # Host unreachable
                return

            # Get bound address
            bound_addr = dest_writer.get_extra_info("sockname")
            if bound_addr:
                bound_ip, bound_port = bound_addr[0], bound_addr[1]
            else:
                bound_ip, bound_port = "0.0.0.0", 0

            # Send success reply
            await self._send_reply(writer, 0x00, bound_ip, bound_port)

            self.events.emit(
                "proxy_connect", (client_ip, client_port), (dest_addr, dest_port)
            )

            # Proxy data
            await self._proxy_data(
                reader,
                writer,
                dest_reader,
                dest_writer,
                client_ip,
                client_port,
                dest_addr,
                dest_port,
            )

        except asyncio.TimeoutError:
            await self._send_reply(writer, 0x06)  # TTL expired
        except Exception as e:
            self.events.emit(
                "proxy_error", e, client_ip, client_port, dest_addr, dest_port
            )
            await self._send_reply(writer, 0x01)  # General failure

    async def _read_address(
        self, reader: asyncio.StreamReader, atyp: int
    ) -> Tuple[Optional[str], Optional[int]]:
        """Read address from stream."""
        try:
            if atyp == 1:  # IPv4
                addr_bytes = await asyncio.wait_for(
                    reader.readexactly(4), timeout=self.idle_timeout
                )
                addr = socket.inet_ntoa(addr_bytes)
            elif atyp == 4:  # IPv6
                addr_bytes = await asyncio.wait_for(
                    reader.readexactly(16), timeout=self.idle_timeout
                )
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            elif atyp == 3:  # Domain name
                len_byte = await asyncio.wait_for(
                    reader.readexactly(1), timeout=self.idle_timeout
                )
                addr_len = len_byte[0]
                addr_bytes = await asyncio.wait_for(
                    reader.readexactly(addr_len), timeout=self.idle_timeout
                )
                addr = addr_bytes.decode("utf-8")
            else:
                return None, None

            port_bytes = await asyncio.wait_for(
                reader.readexactly(2), timeout=self.idle_timeout
            )
            port = struct.unpack("!H", port_bytes)[0]

            return addr, port
        except Exception:
            return None, None

    async def _send_reply(
        self,
        writer: asyncio.StreamWriter,
        rep: int,
        bound_addr: str = "0.0.0.0",
        bound_port: int = 0,
    ) -> None:
        """Send reply to client."""
        try:
            # Determine address type
            try:
                ipaddress.ip_address(bound_addr)
                if ":" in bound_addr:
                    atyp = 4  # IPv6
                    addr_bytes = socket.inet_pton(socket.AF_INET6, bound_addr)
                else:
                    atyp = 1  # IPv4
                    addr_bytes = socket.inet_aton(bound_addr)
            except ValueError:
                # Domain name
                atyp = 3
                addr_bytes = bytes([len(bound_addr)]) + bound_addr.encode("utf-8")

            port_bytes = struct.pack("!H", bound_port)
            reply = struct.pack("!BBBB", 5, rep, 0, atyp) + addr_bytes + port_bytes
            writer.write(reply)
            await writer.drain()
        except Exception:
            pass  # Ignore send errors

    async def _proxy_data(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        dest_reader: asyncio.StreamReader,
        dest_writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int,
        dest_addr: str,
        dest_port: int,
    ) -> None:
        """Proxy data between client and destination."""
        try:
            # Create tasks for bidirectional copying
            client_to_dest = asyncio.create_task(
                self._copy_with_timeout(client_reader, dest_writer, "client_to_dest")
            )
            dest_to_client = asyncio.create_task(
                self._copy_with_timeout(dest_reader, client_writer, "dest_to_client")
            )

            # Wait for either to finish or timeout
            done, pending = await asyncio.wait(
                [client_to_dest, dest_to_client],
                timeout=self.idle_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Check for errors
            for task in done:
                if not task.cancelled():
                    try:
                        result = task.result()
                        if isinstance(result, Exception):
                            raise result
                    except Exception as e:
                        raise e

        except Exception as e:
            self.events.emit(
                "proxy_error", e, client_ip, client_port, dest_addr, dest_port
            )
        finally:
            # Close destination connection
            dest_writer.close()
            await dest_writer.wait_closed()
            self.events.emit(
                "proxy_disconnect", (client_ip, client_port), (dest_addr, dest_port)
            )

    async def _copy_with_timeout(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, direction: str
    ) -> None:
        """Copy data with idle timeout."""
        try:
            while True:
                data = await asyncio.wait_for(
                    reader.read(8192), timeout=self.idle_timeout
                )
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                self.events.emit("proxy_data", direction, len(data))
        except asyncio.TimeoutError:
            raise Exception(f"Idle timeout on {direction}")
        except Exception as e:
            raise e
