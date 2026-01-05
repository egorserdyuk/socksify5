# Socksify5

A Python library for creating SOCKS5 proxy servers compliant with RFC 1928, RFC 1929, and RFC 1961.

## Features

- **RFC 1928, RFC 1929 & RFC 1961 Compliant**: Full SOCKS5 protocol support including authentication
- **Multiple Auth Methods**: No authentication, username/password, and GSSAPI/Kerberos
- **Event-Driven**: Rich event system for monitoring connection lifecycle
- **Connection Filtering**: Configurable access control based on origin/destination
- **Address Support**: IPv4, IPv6, and domain name resolution
- **Timeout Management**: Configurable idle timeouts for connections
- **Async/Await**: Built on asyncio for high performance
- **Pure Python**: No external dependencies

## Installation

```bash
pip install socksify5
```

## Quick Start

```python
import asyncio
from socksify5 import Socks5Server, UsernamePasswordProvider

async def main():
    # Create server with username/password auth
    auth_provider = UsernamePasswordProvider({'user': 'pass'})
    server = Socks5Server(auth_providers=[auth_provider])

    # Listen for events
    server.events.on('handshake', lambda ip, port: print(f"New connection from {ip}:{port}"))
    server.events.on('authenticate', lambda user: print(f"User {user} authenticated"))
    server.events.on('proxy_connect', lambda client, dest: print(f"Proxying {client} -> {dest}"))

    # Start server
    await server.start()

    # Keep running
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        await server.stop()

asyncio.run(main())
```

## API Reference

### Socks5Server

#### Constructor

```python
Socks5Server(
    auth_providers=None,      # List of AuthProvider instances
    filter_func=None,         # Function(client_ip, client_port, dest_ip, dest_port) -> bool
    idle_timeout=300.0,       # Idle timeout in seconds
    bind_address='0.0.0.0',   # Bind address
    bind_port=1080            # Bind port
)
```

#### Methods

- `await start()`: Start the server
- `await stop()`: Stop the server

#### Events

- `handshake(client_ip, client_port)`: New client connection
- `authenticate(username)`: Successful authentication
- `authenticate_error(username)`: Failed authentication
- `proxy_connect(client_info, dest_info)`: Connection established to destination
- `proxy_data(direction, bytes_count)`: Data transferred
- `proxy_error(error, client_ip, client_port, dest_addr, dest_port)`: Connection error
- `proxy_disconnect(client_info, dest_info)`: Connection closed
- `disconnect(client_ip, client_port)`: Client disconnected
- `error(error, client_ip, client_port)`: General error

### Authentication Providers

#### NoAuthProvider

No authentication required.

```python
from socksify5 import NoAuthProvider
auth = NoAuthProvider()
```

#### UsernamePasswordProvider

Username/password authentication.

```python
from socksify5 import UsernamePasswordProvider
auth = UsernamePasswordProvider({'user1': 'pass1', 'user2': 'pass2'})
```

#### GSSAPIProvider

GSSAPI/Kerberos authentication (RFC 1961). This implementation provides a basic framework that can be extended with real GSSAPI/Kerberos support.

```python
from socksify5 import GSSAPIProvider
auth = GSSAPIProvider(service_name='SOCKS5')
```

#### Custom AuthProvider

Implement the `AuthProvider` abstract base class.

```python
from socksify5 import AuthProvider

class MyAuth(AuthProvider):
    async def authenticate(self, username=None, password=None):
        # Your auth logic
        return True

    @property
    def method(self):
        return 0x02  # Custom method code
```

## Connection Filtering

Use the `filter_func` parameter to control which connections are allowed:

```python
def allow_local_only(client_ip, client_port, dest_ip, dest_port):
    return dest_ip.startswith('192.168.') or dest_ip == '127.0.0.1'

server = Socks5Server(filter_func=allow_local_only)
```

## License

MIT License - see LICENSE file for details.

## Author

Egor Serdiuk