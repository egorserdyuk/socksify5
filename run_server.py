#!/usr/bin/env python3
"""
Entrypoint script for running the SOCKS5 server with configurable authentication.
"""

import asyncio
import os
from socksify5 import Socks5Server, NoAuthProvider, UsernamePasswordProvider


def main():
    auth_method = os.getenv("AUTH_METHOD", "no_auth").lower()
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    port = int(os.getenv("PORT", "1080"))
    bind_address = os.getenv("BIND_ADDRESS", "0.0.0.0")

    if auth_method == "no_auth":
        auth_providers = [NoAuthProvider()]
    elif auth_method == "username_password":
        if not username or not password:
            raise ValueError(
                "USERNAME and PASSWORD environment variables must be set for username_password auth"
            )
        auth_providers = [UsernamePasswordProvider({username: password})]
    else:
        raise ValueError("AUTH_METHOD must be 'no_auth' or 'username_password'")

    server = Socks5Server(
        auth_providers=auth_providers, bind_port=port, bind_address=bind_address
    )

    async def run_server():
        await server.start()
        try:
            # Keep running until interrupted
            await asyncio.Future()
        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            await server.stop()

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
