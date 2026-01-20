#!/usr/bin/env python3
"""
WorldPosta Authentication Proxy

RADIUS and LDAP proxy server for two-factor authentication
"""

import argparse
import asyncio
import signal
import sys
import logging
from typing import List

from . import __version__
from .config import load_config, ProxyConfig
from .logging_setup import setup_logging
from .api import WorldPostaClient
from .auth import AuthEngine
from .radius import RADIUSServer
from .ldap import LDAPServer

logger = logging.getLogger(__name__)


class AuthProxy:
    """
    Main authentication proxy application
    """

    def __init__(self, config: ProxyConfig):
        self.config = config
        self.radius_servers: List[RADIUSServer] = []
        self.ldap_servers = []  # TODO: Implement LDAP server
        self.running = False

    async def start(self):
        """Start all configured servers"""
        logger.info(f"WorldPosta Authentication Proxy v{__version__} starting...")

        # Create auth engines and servers for each RADIUS server config
        for name, server_config in self.config.radius_servers.items():
            logger.info(f"Initializing RADIUS server: {name}")

            # Get AD client config if specified
            ad_config = None
            if server_config.client_name:
                ad_config = self.config.ad_clients.get(server_config.client_name)
                if not ad_config:
                    logger.warning(f"AD client '{server_config.client_name}' not found for {name}")

            # Create auth engine
            auth_engine = AuthEngine(
                ad_config=ad_config,
                api_config=self.config.api,
                service_name="VPN Authentication"
            )

            # Create RADIUS server
            radius_server = RADIUSServer(
                config=server_config,
                auth_engine=auth_engine,
                service_name="VPN Authentication"
            )
            self.radius_servers.append(radius_server)

        # Initialize LDAP servers
        for name, server_config in self.config.ldap_servers.items():
            logger.info(f"Initializing LDAP server: {name}")

            # Get AD client config if specified
            ad_config = None
            if server_config.client_name:
                ad_config = self.config.ad_clients.get(server_config.client_name)
                if not ad_config:
                    logger.warning(f"AD client '{server_config.client_name}' not found for {name}")

            # Create LDAP server
            ldap_server = LDAPServer(
                config=server_config,
                ad_config=ad_config,
                api_config=self.config.api,
                service_name="LDAP Authentication"
            )
            self.ldap_servers.append(ldap_server)

        self.running = True

        # Start LDAP servers (Twisted-based, runs in thread)
        if self.ldap_servers:
            import threading
            from twisted.internet import reactor as twisted_reactor

            def run_twisted():
                for server in self.ldap_servers:
                    server.start()
                twisted_reactor.run(installSignalHandlers=False)

            self._twisted_thread = threading.Thread(target=run_twisted, daemon=True)
            self._twisted_thread.start()
            logger.info("LDAP servers started in background thread")

        # Start all RADIUS servers
        tasks = []
        for server in self.radius_servers:
            tasks.append(asyncio.create_task(server.start()))

        # Wait for all RADIUS servers
        if tasks:
            await asyncio.gather(*tasks)

    async def stop(self):
        """Stop all servers"""
        logger.info("Stopping authentication proxy...")
        self.running = False

        # Stop RADIUS servers
        for server in self.radius_servers:
            await server.stop()

        # Stop LDAP servers (Twisted reactor)
        if self.ldap_servers:
            from twisted.internet import reactor as twisted_reactor
            twisted_reactor.callFromThread(twisted_reactor.stop)

        # Close auth engine connections
        for server in self.radius_servers:
            await server.auth_engine.close()

        logger.info("Authentication proxy stopped")


def setup_signal_handlers(proxy: AuthProxy, loop: asyncio.AbstractEventLoop):
    """Setup signal handlers for graceful shutdown"""

    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(proxy.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WorldPosta Authentication Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Use default config location
  %(prog)s -c /path/to/cfg      # Specify config file
  %(prog)s --debug              # Enable debug logging
  %(prog)s --test-config        # Validate configuration and exit
"""
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default=None
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--test-config",
        action="store_true",
        help="Validate configuration and exit"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    setup_logging(
        log_level=config.main.log_level,
        log_file=config.main.log_file,
        debug=args.debug
    )

    # Test config mode
    if args.test_config:
        logger.info("Configuration is valid")
        print("Configuration is valid")

        # Print summary
        print(f"\nAPI Endpoint: {config.api.endpoint}")
        print(f"Integration Key: {config.api.integration_key[:20]}...")
        print(f"\nRADIUS Servers:")
        for name, srv in config.radius_servers.items():
            print(f"  - {name}: port {srv.port}, {len(srv.clients)} clients")
        print(f"\nLDAP Servers:")
        for name, srv in config.ldap_servers.items():
            print(f"  - {name}: port {srv.port}")
        print(f"\nAD Clients:")
        for name, cli in config.ad_clients.items():
            print(f"  - {name}: {cli.host}:{cli.port}")

        sys.exit(0)

    # Create and run proxy
    proxy = AuthProxy(config)

    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Setup signal handlers
    setup_signal_handlers(proxy, loop)

    # Run proxy
    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        loop.run_until_complete(proxy.stop())
        loop.close()


if __name__ == "__main__":
    main()
