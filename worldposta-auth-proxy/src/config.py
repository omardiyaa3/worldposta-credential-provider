"""
WorldPosta Authentication Proxy - Configuration Parser
Parses INI-style configuration file similar to Duo's authproxy.cfg
"""

import os
import configparser
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATHS = [
    "/etc/worldposta/authproxy.cfg",
    "/opt/worldposta/conf/authproxy.cfg",
    "./authproxy.cfg",
]


@dataclass
class WorldPostaAPIConfig:
    """WorldPosta API configuration"""
    endpoint: str = "https://api.worldposta.com"
    integration_key: str = ""
    secret_key: str = ""
    push_timeout: int = 60


@dataclass
class ADClientConfig:
    """Active Directory / LDAP client configuration"""
    name: str = ""
    host: str = ""
    port: int = 389
    use_ssl: bool = False
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    search_filter: str = "(sAMAccountName={username})"
    search_attribute: str = "sAMAccountName"


@dataclass
class RADIUSClient:
    """RADIUS client (NAS) configuration"""
    ip: str = ""
    secret: str = ""


@dataclass
class RADIUSServerConfig:
    """RADIUS server configuration"""
    name: str = ""
    port: int = 1812
    client_name: str = ""  # Reference to ad_client or radius_client
    mode: str = "auto"  # auto, concat, challenge
    clients: List[RADIUSClient] = field(default_factory=list)
    fail_open: bool = False


@dataclass
class LDAPServerConfig:
    """LDAP server configuration"""
    name: str = ""
    port: int = 389
    ssl_port: int = 636
    use_ssl: bool = False
    ssl_cert: str = ""
    ssl_key: str = ""
    client_name: str = ""  # Reference to ad_client


@dataclass
class MainConfig:
    """Main configuration"""
    log_level: str = "INFO"
    log_file: str = "/var/log/worldposta/authproxy.log"
    debug: bool = False


@dataclass
class ProxyConfig:
    """Complete proxy configuration"""
    main: MainConfig = field(default_factory=MainConfig)
    api: WorldPostaAPIConfig = field(default_factory=WorldPostaAPIConfig)
    ad_clients: Dict[str, ADClientConfig] = field(default_factory=dict)
    radius_servers: Dict[str, RADIUSServerConfig] = field(default_factory=dict)
    ldap_servers: Dict[str, LDAPServerConfig] = field(default_factory=dict)


class ConfigParser:
    """Parse authproxy.cfg configuration file"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self.config = ProxyConfig()

    def _find_config(self) -> str:
        """Find configuration file in default locations"""
        for path in DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                return path
        raise FileNotFoundError(
            f"Configuration file not found. Searched: {DEFAULT_CONFIG_PATHS}"
        )

    def parse(self) -> ProxyConfig:
        """Parse configuration file and return ProxyConfig"""
        parser = configparser.ConfigParser()
        parser.read(self.config_path)

        logger.info(f"Loading configuration from {self.config_path}")

        for section in parser.sections():
            self._parse_section(section, dict(parser[section]))

        self._validate_config()
        return self.config

    def _parse_section(self, section: str, options: Dict[str, str]):
        """Parse a configuration section"""

        if section == "main":
            self._parse_main(options)
        elif section == "worldposta_api":
            self._parse_api(options)
        elif section.startswith("ad_client"):
            self._parse_ad_client(section, options)
        elif section.startswith("radius_server"):
            self._parse_radius_server(section, options)
        elif section.startswith("ldap_server"):
            self._parse_ldap_server(section, options)
        else:
            logger.warning(f"Unknown configuration section: {section}")

    def _parse_main(self, options: Dict[str, str]):
        """Parse [main] section"""
        self.config.main.log_level = options.get("log_level", "INFO").upper()
        self.config.main.log_file = options.get("log_file", "/var/log/worldposta/authproxy.log")
        self.config.main.debug = options.get("debug", "false").lower() == "true"

    def _parse_api(self, options: Dict[str, str]):
        """Parse [worldposta_api] section"""
        self.config.api.endpoint = options.get("endpoint", "https://api.worldposta.com")
        self.config.api.integration_key = options.get("integration_key", "")
        self.config.api.secret_key = options.get("secret_key", "")
        self.config.api.push_timeout = int(options.get("push_timeout", "60"))

    def _parse_ad_client(self, section: str, options: Dict[str, str]):
        """Parse [ad_client] section"""
        client = ADClientConfig()
        client.name = section
        client.host = options.get("host", "")
        client.port = int(options.get("port", "389"))
        client.use_ssl = options.get("use_ssl", "false").lower() == "true"
        client.base_dn = options.get("base_dn", "")
        client.bind_dn = options.get("bind_dn", "")
        client.bind_password = options.get("bind_password", "")
        client.search_filter = options.get("search_filter", "(sAMAccountName={username})")
        client.search_attribute = options.get("search_attribute", "sAMAccountName")

        self.config.ad_clients[section] = client

    def _parse_radius_server(self, section: str, options: Dict[str, str]):
        """Parse [radius_server_*] section"""
        server = RADIUSServerConfig()
        server.name = section
        server.port = int(options.get("port", "1812"))
        server.client_name = options.get("client", "")
        server.fail_open = options.get("fail_open", "false").lower() == "true"

        # Determine mode from section name
        if "_auto" in section:
            server.mode = "auto"
        elif "_concat" in section:
            server.mode = "concat"
        elif "_challenge" in section:
            server.mode = "challenge"

        # Parse RADIUS clients (radius_ip_1, radius_secret_1, etc.)
        client_index = 1
        while f"radius_ip_{client_index}" in options:
            client = RADIUSClient()
            client.ip = options[f"radius_ip_{client_index}"]
            client.secret = options.get(f"radius_secret_{client_index}", "")
            server.clients.append(client)
            client_index += 1

        self.config.radius_servers[section] = server

    def _parse_ldap_server(self, section: str, options: Dict[str, str]):
        """Parse [ldap_server_*] section"""
        server = LDAPServerConfig()
        server.name = section
        server.port = int(options.get("port", "389"))
        server.ssl_port = int(options.get("ssl_port", "636"))
        server.use_ssl = options.get("use_ssl", "false").lower() == "true"
        server.ssl_cert = options.get("ssl_cert", "")
        server.ssl_key = options.get("ssl_key", "")
        server.client_name = options.get("client", "")

        self.config.ldap_servers[section] = server

    def _validate_config(self):
        """Validate configuration"""
        errors = []

        # Check API config
        if not self.config.api.integration_key:
            errors.append("worldposta_api.integration_key is required")
        if not self.config.api.secret_key:
            errors.append("worldposta_api.secret_key is required")

        # Check that servers reference valid clients
        for name, server in self.config.radius_servers.items():
            if server.client_name and server.client_name not in self.config.ad_clients:
                errors.append(f"{name}.client '{server.client_name}' not found")
            if not server.clients:
                errors.append(f"{name} has no RADIUS clients configured")

        for name, server in self.config.ldap_servers.items():
            if server.client_name and server.client_name not in self.config.ad_clients:
                errors.append(f"{name}.client '{server.client_name}' not found")

        if errors:
            raise ValueError("Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))

        logger.info("Configuration validated successfully")


def load_config(config_path: Optional[str] = None) -> ProxyConfig:
    """Load and parse configuration file"""
    parser = ConfigParser(config_path)
    return parser.parse()
