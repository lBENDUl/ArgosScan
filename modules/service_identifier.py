"""
ArgosScan - Service Identifier (banner grabbing)
"""

import logging
import socket
import ssl
from typing import Dict, List, Optional

logger = logging.getLogger("argosScan.service_identifier")

# Well-known port → service name fallback
_PORT_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}


class ServiceIdentifier:
    """
    Enriches port scan results with banner-grabbed version strings when
    nmap didn't detect a version.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def identify_batch(self, open_ports: List[Dict], target: str) -> List[Dict]:
        """
        Enrich a list of open ports with service information.

        Args:
            open_ports: Output from PortScanner.scan().
            target:     Hostname / IP to connect to for banner grabbing.

        Returns:
            Enriched list of service dicts.
        """
        services: List[Dict] = []

        for port_info in open_ports:
            service = dict(port_info)

            # Fallback service name from well-known ports
            if service.get("name") in ("", "unknown"):
                service["name"] = _PORT_NAMES.get(service["port"], "unknown")

            # Banner grab only when nmap didn't detect a version
            if not service.get("version") and not service.get("product"):
                banner = self._grab_banner(target, service["port"])
                if banner:
                    service["banner"] = banner
                    logger.debug(f"Banner [{service['port']}]: {banner[:80]}")

            services.append(service)

        return services

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """
        Attempt a raw TCP banner grab, with HTTPS fallback for port 443.

        Returns:
            Banner string or None.
        """
        if port == 443:
            return self._grab_tls_banner(target, port)

        try:
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                # Some services send a banner immediately; others need a probe
                try:
                    data = sock.recv(2048)
                except socket.timeout:
                    # Send an HTTP-like probe as fallback
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(2048)

                banner = data.decode("utf-8", errors="ignore").strip()
                return banner[:256] if banner else None

        except (OSError, socket.timeout):
            return None

    def _grab_tls_banner(self, target: str, port: int) -> Optional[str]:
        """TLS-wrapped banner grab (HTTPS)."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as tls:
                    tls.sendall(b"HEAD / HTTP/1.0\r\nHost: " + target.encode() + b"\r\n\r\n")
                    data = tls.recv(2048)
                    banner = data.decode("utf-8", errors="ignore").strip()
                    return banner[:256] if banner else None
        except (OSError, ssl.SSLError, socket.timeout):
            return None
