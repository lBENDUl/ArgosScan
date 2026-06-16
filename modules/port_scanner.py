import logging
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("argosScan.port_scanner")


# ─────────────────────────────────────────────────────────────
# Well-known service names  (IANA + common additions)
# ─────────────────────────────────────────────────────────────
_SERVICE_NAMES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "domain", 67: "dhcps", 68: "dhcpc",
    69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer",
    587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 2049: "nfs",
    2121: "ftp-alt", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "ppp", 3306: "mysql",
    3389: "ms-wbt-server", 4369: "epmd", 5000: "upnp",
    5432: "postgresql", 5900: "vnc", 5985: "wsman",
    5986: "wsmans", 6379: "redis", 6443: "sun-sr-https",
    7001: "afs3-callback", 8000: "http-alt", 8080: "http-proxy",
    8081: "tproxy", 8443: "https-alt", 8888: "sun-answerbook",
    9000: "cslistener", 9090: "zeus-admin", 9092: "xmpp-client",
    9200: "wap-wsp", 9300: "vrace", 10250: "kubelets",
    11211: "memcache", 15672: "amqp-mgmt", 27017: "mongod",
    27018: "mongod-shard", 28017: "mongod-http", 50070: "hdfs",
}

# Top-100 ports by scan frequency (similar to nmap's --top-ports 100)
_TOP_100_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 500, 514, 515, 543, 544, 548, 554,
    587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1080, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    6666, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999,
    10000, 10001, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
    11211, 27017, 6379, 5985, 9200,
]

# Preset: (workers, timeout_seconds)
_PRESETS: Dict[str, Tuple[int, float]] = {
    "fast":     (200, 0.5),
    "normal":   (100, 1.0),
    "thorough": ( 50, 2.0),
}


# ─────────────────────────────────────────────────────────────
# Banner probes
# ─────────────────────────────────────────────────────────────
_PROBES: Dict[int, bytes] = {
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    21:   b"",          # FTP sends banner first
    22:   b"",          # SSH sends banner first
    25:   b"EHLO argosscan\r\n",
    110:  b"",
    143:  b"",
    3306: b"",          # MySQL sends handshake first
    5432: b"",          # PostgreSQL handshake
    6379: b"INFO server\r\n",
    27017: b"\x41\x00\x00\x00\x3a\x00\x00\x00\x00\x00\x00\x00"  # MongoDB OP_QUERY
            b"\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00"
            b"\x15\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
}


class PortScannerError(Exception):
    """Raised when a port scan fails."""


class PortScanner:
    """
    Pure-Python TCP connect scanner.

    Scan presets
    ------------
    fast      200 workers, 0.5s timeout, scans top-100 common ports
    normal    100 workers, 1.0s timeout, user-defined range (default 1-10000)
    thorough   50 workers, 2.0s timeout, user-defined range
    """

    def __init__(self, target: str, ports: str = "1-10000", speed: str = "normal"):
        """
        Args:
            target: Hostname or IP address.
            ports:  Port range / list (e.g. "22,80,443" or "1-1024").
                    Ignored when speed == 'fast' (uses top-100 list).
            speed:  One of 'fast', 'normal', 'thorough'.
        """
        self.target = target
        self.ports = ports
        self.speed = speed if speed in _PRESETS else "normal"

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def scan(self) -> List[Dict]:
        """
        Execute the port scan.

        Returns:
            List of open-port dicts sorted by port number.

        Raises:
            PortScannerError: If the target cannot be resolved.
        """
        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            raise PortScannerError(f"Cannot resolve '{self.target}': {exc}") from exc

        port_list = self._build_port_list()
        workers, timeout = _PRESETS[self.speed]

        logger.info(
            f"TCP connect scan → {self.target} ({ip}), "
            f"{len(port_list)} ports, {workers} workers, timeout={timeout}s"
        )

        open_ports: List[Dict] = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._probe_port, ip, port, timeout): port
                for port in port_list
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        logger.info(f"Scan complete: {len(open_ports)} open port(s)")
        return open_ports

    # ──────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────

    def _build_port_list(self) -> List[int]:
        """Return the list of ports to scan based on speed and port spec."""
        if self.speed == "fast":
            return _TOP_100_PORTS

        ports: List[int] = []
        for part in self.ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

        # Deduplicate, sort, and clamp to valid range
        return sorted(set(p for p in ports if 1 <= p <= 65535))

    def _probe_port(self, ip: str, port: int, timeout: float) -> Optional[Dict]:
        """
        Attempt a TCP connection to ip:port.

        Returns a port-info dict if the port is open, None otherwise.
        The dict schema mirrors the former nmap output so downstream
        modules need zero changes.
        """
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                banner = self._grab_banner(sock, port, timeout)
        except (OSError, socket.timeout, ConnectionRefusedError):
            return None

        service_name = _SERVICE_NAMES.get(port, "unknown")
        product, version = self._parse_banner(banner, port)

        return {
            "port":      port,
            "protocol":  "tcp",
            "state":     "open",
            "name":      service_name,
            "product":   product,
            "version":   version,
            "extrainfo": banner[:120] if banner else "",
            "cpe":       "",
        }

    @staticmethod
    def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
        """Send a service probe and read the response banner."""
        sock.settimeout(timeout)
        probe = _PROBES.get(port, b"")

        try:
            if probe:
                sock.sendall(probe)
            raw = sock.recv(2048)
            return raw.decode("utf-8", errors="ignore").strip()
        except (OSError, socket.timeout):
            return ""

    @staticmethod
    def _parse_banner(banner: str, port: int) -> Tuple[str, str]:
        """
        Extract (product, version) from a raw banner string.

        Returns empty strings when nothing useful can be extracted.
        """
        if not banner:
            return "", ""

        banner_lower = banner.lower()

        # SSH:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 3:
                software = parts[2].split()[0]   # e.g. OpenSSH_8.9p1
                name_ver = software.split("_", 1)
                product = name_ver[0]
                version = name_ver[1] if len(name_ver) > 1 else ""
                return product, version
            return "SSH", ""

        # HTTP:  "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n..."
        if "server:" in banner_lower:
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    srv = line.split(":", 1)[1].strip()
                    parts = srv.split("/", 1)
                    product = parts[0].strip()
                    version = parts[1].split()[0] if len(parts) > 1 else ""
                    return product, version

        # FTP:  "220 vsftpd 3.0.5"  or  "220 ProFTPD 1.3.7a"
        if banner.startswith("220") and port == 21:
            tokens = banner.split()
            if len(tokens) >= 3:
                return tokens[1], tokens[2] if len(tokens) > 2 else ""

        # SMTP: "220 mail.example.com ESMTP Postfix"
        if banner.startswith("220") and port == 25:
            tokens = banner.split()
            if len(tokens) >= 4:
                return tokens[3], ""

        # MySQL: first byte(s) encode protocol version; readable product
        if port == 3306 and len(banner) > 5 and "mysql" in banner_lower:
            # Version string starts around byte 5 in the handshake
            try:
                ver_start = banner.index("\x00") + 1
                ver_end = banner.index("\x00", ver_start)
                version = banner[ver_start:ver_end]
                return "MySQL", version
            except ValueError:
                return "MySQL", ""

        # Redis: "+redis_version:7.0.11"
        if port == 6379 and "redis_version" in banner_lower:
            for line in banner.splitlines():
                if "redis_version" in line.lower():
                    return "Redis", line.split(":", 1)[-1].strip()

        # PostgreSQL sends a binary handshake — just tag the product
        if port == 5432:
            return "PostgreSQL", ""

        return "", ""
