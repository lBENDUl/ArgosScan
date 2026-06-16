"""
ArgosScan - Target validation
"""

import re
import ipaddress


def validate_target(target: str) -> bool:
    """
    Validate scan target. Accepts:
      - IPv4 addresses (e.g. 192.168.1.1)
      - IPv4 CIDR ranges (e.g. 192.168.1.0/24)
      - Hostnames / FQDNs (e.g. example.com, sub.example.co.uk)
      - localhost

    Args:
        target: The target string provided by the user.

    Returns:
        True if valid, False otherwise.
    """
    if not target or not isinstance(target, str):
        return False

    target = target.strip()

    # localhost shorthand
    if target.lower() == "localhost":
        return True

    # IPv4 or CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Hostname / FQDN
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    if hostname_pattern.match(target):
        return True

    return False
