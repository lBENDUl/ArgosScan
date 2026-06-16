"""
ArgosScan - SSL/TLS Analyzer
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("argosScan.ssl_analyzer")

# TLS versions considered weak
_WEAK_TLS = {ssl.TLSVersion.SSLv3, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}  # type: ignore[attr-defined]

# Days before expiry to warn
_EXPIRY_WARN_DAYS = 30


class SSLAnalyzer:
    """
    Checks SSL/TLS configuration on a given host:port and returns a
    structured dict with findings and severity-tagged issues.
    """

    def __init__(self, target: str, port: int = 443, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout

    def analyze(self) -> Dict:
        """
        Run the full SSL/TLS analysis.

        Returns:
            Dict with keys: target, port, certificate, tls_version, issues.
        """
        result: Dict = {
            "target": self.target,
            "port": self.port,
            "certificate": None,
            "tls_version": None,
            "issues": [],
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target, self.port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as tls:
                    result["tls_version"] = tls.version()
                    # getpeercert() returns {} when CERT_NONE; use binary form instead
                    cert_bin = tls.getpeercert(binary_form=True)
                    cipher = tls.cipher()

            if cert_bin:
                try:
                    import ssl as _ssl
                    # Re-decode the DER cert using a context that accepts it
                    cert = ssl.DER_cert_to_PEM_cert(cert_bin)
                    # Parse via a temporary SSLSocket trick — use x509 info from binary
                    # Fallback: use cryptography library if available, else parse manually
                    try:
                        from cryptography import x509 as _x509
                        from cryptography.hazmat.backends import default_backend
                        from datetime import timezone as _tz
                        c = _x509.load_der_x509_certificate(cert_bin, default_backend())
                        parsed = {
                            "subject": {k.oid.dotted_string: v for k, v in [
                                (attr, attr.value) for attr in c.subject
                            ]},
                            "issuer": {k.oid.dotted_string: v for k, v in [
                                (attr, attr.value) for attr in c.issuer
                            ]},
                            "not_before": c.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y UTC"),
                            "not_after": c.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y UTC"),
                            "serial_number": str(c.serial_number),
                            "san": [],
                        }
                        try:
                            san_ext = c.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
                            parsed["san"] = san_ext.value.get_values_for_type(_x509.DNSName)
                        except Exception:
                            pass
                        # Friendly subject/issuer
                        parsed["subject"] = {attr.rfc4514_attribute_name: attr.value for attr in c.subject}
                        parsed["issuer"] = {attr.rfc4514_attribute_name: attr.value for attr in c.issuer}
                        result["certificate"] = parsed
                        result["issues"] += self._check_cert(parsed)
                    except ImportError:
                        # cryptography not installed — do a minimal parse via openssl ctx trick
                        # Re-connect with CERT_REQUIRED to get structured dict (may fail for self-signed)
                        try:
                            ctx2 = ssl.create_default_context()
                            ctx2.check_hostname = False
                            ctx2.verify_mode = ssl.CERT_REQUIRED
                            ctx2.load_default_certs()
                            with socket.create_connection((self.target, self.port), timeout=self.timeout) as raw2:
                                with ctx2.wrap_socket(raw2, server_hostname=self.target) as tls2:
                                    cert2 = tls2.getpeercert()
                            if cert2:
                                result["certificate"] = self._parse_cert(cert2)
                                result["issues"] += self._check_cert(result["certificate"])
                        except Exception:
                            result["certificate"] = {"note": "Certificate present but could not be fully parsed (install 'cryptography' package for details)"}
                except Exception as parse_exc:
                    logger.debug(f"Certificate parse error: {parse_exc}")
                    result["certificate"] = {"note": "Certificate present but parsing failed"}

            if result["tls_version"]:
                result["issues"] += self._check_tls_version(result["tls_version"])

            if cipher:
                result["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
                result["issues"] += self._check_cipher(cipher[0])

        except ssl.SSLError as exc:
            logger.warning(f"SSL error on {self.target}:{self.port}: {exc}")
            result["issues"].append({"severity": "HIGH", "issue": f"SSL handshake failed: {exc}"})
        except OSError as exc:
            logger.warning(f"Connection error on {self.target}:{self.port}: {exc}")
            result["issues"].append(
                {"severity": "INFO", "issue": f"Could not connect to {self.target}:{self.port} — port may be closed or not serving SSL/TLS."}
            )

        return result

    # ------------------------------------------------------------------
    # Parsers & checks
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_cert(cert: Dict) -> Dict:
        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "version": cert.get("version"),
            "serial_number": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [v for _, v in cert.get("subjectAltName", [])],
        }

    def _check_cert(self, cert: Dict) -> List[Dict]:
        issues: List[Dict] = []

        not_after = cert.get("not_after")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(timezone.utc)
                delta = (expiry - now).days

                if delta < 0:
                    issues.append(
                        {"severity": "CRITICAL", "issue": f"Certificate EXPIRED {abs(delta)} day(s) ago."}
                    )
                elif delta <= _EXPIRY_WARN_DAYS:
                    issues.append(
                        {"severity": "MEDIUM", "issue": f"Certificate expires in {delta} day(s)."}
                    )
            except ValueError:
                pass

        # Self-signed check
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        if subject and subject == issuer:
            issues.append({"severity": "MEDIUM", "issue": "Self-signed certificate detected."})

        return issues

    @staticmethod
    def _check_tls_version(version_str: str) -> List[Dict]:
        """Flag deprecated TLS/SSL protocol versions."""
        issues: List[Dict] = []
        # Only SSLv2, SSLv3, TLSv1.0 and TLSv1.1 are weak.
        # TLSv1.2 and TLSv1.3 are secure — do NOT flag them.
        weak = {"SSLv2", "SSLv3", "TLSv1 ", "TLSv1.1"}
        # Use exact matching to avoid "TLSv1.3".startswith("TLSv1") false-positives
        version_is_weak = (
            version_str in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
            or version_str.startswith("SSL")
        )
        if version_is_weak:
            issues.append(
                {
                    "severity": "HIGH",
                    "issue": f"Weak/deprecated protocol in use: {version_str}. Upgrade to TLS 1.2+.",
                }
            )
        return issues

    @staticmethod
    def _check_cipher(cipher_name: str) -> List[Dict]:
        """Flag known-weak cipher suites."""
        issues: List[Dict] = []
        weak_patterns = ("RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5")
        for pattern in weak_patterns:
            if pattern in cipher_name.upper():
                issues.append(
                    {
                        "severity": "HIGH",
                        "issue": f"Weak cipher suite detected: {cipher_name}",
                    }
                )
                break
        return issues
