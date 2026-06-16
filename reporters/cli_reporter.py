"""
ArgosScan - CLI Reporter
"""

from typing import Dict

# ANSI helpers
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[91m"
_ORANGE = "\033[93m"  # bright yellow looks orange-ish in many terminals
_YELLOW = "\033[33m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_PURPLE = "\033[95m"
_WHITE  = "\033[97m"

_SEV_COLOR = {
    "CRITICAL": _RED,
    "HIGH":     _ORANGE,
    "MEDIUM":   _YELLOW,
    "LOW":      _GREEN,
    "UNKNOWN":  _DIM,
}
_SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}


class CLIReporter:
    """
    Prints a human-readable scan report to stdout using ANSI colours.
    """

    def __init__(self, results: Dict):
        self._r = results

    def print_report(self) -> None:
        self._header()
        self._summary()
        self._open_ports()
        self._vulnerabilities()
        self._ssl()

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self) -> None:
        print()
        print(f"{_PURPLE}{_BOLD}  👁️  ArgosScan{_RESET}")
        print(f"{_DIM}  Target : {self._r['target']}")
        print(f"  Time   : {self._r['timestamp']}")
        print(f"  Ports  : {self._r['scan_params']['ports']}")
        print(f"  Speed  : {self._r['scan_params']['speed']}{_RESET}")
        print()

    def _summary(self) -> None:
        s = self._r["summary"]
        self._section("SUMMARY")
        print(f"  Total vulnerabilities : {_BOLD}{s['total']}{_RESET}")
        print(f"  {_RED}🔴 Critical{_RESET} : {s['critical']}")
        print(f"  {_ORANGE}🟠 High    {_RESET} : {s['high']}")
        print(f"  {_YELLOW}🟡 Medium  {_RESET} : {s['medium']}")
        print(f"  {_GREEN}🟢 Low     {_RESET} : {s['low']}")
        print(f"  Risk Score : {_BOLD}{_PURPLE}{s['risk_score']}/100{_RESET}")
        print()

    def _open_ports(self) -> None:
        ports = self._r.get("open_ports", [])
        if not ports:
            return
        self._section(f"OPEN PORTS  ({len(ports)} found)")
        print(f"  {_BOLD}{'PORT':<8} {'PROTO':<7} {'SERVICE':<15} {'PRODUCT & VERSION':<30}{_RESET}")
        print(f"  {'─'*62}")
        for p in ports:
            product_ver = f"{p.get('product','')} {p.get('version','')}".strip()
            print(
                f"  {_CYAN}{p['port']:<8}{_RESET}"
                f"{p['protocol']:<7}"
                f"{p.get('name',''):<15}"
                f"{product_ver:<30}"
            )
        print()

    def _vulnerabilities(self) -> None:
        vulns = self._r.get("vulnerabilities", [])
        self._section(f"VULNERABILITIES  ({len(vulns)} found)")
        if not vulns:
            print(f"  {_GREEN}✓ No vulnerabilities matched for detected services.{_RESET}\n")
            return

        for v in vulns:
            sev   = v.get("severity", "UNKNOWN")
            color = _SEV_COLOR.get(sev, _DIM)
            emoji = _SEV_EMOJI.get(sev, "⚪")
            cvss  = v.get("cvss_score", 0.0)
            desc  = v.get("description", "")
            desc_short = desc[:120] + "…" if len(desc) > 120 else desc

            print(f"  {emoji} {color}{_BOLD}{v.get('cve_id','?')}{_RESET}  {color}[{sev}]{_RESET}  CVSS {_BOLD}{cvss}{_RESET}")
            print(f"     Product  : {v.get('affected_product','')} {v.get('affected_version','')}")
            print(f"     Port     : {v.get('port','')}")
            print(f"     Desc     : {_DIM}{desc_short}{_RESET}")
            print(f"     Fix      : {v.get('remediation','')}")
            print(f"     Ref      : {_CYAN}{v.get('url','')}{_RESET}")
            print()

    def _ssl(self) -> None:
        ssl = self._r.get("ssl_analysis")
        if not ssl:
            return
        self._section("SSL / TLS")
        print(f"  Protocol : {ssl.get('tls_version','—')}")
        if ssl.get("cipher"):
            c = ssl["cipher"]
            print(f"  Cipher   : {c['name']} ({c['bits']} bit)")
        cert = ssl.get("certificate", {})
        if cert:
            subj = cert.get("subject", {})
            cn   = subj.get("commonName", "—")
            print(f"  CN       : {cn}")
            print(f"  Expires  : {cert.get('not_after','—')}")

        issues = ssl.get("issues", [])
        if issues:
            print(f"\n  Issues ({len(issues)}):")
            for iss in issues:
                sev   = iss.get("severity","INFO")
                color = _SEV_COLOR.get(sev, _DIM)
                print(f"    {color}[{sev}]{_RESET} {iss.get('issue','')}")
        else:
            print(f"  {_GREEN}✓ No SSL/TLS issues found.{_RESET}")
        print()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _section(title: str) -> None:
        bar = "─" * (len(title) + 4)
        print(f"{_PURPLE}{_BOLD}┌{bar}┐")
        print(f"│  {title}  │")
        print(f"└{bar}┘{_RESET}")
        print()
