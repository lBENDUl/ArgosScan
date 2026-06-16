#!/usr/bin/env python3
"""
ArgosScan — Professional Vulnerability Scanner
The guardian with a thousand eyes.

Usage:
    python argosScan.py scan example.com
    python argosScan.py scan 192.168.1.1 -p 22,80,443 --format html -o report.html
    python argosScan.py ssl example.com
    python argosScan.py ports example.com
"""

__version__ = "0.1.0"
__author__ = "Bendu"
__license__ = "MIT"

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

# Local imports — add project root to path so subfolders resolve correctly
sys.path.insert(0, str(Path(__file__).parent))

from modules import CVEMatcher, PortScanner, ServiceIdentifier, SSLAnalyzer
from modules.port_scanner import PortScannerError
from reporters import CLIReporter, HTMLReporter, JSONReporter
from utils import cache_clear, setup_logger, validate_target

logger = setup_logger()


# ─────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="ArgosScan")
def cli():
    """ArgosScan — The guardian with a thousand eyes 👁️"""


# ─────────────────────────────────────────────
# scan command
# ─────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option(
    "-p", "--ports",
    default="1-10000",
    show_default=True,
    help="Port range or comma-separated list (e.g. 22,80,443 or 1-1024).",
)
@click.option(
    "-s", "--speed",
    type=click.Choice(["fast", "normal", "thorough"]),
    default="normal",
    show_default=True,
    help="Scan speed preset.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["cli", "html", "json"]),
    default="cli",
    show_default=True,
    help="Output format.",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    default=None,
    help="Output file path (required for html/json; optional for cli).",
)
@click.option(
    "--nvd-key",
    envvar="NVD_API_KEY",
    default=None,
    help="NVD API key for higher rate limits (or set NVD_API_KEY env var).",
)
@click.option(
    "--no-ssl",
    is_flag=True,
    default=False,
    help="Skip SSL/TLS analysis even if port 443 is open.",
)
@click.option(
    "--log-file",
    type=click.Path(),
    default=None,
    help="Write debug logs to this file.",
)
def scan(target, ports, speed, output_format, output, nvd_key, no_ssl, log_file):
    """
    Full vulnerability scan against TARGET.

    \b
    Examples:
        argosScan scan example.com
        argosScan scan 192.168.1.1 -p 22,80,443
        argosScan scan example.com -s thorough --format html -o report.html
    """
    if log_file:
        setup_logger(log_file=log_file, level=logging.DEBUG)

    if not validate_target(target):
        _err(f"Invalid target: '{target}'. Provide a valid hostname, IP, or CIDR.")
        sys.exit(1)

    _banner()
    click.echo(f"  Target : {click.style(target, bold=True)}")
    click.echo(f"  Ports  : {ports}   Speed: {speed}   Format: {output_format}")
    click.echo()

    try:
        # ── Stage 1: Port scan ───────────────────────────────────────
        _stage(1, 4, "Port scanning…")
        try:
            scanner = PortScanner(target, ports, speed)
            open_ports = scanner.scan()
        except PortScannerError as exc:
            _err(str(exc))
            sys.exit(1)

        if not open_ports:
            click.echo(click.style("  [!] No open ports found.", fg="yellow"))
            sys.exit(0)
        click.echo(click.style(f"  [+] {len(open_ports)} open port(s) found.", fg="green"))

        # ── Stage 2: Service identification ─────────────────────────
        _stage(2, 4, "Identifying services…")
        identifier = ServiceIdentifier()
        services = identifier.identify_batch(open_ports, target)
        click.echo(click.style(f"  [+] {len(services)} service(s) identified.", fg="green"))

        # ── Stage 3: CVE matching ────────────────────────────────────
        _stage(3, 4, "Matching CVEs via NVD…")
        matcher = CVEMatcher(api_key=nvd_key)
        vulnerabilities = matcher.match_services(services)
        vuln_count = len(vulnerabilities)
        color = "red" if vuln_count else "green"
        click.echo(click.style(f"  [+] {vuln_count} vulnerability(ies) matched.", fg=color))

        # ── Stage 4: SSL/TLS ─────────────────────────────────────────
        ssl_results = None
        has_443 = any(s.get("port") == 443 for s in services)

        if has_443 and not no_ssl:
            _stage(4, 4, "Analysing SSL/TLS…")
            ssl_analyzer = SSLAnalyzer(target)
            ssl_results = ssl_analyzer.analyze()
            issue_count = len(ssl_results.get("issues", []))
            click.echo(click.style(f"  [+] SSL analysis done. {issue_count} issue(s) found.", fg="green"))
        else:
            reason = "--no-ssl flag" if no_ssl else "port 443 is closed"
            click.echo(f"\n  [Stage 4/4] SSL analysis skipped ({reason}).")

        # ── Build results ────────────────────────────────────────────
        results = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_params": {"ports": ports, "speed": speed},
            "open_ports": open_ports,
            "services": services,
            "vulnerabilities": vulnerabilities,
            "ssl_analysis": ssl_results,
            "summary": _build_summary(vulnerabilities),
        }

        click.echo()

        # ── Output ───────────────────────────────────────────────────
        if output_format == "html":
            out = output or _default_output(target, "html")
            HTMLReporter(results).generate(out)
            click.echo(click.style(f"  [+] HTML report → {out}", fg="green"))

        elif output_format == "json":
            out = output or _default_output(target, "json")
            JSONReporter(results).generate(out)
            click.echo(click.style(f"  [+] JSON report → {out}", fg="green"))

        else:  # cli
            CLIReporter(results).print_report()
            if output:
                # Also write CLI text to file if -o provided
                JSONReporter(results).generate(output.replace(".txt", ".json") if output else _default_output(target, "json"))

        click.echo(click.style("\n  ✓ Scan complete!\n", fg="green", bold=True))

    except KeyboardInterrupt:
        click.echo(click.style("\n  [!] Interrupted by user.", fg="yellow"))
        sys.exit(130)
    except Exception as exc:
        _err(f"Unexpected error: {exc}")
        logger.exception("Unhandled exception during scan")
        sys.exit(1)


# ─────────────────────────────────────────────
# ssl command
# ─────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("-p", "--port", default=443, show_default=True, help="HTTPS port.")
def ssl(target, port):
    """Analyse SSL/TLS configuration on TARGET."""
    if not validate_target(target):
        _err(f"Invalid target: '{target}'.")
        sys.exit(1)

    click.echo(f"  Analysing SSL/TLS on {target}:{port}…\n")
    analyzer = SSLAnalyzer(target, port)
    results = analyzer.analyze()
    click.echo(json.dumps(results, indent=2, default=str))


# ─────────────────────────────────────────────
# ports command
# ─────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("-p", "--ports", default="1-10000", show_default=True, help="Port range.")
@click.option(
    "-s", "--speed",
    type=click.Choice(["fast", "normal", "thorough"]),
    default="fast",
    show_default=True,
)
def ports(target, ports, speed):
    """Quick port scan without service detection or CVE matching."""
    if not validate_target(target):
        _err(f"Invalid target: '{target}'.")
        sys.exit(1)

    click.echo(f"  Scanning {target} (speed={speed})…\n")
    try:
        scanner = PortScanner(target, ports, speed)
        open_ports = scanner.scan()
    except PortScannerError as exc:
        _err(str(exc))
        sys.exit(1)

    if not open_ports:
        click.echo("  No open ports found.")
        return

    click.echo(f"  {'PORT':<8} {'PROTO':<7} {'SERVICE':<20}")
    click.echo(f"  {'─'*37}")
    for p in open_ports:
        click.echo(f"  {p['port']:<8} {p['protocol']:<7} {p.get('name',''):<20}")
    click.echo(f"\n  {len(open_ports)} port(s) open.")


# ─────────────────────────────────────────────
# cache command
# ─────────────────────────────────────────────

@cli.command("clear-cache")
def clear_cache():
    """Remove the local NVD response cache."""
    cache_clear()
    click.echo(click.style("  [+] Cache cleared.", fg="green"))


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _banner() -> None:
    click.echo()
    click.echo(click.style("  ╔══════════════════════════════╗", fg="magenta", bold=True))
    click.echo(click.style("  ║  👁️  ArgosScan  v" + __version__ + "         ║", fg="magenta", bold=True))
    click.echo(click.style("  ║  The guardian with 1000 eyes ║", fg="magenta"))
    click.echo(click.style("  ╚══════════════════════════════╝", fg="magenta", bold=True))
    click.echo()


def _stage(n: int, total: int, msg: str) -> None:
    click.echo(click.style(f"\n  [Stage {n}/{total}] ", fg="cyan") + msg)


def _err(msg: str) -> None:
    click.echo(click.style(f"  [!] {msg}", fg="red"), err=True)


def _default_output(target: str, ext: str) -> str:
    safe = target.replace(".", "_").replace("/", "_")
    return f"argosScan_{safe}.{ext}"


def _build_summary(vulnerabilities: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "UNKNOWN")
        if sev in counts:
            counts[sev] += 1

    total = len(vulnerabilities)
    risk = min(
        100.0,
        (counts["CRITICAL"] * 40 + counts["HIGH"] * 20 + counts["MEDIUM"] * 5)
        / max(1, total),
    )

    return {
        "total": total,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "unknown": counts["UNKNOWN"],
        "risk_score": round(risk, 1),
    }


if __name__ == "__main__":
    cli()
