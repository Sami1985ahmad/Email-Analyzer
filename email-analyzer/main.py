#!/usr/bin/env python3
"""
Email Security & Header Analyzer CLI
A high-fidelity tool for Junior SOC Analysts and Incident Responders.
"""

import sys
import os
import argparse
from rich.console import Console
from rich.panel import Panel

import config
from modules.parser import parse_email_message
from modules.auth_checker import verify_email_auth
from modules.threat_intel import analyze_threats
from modules.reporter import render_report

__version__ = "1.0.0"

BANNER = r"""
 ███████╗███╗   ███╗ █████╗ ██╗██╗         █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
 ██╔════╝████╗ ████║██╔══██╗██║██║        ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 █████╗  ██╔████╔██║███████║██║██║  █████╗███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║  ╚════╝██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗   ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
 ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
"""


def show_banner(console: Console) -> None:
    """Display the professional ASCII art banner."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        f"[dim white]Email Security & Header Analyzer CLI v{__version__} | Target: SOC Analyst / IR[/dim white]\n"
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI arguments parser."""
    parser = argparse.ArgumentParser(
        description="Analyze email files (.eml) for phishing, spoofing, and malicious indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f", "--file",
        dest="file_path",
        required=True,
        help="Path to the .eml file to analyze."
    )
    parser.add_argument(
        "-k", "--vt-key",
        dest="vt_key",
        default=None,
        help="VirusTotal API key (optional; defaults to VT_API_KEY env var or config.py)."
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"Email Security Analyzer v{__version__}"
    )
    return parser


def main() -> int:
    """Main execution entry point."""
    console = Console()
    show_banner(console)

    parser = build_parser()
    args = parser.parse_args()

    file_path = args.file_path

    # Validate file existence
    if not os.path.exists(file_path):
        console.print(
            Panel(
                f"[bold red]Error:[/bold red] The specified file does not exist:\n[white]{file_path}[/white]",
                title="[red]File Not Found[/red]",
                border_style="red"
            )
        )
        return 1

    if not os.path.isfile(file_path):
        console.print(
            Panel(
                f"[bold red]Error:[/bold red] Specified path is a directory, not a file:\n[white]{file_path}[/white]",
                title="[red]Invalid Path[/red]",
                border_style="red"
            )
        )
        return 1

    # 1. Parsing Phase
    with console.status("[bold cyan]Parsing email headers, body, links, and attachments...", spinner="dots"):
        try:
            parsed_data = parse_email_message(file_path)
        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Parsing Error:[/bold red] Failed to parse email message:\n[white]{str(e)}[/white]",
                    title="[red]Malformed Email[/red]",
                    border_style="red"
                )
            )
            return 1

    # 2. Authentication Verification Phase
    with console.status("[bold cyan]Performing SPF, DKIM, and DMARC DNS lookups...", spinner="dots"):
        try:
            auth_data = verify_email_auth(parsed_data)
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/bold yellow] Authentication check encountered an issue: {e}")
            auth_data = {
                "spf": {"status": "WARNING", "record": "Error", "details": str(e)},
                "dkim": {"status": "WARNING", "selector": "Error", "domain": "", "details": str(e)},
                "dmarc": {"status": "WARNING", "policy": "Error", "details": str(e)},
            }

    # 3. Threat Intelligence Phase
    with console.status("[bold cyan]Querying VirusTotal threat intelligence...", spinner="dots"):
        try:
            threat_data = analyze_threats(
                urls=parsed_data.get("urls", []),
                attachments=parsed_data.get("attachments", []),
                api_key=args.vt_key
            )
        except Exception as e:
            console.print(f"[bold yellow]Warning:[/bold yellow] Threat intel query encountered an issue: {e}")
            threat_data = {
                "api_key_configured": False,
                "urls": [],
                "attachments": [],
                "total_malicious": 0,
                "total_suspicious": 0,
            }

    # 4. Render Report
    render_report(
        file_path=file_path,
        parsed_email=parsed_data,
        auth_data=auth_data,
        threat_data=threat_data,
        console=console
    )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Analysis cancelled by user.")
        sys.exit(130)
