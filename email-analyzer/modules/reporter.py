"""Rich CLI UI and risk scoring engine for email analysis reports."""

import os
import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich import box


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".hta", ".iso", ".img",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".docm", ".xlsm", ".pptm"
}


def calculate_risk_score(
    auth_data: Dict[str, Any],
    threat_data: Dict[str, Any],
    urls: List[Dict[str, Any]],
    attachments: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Calculate overall risk level: Low (Safe), Medium (Suspicious), or High (Malicious)."""
    score = 0
    reasons = []

    # 1. Authentication evaluations
    spf = auth_data.get("spf", {})
    dkim = auth_data.get("dkim", {})
    dmarc = auth_data.get("dmarc", {})

    spf_status = spf.get("status", "WARNING")
    dkim_status = dkim.get("status", "WARNING")
    dmarc_status = dmarc.get("status", "WARNING")

    auth_fails = sum(1 for s in (spf_status, dkim_status, dmarc_status) if s == "FAIL")
    auth_warnings = sum(1 for s in (spf_status, dkim_status, dmarc_status) if s == "WARNING")

    if auth_fails > 0:
        score += auth_fails * 2
        reasons.append(f"{auth_fails} email authentication check(s) strictly failed (SPF/DKIM/DMARC).")
    elif auth_warnings > 0:
        score += auth_warnings * 1
        reasons.append(f"{auth_warnings} authentication check(s) returned warnings or missing records.")

    # 2. VirusTotal evaluations
    vt_malicious = threat_data.get("total_malicious", 0)
    vt_suspicious = threat_data.get("total_suspicious", 0)

    if vt_malicious >= 2:
        score += 5
        reasons.append(f"Multiple VirusTotal malicious hits detected ({vt_malicious} detections).")
    elif vt_malicious == 1:
        score += 3
        reasons.append("1 VirusTotal malicious hit detected on email links or attachments.")
    elif vt_suspicious >= 1:
        score += 1
        reasons.append(f"{vt_suspicious} engine(s) flagged URL or attachment as suspicious.")

    # 3. Phishing heuristics (Link deception & suspicious files)
    deceptive_links = 0
    for u in urls:
        raw_url = u.get("url", "")
        display = u.get("display_text", "")
        # If display text is an http/domain link but target is different
        if display and (display.startswith("http://") or display.startswith("https://") or display.startswith("www.")):
            disp_domain = urlparse(display if "://" in display else "http://" + display).netloc.lower()
            url_domain = urlparse(raw_url).netloc.lower()
            if disp_domain and url_domain and disp_domain != url_domain:
                deceptive_links += 1

    if deceptive_links > 0:
        score += 3
        reasons.append(f"Detected {deceptive_links} deceptive hyperlink(s) where anchor text masks actual destination.")

    suspicious_attachments = 0
    for a in attachments:
        fname = a.get("filename", "").lower()
        _, ext = os.path.splitext(fname)
        if ext in DANGEROUS_EXTENSIONS:
            suspicious_attachments += 1

    if suspicious_attachments > 0:
        score += 2
        reasons.append(f"Detected {suspicious_attachments} attachment(s) with potentially risky file extensions.")

    # Categorize Verdict
    if score >= 5 or vt_malicious >= 2 or (auth_fails >= 1 and vt_malicious >= 1):
        level = "MALICIOUS"
        color = "bold red"
        badge = "⛔ HIGH RISK: MALICIOUS"
    elif score >= 2 or auth_fails >= 1 or auth_warnings >= 2 or vt_malicious == 1 or vt_suspicious >= 1:
        level = "SUSPICIOUS"
        color = "bold yellow"
        badge = "⚠️  MEDIUM RISK: SUSPICIOUS"
    else:
        level = "SAFE"
        color = "bold green"
        badge = "✅ LOW RISK: SAFE"

    if not reasons:
        reasons.append("All authentication records validated with 0 threat intelligence detections.")

    return {
        "level": level,
        "badge": badge,
        "color": color,
        "score": score,
        "reasons": reasons,
    }


def render_report(
    file_path: str,
    parsed_email: Dict[str, Any],
    auth_data: Dict[str, Any],
    threat_data: Dict[str, Any],
    console: Console = None
) -> None:
    """Render the comprehensive color-coded security report to the terminal using Rich."""
    if console is None:
        console = Console()

    file_size_kb = os.path.getsize(file_path) / 1024.0 if os.path.exists(file_path) else 0.0
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Header Panel
    console.print()
    header_content = (
        f"[bold cyan]File:[/bold cyan] [white]{os.path.abspath(file_path)}[/white]  "
        f"([dim]{file_size_kb:.2f} KB[/dim])\n"
        f"[bold cyan]Analysis Timestamp:[/bold cyan] [dim]{now_str}[/dim]"
    )
    console.print(Panel(header_content, title="📧 [bold white]Email Security & Header Analyzer[/bold white]", border_style="cyan"))

    # 2. Metadata Table
    metadata = parsed_email.get("metadata", {})
    meta_table = Table(title="📌 Email Metadata", box=box.ROUNDED, expand=True)
    meta_table.add_column("Property", style="bold cyan", width=18)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("From", metadata.get("from", "N/A"))
    meta_table.add_row("Sender Domain", metadata.get("sender_domain", "N/A"))
    meta_table.add_row("To", metadata.get("to", "N/A"))
    meta_table.add_row("Subject", metadata.get("subject", "N/A"))
    meta_table.add_row("Date", metadata.get("date", "N/A"))
    meta_table.add_row("Message-ID", metadata.get("message_id", "N/A"))
    meta_table.add_row("Originating IP", parsed_email.get("originating_ip", "Not detected"))
    console.print(meta_table)

    # 3. Authentication Checks Table
    auth_table = Table(title="🛡️  Authentication & Spoofing Checks", box=box.ROUNDED, expand=True)
    auth_table.add_column("Mechanism", style="bold", width=11)
    auth_table.add_column("Status", width=12, justify="center")
    auth_table.add_column("Record / Policy", style="dim", ratio=1)
    auth_table.add_column("Assessment Details", style="white", ratio=2)

    def format_status(status_str: str) -> Text:
        s = status_str.upper()
        if s == "PASS":
            return Text("✔ PASS", style="bold green")
        elif s == "WARNING":
            return Text("▲ WARNING", style="bold yellow")
        elif s == "FAIL":
            return Text("✖ FAIL", style="bold red")
        return Text(s, style="dim")

    spf = auth_data.get("spf", {})
    auth_table.add_row(
        "SPF",
        format_status(spf.get("status", "UNKNOWN")),
        spf.get("record", "None")[:45],
        spf.get("details", "")
    )

    dkim = auth_data.get("dkim", {})
    dkim_tag = f"s={dkim.get('selector', 'none')} d={dkim.get('domain', 'none')}"
    auth_table.add_row(
        "DKIM",
        format_status(dkim.get("status", "UNKNOWN")),
        dkim_tag,
        dkim.get("details", "")
    )

    dmarc = auth_data.get("dmarc", {})
    auth_table.add_row(
        "DMARC",
        format_status(dmarc.get("status", "UNKNOWN")),
        f"policy: {dmarc.get('policy', 'none')}",
        dmarc.get("details", "")
    )
    console.print(auth_table)

    # 4. Routing Hops Tree
    hops = parsed_email.get("hops", [])
    hops_tree = Tree("🌐 [bold cyan]Chronological Relay Hops (Sender ➔ Recipient)[/bold cyan]")
    if hops:
        for hop in hops:
            ip_str = ", ".join(hop.get("ips", [])) or "No IP extracted"
            hop_node = hops_tree.add(
                f"[bold yellow]Hop {hop['hop']}:[/bold yellow] "
                f"[white]{hop.get('from', 'Unknown')}[/white] ➔ [white]{hop.get('by', 'Unknown')}[/white]"
            )
            hop_node.add(f"[dim]IPs:[/dim] [cyan]{ip_str}[/cyan]")
            if hop.get("with"):
                hop_node.add(f"[dim]Protocol:[/dim] {hop.get('with')}")
            if hop.get("timestamp"):
                hop_node.add(f"[dim]Timestamp:[/dim] {hop.get('timestamp')}")
    else:
        hops_tree.add("[dim italic]No Received headers found.[/dim italic]")
    console.print(Panel(hops_tree, box=box.ROUNDED))

    # 5. Extracted URLs Tree & Threat Intel
    url_items = threat_data.get("urls", [])
    urls_tree = Tree(f"🔗 [bold cyan]Extracted Hyperlinks & URLs ({len(url_items)} found)[/bold cyan]")
    if url_items:
        for item in url_items:
            url_str = item.get("url", "")
            display = item.get("display_text", url_str)
            vt_rep = item.get("vt_report", {})
            vt_status = vt_rep.get("status", "SKIPPED")

            if vt_status == "MALICIOUS":
                vt_text = f"[bold red]⛔ MALICIOUS ({vt_rep.get('malicious')} detections)[/bold red]"
            elif vt_status == "SUSPICIOUS":
                vt_text = f"[bold yellow]⚠️ SUSPICIOUS ({vt_rep.get('suspicious')} detections)[/bold yellow]"
            elif vt_status == "CLEAN":
                vt_text = "[green]✔ Clean in VirusTotal[/green]"
            elif vt_status == "NOT_FOUND":
                vt_text = "[dim]Unseen in VirusTotal[/dim]"
            else:
                vt_text = f"[dim]VT: {vt_rep.get('details', 'Skipped')}[/dim]"

            u_node = urls_tree.add(f"[white]{url_str}[/white] ➔ {vt_text}")
            if display and display != url_str:
                u_node.add(f"[dim]Anchor display text:[/dim] [italic yellow]\"{display}\"[/italic yellow]")
    else:
        urls_tree.add("[dim italic]No embedded URLs discovered in message body.[/dim italic]")
    console.print(Panel(urls_tree, box=box.ROUNDED))

    # 6. Attachments & Cryptographic Hashes Table
    att_items = threat_data.get("attachments", [])
    if att_items:
        att_table = Table(title="📎 File Attachments & Cryptographic Hashes", box=box.ROUNDED, expand=True)
        att_table.add_column("Filename", style="bold cyan")
        att_table.add_column("Size", justify="right")
        att_table.add_column("SHA-256 Hash", style="dim")
        att_table.add_column("VT Threat Verdict", justify="center")

        for att in att_items:
            sz = f"{att.get('size_bytes', 0) / 1024.0:.1f} KB"
            vt_rep = att.get("vt_report", {})
            st = vt_rep.get("status", "SKIPPED")
            if st == "MALICIOUS":
                vt_cell = f"[bold red]MALICIOUS ({vt_rep.get('malicious')})[/bold red]"
            elif st == "SUSPICIOUS":
                vt_cell = f"[bold yellow]SUSPICIOUS ({vt_rep.get('suspicious')})[/bold yellow]"
            elif st == "CLEAN":
                vt_cell = "[green]CLEAN[/green]"
            elif st == "NOT_FOUND":
                vt_cell = "[dim]NOT FOUND[/dim]"
            else:
                vt_cell = "[dim]SKIPPED[/dim]"

            att_table.add_row(
                att.get("filename", "unnamed"),
                sz,
                att.get("sha256", "N/A"),
                vt_cell
            )
        console.print(att_table)

    # 7. Final Verdict Panel
    verdict = calculate_risk_score(
        auth_data=auth_data,
        threat_data=threat_data,
        urls=threat_data.get("urls", []),
        attachments=threat_data.get("attachments", [])
    )

    reasons_text = "\n".join([f"• {r}" for r in verdict["reasons"]])
    verdict_content = (
        f"[{verdict['color']}]{verdict['badge']}[/{verdict['color']}]\n\n"
        f"[bold white]Key Findings:[/bold white]\n"
        f"{reasons_text}\n\n"
        f"[dim]Risk Assessment Score: {verdict['score']}[/dim]"
    )
    console.print(Panel(verdict_content, title="🎯 [bold white]Final Security Verdict[/bold white]", border_style=verdict["color"].split()[-1]))
    console.print()
