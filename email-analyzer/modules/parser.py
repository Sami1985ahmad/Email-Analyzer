"""Email parser module for extracting headers, hops, body, URLs, and attachments."""

import os
import re
import hashlib
import ipaddress
import email
from email import policy
from email.utils import parseaddr
from typing import Dict, List, Any, Optional, Tuple


IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\',;]+|www\.[^\s<>"\',;]+', re.IGNORECASE)
HTML_LINK_REGEX = re.compile(
    r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)
STRIP_TAGS_REGEX = re.compile(r'<[^>]+>')


def is_public_ip(ip_str: str) -> bool:
    """Check if an IPv4/IPv6 string is a routable public address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def extract_ips(text: str) -> List[str]:
    """Extract IPv4 addresses from text."""
    return IP_REGEX.findall(text)


def clean_html_text(raw_html: str) -> str:
    """Remove HTML tags to extract display text."""
    return STRIP_TAGS_REGEX.sub('', raw_html).strip()


def parse_received_header(header_value: str, hop_index: int) -> Dict[str, Any]:
    """Parse a single Received header to extract from, by, with, protocol, and IPs."""
    clean_val = " ".join(header_value.split())
    ips = extract_ips(clean_val)
    
    # Extract "from", "by", "with", "id", "for", and date if present
    from_match = re.search(r'\bfrom\s+([^\s;]+(?:\s+\([^\)]+\))?)', clean_val, re.IGNORECASE)
    by_match = re.search(r'\bby\s+([^\s;]+)', clean_val, re.IGNORECASE)
    with_match = re.search(r'\bwith\s+([^\s;]+)', clean_val, re.IGNORECASE)
    date_part = clean_val.split(';')[-1].strip() if ';' in clean_val else ""

    return {
        "hop": hop_index,
        "raw": clean_val,
        "from": from_match.group(1).strip() if from_match else "Unknown",
        "by": by_match.group(1).strip() if by_match else "Unknown",
        "with": with_match.group(1).strip() if with_match else "Unknown",
        "timestamp": date_part,
        "ips": ips,
    }


def parse_email_message(file_path: str) -> Dict[str, Any]:
    """Parse an .eml file and return comprehensive extracted data."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Email file not found: {file_path}")

    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # 1. Metadata
    from_hdr = str(msg.get("From", "") or "")
    to_hdr = str(msg.get("To", "") or "")
    subject_hdr = str(msg.get("Subject", "") or "")
    date_hdr = str(msg.get("Date", "") or "")
    msg_id_hdr = str(msg.get("Message-ID", "") or "")
    reply_to_hdr = str(msg.get("Reply-To", "") or "")
    return_path_hdr = str(msg.get("Return-Path", "") or "")

    real_name, sender_email = parseaddr(from_hdr)
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

    metadata = {
        "from": from_hdr,
        "sender_name": real_name,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "to": to_hdr,
        "subject": subject_hdr,
        "date": date_hdr,
        "message_id": msg_id_hdr,
        "reply_to": reply_to_hdr,
        "return_path": return_path_hdr,
    }

    # 2. Received Hops (bottom-to-top chronological order)
    received_headers = msg.get_all("Received", [])
    hops: List[Dict[str, Any]] = []
    # Bottom-most is index -1 (originating hop)
    chronological_received = list(reversed(received_headers))
    originating_ip: Optional[str] = None
    first_any_ip: Optional[str] = None

    for i, recv in enumerate(chronological_received, 1):
        hop_info = parse_received_header(str(recv), i)
        hops.append(hop_info)
        for ip in hop_info["ips"]:
            if not first_any_ip:
                first_any_ip = ip
            if not originating_ip and is_public_ip(ip):
                originating_ip = ip

    if not originating_ip:
        originating_ip = first_any_ip

    # 3. Body (Plain & HTML)
    text_content = []
    html_content = []
    attachments: List[Dict[str, Any]] = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()

        if filename or disposition.lower() in ("attachment", "inline") and not content_type.startswith("multipart/"):
            # Attachment handling
            payload = part.get_payload(decode=True)
            if payload is not None:
                fname = filename or "unnamed_attachment"
                file_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename": fname,
                    "content_type": content_type,
                    "size_bytes": len(payload),
                    "sha256": file_hash,
                })
        elif content_type == "text/plain" and disposition.lower() != "attachment":
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text_content.append(payload.decode(charset, errors="replace"))
                except Exception:
                    text_content.append(payload.decode("utf-8", errors="replace"))
        elif content_type == "text/html" and disposition.lower() != "attachment":
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                try:
                    html_content.append(payload.decode(charset, errors="replace"))
                except Exception:
                    html_content.append(payload.decode("utf-8", errors="replace"))

    full_plain_text = "\n".join(text_content)
    full_html_text = "\n".join(html_content)

    # 4. URL & Link Extraction
    urls_seen = set()
    extracted_urls: List[Dict[str, str]] = []

    # HTML <a> tag hyperlinks
    if full_html_text:
        for match in HTML_LINK_REGEX.finditer(full_html_text):
            url = match.group(1).strip()
            display_text = clean_html_text(match.group(2))
            if url and url not in urls_seen:
                urls_seen.add(url)
                extracted_urls.append({
                    "url": url,
                    "display_text": display_text or url,
                    "source": "html_link"
                })

    # Plain text regex links
    all_text = f"{full_plain_text}\n{full_html_text}"
    for match in URL_REGEX.finditer(all_text):
        raw_url = match.group(0).rstrip(".,;)>'\"")
        if raw_url and raw_url not in urls_seen:
            urls_seen.add(raw_url)
            extracted_urls.append({
                "url": raw_url,
                "display_text": raw_url,
                "source": "text_body"
            })

    # 5. Raw DKIM signatures & auth headers
    dkim_signatures = [str(sig) for sig in msg.get_all("DKIM-Signature", [])]
    auth_results = [str(ar) for ar in msg.get_all("Authentication-Results", [])]

    return {
        "metadata": metadata,
        "hops": hops,
        "originating_ip": originating_ip,
        "body_plain": full_plain_text,
        "body_html": full_html_text,
        "urls": extracted_urls,
        "attachments": attachments,
        "dkim_signatures": dkim_signatures,
        "auth_results": auth_results,
    }
