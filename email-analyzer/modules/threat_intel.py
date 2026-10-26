"""Threat Intelligence module querying VirusTotal v3 API for URLs, domains, and file hashes."""

import os
import base64
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import requests

import config


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_api_key(cli_key: Optional[str] = None) -> str:
    """Resolve VirusTotal API key from CLI argument, environment, or config."""
    if cli_key and cli_key.strip():
        return cli_key.strip()
    env_key = os.getenv("VT_API_KEY", "")
    if env_key.strip():
        return env_key.strip()
    return getattr(config, "VT_API_KEY", "").strip()


def url_to_vt_id(url: str) -> str:
    """Encode URL as base64 string without trailing '=' for VT v3 API."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def query_file_hash(file_hash: str, api_key: str) -> Dict[str, Any]:
    """Query VirusTotal v3 API for a file SHA-256 hash."""
    if not api_key:
        return {
            "status": "SKIPPED",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "details": "VirusTotal API key not configured.",
        }

    url = f"{VT_BASE_URL}/files/{file_hash}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    timeout = getattr(config, "REQUEST_TIMEOUT", 10)

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            verdict = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
            return {
                "status": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "details": f"{malicious} engine(s) flagged as malicious, {suspicious} suspicious.",
            }
        elif response.status_code == 404:
            return {
                "status": "NOT_FOUND",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "Hash not found in VirusTotal database (unseen sample).",
            }
        elif response.status_code in (401, 403):
            return {
                "status": "ERROR",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "Invalid or unauthorized VirusTotal API key.",
            }
        elif response.status_code == 429:
            return {
                "status": "RATE_LIMITED",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "VirusTotal API rate limit exceeded.",
            }
        else:
            return {
                "status": "ERROR",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": f"VT API returned status code {response.status_code}.",
            }
    except requests.exceptions.RequestException as e:
        return {
            "status": "ERROR",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "details": f"Network error contacting VirusTotal: {str(e)}",
        }


def query_url_report(target_url: str, api_key: str) -> Dict[str, Any]:
    """Query VirusTotal v3 API for a URL."""
    if not api_key:
        return {
            "status": "SKIPPED",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "details": "VirusTotal API key not configured.",
        }

    url_id = url_to_vt_id(target_url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    timeout = getattr(config, "REQUEST_TIMEOUT", 10)

    try:
        response = requests.get(endpoint, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            verdict = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
            return {
                "status": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "details": f"{malicious} engine(s) flagged as malicious, {suspicious} suspicious.",
            }
        elif response.status_code == 404:
            return {
                "status": "NOT_FOUND",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "URL not found in VirusTotal database.",
            }
        elif response.status_code in (401, 403):
            return {
                "status": "ERROR",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "Invalid or unauthorized VirusTotal API key.",
            }
        elif response.status_code == 429:
            return {
                "status": "RATE_LIMITED",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": "VirusTotal API rate limit exceeded.",
            }
        else:
            return {
                "status": "ERROR",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "details": f"VT API returned status code {response.status_code}.",
            }
    except requests.exceptions.RequestException as e:
        return {
            "status": "ERROR",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "details": f"Network error contacting VirusTotal: {str(e)}",
        }


def analyze_threats(
    urls: List[Dict[str, str]],
    attachments: List[Dict[str, Any]],
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """Perform threat intelligence queries on all extracted URLs and attachments."""
    resolved_key = get_api_key(api_key)
    
    url_results = []
    for u in urls:
        target = u.get("url", "")
        res = query_url_report(target, resolved_key)
        url_results.append({
            "url": target,
            "display_text": u.get("display_text", target),
            "vt_report": res
        })

    attachment_results = []
    for att in attachments:
        sha256 = att.get("sha256", "")
        res = query_file_hash(sha256, resolved_key)
        attachment_results.append({
            "filename": att.get("filename", "unnamed"),
            "content_type": att.get("content_type", ""),
            "size_bytes": att.get("size_bytes", 0),
            "sha256": sha256,
            "vt_report": res
        })

    has_key = bool(resolved_key)
    total_malicious = sum(
        u["vt_report"].get("malicious", 0) for u in url_results
    ) + sum(
        a["vt_report"].get("malicious", 0) for a in attachment_results
    )
    total_suspicious = sum(
        u["vt_report"].get("suspicious", 0) for u in url_results
    ) + sum(
        a["vt_report"].get("suspicious", 0) for a in attachment_results
    )

    return {
        "api_key_configured": has_key,
        "urls": url_results,
        "attachments": attachment_results,
        "total_malicious": total_malicious,
        "total_suspicious": total_suspicious,
    }
