"""Email authentication verification module (SPF, DKIM, DMARC) via DNS."""

import re
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
import dns.resolver
import dns.exception

import config


def get_resolver() -> dns.resolver.Resolver:
    """Create a DNS resolver configured with standard timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = getattr(config, "DNS_TIMEOUT", 5.0)
    resolver.lifetime = getattr(config, "DNS_TIMEOUT", 5.0)
    return resolver


def _evaluate_spf_record(record: str, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, resolver: dns.resolver.Resolver, depth: int = 0) -> Tuple[bool, Optional[str]]:
    """Recursively evaluate SPF mechanisms including ip4, ip6, include, and redirect."""
    if depth > 4:
        return False, None

    terms = record.split()
    qualifier = None

    for term in terms:
        t_lower = term.lower()
        if t_lower.startswith("ip4:"):
            try:
                net = ipaddress.ip_network(term[4:], strict=False)
                if client_ip in net:
                    return True, None
            except ValueError:
                pass
        elif t_lower.startswith("ip6:"):
            try:
                net = ipaddress.ip_network(term[4:], strict=False)
                if client_ip in net:
                    return True, None
            except ValueError:
                pass
        elif t_lower.startswith("include:"):
            inc_domain = term[8:]
            try:
                ans = resolver.resolve(inc_domain, "TXT")
                for r in ans:
                    txt = "".join([b.decode("utf-8", errors="replace") for b in r.strings])
                    if txt.startswith("v=spf1"):
                        matched, _ = _evaluate_spf_record(txt, client_ip, resolver, depth + 1)
                        if matched:
                            return True, None
            except Exception:
                pass
        elif t_lower.startswith("redirect="):
            red_domain = term[9:]
            try:
                ans = resolver.resolve(red_domain, "TXT")
                for r in ans:
                    txt = "".join([b.decode("utf-8", errors="replace") for b in r.strings])
                    if txt.startswith("v=spf1"):
                        return _evaluate_spf_record(txt, client_ip, resolver, depth + 1)
            except Exception:
                pass
        elif t_lower in ("-all", "~all", "+all", "?all"):
            qualifier = t_lower

    return False, qualifier


def check_spf(sender_domain: str, originating_ip: Optional[str]) -> Dict[str, Any]:
    """Check SPF TXT records for the sender domain and verify the originating IP."""
    if not sender_domain:
        return {
            "status": "FAIL",
            "record": "None",
            "details": "Missing sender domain for SPF lookup."
        }

    resolver = get_resolver()
    try:
        answers = resolver.resolve(sender_domain, "TXT")
        spf_records = []
        for rdata in answers:
            txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_records.append(txt_str)

        if not spf_records:
            return {
                "status": "WARNING",
                "record": "None",
                "details": f"No SPF record published for {sender_domain}."
            }

        if len(spf_records) > 1:
            return {
                "status": "FAIL",
                "record": "Multiple SPF records",
                "details": f"PermError: Multiple SPF records found for {sender_domain}."
            }

        spf_record = spf_records[0]

        if not originating_ip:
            return {
                "status": "WARNING",
                "record": spf_record,
                "details": "SPF record found, but no originating IP could be identified from hops."
            }

        # Check if originating IP is private
        try:
            ip_obj = ipaddress.ip_address(originating_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "status": "WARNING",
                    "record": spf_record,
                    "details": f"Originating IP ({originating_ip}) is private/internal RFC1918."
                }
        except ValueError:
            return {
                "status": "WARNING",
                "record": spf_record,
                "details": f"Invalid IP address format: {originating_ip}."
            }

        ip_matched, qualifier = _evaluate_spf_record(spf_record, ip_obj, resolver, depth=0)

        if ip_matched:
            return {
                "status": "PASS",
                "record": spf_record,
                "details": f"Originating IP {originating_ip} authorized in SPF mechanisms (direct/include/redirect)."
            }

        # Check qualifier
        if qualifier == "-all" or "-all" in spf_record:
            return {
                "status": "FAIL",
                "record": spf_record,
                "details": f"IP {originating_ip} not authorized under hardfail policy (-all)."
            }
        elif qualifier == "~all" or "~all" in spf_record:
            return {
                "status": "WARNING",
                "record": spf_record,
                "details": f"IP {originating_ip} not explicitly listed; softfail policy (~all)."
            }
        elif qualifier == "+all" or "+all" in spf_record:
            return {
                "status": "WARNING",
                "record": spf_record,
                "details": "Insecure SPF policy: +all authorizes any sending IP."
            }
        else:
            return {
                "status": "WARNING",
                "record": spf_record,
                "details": f"SPF record present; evaluated with neutral/unknown match for IP {originating_ip}."
            }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "status": "WARNING",
            "record": "None",
            "details": f"Domain {sender_domain} has no DNS TXT records."
        }
    except dns.exception.Timeout:
        return {
            "status": "WARNING",
            "record": "Timeout",
            "details": f"DNS query timed out resolving SPF for {sender_domain}."
        }
    except Exception as e:
        return {
            "status": "WARNING",
            "record": "Error",
            "details": f"DNS resolution error: {str(e)}"
        }


def parse_dkim_header(header_val: str) -> Dict[str, str]:
    """Parse key=value tags from a DKIM-Signature header."""
    clean_val = re.sub(r'\s+', ' ', header_val)
    tags = {}
    for part in clean_val.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dkim(dkim_signatures: List[str], sender_domain: str) -> Dict[str, Any]:
    """Inspect DKIM-Signature headers and check DNS public key records."""
    if not dkim_signatures:
        return {
            "status": "WARNING",
            "selector": "None",
            "domain": "None",
            "record": "None",
            "details": "No DKIM-Signature header present in the message."
        }

    first_sig = dkim_signatures[0]
    tags = parse_dkim_header(first_sig)
    selector = tags.get("s", "")
    domain = tags.get("d", "")

    if not selector or not domain:
        return {
            "status": "FAIL",
            "selector": selector or "Missing",
            "domain": domain or "Missing",
            "record": "Malformed",
            "details": "Malformed DKIM-Signature: missing required selector ('s=') or domain ('d=')."
        }

    # Query public key selector: <selector>._domainkey.<domain>
    dkim_dns_name = f"{selector}._domainkey.{domain}"
    resolver = get_resolver()

    try:
        answers = resolver.resolve(dkim_dns_name, "TXT")
        pubkey_records = []
        for rdata in answers:
            txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
            pubkey_records.append(txt_str)

        if pubkey_records:
            full_record = " ".join(pubkey_records)
            has_pubkey = "p=" in full_record
            if has_pubkey:
                domain_match = (domain.lower() == sender_domain.lower()) if sender_domain else True
                details = f"DKIM selector resolved ({dkim_dns_name}). Public key published."
                if not domain_match:
                    details += f" Warning: DKIM domain ({domain}) does not match From domain ({sender_domain})."
                    return {
                        "status": "WARNING",
                        "selector": selector,
                        "domain": domain,
                        "record": full_record[:60] + "...",
                        "details": details
                    }
                return {
                    "status": "PASS",
                    "selector": selector,
                    "domain": domain,
                    "record": full_record[:60] + "...",
                    "details": details
                }
            else:
                return {
                    "status": "WARNING",
                    "selector": selector,
                    "domain": domain,
                    "record": full_record[:60] + "...",
                    "details": f"DNS record found for {dkim_dns_name}, but public key ('p=') tag is absent."
                }
        else:
            return {
                "status": "WARNING",
                "selector": selector,
                "domain": domain,
                "record": "None",
                "details": f"DKIM header present, but no public key record found at {dkim_dns_name}."
            }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "status": "WARNING",
            "selector": selector,
            "domain": domain,
            "record": "NXDOMAIN",
            "details": f"DKIM header present (s={selector}, d={domain}), but public key record not found in DNS."
        }
    except dns.exception.Timeout:
        return {
            "status": "WARNING",
            "selector": selector,
            "domain": domain,
            "record": "Timeout",
            "details": f"DNS query timed out resolving {dkim_dns_name}."
        }
    except Exception as e:
        return {
            "status": "WARNING",
            "selector": selector,
            "domain": domain,
            "record": "Error",
            "details": f"DKIM DNS check error: {str(e)}"
        }


def check_dmarc(sender_domain: str) -> Dict[str, Any]:
    """Query and parse DMARC policy for the sender domain."""
    if not sender_domain:
        return {
            "status": "FAIL",
            "policy": "None",
            "record": "None",
            "details": "Missing sender domain for DMARC evaluation."
        }

    resolver = get_resolver()
    dmarc_domain = f"_dmarc.{sender_domain}"

    try:
        answers = resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = []
        for rdata in answers:
            txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
            if txt_str.startswith("v=DMARC1"):
                dmarc_records.append(txt_str)

        if not dmarc_records:
            # Fallback to parent domain if domain is a subdomain
            parts = sender_domain.split(".")
            if len(parts) > 2:
                parent_domain = ".".join(parts[1:])
                return check_dmarc(parent_domain)

            return {
                "status": "WARNING",
                "policy": "None",
                "record": "None",
                "details": f"No DMARC record found at {dmarc_domain}."
            }

        dmarc_record = dmarc_records[0]
        # Parse policy tag
        policy_match = re.search(r'\bp=([a-zA-Z]+)', dmarc_record)
        policy_val = policy_match.group(1).lower() if policy_match else "unknown"

        if policy_val == "reject":
            status = "PASS"
            details = "DMARC policy 'reject' actively enforces message blocking on failure."
        elif policy_val == "quarantine":
            status = "PASS"
            details = "DMARC policy 'quarantine' directs failing messages to spam/quarantine."
        elif policy_val == "none":
            status = "WARNING"
            details = "DMARC policy 'none' (monitoring only; no enforcement against spoofing)."
        else:
            status = "WARNING"
            details = f"DMARC record present with policy: {policy_val}."

        return {
            "status": status,
            "policy": policy_val,
            "record": dmarc_record,
            "details": details
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Try parent domain if subdomain
        parts = sender_domain.split(".")
        if len(parts) > 2:
            parent_domain = ".".join(parts[1:])
            return check_dmarc(parent_domain)

        return {
            "status": "WARNING",
            "policy": "None",
            "record": "NXDOMAIN",
            "details": f"No DMARC record found for {sender_domain}."
        }
    except dns.exception.Timeout:
        return {
            "status": "WARNING",
            "policy": "Timeout",
            "record": "Timeout",
            "details": f"DNS query timed out resolving DMARC for {sender_domain}."
        }
    except Exception as e:
        return {
            "status": "WARNING",
            "policy": "Error",
            "record": "Error",
            "details": f"DMARC check error: {str(e)}"
        }


def verify_email_auth(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """Run SPF, DKIM, and DMARC verification on parsed email data."""
    metadata = parsed_email.get("metadata", {})
    sender_domain = metadata.get("sender_domain", "")
    originating_ip = parsed_email.get("originating_ip", "")
    dkim_signatures = parsed_email.get("dkim_signatures", [])

    spf_res = check_spf(sender_domain, originating_ip)
    dkim_res = check_dkim(dkim_signatures, sender_domain)
    dmarc_res = check_dmarc(sender_domain)

    return {
        "sender_domain": sender_domain,
        "originating_ip": originating_ip,
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res,
    }
