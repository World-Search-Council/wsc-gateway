"""
WSC Domain & Tech Health Sentinel Scanner Service
Enterprise-grade DNS, Mail Security, Web/SSL, Security Headers,
DNSSEC, and Drift Tracking Engine powered by CZ.NIC dns-crawler.
"""

import os
import ssl
import time
import socket
import logging
import datetime
import urllib.parse
import copy
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("wsc-sentinel-scanner")

# Status Constants
STATUS_GOOD = "GOOD"
STATUS_OK = "OK"
STATUS_LOW = "LOW"
STATUS_PROBLEM = "PROBLEM"
STATUS_ERROR = "ERROR"
STATUS_NA = "N/A"
STATUS_EXPIRES_SOON = "EXPIRES_SOON"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"

KNOWN_MAIL_PATTERNS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "office365.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail",
    "zohomail.com": "Zoho Mail",
    "yandex.net": "Yandex Mail",
    "protonmail.ch": "ProtonMail",
    "amazonses.com": "Amazon SES",
    "sendgrid.net": "Twilio SendGrid",
    "mailgun.org": "Mailgun",
    "postmarkapp.com": "Postmark",
    "mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mandrill",
    "ispgateway.de": "Host Europe / DomainFactory",
    "ionos.": "IONOS by 1&1",
    "strato.de": "Strato",
    "hetzner.": "Hetzner Online"
}

KNOWN_SERVICE_PATTERNS = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail",
    "zohomail.com": "Zoho Mail",
    "amazonses.com": "Amazon SES",
    "sendgrid.net": "Twilio SendGrid",
    "servers.mcsv.net": "Mailchimp",
    "_spf.salesforce.com": "Salesforce",
    "shops.shopify.com": "Shopify",
    "mail.zendesk.com": "Zendesk",
    "secureserver.net": "GoDaddy",
    "google-site-verification=": "Google Services",
    "MS=ms": "Microsoft 365",
    "facebook-domain-verification=": "Meta (Facebook)",
    "pinterest-site-verification=": "Pinterest",
    "adobe-sign-verification=": "Adobe Sign",
    "atlassian-domain-verification=": "Atlassian Cloud",
    "docusign=": "DocuSign",
    "zoom-domain-verification=": "Zoom",
    "miro-verification=": "Miro",
    "canva-site-verification=": "Canva",
    "hubspot": "HubSpot",
    "stripe": "Stripe"
}


def clean_domain_name(raw: str) -> str:
    """Extracts clean FQDN hostname from input string or URL."""
    if not raw:
        return "example.com"
    clean = raw.strip().lower()
    if "://" in clean:
        try:
            parsed = urllib.parse.urlparse(clean)
            clean = parsed.hostname or clean
        except Exception:
            pass
    clean = clean.split("/")[0].split(":")[0]
    return clean


def is_local_or_dev_domain(domain: str) -> bool:
    """Returns True if the domain is a local or unroutable development domain."""
    d = domain.lower()
    if d in ["localhost", "127.0.0.1", "::1"]:
        return True
    if any(d.endswith(suffix) for suffix in [".localhost", ".local", ".test", ".example", ".invalid"]):
        return True
    return False


def _crawl_domain_with_dns_crawler(domain: str) -> Dict[str, Any]:
    """
    Executes deep protocol and DNS crawling via CZ.NIC dns-crawler.
    Requirement 1: Pure DNS records, no SMTP connection probes on port 25.
    """
    try:
        import dns_crawler.crawl
        import dns_crawler.config_loader

        _orig_loader = dns_crawler.config_loader.load_config

        def _patched_loader(*args, **kwargs):
            cfg = _orig_loader(*args, **kwargs)
            # Requirement 1: Pure DNS records, NO SMTP connection on port 25
            cfg["mail"]["ports"] = []
            cfg["mail"]["get_banners"] = False
            # Disable GeoIP warnings if mmdb files are not mounted
            cfg["geoip"] = {}
            cfg["timeouts"]["dns"] = 4
            cfg["timeouts"]["http"] = 4
            return cfg

        dns_crawler.crawl.load_config = _patched_loader

        result = dns_crawler.crawl.process_domain(domain)
        return result or {}
    except Exception as e:
        logger.error(f"dns-crawler execution failed for {domain}: {e}")
        return {}


def evaluate_mail_security(dns_local: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates MX records, SPF, DKIM, and DMARC without connecting to SMTP ports."""
    mail_records = dns_local.get("MAIL", []) or []
    mx_count = len(mail_records)
    if mx_count >= 2:
        mx_status = STATUS_OK
    elif mx_count == 1:
        mx_status = STATUS_LOW
    else:
        mx_status = STATUS_NA

    # Mail Provider detection
    provider = "Self-hosted / Custom"
    mx_string = " ".join([str(r.get("value", "")) for r in mail_records]).lower()
    for pattern, name in KNOWN_MAIL_PATTERNS.items():
        if pattern in mx_string:
            provider = name
            break

    # SPF Evaluation
    spf_records = dns_local.get("TXT_SPF", []) or []
    has_spf = len(spf_records) > 0
    spf_error = any(rec.get("error") for rec in spf_records) if has_spf else False
    if has_spf and not spf_error:
        spf_status = STATUS_OK
    elif spf_error:
        spf_status = STATUS_ERROR
    else:
        spf_status = STATUS_NA

    # DKIM Evaluation
    dkim_records = dns_local.get("TXT_DKIM", {}) or {}
    has_dkim = bool(dkim_records and any(dkim_records.values()))
    dkim_status = STATUS_OK if has_dkim else STATUS_NA

    # DMARC Evaluation
    dmarc_records = dns_local.get("TXT_DMARC", []) or []
    has_dmarc = len(dmarc_records) > 0
    dmarc_policy = "missing"
    if has_dmarc:
        first_dmarc = dmarc_records[0]
        if isinstance(first_dmarc, dict):
            p_val = first_dmarc.get("p", {})
            if isinstance(p_val, dict):
                dmarc_policy = str(p_val.get("value", "none")).lower()
            elif isinstance(p_val, str):
                dmarc_policy = p_val.lower()
        if dmarc_policy in ["quarantine", "reject"]:
            dmarc_status = STATUS_GOOD
        elif dmarc_policy == "none":
            dmarc_status = STATUS_OK
        else:
            dmarc_status = STATUS_PROBLEM
    else:
        dmarc_status = STATUS_PROBLEM

    # Overall Mail Health
    if has_spf and has_dmarc and dmarc_policy in ["quarantine", "reject"] and mx_count >= 2:
        mail_health = STATUS_GOOD
    elif has_spf or has_dmarc or mx_count > 0:
        mail_health = STATUS_OK
    else:
        mail_health = STATUS_PROBLEM

    return {
        "provider": provider,
        "mx_status": mx_status,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "mail_health": mail_health,
        "mx_count": mx_count,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "has_dkim": has_dkim
    }


def evaluate_web_security(web_results: Dict[str, Any], hsts_flag: bool = False) -> Dict[str, Any]:
    """Evaluates HTTP to HTTPS redirect, canonicalization, IPv6 and HSTS."""
    web4_80 = web_results.get("WEB4_80", []) or []
    web4_80_www = web_results.get("WEB4_80_www", []) or []
    
    http_redirects_to_https = False
    for res_list in [web4_80, web4_80_www]:
        if res_list and isinstance(res_list, list):
            entry = res_list[0]
            if isinstance(entry, dict) and entry.get("redirect_count", 0) > 0:
                steps = entry.get("steps", [])
                if steps and "https://" in steps[-1].get("url", ""):
                    http_redirects_to_https = True
                    break

    http_to_https_status = STATUS_OK if http_redirects_to_https else STATUS_PROBLEM

    web4_443 = web_results.get("WEB4_443", []) or []
    web4_443_www = web_results.get("WEB4_443_www", []) or []
    
    canonical_url = ""
    for res_list in [web4_443, web4_443_www]:
        if res_list and isinstance(res_list, list):
            entry = res_list[0]
            if isinstance(entry, dict) and entry.get("steps"):
                canonical_url = entry["steps"][-1].get("url", "")
                if canonical_url:
                    break

    www_canonical = STATUS_OK if (http_redirects_to_https or bool(canonical_url)) else STATUS_PROBLEM

    # IPv6 accessibility
    web6_443 = web_results.get("WEB6_443", []) or []
    web6_443_www = web_results.get("WEB6_443_www", []) or []
    ipv6_ready = False
    for res_list in [web6_443, web6_443_www]:
        if res_list and isinstance(res_list, list):
            entry = res_list[0]
            if isinstance(entry, dict) and entry.get("steps") and not entry.get("error"):
                ipv6_ready = True
                break

    hsts_status = STATUS_GOOD if hsts_flag else STATUS_PROBLEM
    web_health = STATUS_GOOD if (http_to_https_status == STATUS_OK and hsts_flag) else STATUS_OK

    return {
        "http_to_https": http_to_https_status,
        "www_canonicalization": www_canonical,
        "canonical_url": canonical_url,
        "hsts_enabled": hsts_status,
        "ipv6_accessible": "Yes" if ipv6_ready else "No",
        "web_health": web_health
    }


def extract_ssl_certificate(web_results: Dict[str, Any], domain: str) -> Dict[str, Any]:
    """Extracts SSL certificate validity and expiration from crawl steps or fallback socket."""
    for key in ["WEB4_443", "WEB4_443_www", "WEB6_443", "WEB6_443_www"]:
        res_list = web_results.get(key, []) or []
        if res_list and isinstance(res_list, list):
            entry = res_list[0]
            if isinstance(entry, dict) and entry.get("steps"):
                for step in reversed(entry["steps"]):
                    certs = step.get("cert", [])
                    if certs and isinstance(certs, list):
                        c = certs[0]
                        expires_in = c.get("expires_in", 0)
                        expired = c.get("expired", False)
                        issuer = c.get("issuer", {})
                        issuer_str = "Trusted SSL/TLS Certificate"
                        if isinstance(issuer, dict):
                            issuer_str = issuer.get("O") or issuer.get("CN") or issuer_str
                        elif isinstance(issuer, str):
                            issuer_str = issuer

                        if expired:
                            ssl_status = STATUS_ERROR
                        elif expires_in <= 14:
                            ssl_status = STATUS_EXPIRES_SOON
                        else:
                            ssl_status = STATUS_OK

                        return {
                            "status": ssl_status,
                            "days_left": max(0, int(expires_in)),
                            "issuer": issuer_str,
                            "is_valid": not expired
                        }

    # Fallback direct socket
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get("notAfter", "")
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = max(0, (not_after - datetime.datetime.utcnow()).days)
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Trusted SSL/TLS"
                return {
                    "status": STATUS_OK if days_left > 14 else STATUS_EXPIRES_SOON,
                    "days_left": days_left,
                    "issuer": issuer_name,
                    "is_valid": True
                }
    except Exception as e:
        logger.debug(f"Direct SSL fallback failed for {domain}: {e}")
        return {
            "status": STATUS_ERROR,
            "days_left": 0,
            "issuer": "None",
            "is_valid": False
        }


def analyze_security_headers(web_results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyzes security headers at the final destination hop."""
    headers = {}
    for key in ["WEB4_443_www", "WEB4_443", "WEB6_443_www", "WEB6_443"]:
        res_list = web_results.get(key, []) or []
        if res_list and isinstance(res_list, list):
            entry = res_list[0]
            if isinstance(entry, dict) and entry.get("steps"):
                for step in reversed(entry["steps"]):
                    if step.get("status") == 200 and step.get("headers"):
                        raw_h = step.get("headers", {})
                        if isinstance(raw_h, dict):
                            headers = {k.lower(): str(v) for k, v in raw_h.items()}
                            break
            if headers:
                break

    hsts = "strict-transport-security" in headers
    csp = "content-security-policy" in headers
    x_frame = "x-frame-options" in headers
    x_content_type = "x-content-type-options" in headers
    referrer = "referrer-policy" in headers
    permissions = ("permissions-policy" in headers) or ("feature-policy" in headers)

    score = sum([1 for val in [hsts, csp, x_frame, x_content_type, referrer, permissions] if val])

    return {
        "score": score,
        "total": 6,
        "hsts": hsts,
        "csp": csp,
        "x_frame_options": x_frame,
        "x_content_type_options": x_content_type,
        "referrer_policy": referrer,
        "permissions_policy": permissions,
        "headers_score": f"{score}/6"
    }


def evaluate_dns_security(dns_local: Dict[str, Any], parent: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates authoritative nameserver count and DNSSEC validation."""
    ns_set = set()
    for item in parent.get("ns", []) or []:
        if isinstance(item, dict) and item.get("ns"):
            ns_set.add(item["ns"].rstrip("."))
        elif isinstance(item, str):
            ns_set.add(item.rstrip("."))
    
    for item in dns_local.get("NS_AUTH", []) or []:
        if isinstance(item, dict) and item.get("value"):
            ns_set.add(item["value"].rstrip("."))
        elif isinstance(item, str):
            ns_set.add(item.rstrip("."))

    ns_count = len(ns_set)

    # DNSSEC
    dnssec_info = dns_local.get("DNSSEC")
    dnssec_status = STATUS_NOT_CONFIGURED
    if dnssec_info:
        if isinstance(dnssec_info, dict):
            if dnssec_info.get("valid") is True:
                dnssec_status = STATUS_GOOD
            elif dnssec_info.get("valid") is False:
                dnssec_status = STATUS_PROBLEM
        elif dnssec_info is True:
            dnssec_status = STATUS_GOOD

    if ns_count >= 2 and dnssec_status == STATUS_GOOD:
        dns_health = STATUS_GOOD
    elif ns_count >= 2:
        dns_health = STATUS_OK
    elif ns_count == 1:
        dns_health = STATUS_LOW
    else:
        dns_health = STATUS_PROBLEM

    return {
        "nameserver_count": ns_count,
        "nameservers": sorted(list(ns_set)),
        "dnssec_status": dnssec_status,
        "dns_health": dns_health
    }


def analyze_domain_services(dns_local: Dict[str, Any]) -> List[str]:
    """Discovers 3rd-party SaaS integrations from SPF includes and TXT records."""
    services = set()
    for rec in dns_local.get("TXT_SPF", []) or []:
        if isinstance(rec, dict):
            for incl in rec.get("include", []) or []:
                domain = incl.get("domain", "") if isinstance(incl, dict) else str(incl)
                for pattern, service in KNOWN_SERVICE_PATTERNS.items():
                    if pattern in domain:
                        services.add(service)

    for rec in dns_local.get("TXT", []) or []:
        val = rec.get("value", "") if isinstance(rec, dict) else str(rec)
        for pattern, service in KNOWN_SERVICE_PATTERNS.items():
            if pattern in val:
                services.add(service)

    return sorted(list(services))


def calculate_overall_score(
    dns_res: Dict[str, Any],
    mail_res: Dict[str, Any],
    web_res: Dict[str, Any],
    ssl_res: Dict[str, Any],
    headers_res: Dict[str, Any]
) -> Tuple[int, str]:
    """Calculates canonical 0-100 score and qualitative rating."""
    pts = 0

    # 1. DNS (25 pts max)
    ns_cnt = dns_res.get("nameserver_count", 0)
    if ns_cnt >= 2:
        pts += 15
    elif ns_cnt == 1:
        pts += 8
    
    if web_res.get("ipv6_accessible") == "Yes":
        pts += 5
    else:
        pts += 2

    if dns_res.get("dnssec_status") == STATUS_GOOD:
        pts += 5

    # 2. Mail Security (30 pts max)
    if mail_res.get("mx_status") == STATUS_OK:
        pts += 10
    elif mail_res.get("mx_status") == STATUS_LOW:
        pts += 5

    if mail_res.get("has_spf"):
        pts += 10

    if mail_res.get("has_dmarc"):
        pts += 8
        if mail_res.get("dmarc_policy") in ["quarantine", "reject"]:
            pts += 2

    # 3. Web & SSL (30 pts max)
    if ssl_res.get("is_valid"):
        pts += 12
        if ssl_res.get("days_left", 0) > 30:
            pts += 4
    
    if web_res.get("http_to_https") == STATUS_OK:
        pts += 8
    if web_res.get("www_canonicalization") == STATUS_OK:
        pts += 4
    if web_res.get("hsts_enabled") == STATUS_GOOD:
        pts += 2

    # 4. Security Headers (15 pts max)
    h_score = headers_res.get("score", 0)
    pts += int(round((h_score / 6.0) * 15))

    total_score = max(0, min(100, pts))

    if total_score >= 90:
        rating = "EXCELLENT"
    elif total_score >= 75:
        rating = "GOOD"
    elif total_score >= 50:
        rating = "ATTENTION"
    else:
        rating = "CRITICAL"

    return total_score, rating


def generate_action_items(
    dns_res: Dict[str, Any],
    mail_res: Dict[str, Any],
    web_res: Dict[str, Any],
    ssl_res: Dict[str, Any],
    headers_res: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Generates actionable recommendations based on concrete findings."""
    items = []

    # DNS
    if dns_res.get("nameserver_count", 0) < 2:
        items.append({
            "id": "dns_ns_redundancy",
            "category": "DNS",
            "severity": "HIGH",
            "title": "Nameserver Redundancy Missing",
            "description": "Your domain should have at least 2 independent nameservers to guarantee high availability.",
            "tip": "Add secondary nameservers with your DNS host.",
            "remediation": "Add secondary nameservers with your DNS host."
        })
    if web_res.get("ipv6_accessible") != "Yes":
        items.append({
            "id": "dns_ipv6_missing",
            "category": "DNS",
            "severity": "LOW",
            "title": "IPv6 (AAAA) Record Missing",
            "description": "Adding an IPv6 address ensures modern connectivity and optimal global routing.",
            "tip": "Add an AAAA DNS record pointing to your server IPv6 address.",
            "remediation": "Add an AAAA DNS record pointing to your server IPv6 address."
        })

    # Mail
    if not mail_res.get("has_spf"):
        items.append({
            "id": "mail_spf_missing",
            "category": "Email Security",
            "severity": "HIGH",
            "title": "Missing SPF Record",
            "description": "An SPF record prevents spammers from sending unauthorized emails from your domain.",
            "tip": "Add a TXT record with 'v=spf1 ... ~all' tailored to your mail services.",
            "remediation": "Add a TXT record with 'v=spf1 ... ~all' tailored to your mail services."
        })
    if not mail_res.get("has_dmarc"):
        items.append({
            "id": "mail_dmarc_missing",
            "category": "Email Security",
            "severity": "HIGH",
            "title": "Missing DMARC Policy",
            "description": "DMARC protects your brand reputation and prevents email spoofing.",
            "tip": "Publish a DMARC policy under _dmarc.yourdomain.com (e.g. 'v=DMARC1; p=quarantine;').",
            "remediation": "Publish a DMARC policy under _dmarc.yourdomain.com (e.g. 'v=DMARC1; p=quarantine;')."
        })
    elif mail_res.get("dmarc_policy") == "none":
        items.append({
            "id": "mail_dmarc_none",
            "category": "Email Security",
            "severity": "MEDIUM",
            "title": "DMARC Policy is Monitoring Only (p=none)",
            "description": "Your DMARC policy is currently in report-only mode and does not reject or quarantine spoofed emails.",
            "tip": "Upgrade your DMARC policy to 'p=quarantine' or 'p=reject'.",
            "remediation": "Upgrade your DMARC policy to 'p=quarantine' or 'p=reject'."
        })

    # SSL
    if not ssl_res.get("is_valid"):
        items.append({
            "id": "ssl_invalid",
            "category": "SSL / TLS",
            "severity": "CRITICAL",
            "title": "Invalid or Expired SSL Certificate",
            "description": "Your website lacks a valid TLS/SSL certificate, resulting in security warnings for visitors.",
            "tip": "Renew or install a trusted SSL/TLS certificate immediately.",
            "remediation": "Renew or install a trusted SSL/TLS certificate immediately."
        })
    elif ssl_res.get("days_left", 0) <= 14:
        items.append({
            "id": "ssl_expiring_soon",
            "category": "SSL / TLS",
            "severity": "HIGH",
            "title": f"SSL Certificate Expires in {ssl_res.get('days_left')} Days",
            "description": "Your certificate will expire soon. Ensure automatic renewal is working properly.",
            "tip": "Verify your Let's Encrypt / ACME bot or renew your SSL certificate.",
            "remediation": "Verify your Let's Encrypt / ACME bot or renew your SSL certificate."
        })

    # Security Headers
    if not headers_res.get("hsts"):
        items.append({
            "id": "hdr_hsts_missing",
            "category": "Security Headers",
            "severity": "MEDIUM",
            "title": "HSTS Header Missing",
            "description": "HTTP Strict Transport Security forces browsers to use secure HTTPS connections exclusively.",
            "tip": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your web server config.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your web server config."
        })
    if not headers_res.get("csp"):
        items.append({
            "id": "hdr_csp_missing",
            "category": "Security Headers",
            "severity": "LOW",
            "title": "Content Security Policy (CSP) Missing",
            "description": "A CSP header protects your website from Cross-Site Scripting (XSS) and data injection attacks.",
            "tip": "Define a Content-Security-Policy header restricting trusted content sources.",
            "remediation": "Define a Content-Security-Policy header restricting trusted content sources."
        })
    if not headers_res.get("x_frame_options"):
        items.append({
            "id": "hdr_xfo_missing",
            "category": "Security Headers",
            "severity": "LOW",
            "title": "X-Frame-Options Header Missing",
            "description": "Prevents clickjacking by controlling whether your site can be embedded in an iframe.",
            "tip": "Add 'X-Frame-Options: SAMEORIGIN' to your web server responses.",
            "remediation": "Add 'X-Frame-Options: SAMEORIGIN' to your web server responses."
        })

    return items


def track_drift_with_deepdiff(
    current_signature: Dict[str, Any],
    previous_snapshot: Optional[Dict[str, Any]],
    now_ts: int
) -> Tuple[str, int, int]:
    """Tracks infrastructure drift and configuration changes using DeepDiff."""
    if not previous_snapshot:
        return "NEW_RECORD", now_ts, 0

    try:
        from deepdiff import DeepDiff
        prev_sig = previous_snapshot.get("_signature") or {}
        diff = DeepDiff(prev_sig, current_signature, ignore_order=True)
        if diff:
            return "CHANGED", now_ts, 0
        else:
            last_change = previous_snapshot.get("last_change_at", now_ts)
            days = max(0, int((now_ts - last_change) / 86400))
            return "NO_CHANGE", last_change, days
    except Exception as e:
        logger.warning(f"Drift tracking error: {e}")
        return "NO_CHANGE", now_ts, 0


def run_full_sentinel_scan(
    domain: str,
    project_id: str = "proj_default",
    previous_snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main entry point for executing a full Sentinel scan using dns-crawler.
    Returns canonical DomainHealthReport conforming dictionary.
    """
    clean_domain = clean_domain_name(domain)
    now_ts = int(time.time())

    # Fallback for local or test environments
    if is_local_or_dev_domain(clean_domain):
        return {
            "project_id": project_id,
            "domain": clean_domain,
            "last_scan_at": now_ts,
            "last_change_at": now_ts,
            "days_since_change": 0,
            "drift_status": "NO_CHANGE",
            "score": 100,
            "rating": "EXCELLENT",
            "summary": {
                "overall_health": STATUS_OK,
                "ssl_status": STATUS_OK,
                "ssl_days_left": 365,
                "mail_health": STATUS_OK,
                "web_health": STATUS_OK,
                "dns_health": STATUS_OK,
                "headers_score": "6/6"
            },
            "mail_security": {
                "provider": "Local Dev Mail",
                "mx_status": STATUS_OK,
                "spf_status": STATUS_OK,
                "dkim_status": STATUS_OK,
                "dmarc_status": STATUS_GOOD,
                "dmarc_policy": "reject"
            },
            "web_security": {
                "http_to_https": STATUS_OK,
                "www_canonicalization": STATUS_OK,
                "canonical_url": f"http://{clean_domain}",
                "hsts_enabled": STATUS_GOOD,
                "ipv6_accessible": "No"
            },
            "security_headers": {
                "score": 6,
                "total": 6,
                "hsts": True,
                "csp": True,
                "x_frame_options": True,
                "x_content_type_options": True,
                "referrer_policy": True,
                "permissions_policy": True
            },
            "dns_security": {
                "dnssec_status": STATUS_NOT_CONFIGURED,
                "nameserver_count": 2
            },
            "identified_services": ["Local Environment"],
            "action_items": []
        }

    # 1. Run live crawl via CZ.NIC dns-crawler (no SMTP port 25 checks)
    raw_crawl = _crawl_domain_with_dns_crawler(clean_domain)
    results = raw_crawl.get("results", {}) if isinstance(raw_crawl, dict) else {}
    dns_local = results.get("DNS_LOCAL", {}) or {}
    web_results = results.get("WEB", {}) or {}
    hsts_flag = bool(results.get("HSTS", False))
    parent = raw_crawl.get("parent", {}) if isinstance(raw_crawl, dict) else {}

    # Check unconfigured domain
    if not dns_local.get("WEB4") and not dns_local.get("WEB6") and not dns_local.get("MAIL") and not parent.get("ns"):
        return {
            "project_id": project_id,
            "domain": clean_domain,
            "last_scan_at": now_ts,
            "last_change_at": now_ts,
            "days_since_change": 0,
            "drift_status": "NEW_RECORD",
            "score": 0,
            "rating": "CRITICAL",
            "summary": {
                "overall_health": "UNCONFIGURED",
                "ssl_status": STATUS_ERROR,
                "ssl_days_left": 0,
                "mail_health": "UNCONFIGURED",
                "web_health": "UNCONFIGURED",
                "dns_health": "UNCONFIGURED",
                "headers_score": "0/6"
            },
            "mail_security": {
                "provider": "None",
                "mx_status": STATUS_NA,
                "spf_status": STATUS_NA,
                "dkim_status": STATUS_NA,
                "dmarc_status": STATUS_PROBLEM,
                "dmarc_policy": "missing"
            },
            "web_security": {
                "http_to_https": STATUS_PROBLEM,
                "www_canonicalization": STATUS_PROBLEM,
                "canonical_url": "",
                "hsts_enabled": STATUS_PROBLEM,
                "ipv6_accessible": "No"
            },
            "security_headers": {
                "score": 0,
                "total": 6,
                "hsts": False,
                "csp": False,
                "x_frame_options": False,
                "x_content_type_options": False,
                "referrer_policy": False,
                "permissions_policy": False
            },
            "dns_security": {
                "dnssec_status": STATUS_NOT_CONFIGURED,
                "nameserver_count": 0
            },
            "identified_services": [],
            "action_items": [{
                "id": "unconfigured_domain",
                "category": "DNS",
                "severity": "CRITICAL",
                "title": "Domain Not Configured",
                "description": "This domain has no active DNS A/AAAA or MX records pointing to any web or mail servers.",
                "tip": "Configure DNS records with your registrar or DNS provider.",
                "remediation": "Configure DNS records with your registrar or DNS provider."
            }]
        }

    # 2. Evaluate all categories
    mail_eval = evaluate_mail_security(dns_local)
    web_eval = evaluate_web_security(web_results, hsts_flag)
    ssl_eval = extract_ssl_certificate(web_results, clean_domain)
    headers_eval = analyze_security_headers(web_results)
    dns_eval = evaluate_dns_security(dns_local, parent)
    services_eval = analyze_domain_services(dns_local)

    # 3. Overall Score and Action Items
    score, rating = calculate_overall_score(dns_eval, mail_eval, web_eval, ssl_eval, headers_eval)
    action_items = generate_action_items(dns_eval, mail_eval, web_eval, ssl_eval, headers_eval)

    # 4. Drift Tracking
    current_sig = {
        "nameservers": dns_eval.get("nameservers", []),
        "mx_count": mail_eval.get("mx_count", 0),
        "has_spf": mail_eval.get("has_spf", False),
        "has_dmarc": mail_eval.get("has_dmarc", False),
        "dmarc_policy": mail_eval.get("dmarc_policy", "missing"),
        "ssl_valid": ssl_eval.get("is_valid", False),
        "headers_score": headers_eval.get("score", 0),
        "ipv6": web_eval.get("ipv6_accessible") == "Yes"
    }
    drift_status, last_change_at, days_since_change = track_drift_with_deepdiff(
        current_sig, previous_snapshot, now_ts
    )

    overall_health = STATUS_GOOD if score >= 80 else (STATUS_OK if score >= 60 else STATUS_PROBLEM)

    return {
        "project_id": project_id,
        "domain": clean_domain,
        "last_scan_at": now_ts,
        "last_change_at": last_change_at,
        "days_since_change": days_since_change,
        "drift_status": drift_status,
        "score": score,
        "rating": rating,
        "summary": {
            "overall_health": overall_health,
            "ssl_status": ssl_eval["status"],
            "ssl_days_left": ssl_eval["days_left"],
            "mail_health": mail_eval["mail_health"],
            "web_health": web_eval["web_health"],
            "dns_health": dns_eval["dns_health"],
            "headers_score": headers_eval["headers_score"]
        },
        "mail_security": {
            "provider": mail_eval["provider"],
            "mx_status": mail_eval["mx_status"],
            "spf_status": mail_eval["spf_status"],
            "dkim_status": mail_eval["dkim_status"],
            "dmarc_status": mail_eval["dmarc_status"],
            "dmarc_policy": mail_eval["dmarc_policy"]
        },
        "web_security": {
            "http_to_https": web_eval["http_to_https"],
            "www_canonicalization": web_eval["www_canonicalization"],
            "canonical_url": web_eval["canonical_url"],
            "hsts_enabled": web_eval["hsts_enabled"],
            "ipv6_accessible": web_eval["ipv6_accessible"]
        },
        "security_headers": {
            "score": headers_eval["score"],
            "total": headers_eval["total"],
            "hsts": headers_eval["hsts"],
            "csp": headers_eval["csp"],
            "x_frame_options": headers_eval["x_frame_options"],
            "x_content_type_options": headers_eval["x_content_type_options"],
            "referrer_policy": headers_eval["referrer_policy"],
            "permissions_policy": headers_eval["permissions_policy"]
        },
        "dns_security": {
            "dnssec_status": dns_eval["dnssec_status"],
            "nameserver_count": dns_eval["nameserver_count"]
        },
        "identified_services": services_eval,
        "action_items": action_items,
        "_signature": current_sig
    }
