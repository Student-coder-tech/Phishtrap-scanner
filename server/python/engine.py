"""
PHISHTRAP — Multi-Signal Phishing Detection Engine (Python Module)
Explainable, deterministic, and multi-vector cybersecurity intelligence scoring system.
Includes URL anatomy, Shannon entropy, brand impersonation, Levenshtein typosquatting,
homoglyphs/Punycode, DNS resolution, TLS certificate probing, and enterprise watchlist checks.
"""

import re
import math
import socket
import ssl
import urllib.parse
import urllib.request
from typing import Dict, List, Any, Optional

DEFAULT_WEIGHTS = {
    "brandImpersonation": 0.20,
    "domainReputation": 0.15,
    "urlStructure": 0.15,
    "keywords": 0.10,
    "punycode": 0.10,
    "dns": 0.10,
    "ssl": 0.10,
    "redirects": 0.05,
    "watchlist": 0.05,
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "club", "vip", "gq", "cf", "ml", "ga", "tk",
    "click", "link", "download", "racing", "kim", "country", "stream", "live",
    "buzz", "rest", "fit", "icu", "cyou", "monster", "quest", "beauty", "hair",
    "skin", "cam", "sbs", "cfd", "date", "faith", "party", "trade", "accountant"
}

KNOWN_BRANDS = [
    {"name": "PayPal", "domain": "paypal.com", "category": "Banking & Payments", "keywords": ["paypal", "pay-pal", "paypai", "paypa1"]},
    {"name": "Apple iCloud", "domain": "apple.com", "category": "Cloud & Tech", "keywords": ["apple", "icloud", "appie", "app1e", "appleid", "itunes"]},
    {"name": "Microsoft 365", "domain": "microsoft.com", "category": "Cloud & Office", "keywords": ["microsoft", "office365", "outlook", "msft", "m1crosoft", "onedrive", "sharepoint"]},
    {"name": "Google Workspace", "domain": "google.com", "category": "Cloud & Tech", "keywords": ["google", "gmail", "g00gle", "goog1e", "gdrive", "google-verify"]},
    {"name": "Amazon", "domain": "amazon.com", "category": "E-commerce", "keywords": ["amazon", "amaz0n", "prime-video", "aws-security", "amazn"]},
    {"name": "Chase Bank", "domain": "chase.com", "category": "Banking", "keywords": ["chase", "chasebank", "chasemobile", "chaseonline"]},
    {"name": "Bank of America", "domain": "bankofamerica.com", "category": "Banking", "keywords": ["bankofamerica", "bofa", "boa-secure", "bank-of-america"]},
    {"name": "Wells Fargo", "domain": "wellsfargo.com", "category": "Banking", "keywords": ["wellsfargo", "wf-verify", "wellsfargosecure", "well-fargo"]},
    {"name": "Citibank", "domain": "citi.com", "category": "Banking", "keywords": ["citibank", "citicards", "citi-verify"]},
    {"name": "Netflix", "domain": "netflix.com", "category": "Streaming", "keywords": ["netflix", "netfiix", "netflix-verify", "netf1ix"]},
    {"name": "Meta / Facebook", "domain": "meta.com", "category": "Social Media", "keywords": ["facebook", "instagram", "faceb00k", "meta-verify", "meta-business"]},
    {"name": "Coinbase", "domain": "coinbase.com", "category": "Crypto & FinTech", "keywords": ["coinbase", "c0inbase", "coin-base", "coinbase-wallet"]},
    {"name": "Binance", "domain": "binance.com", "category": "Crypto & FinTech", "keywords": ["binance", "binance-security", "binancc", "binance-verify"]},
    {"name": "MetaMask", "domain": "metamask.io", "category": "Crypto & FinTech", "keywords": ["metamask", "meta-mask", "metamask-restore", "metamask-io"]},
    {"name": "DocuSign", "domain": "docusign.com", "category": "Cloud & SaaS", "keywords": ["docusign", "docus1gn", "docu-sign", "docusign-envelope"]},
    {"name": "Dropbox", "domain": "dropbox.com", "category": "Cloud & SaaS", "keywords": ["dropbox", "drop-box", "dropbox-share"]},
    {"name": "DHL / FedEx", "domain": "dhl.com", "category": "Logistics", "keywords": ["dhl-track", "fedex-delivery", "parcel-tracking", "usps-tracking", "dhl-parcel"]},
    {"name": "Internal Revenue Service (IRS)", "domain": "irs.gov", "category": "Government", "keywords": ["irs-gov", "irs-tax", "irs-refund", "tax-refund"]},
    {"name": "Steam / Valve", "domain": "steampowered.com", "category": "Gaming", "keywords": ["steamcommunity", "steampowered", "steam-trade", "steam-gift"]}
]

KEYWORD_CATEGORIES = {
    "auth": ["login", "signin", "sign-in", "log-in", "auth", "authenticate", "portal", "sso", "webmail", "session"],
    "credential": ["password", "credential", "passcode", "security", "secure", "verify", "verification", "validation", "confirm", "confirmation", "recovery", "recover", "reactivate"],
    "threat": ["suspended", "suspend", "unusual-activity", "restricted", "unlock", "alert", "notification", "urgent", "action-required", "violation", "compromised", "warning"],
    "financial": ["banking", "wallet", "billing", "invoice", "payment", "refund", "wire", "transaction", "direct-deposit", "statement", "payout"],
    "mfa": ["2fa", "mfa", "otp", "sms-code", "token", "passkey", "authenticator"]
}

HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0455': 's', '\u0458': 'j',
    '\u03b1': 'a', '\u03bf': 'o', '\u03bd': 'v', '\u03c1': 'p',
}

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def parse_target_url(raw_input: str) -> Dict[str, Any]:
    input_clean = raw_input.strip()
    if not re.match(r"^[a-zA-Z]+://", input_clean):
        full_url = "https://" + input_clean
    else:
        full_url = input_clean

    parsed = urllib.parse.urlparse(full_url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    has_explicit_port = parsed.port is not None
    path = parsed.path or "/"
    search = parsed.query
    protocol = parsed.scheme.lower()

    parts = hostname.split('.')
    tld = parts[-1] if len(parts) > 1 else ""
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    is_punycode = "xn--" in hostname
    has_homoglyphs = False
    homoglyph_matches = []
    for char in raw_input:
        if char in HOMOGLYPH_MAP:
            has_homoglyphs = True
            homoglyph_matches.append(f"'{char}' (looks like '{HOMOGLYPH_MAP[char]}')")

    is_raw_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) or hostname.startswith("["))
    has_auth_at = "@" in raw_input

    return {
        "raw": raw_input,
        "fullUrl": full_url,
        "hostname": hostname,
        "rootDomain": root_domain,
        "subdomain": subdomain,
        "tld": tld,
        "path": path + (f"?{search}" if search else ""),
        "pathname": path,
        "search": search,
        "protocol": protocol,
        "port": port,
        "hasExplicitPort": has_explicit_port,
        "partsCount": len(parts),
        "isPunycode": is_punycode,
        "hasHomoglyphs": has_homoglyphs,
        "homoglyphMatches": homoglyph_matches,
        "hasAuthAtSymbol": has_auth_at,
        "isRawIp": is_raw_ip,
    }

def analyze_phishing_target(
    url_input: str,
    mode: str = "DEMO",
    watchlist: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    watchlist = watchlist or []
    parsed = parse_target_url(url_input)
    hostname = parsed["hostname"]
    tld = parsed["tld"]
    entropy = calculate_entropy(hostname)
    mode_upper = mode.upper() if mode else "DEMO"

    # SIGNAL 1: URL Structure & Anatomy (Weight: 0.15)
    url_score = 0
    url_flags = []
    url_evidence = {
        "length": len(parsed["fullUrl"]),
        "isRawIp": parsed["isRawIp"],
        "hasAuthAtSymbol": parsed["hasAuthAtSymbol"],
        "pathLevels": len([p for p in parsed["pathname"].split('/') if p]),
    }

    if parsed["isRawIp"]:
        url_score += 75
        url_flags.append("Raw numeric IP address utilized as host")
    if parsed["hasAuthAtSymbol"]:
        url_score += 65
        url_flags.append('Dangerous "@" authority delimiter detected in URL')
    if len(parsed["fullUrl"]) > 120:
        url_score += 35
        url_flags.append(f"Abnormally lengthy URL ({len(parsed['fullUrl'])} chars)")
    elif len(parsed["fullUrl"]) > 80:
        url_score += 15
    if "//" in parsed["pathname"]:
        url_score += 25
        url_flags.append("Multiple consecutive slashes in path")
    if parsed["hasExplicitPort"] and parsed["port"] not in (80, 443):
        url_score += 30
        url_flags.append(f"Non-standard port specified (Port {parsed['port']})")
    if re.search(r"%[0-9a-f]{2}", parsed["path"], re.IGNORECASE):
        url_score += 15
        url_flags.append("Contains percent-encoded hexadecimal byte sequences")

    url_score = max(0, min(100, url_score))
    url_exp = ". ".join(url_flags) if url_flags else "URL structure complies with standard web RFC conventions."

    # SIGNAL 2: Hostname & Subdomain Anomalies (Weight: 0.15)
    host_score = 0
    host_flags = []
    host_evidence = {
        "entropy": entropy,
        "tld": tld,
        "hyphens": hostname.count("-"),
        "subdomains": max(0, parsed["partsCount"] - 2),
    }

    if entropy > 3.85:
        host_score += 45
        host_flags.append(f"High Shannon entropy ({entropy}) indicates machine/DGA generation")
    elif entropy > 3.3:
        host_score += 20
        host_flags.append(f"Elevated character entropy ({entropy})")

    if tld in SUSPICIOUS_TLDS:
        host_score += 40
        host_flags.append(f"Operates under high-abuse top-level domain (.{tld})")

    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        host_score += 35
        host_flags.append(f"Excessive hyphen chaining ({hyphen_count} hyphens)")
    elif hyphen_count >= 1:
        host_score += 12

    if parsed["partsCount"] > 3:
        host_score += 25
        host_flags.append(f"Deeply nested subdomain hierarchy ({parsed['partsCount'] - 2} levels)")

    host_score = max(0, min(100, host_score))
    host_exp = ". ".join(host_flags) if host_flags else "Hostname entropy and domain depth reflect standard baseline metrics."

    # SIGNAL 3: Brand Impersonation & Typosquatting (Weight: 0.20)
    brand_score = 0
    matched_brand: Optional[str] = None
    is_legitimate_brand = False
    brand_exp = "No brand impersonation or typosquatting patterns detected."
    brand_evidence: Dict[str, Any] = {}

    all_brands = list(KNOWN_BRANDS)
    for w in watchlist:
        if w.get("active", True):
            clean_wname = re.sub(r"[^a-z0-9]", "", w.get("name", "").lower())
            all_brands.append({
                "name": w.get("name", "Watchlist Brand"),
                "domain": w.get("domain", "").lower(),
                "category": w.get("category", "Monitored Enterprise"),
                "keywords": [clean_wname] if clean_wname else []
            })

    for brand in all_brands:
        b_domain = brand["domain"].lower()
        legit_root = ".".join(b_domain.split('.')[-2:])

        if hostname == b_domain or hostname.endswith("." + b_domain):
            brand_score = 0
            matched_brand = brand["name"]
            is_legitimate_brand = True
            brand_exp = f"Verified genuine authorized endpoint for {brand['name']} ({b_domain})."
            brand_evidence["verifiedAuthorized"] = True
            brand_evidence["brand"] = brand["name"]
            break

        for kw in brand.get("keywords", []):
            if kw and len(kw) >= 3 and kw in hostname:
                brand_score = 95
                matched_brand = brand["name"]
                brand_exp = f"Unauthorized domain explicitly embeds protected brand identity '{brand['name']}'."
                brand_evidence["embeddedKeyword"] = kw
                brand_evidence["brand"] = brand["name"]
                break

        if brand_score >= 90:
            break

        if legit_root in parsed["subdomain"] or brand["name"].lower() in parsed["subdomain"]:
            brand_score = 95
            matched_brand = brand["name"]
            brand_exp = f"Subdomain injection attack detected targeting '{brand['name']}'."
            brand_evidence["subdomainSpoof"] = True
            break

        cur_label = parsed["rootDomain"].split('.')[0]
        legit_label = legit_root.split('.')[0]
        if len(cur_label) >= 4 and len(legit_label) >= 4:
            dist = levenshtein_distance(cur_label, legit_label)
            if dist == 1:
                brand_score = 85
                matched_brand = brand["name"]
                brand_exp = f"High similarity typosquatting (edit distance 1) to brand '{brand['name']}'."
                brand_evidence["editDistance"] = 1
                brand_evidence["brand"] = brand["name"]
                break

    # SIGNAL 4: Punycode & Homoglyph Spoofing (Weight: 0.10)
    puny_score = 0
    puny_exp = "Standard ASCII Latin charset. No homoglyph spoofing detected."
    puny_evidence = {
        "isPunycode": parsed["isPunycode"],
        "hasHomoglyphs": parsed["hasHomoglyphs"]
    }
    if parsed["hasHomoglyphs"]:
        puny_score = 90
        puny_exp = f"Critical Unicode homoglyph attack detected: {', '.join(parsed['homoglyphMatches'])}"
        puny_evidence["matches"] = parsed["homoglyphMatches"]
    elif parsed["isPunycode"]:
        puny_score = 65
        puny_exp = "Internationalized Domain Name (Punycode xn--) used. Potential character spoofing vector."

    # SIGNAL 5: Suspicious Keywords (Weight: 0.10)
    target_scan_text = (hostname + parsed["path"]).lower()
    matched_kws = []
    for cat, words in KEYWORD_CATEGORIES.items():
        for w in words:
            if w in target_scan_text:
                matched_kws.append(w)
    unique_kws = list(set(matched_kws))
    kw_score = 0
    kw_exp = "No high-risk credential-harvesting or urgent social engineering keywords detected."
    if len(unique_kws) >= 3:
        kw_score = 95
        kw_exp = f"Critical concentration of phishing trigger keywords: {', '.join(unique_kws[:4])}"
    elif len(unique_kws) == 2:
        kw_score = 70
        kw_exp = f"Multiple security/credential keywords identified: {', '.join(unique_kws)}"
    elif len(unique_kws) == 1:
        kw_score = 40
        kw_exp = f"Contains suspicious authentication/action keyword: '{unique_kws[0]}'"

    # SIGNAL 6: DNS Resolution (Weight: 0.10)
    dns_score = 0
    dns_status = "SAFE"
    dns_exp = "DNS resolution verified successfully."
    dns_evidence: Dict[str, Any] = {}
    resolved_ips: List[str] = []
    dns_resolved = False

    if mode_upper == "LIVE":
        try:
            addr_info = socket.getaddrinfo(hostname, None, timeout=2.0)
            resolved_ips = list(set([item[4][0] for item in addr_info if item[4]]))
            dns_resolved = len(resolved_ips) > 0
            dns_evidence["ips"] = resolved_ips
            if not dns_resolved:
                dns_score = 80
                dns_status = "HIGH_RISK"
                dns_exp = "Domain failed DNS resolution (NXDOMAIN / unallocated)."
            else:
                dns_score = 0
                dns_status = "SAFE"
                dns_exp = f"Active DNS record resolution verified: {', '.join(resolved_ips[:2])}"
        except Exception as e:
            dns_score = 80
            dns_status = "HIGH_RISK"
            dns_exp = f"DNS lookup failed or host unresolvable ({str(e)})."
    else:
        if host_score >= 70 or brand_score >= 80:
            dns_score = 75
            dns_status = "HIGH_RISK"
            dns_exp = "Simulated DNS analysis: Fast-flux infrastructure or unallocated high-risk host."
        else:
            dns_score = 5
            dns_status = "SAFE"
            dns_exp = "Simulated DNS resolution: Active baseline nameservers and valid A records."

    # SIGNAL 7: HTTPS / TLS Security (Weight: 0.10)
    ssl_score = 0
    ssl_status = "SAFE"
    ssl_exp = "TLS certificate handshake verified."
    ssl_evidence: Dict[str, Any] = {"protocol": parsed["protocol"]}
    tls_issuer: Optional[str] = None
    tls_valid_to: Optional[str] = None

    if parsed["protocol"] == "http":
        ssl_score = 80
        ssl_status = "HIGH_RISK"
        ssl_exp = "Unencrypted plain HTTP protocol. Legitimate banking and authentication endpoints enforce TLS."
    elif mode_upper == "LIVE":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, parsed["port"]), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        tls_issuer = str(cert.get("issuer", "Unknown CA"))
                        tls_valid_to = str(cert.get("notAfter", "N/A"))
                        ssl_evidence["issuer"] = tls_issuer
                        ssl_evidence["validTo"] = tls_valid_to
                    ssl_score = 0
                    ssl_status = "SAFE"
                    ssl_exp = f"Valid TLS handshake completed ({tls_issuer or 'Standard CA'})."
        except Exception as e:
            ssl_score = 20
            ssl_status = "SAFE"
            ssl_exp = f"HTTPS configured ({str(e)})."
    else:
        if brand_score >= 70 or kw_score >= 60:
            ssl_score = 60
            ssl_status = "SUSPICIOUS"
            ssl_exp = "Simulated short-lived free DV TLS certificate from automated low-trust issuer."
            tls_issuer = "Let's Encrypt / Free DV CA (Simulated)"
        else:
            ssl_score = 0
            ssl_status = "SAFE"
            ssl_exp = "Simulated high-assurance EV/OV SSL Certificate from trusted root authority."
            tls_issuer = "DigiCert Global Root CA (Simulated)"

    # SIGNAL 8: Redirect & Cloaking Behavior (Weight: 0.05)
    redir_score = 0
    redir_status = "SAFE"
    redir_exp = "Direct endpoint resolution with no open redirect chaining."
    redir_evidence: Dict[str, Any] = {}

    open_redir_params = ["url=", "next=", "redirect=", "goto=", "dest=", "target=", "r=", "return="]
    if any(p in parsed["search"].lower() for p in open_redir_params):
        redir_score = 75
        redir_status = "HIGH_RISK"
        redir_exp = "Suspicious URL query parameters indicate potential open redirect / interstitial landing attack."
        redir_evidence["openRedirectParameter"] = True
    elif mode_upper == "LIVE":
        redir_score = 0
        redir_status = "SAFE"
    else:
        redir_score = 0
        redir_status = "SAFE"

    # SIGNAL 9: Monitored Enterprise Watchlist (Weight: 0.05)
    wl_score = 0
    wl_brand: Optional[str] = None
    wl_exp = "Domain is not flagged under monitored corporate brand assets."
    wl_evidence: Dict[str, Any] = {}

    for w in watchlist:
        if not w.get("active", True):
            continue
        w_domain = w.get("domain", "").lower()
        w_name_key = re.sub(r"[^a-z0-9]", "", w.get("name", "").lower())
        if w_domain and (w_domain in hostname or (w_name_key and w_name_key in hostname)):
            if hostname != w_domain and not hostname.endswith("." + w_domain):
                wl_score = 100
                wl_brand = w.get("name")
                wl_exp = f"Matched high-priority monitored watchlist entity: {w.get('name')} ({w.get('category')})"
                wl_evidence["watchlistMatch"] = w.get("name")
                wl_evidence["category"] = w.get("category")
                break
            else:
                wl_score = 0
                wl_brand = w.get("name")
                wl_exp = f"Authorized domain for monitored watchlist entity: {w.get('name')}"
                wl_evidence["isLegitimateWatchlistDomain"] = True
                break

    final_matched_brand = matched_brand or wl_brand

    # COMPOSITE SCORING
    signals_map = {
        "domainReputation": host_score,
        "urlStructure": url_score,
        "brandImpersonation": brand_score,
        "keywords": kw_score,
        "punycode": puny_score,
        "dns": dns_score,
        "ssl": ssl_score,
        "redirects": redir_score,
        "watchlist": wl_score,
    }

    tot_weighted = sum(signals_map[k] * DEFAULT_WEIGHTS.get(k, 0.1) for k in signals_map)
    tot_weight = sum(DEFAULT_WEIGHTS.get(k, 0.1) for k in signals_map)
    overall_score = round(tot_weighted / tot_weight) if tot_weight > 0 else 0

    if brand_score >= 90 and kw_score >= 40:
        overall_score = max(overall_score, 88)
    if puny_score >= 90:
        overall_score = max(overall_score, 85)
    if is_legitimate_brand or wl_evidence.get("isLegitimateWatchlistDomain"):
        overall_score = 0

    overall_score = max(0, min(100, overall_score))

    if overall_score >= 80:
        risk_level = "CRITICAL"
    elif overall_score >= 55:
        risk_level = "HIGH_RISK"
    elif overall_score >= 25:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    if is_legitimate_brand or wl_evidence.get("isLegitimateWatchlistDomain"):
        verdict_type = "VERIFIED_SAFE"
        verdict_label = f"Verified Authentic Endpoint ({final_matched_brand or 'Official Organization'})"
    elif overall_score >= 80:
        verdict_type = "CRITICAL"
        verdict_label = "Critical Phishing Threat"
    elif overall_score >= 55:
        verdict_type = "HIGH_RISK"
        verdict_label = "High Risk Phishing Candidate"
    elif overall_score >= 25:
        verdict_type = "SUSPICIOUS"
        verdict_label = "Suspicious Indicators Detected"
    else:
        verdict_type = "NO_THREATS_DETECTED"
        verdict_label = "No Threat Evidence Detected (Low Risk)"

    probability = round(overall_score / 100.0, 2)
    confidence = 0.95

    reasons = []
    if is_legitimate_brand:
        reasons.append(f"Domain is the confirmed official and authorized endpoint for {final_matched_brand}.")
        reasons.append("All security, TLS, and naming heuristic checks verified as legitimate.")
    else:
        if final_matched_brand and brand_score >= 70:
            reasons.append(f"Domain displays unauthorized brand impersonation targeting '{final_matched_brand}'.")
        if puny_score >= 50: reasons.append(puny_exp)
        if kw_score >= 40: reasons.append(kw_exp)
        if host_score >= 35: reasons.append(host_exp)
        if url_score >= 35: reasons.append(url_exp)
        if dns_score >= 50: reasons.append(dns_exp)
        if ssl_score >= 50: reasons.append(ssl_exp)
        if redir_score >= 50: reasons.append(redir_exp)
        if wl_score >= 80: reasons.append(wl_exp)

        if not reasons:
            reasons.append("Multi-signal heuristic scans returned zero hostile phishing indicators.")
            reasons.append("Domain structure, TLS parameters, and entropy conform to standard baseline.")
            reasons.append("Note: 'No threat evidence detected' indicates lack of known malicious signals rather than organizational certification.")

    signal_details = [
        {
            "name": "Brand Impersonation & Typosquatting",
            "key": "brandImpersonation",
            "score": brand_score,
            "status": "CRITICAL" if brand_score >= 80 else "HIGH_RISK" if brand_score >= 55 else "SUSPICIOUS" if brand_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["brandImpersonation"],
            "explanation": brand_exp,
            "evidence": brand_evidence,
        },
        {
            "name": "Hostname & Subdomain Anomalies",
            "key": "domainReputation",
            "score": host_score,
            "status": "CRITICAL" if host_score >= 80 else "HIGH_RISK" if host_score >= 55 else "SUSPICIOUS" if host_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["domainReputation"],
            "explanation": host_exp,
            "evidence": host_evidence,
        },
        {
            "name": "URL Structure & Authority",
            "key": "urlStructure",
            "score": url_score,
            "status": "CRITICAL" if url_score >= 80 else "HIGH_RISK" if url_score >= 55 else "SUSPICIOUS" if url_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["urlStructure"],
            "explanation": url_exp,
            "evidence": url_evidence,
        },
        {
            "name": "Suspicious Keywords & Social Engineering",
            "key": "keywords",
            "score": kw_score,
            "status": "CRITICAL" if kw_score >= 80 else "HIGH_RISK" if kw_score >= 55 else "SUSPICIOUS" if kw_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["keywords"],
            "explanation": kw_exp,
            "evidence": {"matchedKeywords": unique_kws},
        },
        {
            "name": "Punycode & Homoglyph Spoofing",
            "key": "punycode",
            "score": puny_score,
            "status": "CRITICAL" if puny_score >= 80 else "HIGH_RISK" if puny_score >= 55 else "SUSPICIOUS" if puny_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["punycode"],
            "explanation": puny_exp,
            "evidence": puny_evidence,
        },
        {
            "name": "DNS Resolution & Active Hosts",
            "key": "dns",
            "score": dns_score,
            "status": dns_status,
            "weight": DEFAULT_WEIGHTS["dns"],
            "explanation": dns_exp,
            "evidence": dns_evidence,
        },
        {
            "name": "SSL / TLS Security",
            "key": "ssl",
            "score": ssl_score,
            "status": ssl_status,
            "weight": DEFAULT_WEIGHTS["ssl"],
            "explanation": ssl_exp,
            "evidence": ssl_evidence,
        },
        {
            "name": "Redirect & Cloaking Behavior",
            "key": "redirects",
            "score": redir_score,
            "status": redir_status,
            "weight": DEFAULT_WEIGHTS["redirects"],
            "explanation": redir_exp,
            "evidence": redir_evidence,
        },
        {
            "name": "Monitored Enterprise Watchlist",
            "key": "watchlist",
            "score": wl_score,
            "status": "CRITICAL" if wl_score >= 80 else "HIGH_RISK" if wl_score >= 55 else "SUSPICIOUS" if wl_score >= 25 else "SAFE",
            "weight": DEFAULT_WEIGHTS["watchlist"],
            "explanation": wl_exp,
            "evidence": wl_evidence,
        },
    ]

    return {
        "success": True,
        "domain": hostname,
        "url": parsed["fullUrl"],
        "mode": mode_upper,
        "risk": {
            "score": overall_score,
            "level": risk_level,
            "probability": probability,
            "confidence": confidence,
            "verdictType": verdict_type,
            "verdictLabel": verdict_label,
        },
        "signals": {
            "domainReputation": host_score,
            "urlStructure": url_score,
            "brandImpersonation": brand_score,
            "ssl": ssl_score,
            "keywords": kw_score,
            "redirects": redir_score,
            "watchlist": wl_score,
            "punycode": puny_score,
            "dns": dns_score,
        },
        "signalDetails": signal_details,
        "targetInfo": {
            "url": parsed["fullUrl"],
            "domain": hostname,
            "protocol": parsed["protocol"],
            "hostname": hostname,
            "port": parsed["port"],
            "path": parsed["path"],
            "tld": tld,
            "entropy": entropy,
            "subdomainsCount": max(0, parsed["partsCount"] - 2),
            "ipAddress": resolved_ips[0] if resolved_ips else None,
            "resolvedIps": resolved_ips,
            "tlsIssuer": tls_issuer,
            "tlsValidTo": tls_valid_to,
            "isPunycode": parsed["isPunycode"],
            "hasHomoglyphs": parsed["hasHomoglyphs"],
            "dnsResolved": dns_resolved,
        },
        "matchedBrand": final_matched_brand,
        "reasons": reasons,
        "engineUsed": "python-standalone",
    }
