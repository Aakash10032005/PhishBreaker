import re
from urllib.parse import urlparse
from src.utils import safe_dns_lookup, get_domain_age, get_ssl_info, get_http_headers

IP_REGEX = re.compile(r'\d+\.\d+\.\d+\.\d+')

def extract_basic_features(url):
    try:
        # Ensure URL has a scheme for parsing
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc or ''
        path = parsed.path or ''
    except Exception:
        # Handle invalid URLs gracefully
        domain = ''
        path = ''
        parsed = None

    return {
        "domain": domain,
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "https": 1 if parsed and parsed.scheme == "https" else 0,
        "has_ip": 1 if re.match(r'\b\d{1,3}(\.\d{1,3}){3}\b', domain) else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdirs": path.count('/'),
        "num_params": url.count('='),
        "num_fragments": url.count('#'),
        "contains_login": int("login" in url.lower()),
        "contains_secure": int("secure" in url.lower()),
        "contains_update": int("update" in url.lower()),
        "contains_pay": int("pay" in url.lower()),
        "contains_account": int("account" in url.lower()),
        "contains_verify": int("verify" in url.lower()),
        "contains_bank": int("bank" in url.lower()),
    }


def extract_network_features(url):
    """
    DNS/WHOIS/SSL/HTTP features. May be slower (network calls).
    Returns dict with dns_ttl, dns_resolves, domain_age, ssl_days_left, ssl_issuer,
    redirects, has_csp, server.
    """
    parsed = urlparse(url if '://' in url else 'http://' + url)
    domain = parsed.netloc
    net_features = {
        "dns_ttl": None,
        "dns_resolves": 0,
        "domain_age": None,
        "ssl_days_left": None,
        "ssl_issuer": None,
        "redirects": None,
        "has_csp": None,
        "server": None
    }

    ttl, resolves = safe_dns_lookup(domain)
    net_features["dns_ttl"] = ttl
    net_features["dns_resolves"] = 1 if resolves else 0

    age = get_domain_age(domain)
    net_features["domain_age"] = age

    ssl_info = get_ssl_info(domain)
    if ssl_info:
        net_features["ssl_days_left"] = ssl_info.get("days_left")
        net_features["ssl_issuer"] = ssl_info.get("issued_by")

    headers = get_http_headers(url)
    if headers:
        net_features["redirects"] = headers.get("redirects")
        net_features["has_csp"] = 1 if headers.get("has_csp") else 0
        net_features["server"] = headers.get("server")

    return net_features

def extract_features(url, include_network=False):
    """
    Returns merged features dict. If include_network is True, network lookups are run.
    """
    basic = extract_basic_features(url)
    if include_network:
        net = extract_network_features(url)
        return {**basic, **net}
    else:
        return basic
