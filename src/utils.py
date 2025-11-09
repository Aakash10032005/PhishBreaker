import socket
import ssl
import dns.resolver
import whois
from datetime import datetime
from urllib.parse import urlparse
import httpx

# Use small timeouts to keep UI responsive
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 5
SSL_TIMEOUT = 5

def _normalize_domain(domain):
    # remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain.strip().lower()

def safe_dns_lookup(domain):
    """Return (ttl, resolves_bool)."""
    domain = _normalize_domain(domain)
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'A')
        ttl = answers.rrset.ttl if answers.rrset else None
        return ttl, True
    except Exception:
        return None, False

def get_domain_age(domain):
    """Return domain age in days (int) or None."""
    domain = _normalize_domain(domain)
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        if isinstance(creation, str):
            # whois sometimes returns strings — try parse
            try:
                creation = datetime.fromisoformat(creation)
            except Exception:
                return None
        return (datetime.now() - creation).days
    except Exception:
        return None

def get_ssl_info(domain):
    """Return dict with 'issued_to','issued_by','days_left' or None."""
    domain = _normalize_domain(domain)
    try:
        context = ssl.create_default_context()
        # create_connection will raise on timeout if not reachable
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # issuer and subject are tuples of tuples
                issuer = cert.get('issuer', ())
                subject = cert.get('subject', ())
                issued_by = None
                issued_to = None
                try:
                    # issuer is list of tuples (('organizationName','Let\'s Encrypt'),)
                    for part in issuer:
                        for k, v in part:
                            if k.lower() in ('organizationname', 'o'):
                                issued_by = v
                                break
                        if issued_by:
                            break
                except Exception:
                    issued_by = None
                try:
                    for part in subject:
                        for k, v in part:
                            if k.lower() in ('commonname', 'cn'):
                                issued_to = v
                                break
                        if issued_to:
                            break
                except Exception:
                    issued_to = None

                not_after = cert.get('notAfter')  # e.g. 'Jun  1 12:00:00 2025 GMT'
                days_left = None
                if not_after:
                    try:
                        # Try multiple formats
                        try:
                            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        except Exception:
                            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y")
                        days_left = (dt - datetime.utcnow()).days
                    except Exception:
                        days_left = None

                return {
                    "issued_to": issued_to,
                    "issued_by": issued_by,
                    "days_left": days_left
                }
    except Exception:
        return None

def get_http_headers(url):
    """Return dict {server, redirects, has_csp} or None."""
    try:
        with httpx.Client(follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
            # Some servers block HEAD — try HEAD first, fallback to GET
            try:
                resp = client.head(url)
            except Exception:
                resp = client.get(url)
            headers = resp.headers
            # number of redirects (httpx stores redirects in history)
            redirects = len(getattr(resp, 'history', []))
            server = headers.get('server', None)
            # content-security-policy presence (case-insensitive)
            has_csp = any(h.lower() == 'content-security-policy' for h in headers.keys())
            return {
                "server": server,
                "redirects": redirects,
                "has_csp": has_csp
            }
    except Exception:
        return None
