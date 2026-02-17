"""Website and link scanner for legitimacy verification."""

import re
from typing import Dict, List
from datetime import datetime
from urllib.parse import urlparse

# Mock database of known malicious/phishing URLs
KNOWN_MALICIOUS_URLS = {
    "malware-download.com": {
        "legitimacy_score": 5,
        "threat_type": "Malware Distribution",
        "status": "Malicious",
        "ssl_valid": False,
        "last_seen": "2026-02-16",
        "threat_indicators": ["Malware", "Drive-by Download", "Exploit Kit"],
        "categories": ["Malware"]
    },
    "phishing-bank.net": {
        "legitimacy_score": 8,
        "threat_type": "Phishing",
        "status": "Phishing",
        "ssl_valid": False,
        "last_seen": "2026-02-15",
        "threat_indicators": ["Phishing", "Credential Harvesting"],
        "categories": ["Phishing"]
    },
    "fake-paypal-login.org": {
        "legitimacy_score": 10,
        "threat_type": "Phishing",
        "status": "Phishing",
        "ssl_valid": False,
        "last_seen": "2026-02-14",
        "threat_indicators": ["Phishing", "Credential Harvesting", "Impersonation"],
        "categories": ["Phishing"]
    },
    "cryptomining-infected.xyz": {
        "legitimacy_score": 15,
        "threat_type": "Cryptominer",
        "status": "Suspicious",
        "ssl_valid": False,
        "last_seen": "2026-02-13",
        "threat_indicators": ["Cryptomining", "Resource Abuse"],
        "categories": ["Suspicious"]
    },
}

# Known legitimate domains (whitelist)
KNOWN_LEGITIMATE_URLS = {
    "google.com": {
        "legitimacy_score": 100,
        "threat_type": "Legitimate",
        "status": "Safe",
        "ssl_valid": True,
        "last_verified": "2026-02-17",
        "threat_indicators": [],
        "categories": ["Technology"]
    },
    "github.com": {
        "legitimacy_score": 100,
        "threat_type": "Legitimate",
        "status": "Safe",
        "ssl_valid": True,
        "last_verified": "2026-02-17",
        "threat_indicators": [],
        "categories": ["Technology"]
    },
    "microsoft.com": {
        "legitimacy_score": 100,
        "threat_type": "Legitimate",
        "status": "Safe",
        "ssl_valid": True,
        "last_verified": "2026-02-17",
        "threat_indicators": [],
        "categories": ["Technology"]
    },
    "amazon.com": {
        "legitimacy_score": 100,
        "threat_type": "Legitimate",
        "status": "Safe",
        "ssl_valid": True,
        "last_verified": "2026-02-17",
        "threat_indicators": [],
        "categories": ["E-commerce"]
    },
}


def normalize_url(url: str) -> str:
    """Normalize URL to domain name."""
    # Remove protocol
    url = url.replace("http://", "").replace("https://", "").replace("www.", "")
    # Get domain only
    domain = urlparse(f"http://{url}").netloc or url.split("/")[0]
    return domain.lower()


def check_phishing_patterns(url: str) -> List[str]:
    """Check for common phishing patterns in URL."""
    patterns = []
    
    # Check for IP address instead of domain
    if re.match(r'https?://(\d+\.){3}\d+', url):
        patterns.append("Uses IP address instead of domain")
    
    # Check for suspicious characters
    if '%' in url or '&#' in url:
        patterns.append("Contains encoded characters")
    
    # Check for URL shorteners
    if any(shortener in url for shortener in ['bit.ly', 'tinyurl.com', 'short.link']):
        patterns.append("Uses URL shortener")
    
    # Check for homograph attacks (similar looking domains)
    suspicious_domains = ['paypa1.com', 'amaz0n.com', 'micr0soft.com', 'g00gle.com']
    if any(suspicious in url for suspicious in suspicious_domains):
        patterns.append("Homograph attack detected")
    
    # Check for excessive subdomains
    domain_parts = urlparse(url).netloc.split('.')
    if len(domain_parts) > 4:
        patterns.append("Excessive subdomains")
    
    return patterns


def scan_url(url: str) -> Dict:
    """Scan a URL for legitimacy and threats."""
    domain = normalize_url(url)
    
    # Check whitelist first
    if domain in KNOWN_LEGITIMATE_URLS:
        return {
            "url": url,
            "domain": domain,
            "status": KNOWN_LEGITIMATE_URLS[domain]["status"],
            "legitimacy_score": KNOWN_LEGITIMATE_URLS[domain]["legitimacy_score"],
            "threat_type": KNOWN_LEGITIMATE_URLS[domain]["threat_type"],
            "ssl_valid": KNOWN_LEGITIMATE_URLS[domain]["ssl_valid"],
            "threat_indicators": KNOWN_LEGITIMATE_URLS[domain]["threat_indicators"],
            "categories": KNOWN_LEGITIMATE_URLS[domain]["categories"],
            "last_checked": datetime.now().isoformat(),
            "phishing_patterns": []
        }
    
    # Check blacklist
    if domain in KNOWN_MALICIOUS_URLS:
        return {
            "url": url,
            "domain": domain,
            "status": KNOWN_MALICIOUS_URLS[domain]["status"],
            "legitimacy_score": KNOWN_MALICIOUS_URLS[domain]["legitimacy_score"],
            "threat_type": KNOWN_MALICIOUS_URLS[domain]["threat_type"],
            "ssl_valid": KNOWN_MALICIOUS_URLS[domain]["ssl_valid"],
            "threat_indicators": KNOWN_MALICIOUS_URLS[domain]["threat_indicators"],
            "categories": KNOWN_MALICIOUS_URLS[domain]["categories"],
            "last_checked": datetime.now().isoformat(),
            "phishing_patterns": check_phishing_patterns(url)
        }
    
    # Unknown domain - perform heuristic analysis
    phishing_patterns = check_phishing_patterns(url)
    
    # Calculate legitimacy score based on patterns
    score = 75  # Default for unknown
    if phishing_patterns:
        score -= len(phishing_patterns) * 10
    
    # Check for HTTPS
    if not url.startswith("https://"):
        score -= 15
    
    score = max(0, min(100, score))  # Clamp between 0-100
    
    # Determine status based on score
    if score >= 80:
        status = "Safe"
    elif score >= 60:
        status = "Suspicious"
    elif score >= 40:
        status = "Risky"
    else:
        status = "Malicious"
    
    return {
        "url": url,
        "domain": domain,
        "status": status,
        "legitimacy_score": score,
        "threat_type": "Unknown" if score >= 60 else "Potential Threat",
        "ssl_valid": url.startswith("https://"),
        "threat_indicators": [],
        "categories": ["Uncategorized"],
        "last_checked": datetime.now().isoformat(),
        "phishing_patterns": phishing_patterns
    }


def batch_scan_urls(urls: List[str]) -> List[Dict]:
    """Scan multiple URLs."""
    results = []
    for url in urls:
        results.append(scan_url(url))
    return results


def get_legitimacy_badge(score: int) -> str:
    """Get HTML badge for legitimacy score."""
    if score >= 90:
        return "🟢 Legitimate"
    elif score >= 75:
        return "🟡 Probably Safe"
    elif score >= 50:
        return "🟠 Suspicious"
    else:
        return "🔴 Dangerous"


def get_threat_summary(scan_result: Dict) -> str:
    """Get human-readable threat summary."""
    patterns = scan_result.get("phishing_patterns", [])
    
    if scan_result["status"] == "Safe":
        return "This website appears to be legitimate and safe."
    elif scan_result["status"] == "Malicious":
        return f"⚠️ DANGER: This website is known to be malicious. Threat: {scan_result.get('threat_type')}"
    elif scan_result["status"] == "Phishing":
        return f"⚠️ WARNING: This appears to be a phishing website. Do not enter sensitive information."
    elif scan_result["status"] == "Suspicious":
        indicators = ", ".join(patterns) if patterns else "Unknown indicators"
        return f"⚠️ CAUTION: This website shows suspicious signs. {indicators}"
    else:
        return "Unable to determine website safety."


if __name__ == "__main__":
    # Test
    test_urls = [
        "https://google.com",
        "https://malware-download.com",
        "https://phishing-bank.net",
        "http://suspicious-site.xyz"
    ]
    
    for url in test_urls:
        result = scan_url(url)
        print(f"\nURL: {url}")
        print(f"Status: {result['status']}")
        print(f"Score: {result['legitimacy_score']}/100")
        print(f"Summary: {get_threat_summary(result)}")
