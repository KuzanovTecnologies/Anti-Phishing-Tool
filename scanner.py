from urllib.parse import urlparse
import datetime
import requests

# WHOIS import with fallback
try:
    import whois
except ImportError:
    raise ImportError("Install python-whois with: pip install python-whois")

# Google Safe Browsing API Key
API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

def check_url_heuristics(url):
    """
    Basic heuristic rules for phishing detection.
    """
    parsed = urlparse(url)
    if len(url) > 75:
        return "URL too long — suspicious"
    if "@" in url or "-" in parsed.netloc:
        return "Special characters detected — suspicious"
    if parsed.netloc.count('.') > 3:
        return "Too many subdomains — suspicious"
    return "Passed heuristics"

def is_registered_recently(url):
    """
    WHOIS domain age check.
    """
    domain = urlparse(url).netloc
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if not creation:
            return "WHOIS creation date missing — suspicious"
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.datetime.now() - creation).days
        if age < 30:
            return f"Domain registered recently ({age} days ago) — suspicious"
        return f"Domain age is {age} days — OK"
    except Exception as e:
        return f"WHOIS lookup failed — suspicious ({e})"

def check_google_safe_browsing(url):
    """
    Check URL with Google Safe Browsing API.
    """
    if not API_KEY or API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        return "Google Safe Browsing not enabled (API key missing)"
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(api_url, json=payload, timeout=5)
        if res.status_code != 200:
            return f"Safe Browsing error (HTTP {res.status_code})"
        if res.json().get("matches"):
            return "Flagged by Google Safe Browsing!"
        else:
            return "Not flagged by Google Safe Browsing"
    except Exception as e:
        return f"Error contacting Google Safe Browsing: {e}"