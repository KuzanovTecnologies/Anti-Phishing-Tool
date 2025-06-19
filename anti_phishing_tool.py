import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import datetime
import requests

# Use the correct whois package
try:
    import whois
except ImportError:
    messagebox.showerror("Error", "The 'python-whois' package is not installed.\nInstall it using: pip install python-whois")
    raise

# Optional: Google Safe Browsing API
API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

def check_url_heuristics(url):
    parsed = urlparse(url)
    if len(url) > 75:
        return "URL too long — suspicious"
    if "@" in url or "-" in parsed.netloc:
        return "Special characters detected — suspicious"
    return "Passed heuristics"

def is_registered_recently(url):
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
            return "Domain registered recently — suspicious"
        return "Domain age OK"
    except Exception as e:
        return f"WHOIS lookup failed — suspicious ({e})"

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(api_url, json=payload)
        if res.json().get("matches"):
            return "Flagged by Google Safe Browsing!"
        else:
            return "Not flagged by Google Safe Browsing"
    except Exception as e:
        return f"Error contacting Google Safe Browsing: {e}"

def analyze():
    url = entry.get().strip()
    if not url.startswith("http"):
        url = "http://" + url

    heuristics = check_url_heuristics(url)
    whois_result = is_registered_recently(url)
    gsb_result = check_google_safe_browsing(url)

    result_text = (
        f"URL: {url}\n\n"
        f"Heuristics: {heuristics}\n"
        f"WHOIS: {whois_result}\n"
        f"Google Safe Browsing: {gsb_result}"
    )
    messagebox.showinfo("Analysis Result", result_text)

# GUI Setup
root = tk.Tk()
root.title("Anti-Phishing Tool")
root.geometry("400x250")

tk.Label(root, text="Enter URL to check:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=50)
entry.pack()

tk.Button(root, text="Analyze URL", command=analyze, bg="green", fg="white").pack(pady=20)

root.mainloop()