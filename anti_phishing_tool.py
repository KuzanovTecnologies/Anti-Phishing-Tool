import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import datetime
import requests

# WHOIS import with error alert
try:
    import whois
except ImportError:
    messagebox.showerror("Error", "The 'python-whois' package is not installed.\nInstall it using:\n\npip install python-whois")
    raise

# Optional: Google Safe Browsing API
API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"  # <-- Replace with your key

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

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
            return f"Domain registered {age} days ago — suspicious"
        return f"Domain age OK ({age} days old)"
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
        res = requests.post(api_url, json=payload, timeout=5)
        if res.status_code != 200:
            return f"GSB API error: HTTP {res.status_code}"
        if res.json().get("matches"):
            return "⚠️ Flagged by Google Safe Browsing!"
        else:
            return "✅ Not flagged by Google Safe Browsing"
    except Exception as e:
        return f"Error contacting Google Safe Browsing: {e}"

def show_result_window(text):
    result_win = tk.Toplevel(root)
    result_win.title("Analysis Result")
    result_win.geometry("500x400")

    txt = tk.Text(result_win, wrap="word", font=("Courier", 10))
    txt.insert("1.0", text)
    txt.config(state="disabled")
    txt.pack(expand=True, fill="both")

def analyze():
    url = entry.get().strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    if not is_valid_url(url):
        messagebox.showerror("Invalid URL", "Please enter a valid URL (e.g., example.com or https://example.com)")
        return

    status_label.config(text="Analyzing URL...")
    root.update()

    heuristics = check_url_heuristics(url)
    whois_result = is_registered_recently(url)
    gsb_result = check_google_safe_browsing(url)

    result_text = (
        f"🔍 URL Analysis Report\n"
        f"{'-'*40}\n"
        f"URL: {url}\n\n"
        f"Heuristics: {heuristics}\n"
        f"WHOIS Check: {whois_result}\n"
        f"Google Safe Browsing: {gsb_result}\n"
    )

    show_result_window(result_text)
    status_label.config(text="Analysis complete!")

# GUI Setup
root = tk.Tk()
root.title("Anti-Phishing Tool")
root.geometry("450x300")

tk.Label(root, text="Enter URL to check:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=50)
entry.pack()

tk.Button(root, text="Analyze URL", command=analyze, bg="green", fg="white", font=("Arial", 11)).pack(pady=20)
status_label = tk.Label(root, text="", fg="blue")
status_label.pack()

root.mainloop()
