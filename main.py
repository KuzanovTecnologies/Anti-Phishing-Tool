import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import os
from scanner import *

# --- Modern GUI Theme ---
BG_COLOR = "#000000"
FG_COLOR = "#39FF14"
BTN_COLOR = "#000000"
BTN_HOVER = "#00b140"
BTN_TEXT = "#39FF14"
BORDER_COLOR = "#00b140"
FONT = ("Consolas", 12, "bold")
TITLE_FONT = ("Consolas", 20, "bold")

# Action description dictionaries 

action_descriptions1 = {
    "Get Domain": "Fetch ownership and DNS data for the phishing domain.",
    "Legal Takedown Notice": "Send legal notice to hosting provider to remove the site.",
    "Report To Browser Vendors": "Notify Chrome, Firefox, and other browser security teams.",
    "Report To Cert In": "Report phishing attempts to Indian national CERT.",
    "Report To Email Providers": "Alert email providers used by phishers.",
    "Report To Google Safebrowsing": "Submit the URL to Google’s Safe Browsing blacklist.",
    "Report To Isp": "Inform the Internet Service Provider hosting the phishing site.",
    "Report To Openphish": "Submit phishing URLs to OpenPhish.",
    "Report To Phishtank": "Report to PhishTank for public blacklist registration.",
    "Report To Registrar": "Report to the domain registrar of the phishing site.",
    "Submit Deindex Request": "Ask search engines to deindex the malicious site.",
    "Report To Facebook": "Report links or accounts on Facebook.",
    "Report To Microsoft": "Submit reports via Microsoft security channels.",
    "Report To Netcraft": "Notify Netcraft to investigate and block the phishing.",
    "Report To Twitter": "Report malicious tweets or accounts.",
    "Report To Chrome Security Team": "Directly alert the Chrome team about phishing.",
    "Report To Mozilla": "Alert Mozilla for Firefox-based phishing defense.",
    "Report To Antivirus Vendors": "Inform AV companies to flag the site.",
    "Report To ICANN Abuse Contact": "Notify ICANN of abuse through the contact registry.",
    "Report To FBI IC3": "Report U.S.-targeted phishing to FBI’s IC3 division."
}

white_actions = list(action_descriptions1.keys())

# Grey and Black Actions
action_descriptions2 = {
    "Form Flooding (Credential Pollution)": "Send junk data to phishing forms to corrupt stolen credentials.",
    "Fake Block Alert Injection (JS redirect or popup)": "Inject fake security warnings to deter victims.",
    "Passive Reconnaissance (Directory crawling)": "Scan site structure without interacting.",
    "Light Server Clogging (Low-rate GET flood)": "Subtly overload server with slow traffic.",
    "Automated WHOIS Scanning & Email Alerts": "Track WHOIS changes and send auto alerts.",
    "Automated Fake Account Creation (Bot traps)": "Create fake accounts to pollute attacker’s DB.",
    "Mass Fake Login Attempts (to pollute data)": "Overload phishing DB with random credentials.",
    "Open Redirect Hijacking (reusing phisher’s flaws)": "Exploit open redirect on phishing site.",
    "Search Engine Reporting Automation": "Automate reports to search engines for blacklisting.",
    "Auto-filling Phishing Forms with Junk Data": "Auto-send random data to phisher's form.",
    "Fingerprinting Phishing Kits (unique asset detection)": "Identify kit using its unique assets.",
    "HTML Source Monitoring for Kit Similarities": "Track reused phishing kits via HTML code.",
    "Honeytoken Submission (track phishing backend)": "Submit trackable data to monitor attacker use.",
    "Screenshot Collection & Public Archiving": "Capture phishing site and store publicly.",
    "Auto-responding Bots in Phishing Chatboxes": "Deploy bots to waste phisher's time.",
    "Fake Payment or Credit Card Submissions (sandboxed)": "Simulate card input to pollute logs.",
    "Cross-Site Recon (checking same kit on other domains)": "Scan for same kits on other domains.",
    "AI-Based Cloning Detector & Alert System": "Detect site clones using AI.",
    "IP/Geo Tracking of the Phishing Site Host": "Find out where the phishing server is hosted.",
    "Passive DNS Logging & Shadow Server Detection": "Check historical DNS logs for shadow servers."
}

grey_actions = list(action_descriptions2.keys())

action_descriptions3 = {
        "Distributed Denial-of-Service (DDoS)": "Take down phishing site by overwhelming its server.",
    "Server Exploitation (e.g., RCE, SQLi, file upload vulnerabilities)": "Exploit server flaws to gain access.",
    "Malware Injection (worms, backdoors, trojans on phishing servers)": "Install malicious tools on server.",
    "Domain Hijacking (taking over phishing domain control via exploits)": "Take over domain via vulnerabilities.",
    "DNS Cache Poisoning (redirecting phishing traffic)": "Tamper with DNS to mislead users.",
    "Email Bombing (spamming phishing inbox with junk)": "Flood their email systems with noise.",
    "Credential Honeypot Hijack (stealing phishing victims' info from kits)": "Steal data from poorly secured kits.",
    "Reverse Shell Implantation (gaining remote control of phishing server)": "Gain persistent backdoor access.",
    "FTP/SSH Brute Force Attack": "Crack login credentials to server.",
    "Data Corruption or File Deletion (on the attacker’s server)": "Delete or alter attacker’s files.",
    "Botnet-Based Server Overload": "Use botnets to flood the phishing server.",
    "Phishing the Phisher (counter-phishing their panel)": "Steal phisher’s credentials from their panel.",
    "Poisoning their Analytics / Logs (e.g., injecting garbage into DB)": "Insert false data into attacker’s logs.",
    "Blacklist Forging (falsely reporting legitimate competitors as phishing)": "Abuse blacklists unethically.",
    "Cryptocurrency Drain Attack (if phishing page handles wallets)": "Drain crypto wallets tied to the phishing page.",
    "CMS Exploits (e.g., exploiting WordPress/Joomla plugins used by attacker)": "Exploit known CMS plugin flaws.",
    "SSL Certificate Forgery or Revocation Abuse": "Exploit cert issuance or force revocation.",
    "Hosting Provider Exploits (targeting weak admin panels)": "Access attacker’s host via provider flaws.",
    "Crashing Control Panels with Malformed Requests": "Crash the admin panel with bad payloads.",
    "Lawless “Hack Back” (taking the phishing site offline via force)": "Offensive retaliatory hacking."
}

black_actions = list(action_descriptions3.keys())


# Function to change button color on hover
def on_enter(e):
    e.widget['background'] = BTN_HOVER
    e.widget['foreground'] = BTN_TEXT

def on_leave(e):
    e.widget['background'] = BTN_COLOR
    e.widget['foreground'] = BTN_TEXT

def fade_in_tooltip(label, text, alpha=0):
    label.config(text=text)

def create_scrollable_action_frame(parent, title, color, actions, action_descriptions, vars_dict, checkbox_list):
    outer_frame = tk.LabelFrame(parent, text=title, font=FONT, fg=FG_COLOR, bg=color, bd=0, relief="flat", labelanchor="n")
    outer_frame.pack(side="left", fill="both", expand=True, padx=8, pady=8)

    canvas = tk.Canvas(outer_frame, bg=color, highlightthickness=0, bd=0)
    scrollbar = ttk.Scrollbar(outer_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg=color)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    select_all_var = tk.BooleanVar()
    def toggle_all():
        for var in vars_dict.values():
            var.set(select_all_var.get())

    select_all_cb = tk.Checkbutton(
        scrollable_frame, text="Select All", variable=select_all_var, command=toggle_all,
        font=FONT, bg=color, fg=FG_COLOR, selectcolor=color,
        activebackground=color, activeforeground=FG_COLOR, borderwidth=0
    )
    select_all_cb.pack(anchor="w", padx=10, pady=4)

    for action in actions:
        var = tk.BooleanVar()
        cb = tk.Checkbutton(
            scrollable_frame, text=action.split(" (", 1)[0], variable=var, font=FONT,
            fg=FG_COLOR, bg=color, selectcolor=color,
            activebackground=color, activeforeground=FG_COLOR, borderwidth=0, highlightthickness=0
        )
        cb.pack(anchor="w", padx=10, pady=2)

        desc = action_descriptions.get(action, action)
        def make_enter(desc):
            return lambda event: fade_in_tooltip(tooltip, desc)
        def make_leave():
            return lambda event: tooltip.config(text="")
        cb.bind("<Enter>", make_enter(desc))
        cb.bind("<Leave>", make_leave())

        vars_dict[action] = var
        checkbox_list.append(cb)

    return outer_frame

# --- Functionality ---
def analyze():
    url = entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a URL.")
        return

    if not url.startswith("http"):
        url = "http://" + url

    heuristics = check_url_heuristics(url)
    whois_result = is_registered_recently(url)
    gsb_result = check_google_safe_browsing(url)

    result_text = (
        f"[+] URL: {url}\n"
        f"[+] Heuristics: {heuristics}\n"
        f"[+] WHOIS: {whois_result}\n"
        f"[+] Google Safe Browsing: {gsb_result}\n"
    )

    output_text.config(state="normal")
    output_text.insert(tk.END, result_text + "\n" + "-"*50 + "\n")
    output_text.see(tk.END)
    output_text.config(state="disabled")

    if "suspicious" in heuristics.lower() or "suspicious" in whois_result.lower() or "flagged" in gsb_result.lower():
        initiate_btn.config(state="normal")
    else:
        initiate_btn.config(state="disabled")
'''
def eliminate():
    url = entry.get().strip()
    if not url:
        messagebox.showerror("Error", "No URL to target.")
        return
    flood_form(url)
    clog_server(url)
    messagebox.showinfo("Action Taken", "Elimination attempt triggered (Flood + Clog).")
'''
# --- GUI Setup ---
root = tk.Tk()
root.title("⚔️ Anti-Phishing Analyzer & Eliminator")
root.state('zoomed')
root.configure(bg=BG_COLOR)
root.option_add("*Font", "{Segoe UI} 12 bold")

main_frame = tk.Frame(root, bg=BG_COLOR)
main_frame.pack(fill="both", expand=True)

header = tk.Label(main_frame, text="⚡ ANTI-PHISHING TERMINAL ⚡", font=TITLE_FONT, fg=FG_COLOR, bg=BG_COLOR)
header.pack(pady=(10, 5))

url_frame = tk.Frame(main_frame, bg=BG_COLOR)
url_frame.pack(padx=10, pady=10, fill="x")
tk.Label(url_frame, text="🔗 Enter Suspicious URL:", font=FONT, fg=FG_COLOR, bg=BG_COLOR).pack(side="left", padx=(0, 8))
entry = tk.Entry(url_frame, font=FONT, bg="#232a34", fg=FG_COLOR, insertbackground=FG_COLOR, borderwidth=0, relief="flat", highlightthickness=2, highlightbackground=FG_COLOR)
entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

analyze_btn = tk.Button(url_frame, text="Analyze URL", font=FONT, bg=BTN_COLOR, fg=BTN_TEXT, activebackground=BTN_HOVER, activeforeground=BTN_TEXT, borderwidth=0, cursor="hand2", command=analyze)
analyze_btn.pack(side="left")
analyze_btn.bind("<Enter>", on_enter)
analyze_btn.bind("<Leave>", on_leave)

options_frame = tk.Frame(main_frame, bg=BG_COLOR)
options_frame.pack(fill="both", expand=True, padx=10)

white_vars, grey_vars, black_vars = {}, {}, {}
all_checkboxes = []

create_scrollable_action_frame(options_frame, "White Actions", BG_COLOR, white_actions, action_descriptions1, white_vars, all_checkboxes)
create_scrollable_action_frame(options_frame, "Grey Actions", BG_COLOR, grey_actions, action_descriptions2, grey_vars, all_checkboxes)
create_scrollable_action_frame(options_frame, "Black Actions", BG_COLOR, black_actions, action_descriptions3, black_vars, all_checkboxes)

log_frame = tk.Frame(main_frame, bg=BG_COLOR)
log_frame.pack(padx=10, pady=5, fill="both", expand=True)

tooltip = tk.Label(log_frame, text="", font=("Segoe UI", 11), fg=FG_COLOR, bg=BG_COLOR, wraplength=950, justify="left")
tooltip.pack(pady=(5, 0))

initiate_btn = tk.Button(log_frame, text="🔥 INITIATE", font=FONT, bg=BTN_COLOR, fg=BTN_TEXT, activebackground=BTN_HOVER, activeforeground=BTN_TEXT, borderwidth=0, cursor="hand2", 
#                         command=eliminate
                         )
initiate_btn.pack(pady=5)
initiate_btn.bind("<Enter>", on_enter)
initiate_btn.bind("<Leave>", on_leave)
initiate_btn.config(state="disabled")

output_text = scrolledtext.ScrolledText(
    log_frame,
    state="disabled",
    bg="#000000",  # Fully black
    fg=FG_COLOR,
    insertbackground=FG_COLOR,
    font=("Consolas", 11),
    borderwidth=0,
    highlightthickness=0
)
output_text.pack(pady=5, fill="both", expand=True)
output_text.tag_config("warn", foreground="#bfff00")
output_text.tag_config("success", foreground="#00b140")

root.mainloop()
