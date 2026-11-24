import json
import os

WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except Exception:
        return []

def save_whitelist(entries):
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)

def check_whitelist(ap):
    entries = load_whitelist()
    for entry in entries:
        if entry["bssid"].lower() == ap["bssid"].lower():
            if entry["ssid"] != ap["ssid"]:
                return "spoofed"
            return "authorized"
    return "unauthorized"

def add_to_whitelist(bssid, ssid):
    entries = load_whitelist()
    entries = [e for e in entries if e["bssid"].lower() != bssid.lower()]
    entries.append({"bssid": bssid, "ssid": ssid})
    save_whitelist(entries)

def remove_from_whitelist(bssid):
    entries = load_whitelist()
    entries = [e for e in entries if e["bssid"].lower() != bssid.lower()]
    save_whitelist(entries)