import json
import os

PROFILES_FILE = "vendor_profiles.json"

def load_profiles():
    if not os.path.exists(PROFILES_FILE):
        return []
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except Exception:
        return []

def save_profiles(profiles):
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2)

def add_profile(ssid, vendor, auth, encryption, channel):
    profiles = load_profiles()
    profiles = [p for p in profiles if p["ssid"] != ssid]
    profiles.append({
        "ssid": ssid,
        "vendor": vendor,
        "auth": auth,
        "encryption": encryption,
        "channel": channel,
    })
    save_profiles(profiles)

def remove_profile(ssid):
    profiles = load_profiles()
    profiles = [p for p in profiles if p["ssid"] != ssid]
    save_profiles(profiles)

def get_profile(ssid):
    for p in load_profiles():
        if p["ssid"] == ssid:
            return p
    return None