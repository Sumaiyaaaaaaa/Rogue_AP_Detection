OUI_TABLE = {
    # Networking & Enterprise AP Vendors
    "00:1a:1e": "Cisco Systems",
    "00:1a:2b": "Cisco Systems",
    "00:18:0a": "Cisco Meraki",
    "00:40:96": "Cisco Aironet",
    "68:ff:7b": "TP-Link",
    "d8:07:b6": "TP-Link",
    "b4:fb:e4": "TP-Link",
    "f4:f2:6d": "TP-Link",
    "50:c7:bf": "TP-Link",
    "d8:0d:17": "TP-Link",
    "b0:be:76": "TP-Link",
    "ac:f1:df": "D-Link",
    "1c:7e:e5": "D-Link",
    "f0:9f:c2": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "6c:4f:89": "Airtel / Sercomm",
    "c0:25:e9": "TP-Link",
    "00:24:b2": "Netgear",
    "a0:04:60": "Netgear",
    "2c:56:dc": "ASUS",
    "04:d4:c4": "ASUS",
    # Consumer, Laptop & Mobile Vendors (Samsung, Apple, Dell, HP, Lenovo, Intel, LG)
    "00:16:32": "Samsung",
    "28:39:5e": "Samsung",
    "34:23:ba": "Samsung",
    "8c:f5:a3": "Samsung",
    "ac:5f:3e": "Samsung",
    "00:1c:b3": "Apple",
    "3c:15:c2": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    "00:14:22": "Dell",
    "18:03:73": "Dell",
    "f8:b1:56": "Dell",
    "00:1a:4b": "HP",
    "3c:d9:2b": "HP",
    "94:57:a5": "HP",
    "00:06:1b": "Lenovo",
    "28:d2:44": "Lenovo",
    "54:e1:ad": "Lenovo",
    "00:1e:64": "Intel Corporate",
    "34:13:e8": "Intel Corporate",
    "80:86:f2": "Intel Corporate",
    "00:e0:4c": "Realtek",
    "24:5e:be": "Realtek",
    "a8:1e:84": "LG Electronics",
    "64:bc:0c": "LG Electronics",
}

CHANNEL_PLAN = {1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161}


def lookup_vendor(bssid):
    oui = bssid.lower()[0:8]
    if oui in OUI_TABLE:
        return OUI_TABLE[oui]
    # IEEE 802.11 locally administered MAC check (2nd hex char in {2, 6, a, e})
    if len(oui) >= 2 and oui[1] in ("2", "6", "a", "e"):
        return "Randomized / Virtual MAC"
    return "Unknown Vendor"


def build_fingerprint(ap):
    return {
        "oui": ap["bssid"].upper()[0:8],
        "vendor": lookup_vendor(ap["bssid"]),
        "radio": ap.get("radio", "?"),
        "band": ap.get("band", "?"),
        "auth": ap.get("auth", "?"),
        "encryption": ap.get("encryption", "?"),
        "channel": str(ap.get("channel", "?")),
        "basic_rates": ap.get("basic_rates", "?"),
        "other_rates": ap.get("other_rates", "?"),
    }


def fingerprint_label(fp):
    return f"{fp['vendor']} | {fp['radio']} | {fp['auth']} | ch{fp['channel']}"