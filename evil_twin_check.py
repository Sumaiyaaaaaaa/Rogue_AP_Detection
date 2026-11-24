from whitelist_check import load_whitelist
from fingerprint import build_fingerprint
from vendor_profiles import get_profile


def find_evil_twins(aps):
    whitelist = {w["bssid"].lower(): w["ssid"] for w in load_whitelist()}
    whitelisted_ssids = set(whitelist.values())

    ssid_map = {}
    for ap in aps:
        # Ignore hidden/blank SSIDs so mesh backhauls are not falsely grouped
        if ap.get("is_hidden") or not ap["ssid"] or ap["ssid"] == "<Hidden SSID>":
            continue
        ssid_map.setdefault(ap["ssid"], []).append(ap)

    twins = {}
    for ssid, group in ssid_map.items():
        profile = get_profile(ssid)
        is_managed = (ssid in whitelisted_ssids) or (profile is not None)

        # Trigger whenever >= 2 APs share the same SSID, OR an unwhitelisted AP uses a managed SSID
        if len(group) < 2 and not is_managed:
            continue

        # Case 1: Protected by a saved Vendor OUI Profile -> Malicious Evil Twin
        if profile:
            check_fields = ["vendor", "radio", "auth", "encryption", "channel", "basic_rates", "other_rates"]
            entries = []
            for ap in group:
                if ap["bssid"].lower() in whitelist:
                    continue
                fp = build_fingerprint(ap)
                mismatches = [
                    f for f in check_fields
                    if profile.get(f) and str(profile[f]).strip() != str(fp.get(f)).strip()
                ]
                reasons = [f"Unapproved BSSID broadcasting protected SSID '{ssid}'"]
                for m in mismatches:
                    reasons.append(f"{m.replace('_', ' ').title()} mismatch: got '{fp.get(m)}', expected '{profile.get(m)}'")
                entries.append({
                    "bssid": ap["bssid"],
                    "severity": "malicious",
                    "mismatches": mismatches,
                    "reasons": reasons,
                    "fingerprint": fp
                })
            if entries:
                twins[ssid] = entries
            continue

        # Case 2: Protected by a live Whitelisted AP sharing the same SSID -> Malicious Evil Twin
        trusted_ap = next((a for a in group if a["bssid"].lower() in whitelist), None)
        if trusted_ap:
            trusted_fp = build_fingerprint(trusted_ap)
            compare_keys = ["vendor", "radio", "auth", "encryption", "channel", "basic_rates", "other_rates"]
            entries = []
            for ap in group:
                if ap["bssid"].lower() in whitelist:
                    continue
                fp = build_fingerprint(ap)
                mismatches = [k for k in compare_keys if trusted_fp.get(k) != fp.get(k)]
                reasons = [f"Clones whitelisted SSID '{ssid}' (trusted BSSID is {trusted_ap['bssid']})"]
                for m in mismatches:
                    reasons.append(f"{m.replace('_', ' ').title()} differs: '{fp.get(m)}' vs trusted '{trusted_fp.get(m)}'")
                entries.append({
                    "bssid": ap["bssid"],
                    "severity": "malicious",
                    "mismatches": mismatches,
                    "reasons": reasons,
                    "fingerprint": fp
                })
            if entries:
                twins[ssid] = entries

        # Case 3: Two or more unwhitelisted APs sharing the exact same SSID -> Suspicious
        elif len(group) >= 2:
            fp0 = build_fingerprint(group[0])
            entries = []
            for ap in group:
                fp = build_fingerprint(ap)
                diffs = [k for k in ["vendor", "radio", "auth", "encryption", "channel"] if fp.get(k) != fp0.get(k)]
                reasons = [f"Duplicate SSID '{ssid}' broadcast by {len(group)} unwhitelisted BSSIDs"]
                if diffs:
                    reasons.append(f"Capability differences detected ({', '.join(diffs)})")
                entries.append({
                    "bssid": ap["bssid"],
                    "severity": "suspicious",
                    "mismatches": diffs or ["duplicate_ssid"],
                    "reasons": reasons,
                    "fingerprint": fp
                })
            twins[ssid] = entries

    return twins