import subprocess, re

def scan_networks():
    output = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, encoding="utf-8", errors="ignore"
    ).stdout

    aps = []
    current_ssid = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID"):
            current_ssid = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[1].strip()
            aps.append({"ssid": current_ssid, "bssid": bssid})
        elif line.startswith("Signal") and aps:
            aps[-1]["signal_pct"] = int(re.search(r"\d+", line).group())
        elif line.startswith("Channel") and aps:
            aps[-1]["channel"] = int(re.search(r"\d+", line).group())

    return aps

results = scan_networks()
print(f"Found {len(results)} access points:\n")
for ap in results:
    print(ap)