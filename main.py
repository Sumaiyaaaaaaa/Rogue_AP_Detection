from capture import scan_networks
from whitelist_check import check_whitelist
from evil_twin_check import find_evil_twins

def run_once():
    aps = scan_networks()
    print(f"\nScanned {len(aps)} access points.\n")

    # Layer 1: whitelist check
    for ap in aps:
        ap["status"] = check_whitelist(ap)

    # Layer 2: evil twin check
    twins = find_evil_twins(aps)

    # Print results
    for ap in aps:
        flag = " <-- POSSIBLE EVIL TWIN" if ap["ssid"] in twins else ""
        print(f"[{ap['status'].upper():12}] {ap['ssid']:25} {ap['bssid']}{flag}")

if __name__ == "__main__":
    run_once()