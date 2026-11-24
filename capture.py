import subprocess
import re
import threading
import time
import ctypes
from ctypes import wintypes

_latest_aps = []
_connected_bssid = None
_saved_profiles = set()
_lock = threading.Lock()
_scanner_started = False


def trigger_hardware_scan():
    """Triggers Windows WLAN AutoConfig to perform a fresh RF scan immediately."""
    try:
        wlanapi = ctypes.WinDLL("wlanapi.dll")
        negotiated = wintypes.DWORD()
        handle = wintypes.HANDLE()
        if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)) != 0:
            return

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", wintypes.DWORD),
            ]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
            ]

        p_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(p_list)) == 0:
            count = p_list.contents.dwNumberOfItems
            base_addr = ctypes.addressof(p_list.contents.InterfaceInfo)
            item_size = ctypes.sizeof(WLAN_INTERFACE_INFO)
            for i in range(count):
                iface = WLAN_INTERFACE_INFO.from_address(base_addr + i * item_size)
                wlanapi.WlanScan(handle, ctypes.byref(iface.InterfaceGuid), None, None, None)
            wlanapi.WlanFreeMemory(p_list)
        wlanapi.WlanCloseHandle(handle, None)
    except Exception:
        pass


def get_connection_history():
    """Finds the currently connected BSSID and all previously connected SSIDs on Windows."""
    current_bssid = None
    saved_ssids = set()
    try:
        iface_out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=3
        ).stdout
        for line in iface_out.splitlines():
            line = line.strip()
            if line.startswith("BSSID") and ":" in line:
                current_bssid = line.split(":", 1)[1].strip().lower()
                break
    except Exception:
        pass

    try:
        prof_out = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=3
        ).stdout
        for line in prof_out.splitlines():
            if "All User Profile" in line and ":" in line:
                saved_ssids.add(line.split(":", 1)[1].strip())
    except Exception:
        pass

    return current_bssid, saved_ssids


def parse_netsh():
    current_bssid, saved_ssids = get_connection_history()
    try:
        output = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=4
        ).stdout
    except Exception:
        return []

    aps = []
    current_ssid = "<Hidden SSID>"
    is_hidden = True
    current_auth = "?"
    current_enc = "?"

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID ") and ":" in line:
            val = line.split(":", 1)[1].strip()
            is_hidden = (val == "")
            current_ssid = val if val else "<Hidden SSID>"
        elif line.startswith("Authentication") and ":" in line:
            current_auth = line.split(":", 1)[1].strip()
        elif line.startswith("Encryption") and ":" in line:
            current_enc = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID ") and ":" in line:
            bssid = line.split(":", 1)[1].strip().lower()
            if current_bssid and bssid == current_bssid:
                conn_state = "Connected Now"
            elif not is_hidden and current_ssid in saved_ssids:
                conn_state = "Connected Before"
            else:
                conn_state = "Never Connected"

            aps.append({
                "ssid": current_ssid,
                "is_hidden": is_hidden,
                "bssid": bssid,
                "auth": current_auth,
                "encryption": current_enc,
                "signal_pct": 0,
                "rssi": -90,
                "radio": "802.11n",
                "band": "2.4 GHz",
                "channel": 0,
                "basic_rates": "?",
                "other_rates": "?",
                "connection_history": conn_state
            })
        elif aps:
            if line.startswith("Signal") and ":" in line:
                m = re.search(r"\d+", line)
                pct = int(m.group()) if m else 0
                aps[-1]["signal_pct"] = pct
                aps[-1]["rssi"] = int((pct / 2) - 100)
            elif line.startswith("Radio type") and ":" in line:
                aps[-1]["radio"] = line.split(":", 1)[1].strip()
            elif line.startswith("Band") and ":" in line:
                aps[-1]["band"] = line.split(":", 1)[1].strip()
            elif line.startswith("Channel") and ":" in line:
                m = re.search(r"\d+", line)
                ch = int(m.group()) if m else 0
                aps[-1]["channel"] = ch
                if ch > 14 and aps[-1]["band"] == "2.4 GHz":
                    aps[-1]["band"] = "5 GHz"
            elif line.startswith("Basic rates") and ":" in line:
                aps[-1]["basic_rates"] = line.split(":", 1)[1].strip()
            elif line.startswith("Other rates") and ":" in line:
                aps[-1]["other_rates"] = line.split(":", 1)[1].strip()

    return aps


def _background_loop():
    global _latest_aps
    while True:
        trigger_hardware_scan()
        time.sleep(1.2)
        fresh = parse_netsh()
        with _lock:
            if fresh:
                _latest_aps = fresh
        time.sleep(0.8)


def start_background_scanner():
    global _scanner_started
    if not _scanner_started:
        _scanner_started = True
        with _lock:
            _latest_aps = parse_netsh()
        t = threading.Thread(target=_background_loop, daemon=True)
        t.start()


def scan_networks():
    start_background_scanner()
    with _lock:
        return [dict(ap) for ap in _latest_aps]