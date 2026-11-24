import csv
import io
import json
import os
import subprocess
from datetime import datetime
from flask import Flask, jsonify, request, render_template_string, Response
from capture import scan_networks, start_background_scanner
from whitelist_check import check_whitelist, load_whitelist, add_to_whitelist, remove_from_whitelist
from evil_twin_check import find_evil_twins
from fingerprint import build_fingerprint, fingerprint_label
from vendor_profiles import load_profiles, add_profile, remove_profile, save_profiles, get_profile

app = Flask(__name__)
ALERTS_FILE = "alerts_log.json"
POLICY_FILE = "security_policy.json"
_last_connected_ssid = None


def load_policy():
    if not os.path.exists(POLICY_FILE):
        return {"auto_disconnect": False, "demo_attack": False}
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            data = json.loads(f.read().strip() or "{}")
            return {
                "auto_disconnect": bool(data.get("auto_disconnect", False)),
                "demo_attack": bool(data.get("demo_attack", False))
            }
    except Exception:
        return {"auto_disconnect": False, "demo_attack": False}


def save_policy(policy):
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)


def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return json.loads(content) if content else []
    except Exception:
        return []


def save_alerts(alerts):
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)


def inject_demo_evil_twin(aps, policy):
    """If Demo Attack mode is toggled ON, injects a realistic Evil Twin AP for presentation demos."""
    if not policy.get("demo_attack"):
        return aps

    wl = load_whitelist()
    connected = next((a for a in aps if a.get("connection_history") == "Connected Now"), None)
    target_ssid = (
        connected["ssid"] if connected
        else (wl[0]["ssid"] if wl else (aps[0]["ssid"] if aps else "TJIT-Campus-WiFi"))
    )
    target_ch = connected["channel"] if connected else 6
    rogue_ch = 11 if target_ch != 11 else 3

    demo_ap = {
        "ssid": target_ssid,
        "is_hidden": False,
        "bssid": "de:ad:be:ef:77:01",
        "auth": "Open" if (connected and connected.get("auth") != "Open") else "WPA2-Personal",
        "encryption": "None" if (connected and connected.get("encryption") != "None") else "TKIP",
        "signal_pct": 94,
        "rssi": -36,
        "radio": "802.11g",
        "band": "2.4 GHz",
        "channel": rogue_ch,
        "basic_rates": "1 2 5.5 11",
        "other_rates": "6 9 12 18 24",
        "connection_history": "Never Connected"
    }
    return aps + [demo_ap]


def detect_surge_and_deauth(aps):
    """Detects Evil Twin signal surge (+15% stronger than legitimate AP) and sudden forced disconnects."""
    global _last_connected_ssid
    warnings = []

    current_conn = next((a for a in aps if a.get("connection_history") == "Connected Now"), None)
    if _last_connected_ssid and not current_conn:
        twin_present = any(a.get("ssid") == _last_connected_ssid and a.get("is_twin") for a in aps)
        if twin_present:
            warnings.append(f"DEAUTH WATCHDOG: Suddenly disconnected from '{_last_connected_ssid}' while an Evil Twin is active!")
    _last_connected_ssid = current_conn["ssid"] if current_conn else None

    # Signal Surge Check: unwhitelisted clone broadcasting stronger than the authorized AP
    auth_by_ssid = {a["ssid"]: a for a in aps if a["status"] == "authorized"}
    for ap in aps:
        if ap["status"] != "authorized" and ap["ssid"] in auth_by_ssid:
            legit = auth_by_ssid[ap["ssid"]]
            if ap.get("signal_pct", 0) >= legit.get("signal_pct", 0) + 10:
                msg = f"Signal Hijack Surge: {ap['signal_pct']}% vs legitimate AP {legit['signal_pct']}%"
                ap.setdefault("twin_reasons", []).append(msg)
                warnings.append(f"SIGNAL SURGE: Rogue '{ap['ssid']}' ({ap['signal_pct']}%) is overpowering trusted AP ({legit['signal_pct']}%)")

    return warnings


def enforce_auto_disconnect(aps, policy):
    """If Auto-Disconnect Shield is enabled and client is connected to an Evil Twin, sever Wi-Fi."""
    if not policy.get("auto_disconnect"):
        return None

    for ap in aps:
        is_rogue = (ap["status"] == "spoofed" or ap.get("twin_severity") == "malicious")
        if is_rogue and ap.get("connection_history") == "Connected Now":
            try:
                subprocess.run(["netsh", "wlan", "disconnect"], capture_output=True, text=True, timeout=3)
                return f"SHIELD TRIGGERED: Disconnected from Evil Twin '{ap['ssid']}' ({ap['bssid']})"
            except Exception:
                pass
    return None


def record_forensic_alerts(aps, shield_msg=None):
    alerts = load_alerts()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = False

    for ap in aps:
        if ap["status"] not in ("suspicious", "spoofed") and ap.get("twin_severity") != "malicious":
            continue

        severity = "MALICIOUS (EVIL TWIN)" if (ap["status"] == "spoofed" or ap.get("twin_severity") == "malicious") else "SUSPICIOUS (DUPLICATE SSID)"
        fp = ap.get("fingerprint", {})
        reasons_str = "; ".join(ap.get("twin_reasons") or ["Unapproved MAC / SSID anomaly"])
        if shield_msg and ap.get("connection_history") == "Connected Now":
            reasons_str += f" | [{shield_msg}]"

        existing = next(
            (a for a in alerts if a["bssid"] == ap["bssid"] and a["ssid"] == ap["ssid"] and a["severity"] == severity),
            None
        )
        if existing:
            existing["last_seen"] = now
            existing["seen_count"] = existing.get("seen_count", 1) + 1
            if ap.get("signal_pct", 0) > existing.get("peak_signal_pct", 0):
                existing["peak_signal_pct"] = ap.get("signal_pct", 0)
                existing["peak_rssi"] = ap.get("rssi", -90)
            existing["reasons"] = reasons_str
            updated = True
        else:
            alerts.insert(0, {
                "id": f"{ap['bssid']}_{int(datetime.now().timestamp())}",
                "first_seen": now,
                "last_seen": now,
                "seen_count": 1,
                "severity": severity,
                "ssid": ap["ssid"],
                "bssid": ap["bssid"],
                "vendor": fp.get("vendor", "Unknown"),
                "channel": ap.get("channel", 0),
                "peak_signal_pct": ap.get("signal_pct", 0),
                "peak_rssi": ap.get("rssi", -90),
                "reasons": reasons_str
            })
            updated = True

    if updated:
        save_alerts(alerts[:200])
    return alerts


def get_scan_data():
    policy = load_policy()
    aps = inject_demo_evil_twin(scan_networks(), policy)

    for ap in aps:
        ap["status"] = check_whitelist(ap)
        fp = build_fingerprint(ap)
        ap["fingerprint_label"] = fingerprint_label(fp)
        ap["fingerprint"] = fp

    twins = find_evil_twins(aps)
    mismatch_lookup = {}
    for ssid, entries in twins.items():
        for e in entries:
            mismatch_lookup[e["bssid"]] = e

    for ap in aps:
        twin_info = mismatch_lookup.get(ap["bssid"])
        ap["is_twin"] = twin_info is not None
        ap["twin_severity"] = twin_info["severity"] if twin_info else None
        ap["mismatches"] = twin_info["mismatches"] if twin_info else []
        ap["twin_reasons"] = list(twin_info["reasons"]) if twin_info else []

        if ap["status"] == "unauthorized" and ap["twin_severity"] == "suspicious":
            ap["status"] = "suspicious"

    watchdog_warnings = detect_surge_and_deauth(aps)

    def sort_key(a):
        conn_rank = 0 if a.get("connection_history") == "Connected Now" else 1
        if a["status"] == "spoofed" or a["twin_severity"] == "malicious":
            threat_rank = 0
        elif a["status"] == "suspicious":
            threat_rank = 1
        elif a["status"] == "authorized":
            threat_rank = 2
        else:
            threat_rank = 3
        return (conn_rank, threat_rank, -a.get("signal_pct", 0))

    aps.sort(key=sort_key)
    shield_action = enforce_auto_disconnect(aps, policy)
    alerts = record_forensic_alerts(aps, shield_action)

    stats = {
        "total": len(aps),
        "authorized": sum(1 for a in aps if a["status"] == "authorized"),
        "suspicious": sum(1 for a in aps if a["status"] == "suspicious"),
        "unauthorized": sum(1 for a in aps if a["status"] == "unauthorized" and a["twin_severity"] != "malicious"),
        "rogue": sum(1 for a in aps if a["status"] == "spoofed" or a["twin_severity"] == "malicious"),
    }

    return {
        "aps": aps,
        "stats": stats,
        "whitelist": load_whitelist(),
        "profiles": load_profiles(),
        "alerts": alerts,
        "policy": policy,
        "shield_action": shield_action,
        "watchdog_warnings": watchdog_warnings
    }


@app.route("/api/scan")
def api_scan():
    return jsonify(get_scan_data())


@app.route("/api/policy/toggle_disconnect", methods=["POST"])
def api_toggle_disconnect():
    policy = load_policy()
    policy["auto_disconnect"] = not policy.get("auto_disconnect", False)
    save_policy(policy)
    return jsonify(policy)


@app.route("/api/policy/toggle_demo", methods=["POST"])
def api_toggle_demo():
    policy = load_policy()
    policy["demo_attack"] = not policy.get("demo_attack", False)
    save_policy(policy)
    return jsonify(policy)


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    save_alerts([])
    return jsonify({"status": "ok"})


@app.route("/api/alerts/export")
def api_export_alerts():
    alerts = load_alerts()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "First Seen", "Last Seen", "Frames Seen", "Severity",
        "SSID", "BSSID", "Vendor OUI", "Channel",
        "Peak Signal (%)", "Peak RSSI (dBm)", "Detection Reasons"
    ])
    for a in alerts:
        writer.writerow([
            a.get("first_seen"), a.get("last_seen"), a.get("seen_count"),
            a.get("severity"), a.get("ssid"), a.get("bssid"),
            a.get("vendor"), a.get("channel"), a.get("peak_signal_pct"),
            a.get("peak_rssi"), a.get("reasons")
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=rogue_ap_forensic_report.csv"}
    )


@app.route("/api/whitelist", methods=["POST"])
def api_add_whitelist():
    data = request.get_json()
    bssid = data.get("bssid", "").strip().lower()
    ssid = data.get("ssid", "").strip()
    if not bssid or not ssid:
        return jsonify({"error": "bssid and ssid required"}), 400
    add_to_whitelist(bssid, ssid)

    fp = data.get("fingerprint")
    if fp and not get_profile(ssid):
        add_profile(ssid, fp.get("vendor", "Unknown"), fp.get("auth", ""), fp.get("encryption", ""), str(fp.get("channel", "")))
        profiles = load_profiles()
        for p in profiles:
            if p["ssid"] == ssid:
                p["oui"] = fp.get("oui", bssid[:8].upper())
                p["radio"] = fp.get("radio", "")
                p["basic_rates"] = fp.get("basic_rates", "")
                p["other_rates"] = fp.get("other_rates", "")
        save_profiles(profiles)

    return jsonify({"status": "ok"})


@app.route("/api/whitelist/<path:bssid>", methods=["DELETE"])
def api_remove_whitelist(bssid):
    remove_from_whitelist(bssid)
    return jsonify({"status": "ok"})


@app.route("/api/profiles")
def api_get_profiles():
    return jsonify(load_profiles())


@app.route("/api/profiles", methods=["POST"])
def api_add_profile():
    data = request.get_json()
    ssid = data.get("ssid", "").strip()
    vendor = data.get("vendor", "").strip()
    auth = data.get("auth", "").strip()
    encryption = data.get("encryption", "").strip()
    channel = data.get("channel", "").strip()
    if not ssid or not vendor:
        return jsonify({"error": "ssid and vendor required"}), 400
    add_profile(ssid, vendor, auth, encryption, channel)
    profiles = load_profiles()
    for p in profiles:
        if p["ssid"] == ssid:
            p["radio"] = data.get("radio", "").strip()
            p["basic_rates"] = data.get("basic_rates", "").strip()
            p["other_rates"] = data.get("other_rates", "").strip()
    save_profiles(profiles)
    return jsonify({"status": "ok"})


@app.route("/api/profiles/<path:ssid>", methods=["DELETE"])
def api_remove_profile(ssid):
    remove_profile(ssid)
    return jsonify({"status": "ok"})


PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Rogue AP Detection Dashboard</title>
<style>
  :root {
    --bg:#080C15; --panel:#0F1626; --border:#212C48; --text:#E7ECF5;
    --dim:#8592B0; --cyan:#4FD8C4; --amber:#F0A84E; --orange:#FB923C; --red:#FF5C6C; --violet:#9B8CFF; --blue:#38BDF8;
  }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Segoe UI', Arial, sans-serif; padding:26px; margin:0; }
  .topbar { display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; }
  h1 { font-size:22px; margin:0 0 4px 0; display:flex; align-items:center; gap:10px; }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--cyan); position:relative; }
  .dot::after { content:''; position:absolute; inset:-5px; border-radius:50%; border:1px solid var(--cyan); animation:pulse 2s infinite; }
  @keyframes pulse { 0%{transform:scale(.6);opacity:.9;} 100%{transform:scale(2.2);opacity:0;} }
  .sub { color:var(--dim); font-size:13px; margin-bottom:16px; }

  .ctrl-group { display:flex; gap:8px; flex-wrap:wrap; }
  .shield-btn { padding:9px 14px; border-radius:8px; font-size:12px; font-weight:700; cursor:pointer; border:1px solid var(--border); background:var(--panel); color:var(--dim); }
  .shield-btn.active { background:rgba(79,216,196,0.16); border-color:var(--cyan); color:var(--cyan); }
  .demo-btn { padding:9px 14px; border-radius:8px; font-size:12px; font-weight:700; cursor:pointer; border:1px solid rgba(240,168,78,0.4); background:rgba(240,168,78,0.12); color:var(--amber); }
  .demo-btn.active { background:rgba(255,92,108,0.2); border-color:var(--red); color:var(--red); }

  .watchdog-banner { display:none; background:rgba(255,92,108,0.16); border:1px solid var(--red); color:#FECACA; padding:10px 14px; border-radius:8px; margin-bottom:16px; font-size:12px; font-weight:600; }

  .nav { display:flex; gap:6px; margin-bottom:22px; border-bottom:1px solid var(--border); flex-wrap:wrap; }
  .nav-btn {
    background:none; border:none; color:var(--dim); font-size:13px; font-weight:600;
    padding:10px 16px; cursor:pointer; border-bottom:2px solid transparent;
  }
  .nav-btn.active { color:var(--cyan); border-bottom:2px solid var(--cyan); }
  .alert-pill { background:var(--red); color:white; padding:1px 7px; border-radius:10px; font-size:11px; margin-left:6px; }

  .view { display:none; }
  .view.active { display:block; }

  .stats { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:22px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
  .card .label { color:var(--dim); font-size:11px; text-transform:uppercase; }
  .card .value { font-size:28px; font-weight:700; margin-top:6px; }
  .card.total .value { color:var(--blue); }
  .card.auth .value { color:var(--cyan); }
  .card.susp .value { color:var(--orange); }
  .card.unauth .value { color:var(--amber); }
  .card.rogue .value { color:var(--red); }

  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  th, td { padding:10px 12px; text-align:left; border-bottom:1px solid var(--border); font-size:13px; vertical-align:middle; }
  th { color:var(--dim); text-transform:uppercase; font-size:11px; }
  tr:last-child td { border-bottom:none; }
  .badge { padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; display:inline-block; }
  .authorized { background:rgba(79,216,196,0.15); color:var(--cyan); }
  .suspicious { background:rgba(251,146,60,0.18); color:var(--orange); border:1px solid rgba(251,146,60,0.4); }
  .unauthorized { background:rgba(240,168,78,0.15); color:var(--amber); }
  .spoofed { background:rgba(255,92,108,0.15); color:var(--red); }

  .conn-badge { padding:2px 8px; border-radius:12px; font-size:10px; font-weight:700; display:inline-block; margin-top:4px; }
  .conn-now { background:rgba(56,189,248,0.18); color:var(--blue); border:1px solid rgba(56,189,248,0.4); }
  .conn-before { background:rgba(155,140,255,0.15); color:var(--violet); }
  .conn-never { color:var(--dim); font-size:11px; }

  .twin-row { background:rgba(255,92,108,0.07); }
  .susp-row { background:rgba(251,146,60,0.06); }
  .twin-tag { color:var(--red); font-weight:700; font-size:11px; margin-left:6px; }
  .susp-tag { color:var(--orange); font-weight:700; font-size:11px; margin-left:6px; }
  .reason-list { margin:5px 0 0 0; padding-left:16px; color:#FCA5A5; font-size:11px; }
  .susp-row .reason-list { color:#FDBA74; }

  .sig-bar { width:70px; height:6px; background:#1E293B; border-radius:4px; overflow:hidden; display:inline-block; vertical-align:middle; margin-right:6px; }
  .sig-fill { height:100%; background:var(--cyan); transition:width 0.4s ease; }

  section { margin-top:26px; }
  h2 { font-size:15px; margin-bottom:6px; }
  .hint { color:var(--dim); font-size:12px; margin-bottom:14px; }
  form { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
  input, select { background:#0f1420; border:1px solid var(--border); color:var(--text); padding:8px 10px; border-radius:6px; font-size:12px; }
  button, .btn-link { background:var(--cyan); border:none; color:#080C15; font-weight:700; padding:8px 14px; border-radius:6px; cursor:pointer; font-size:12px; text-decoration:none; display:inline-block; }
  .act-btn { background:rgba(79,216,196,0.12); border:1px solid var(--cyan); color:var(--cyan); padding:4px 9px; border-radius:5px; cursor:pointer; font-size:11px; font-weight:600; margin-right:4px; }
  .cmp-btn { background:rgba(155,140,255,0.12); border:1px solid var(--violet); color:var(--violet); padding:4px 9px; border-radius:5px; cursor:pointer; font-size:11px; font-weight:600; margin-right:4px; }
  .loc-btn { background:rgba(56,189,248,0.12); border:1px solid var(--blue); color:var(--blue); padding:4px 9px; border-radius:5px; cursor:pointer; font-size:11px; font-weight:600; }
  .del-btn { background:none; border:1px solid var(--border); color:var(--dim); padding:4px 10px; border-radius:5px; cursor:pointer; font-size:11px; margin-right:4px; }
  .match-ok { color:var(--cyan); font-weight:700; }
  .match-bad { color:var(--red); font-weight:700; }

  /* Radar Locator Styles */
  .radar-box { background:var(--panel); border:1px solid var(--blue); border-radius:12px; padding:22px; margin-top:16px; }
  .radar-top { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; }
  .prox-meter { width:100%; height:18px; background:#080C15; border-radius:10px; overflow:hidden; border:1px solid var(--border); margin:16px 0 8px 0; }
  .prox-fill { height:100%; background:linear-gradient(90deg, #38BDF8, #4FD8C4, #F0A84E, #FF5C6C); transition:width 0.35s ease; }
  .zone-pill { padding:5px 12px; border-radius:20px; font-size:12px; font-weight:700; display:inline-block; margin-top:6px; }
  .sparkline { display:flex; align-items:flex-end; gap:4px; height:100px; background:#080C15; padding:10px; border-radius:8px; border:1px solid var(--border); margin-top:10px; }
  .spark-bar { flex:1; background:var(--blue); border-radius:3px 3px 0 0; min-height:4px; transition:height 0.3s ease; }

  /* Channel Spectrum Grid */
  .ch-grid { display:grid; grid-template-columns:repeat(11, 1fr); gap:8px; margin-top:14px; margin-bottom:24px; }
  .ch-col { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 8px; text-align:center; }
  .ch-col.std { border-color:rgba(79,216,196,0.45); }
  .ch-col.overlap { border-color:rgba(240,168,78,0.45); }
  .ch-num { font-size:15px; font-weight:700; }
  .ch-tag { font-size:10px; margin-top:2px; margin-bottom:8px; }
  .ch-ap-pill { background:#080C15; border:1px solid var(--border); border-radius:5px; padding:4px; font-size:10px; margin-top:5px; word-break:break-word; }

  .toast { position:fixed; bottom:20px; right:20px; background:var(--panel); border:1px solid var(--cyan); color:var(--text); padding:10px 16px; border-radius:8px; font-size:12px; opacity:0; transition:opacity .3s; z-index:99; }
  .toast.show { opacity:1; }
</style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1><span class="dot"></span>Rogue Access Point Detection Dashboard</h1>
      <p class="sub">Real-time hardware RF scan &middot; updates every 2s &middot; last updated <span id="lastUpdate">—</span></p>
    </div>
    <div class="ctrl-group">
      <button id="demoBtn" class="demo-btn" onclick="toggleDemo()">&#9889; Demo Evil Twin: OFF</button>
      <button id="shieldBtn" class="shield-btn" onclick="toggleShield()">&#128737; Auto-Disconnect Shield: OFF</button>
    </div>
  </div>

  <div id="watchdogBanner" class="watchdog-banner"></div>

  <div class="nav">
    <button class="nav-btn active" data-view="scanView" onclick="switchView('scanView', this)">Live Scan</button>
    <button class="nav-btn" data-view="locateView" onclick="switchView('locateView', this)">Locate Rogue AP (Radar)</button>
    <button class="nav-btn" data-view="channelView" onclick="switchView('channelView', this)">Channel Spectrum Map</button>
    <button class="nav-btn" data-view="compareView" onclick="switchView('compareView', this)">Compare Vendor OUI &amp; Capabilities</button>
    <button class="nav-btn" data-view="alertsView" onclick="switchView('alertsView', this)">Forensic Alert Log <span id="alertBadge" class="alert-pill">0</span></button>
    <button class="nav-btn" data-view="profileView" onclick="switchView('profileView', this)">Vendor OUI Profiles &amp; Whitelist</button>
  </div>

  <!-- ============ 1. LIVE SCAN VIEW ============ -->
  <div class="view active" id="scanView">
    <div class="stats">
      <div class="card total"><div class="label">Total APs</div><div class="value" id="statTotal">0</div></div>
      <div class="card auth"><div class="label">Authorized</div><div class="value" id="statAuth">0</div></div>
      <div class="card susp"><div class="label">Suspicious (Same SSID)</div><div class="value" id="statSusp">0</div></div>
      <div class="card unauth"><div class="label">Unauthorized</div><div class="value" id="statUnauth">0</div></div>
      <div class="card rogue"><div class="label">Spoofed / Evil Twin</div><div class="value" id="statRogue">0</div></div>
    </div>

    <table>
      <tr>
        <th>Status</th>
        <th>SSID &amp; Detection Reasons</th>
        <th>BSSID</th>
        <th>Ch / Band</th>
        <th>Real-Time Signal</th>
        <th>Beacon Fingerprint</th>
        <th>Actions</th>
      </tr>
      <tbody id="apRows"></tbody>
    </table>
  </div>

  <!-- ============ 2. LOCATE ROGUE AP RADAR VIEW ============ -->
  <div class="view" id="locateView">
    <h2>Walk-Around Rogue AP Signal Locator</h2>
    <p class="hint">Select a target AP and walk around the room. Real-time RSSI updates every 2 seconds to guide you toward the physical transmitter.</p>
    <div style="margin-bottom:12px;">
      <label style="font-size:11px; color:var(--dim); display:block; margin-bottom:4px;">Target AP to Track</label>
      <select id="locSelect" onchange="resetLocator()"></select>
    </div>

    <div class="radar-box">
      <div class="radar-top">
        <div>
          <div style="font-size:11px; color:var(--dim); text-transform:uppercase;">Tracking Target</div>
          <div id="locTitle" style="font-size:20px; font-weight:700; margin-top:2px;">Select an AP above</div>
          <div id="locMeta" style="font-size:12px; color:var(--dim); margin-top:4px;">—</div>
        </div>
        <div style="text-align:right;">
          <div id="locRssi" style="font-size:32px; font-weight:700; color:var(--cyan);">— dBm</div>
          <span id="locZone" class="zone-pill" style="background:rgba(56,189,248,0.15); color:var(--blue);">Waiting for signal...</span>
        </div>
      </div>

      <div class="prox-meter"><div id="proxFill" class="prox-fill" style="width:0%;"></div></div>
      <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--dim);">
        <span>Far (-90 dBm / Weak)</span>
        <span>Adjacent Room (-65 dBm / Moderate)</span>
        <span>Immediate / Next to You (-35 dBm / Strong)</span>
      </div>

      <div style="margin-top:20px; font-size:11px; color:var(--dim); text-transform:uppercase;">Live Signal History (Last 30 Scans)</div>
      <div class="sparkline" id="sparkline"></div>
    </div>
  </div>

  <!-- ============ 3. CHANNEL SPECTRUM MAP VIEW ============ -->
  <div class="view" id="channelView">
    <h2>2.4 GHz Channel Plan &amp; Overlap Analyzer (Channels 1–11)</h2>
    <p class="hint">Channels <strong>1, 6, and 11</strong> are non-overlapping standard channels. Rogue APs or unmanaged mobile hotspots frequently broadcast on overlapping off-plan channels (2–5, 7–10).</p>
    <div class="ch-grid" id="chGrid24"></div>

    <h2>5 GHz Band Access Points</h2>
    <p class="hint">High-throughput 5 GHz radios detected in the local airspace.</p>
    <table>
      <tr><th>Channel</th><th>SSID</th><th>BSSID</th><th>Vendor</th><th>Signal</th><th>Status</th></tr>
      <tbody id="chRows5"></tbody>
    </table>
  </div>

  <!-- ============ 4. COMPARE VIEW ============ -->
  <div class="view" id="compareView">
    <h2>Compare Vendor OUI &amp; Beacon Capabilities</h2>
    <p class="hint">Select any detected AP and compare its Vendor OUI, Radio amendment, Supported Rates, Auth, and Channel against a trusted Vendor Profile or another AP.</p>
    <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px;">
      <div>
        <label style="font-size:11px; color:var(--dim); display:block; margin-bottom:4px;">Target / Observed AP</label>
        <select id="cmpLeft" onchange="renderComparison()"></select>
      </div>
      <div>
        <label style="font-size:11px; color:var(--dim); display:block; margin-bottom:4px;">Reference AP or Trusted Profile</label>
        <select id="cmpRight" onchange="renderComparison()"></select>
      </div>
    </div>
    <table>
      <tr><th>Beacon / Hardware Field</th><th>Observed AP</th><th>Trusted Reference</th><th>Result</th></tr>
      <tbody id="cmpRows"></tbody>
    </table>
  </div>

  <!-- ============ 5. FORENSIC ALERT LOG VIEW ============ -->
  <div class="view" id="alertsView">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:14px;">
      <div>
        <h2 style="margin:0;">Persistent Forensic Security Alert Log</h2>
        <p class="hint" style="margin:4px 0 0 0;">Automatically records Suspicious and Malicious AP detections with timestamps and peak signal strength for audit and investigation.</p>
      </div>
      <div>
        <a href="/api/alerts/export" class="btn-link" style="margin-right:6px;">&#11015; Export CSV Report</a>
        <button class="del-btn" onclick="clearAlerts()">Clear Log</button>
      </div>
    </div>

    <table>
      <tr>
        <th>Severity</th>
        <th>SSID &amp; BSSID</th>
        <th>Vendor / Ch</th>
        <th>First Seen</th>
        <th>Last Seen (Count)</th>
        <th>Peak Signal</th>
        <th>Forensic Evidence / Reasons</th>
      </tr>
      <tbody id="alertRows"></tbody>
    </table>
  </div>

  <!-- ============ 6. VENDOR PROFILE & WHITELIST VIEW ============ -->
  <div class="view" id="profileView">
    <section style="margin-top:0;">
      <h2>Manage Whitelist</h2>
      <p class="hint">Approved BSSIDs — networks matching these are marked Authorized.</p>
      <form id="wlForm">
        <input id="wlBssid" placeholder="BSSID (aa:bb:cc:dd:ee:ff)" size="20" required>
        <input id="wlSsid" placeholder="SSID" size="18" required>
        <button type="submit">Add to Whitelist</button>
      </form>
      <table>
        <tr><th>SSID</th><th>BSSID</th><th></th></tr>
        <tbody id="wlRows"></tbody>
      </table>
    </section>

    <section>
      <h2>Vendor OUI &amp; Capability Profiles</h2>
      <p class="hint">Define what a trusted network's vendor and settings SHOULD be so evil twins are caught even when the real AP is offline.</p>
      <form id="profileForm">
        <input id="pfSsid" placeholder="SSID (e.g. ISMAIL_2G)" size="16" required>
        <input id="pfVendor" placeholder="Vendor (e.g. TP-Link)" size="14" required>
        <input id="pfRadio" placeholder="Radio (e.g. 802.11n)" size="12">
        <input id="pfAuth" placeholder="Authentication (e.g. WPA2-Personal)" size="18">
        <input id="pfEnc" placeholder="Encryption (e.g. CCMP)" size="12">
        <input id="pfChannel" placeholder="Channel (e.g. 6)" size="8">
        <button type="submit">Save Profile</button>
      </form>
      <table>
        <tr><th>SSID</th><th>Vendor</th><th>Radio</th><th>Auth</th><th>Encryption</th><th>Channel</th><th></th></tr>
        <tbody id="pfRows"></tbody>
      </table>
    </section>
  </div>

  <div class="toast" id="toast"></div>

<script>
let latestData = { aps: [], whitelist: [], profiles: [], alerts: [], policy: { auto_disconnect: false, demo_attack: false }, watchdog_warnings: [] };
let rssiHistory = [];
let trackedBssid = "";
let knownAlertIds = new Set();
let firstLoadDone = false;

function toast(msg, isAlert = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.borderColor = isAlert ? '#FF5C6C' : '#4FD8C4';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

function switchView(id, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if (btn) btn.classList.add('active');
  else document.querySelector(`.nav-btn[data-view="${id}"]`).classList.add('active');
}

async function toggleShield() {
  const res = await fetch('/api/policy/toggle_disconnect', { method: 'POST' });
  if (res.ok) {
    const pol = await res.json();
    toast(pol.auto_disconnect
      ? 'Auto-Disconnect Shield ENABLED: Will sever Wi-Fi if connected to an Evil Twin'
      : 'Auto-Disconnect Shield disabled');
    refreshScan();
  }
}

async function toggleDemo() {
  const res = await fetch('/api/policy/toggle_demo', { method: 'POST' });
  if (res.ok) {
    const pol = await res.json();
    toast(pol.demo_attack
      ? 'Demo Evil Twin Attack INJECTED into live scan!'
      : 'Demo Evil Twin Attack stopped', pol.demo_attack);
    refreshScan();
  }
}

function openCompareFor(bssid) {
  switchView('compareView');
  document.getElementById('cmpLeft').value = bssid;
  renderComparison();
}

function openLocateFor(bssid) {
  switchView('locateView');
  trackedBssid = bssid;
  rssiHistory = [];
  document.getElementById('locSelect').value = bssid;
  updateLocator();
}

function resetLocator() {
  trackedBssid = document.getElementById('locSelect').value;
  rssiHistory = [];
  updateLocator();
}

function updateLocator() {
  const sel = document.getElementById('locSelect');
  if (!sel || !latestData.aps.length) return;
  const prev = trackedBssid || sel.value;
  sel.innerHTML = latestData.aps.map(ap =>
    `<option value="${ap.bssid}">${ap.ssid} (${ap.bssid}) — ${ap.signal_pct}%</option>`
  ).join('');
  if (prev && latestData.aps.some(a => a.bssid === prev)) {
    sel.value = prev;
  }
  trackedBssid = sel.value;

  const ap = latestData.aps.find(a => a.bssid === trackedBssid);
  if (!ap) return;

  rssiHistory.push(ap.signal_pct);
  if (rssiHistory.length > 30) rssiHistory.shift();

  document.getElementById('locTitle').textContent = `${ap.ssid} (${ap.bssid})`;
  document.getElementById('locMeta').textContent = `Vendor: ${ap.fingerprint.vendor} | Channel ${ap.channel} (${ap.fingerprint.band}) | Status: ${ap.status.toUpperCase()}`;
  document.getElementById('locRssi').textContent = `${ap.rssi} dBm (${ap.signal_pct}%)`;
  document.getElementById('proxFill').style.width = `${ap.signal_pct}%`;

  const zoneEl = document.getElementById('locZone');
  if (ap.signal_pct >= 75) {
    zoneEl.textContent = "IMMEDIATE PROXIMITY (< 3 meters)";
    zoneEl.style.background = "rgba(255,92,108,0.2)";
    zoneEl.style.color = "#FF5C6C";
  } else if (ap.signal_pct >= 45) {
    zoneEl.textContent = "NEARBY / SAME ROOM (3–10 meters)";
    zoneEl.style.background = "rgba(240,168,78,0.2)";
    zoneEl.style.color = "#F0A84E";
  } else {
    zoneEl.textContent = "FAR / ADJACENT AREA (> 10 meters)";
    zoneEl.style.background = "rgba(56,189,248,0.15)";
    zoneEl.style.color = "#38BDF8";
  }

  document.getElementById('sparkline').innerHTML = rssiHistory.map(pct => {
    const color = pct >= 75 ? '#FF5C6C' : (pct >= 45 ? '#F0A84E' : '#38BDF8');
    return `<div class="spark-bar" style="height:${Math.max(6, pct)}%; background:${color};" title="${pct}%"></div>`;
  }).join('');
}

function renderChannelMap() {
  const stdChannels = new Set([1, 6, 11]);
  let gridHtml = '';
  for (let ch = 1; ch <= 11; ch++) {
    const isStd = stdChannels.has(ch);
    const chAps = latestData.aps.filter(a => a.channel === ch);
    const pills = chAps.map(a => {
      const col = a.status === 'authorized' ? '#4FD8C4' : (a.status === 'suspicious' || a.twin_severity === 'malicious' ? '#FF5C6C' : '#F0A84E');
      return `<div class="ch-ap-pill" style="border-color:${col};"><strong style="color:${col}">${a.ssid}</strong><br>${a.signal_pct}%</div>`;
    }).join('');
    gridHtml += `
      <div class="ch-col ${isStd ? 'std' : 'overlap'}">
        <div class="ch-num" style="color:${isStd ? '#4FD8C4' : '#F0A84E'}">Ch ${ch}</div>
        <div class="ch-tag" style="color:${isStd ? '#4FD8C4' : '#F0A84E'}">${isStd ? 'Clean' : 'Overlap'}</div>
        ${pills || '<div style="color:var(--dim);font-size:10px;margin-top:8px;">Empty</div>'}
      </div>`;
  }
  document.getElementById('chGrid24').innerHTML = gridHtml;

  const aps5 = latestData.aps.filter(a => a.channel > 14);
  document.getElementById('chRows5').innerHTML = aps5.length
    ? aps5.map(a => `
        <tr>
          <td><strong>Ch ${a.channel}</strong></td>
          <td>${a.ssid}</td>
          <td><code>${a.bssid}</code></td>
          <td>${a.fingerprint.vendor}</td>
          <td>${a.signal_pct}% (${a.rssi} dBm)</td>
          <td><span class="badge ${a.status}">${a.status.toUpperCase()}</span></td>
        </tr>`).join('')
    : `<tr><td colspan="6" style="color:var(--dim); text-align:center;">No 5 GHz access points detected in range.</td></tr>`;
}

async function quickWhitelist(idx) {
  const ap = latestData.aps[idx];
  if (!ap) return;
  const res = await fetch('/api/whitelist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bssid: ap.bssid, ssid: ap.ssid, fingerprint: ap.fingerprint })
  });
  if (res.ok) {
    toast('Whitelisted & fingerprinted "' + ap.ssid + '"');
    refreshScan();
  }
}

async function clearAlerts() {
  await fetch('/api/alerts/clear', { method: 'POST' });
  knownAlertIds.clear();
  toast('Forensic alert log cleared');
  refreshScan();
}

function updateCompareDropdowns() {
  const leftSel = document.getElementById('cmpLeft');
  const rightSel = document.getElementById('cmpRight');
  const prevLeft = leftSel.value;
  const prevRight = rightSel.value;

  leftSel.innerHTML = latestData.aps.map(ap =>
    `<option value="${ap.bssid}">${ap.ssid} (${ap.bssid})</option>`
  ).join('');

  const profileOpts = (latestData.profiles || []).map(p =>
    `<option value="profile:${p.ssid}">[Profile] ${p.ssid} (${p.vendor})</option>`
  ).join('');
  const apOpts = latestData.aps.map(ap =>
    `<option value="ap:${ap.bssid}">[Live AP] ${ap.ssid} (${ap.bssid})</option>`
  ).join('');

  rightSel.innerHTML = profileOpts + apOpts;
  if (prevLeft) leftSel.value = prevLeft;
  if (prevRight) rightSel.value = prevRight;
  renderComparison();
}

function renderComparison() {
  const leftBssid = document.getElementById('cmpLeft').value;
  const rightVal = document.getElementById('cmpRight').value;
  const targetAp = latestData.aps.find(a => a.bssid === leftBssid);
  if (!targetAp) return;

  let refFp = null;
  if (rightVal && rightVal.startsWith('profile:')) {
    const prof = (latestData.profiles || []).find(p => p.ssid === rightVal.slice(8));
    if (prof) refFp = prof;
  } else if (rightVal && rightVal.startsWith('ap:')) {
    const refAp = latestData.aps.find(a => a.bssid === rightVal.slice(3));
    if (refAp) refFp = refAp.fingerprint;
  }

  const fields = [
    ['oui', 'Vendor OUI'],
    ['vendor', 'Manufacturer'],
    ['radio', 'Radio Type (802.11)'],
    ['channel', 'Channel'],
    ['auth', 'Authentication'],
    ['encryption', 'Encryption'],
    ['basic_rates', 'Supported Basic Rates'],
    ['other_rates', 'Extended Rates']
  ];

  const tFp = targetAp.fingerprint || {};
  document.getElementById('cmpRows').innerHTML = fields.map(([k, label]) => {
    const v1 = tFp[k] || '?';
    const v2 = refFp ? (refFp[k] || '?') : 'Select reference';
    const ok = refFp && (v2 === '?' || String(v1).toLowerCase() === String(v2).toLowerCase());
    return `<tr><td><strong>${label}</strong></td><td>${v1}</td><td>${v2}</td><td>${!refFp ? '—' : (ok ? '<span class="match-ok">MATCH</span>' : '<span class="match-bad">MISMATCH</span>')}</td></tr>`;
  }).join('');
}

async function refreshScan() {
  try {
    const res = await fetch('/api/scan');
    latestData = await res.json();

    const shieldOn = latestData.policy && latestData.policy.auto_disconnect;
    const shieldBtn = document.getElementById('shieldBtn');
    shieldBtn.textContent = shieldOn ? '🛡 Auto-Disconnect Shield: ON' : '🛡 Auto-Disconnect Shield: OFF';
    shieldBtn.className = shieldOn ? 'shield-btn active' : 'shield-btn';

    const demoOn = latestData.policy && latestData.policy.demo_attack;
    const demoBtn = document.getElementById('demoBtn');
    demoBtn.textContent = demoOn ? '⚡ Demo Evil Twin: ACTIVE' : '⚡ Demo Evil Twin: OFF';
    demoBtn.className = demoOn ? 'demo-btn active' : 'demo-btn';

    const banner = document.getElementById('watchdogBanner');
    if (latestData.watchdog_warnings && latestData.watchdog_warnings.length) {
      banner.style.display = 'block';
      banner.innerHTML = '&#9888; ' + latestData.watchdog_warnings.join(' &nbsp;|&nbsp; ');
    } else {
      banner.style.display = 'none';
    }

    if (latestData.shield_action) {
      toast(latestData.shield_action, true);
    }

    document.getElementById('statTotal').textContent = latestData.stats.total;
    document.getElementById('statAuth').textContent = latestData.stats.authorized;
    document.getElementById('statSusp').textContent = latestData.stats.suspicious;
    document.getElementById('statUnauth').textContent = latestData.stats.unauthorized;
    document.getElementById('statRogue').textContent = latestData.stats.rogue;
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

    const alerts = latestData.alerts || [];
    document.getElementById('alertBadge').textContent = alerts.length;
    alerts.forEach(a => {
      if (!knownAlertIds.has(a.id)) {
        knownAlertIds.add(a.id);
        if (firstLoadDone) {
          toast(`ALERT: ${a.severity} detected on "${a.ssid}" (${a.bssid})`, true);
        }
      }
    });
    firstLoadDone = true;

    const wlSet = new Set((latestData.whitelist || []).map(w => w.bssid.toLowerCase()));

    document.getElementById('apRows').innerHTML = (latestData.aps || []).map((ap, i) => {
      const isWl = wlSet.has(ap.bssid.toLowerCase());
      const fp = ap.fingerprint || {};
      const conn = ap.connection_history || 'Never Connected';
      const connBadge = conn === 'Connected Now'
        ? `<span class="conn-badge conn-now">&#9679; Connected Now</span>`
        : (conn === 'Connected Before'
            ? `<span class="conn-badge conn-before">Connected Before</span>`
            : `<span class="conn-never">Never Connected</span>`);

      const reasonsHtml = (ap.is_twin && ap.twin_reasons && ap.twin_reasons.length)
        ? `<ul class="reason-list">${ap.twin_reasons.map(r => `<li>${r}</li>`).join('')}</ul>`
        : '';

      const sigColor = ap.signal_pct >= 65 ? '#4FD8C4' : (ap.signal_pct >= 35 ? '#F0A84E' : '#FF5C6C');
      const rowClass = ap.twin_severity === 'malicious' ? 'twin-row' : (ap.status === 'suspicious' ? 'susp-row' : '');
      const alertTag = ap.twin_severity === 'malicious'
        ? `<span class="twin-tag">&#9888; EVIL TWIN</span>`
        : (ap.status === 'suspicious' ? `<span class="susp-tag">&#9888; DUPLICATE SSID</span>` : '');

      return `
        <tr class="${rowClass}">
          <td><span class="badge ${ap.status}">${ap.status.toUpperCase()}</span></td>
          <td>
            <strong>${ap.ssid}</strong>
            ${alertTag}
            <div>${connBadge}</div>
            ${reasonsHtml}
          </td>
          <td><code>${ap.bssid}</code><br><small style="color:var(--dim)">OUI: ${fp.oui}</small></td>
          <td>Ch ${ap.channel}<br><small style="color:var(--dim)">${fp.band}</small></td>
          <td>
            <div class="sig-bar"><div class="sig-fill" style="width:${ap.signal_pct}%; background:${sigColor};"></div></div>
            <strong>${ap.signal_pct}%</strong> <small style="color:var(--dim)">(${ap.rssi} dBm)</small>
          </td>
          <td>
            <strong>${fp.vendor}</strong> &middot; ${fp.radio}<br>
            <small style="color:var(--dim)">${fp.auth} | Rates: [${fp.basic_rates}]</small>
          </td>
          <td>
            ${isWl
              ? `<button class="del-btn" onclick="removeWhitelist('${ap.bssid}')">Remove WL</button>`
              : `<button class="act-btn" onclick="quickWhitelist(${i})">+ Whitelist</button>`
            }
            <button class="cmp-btn" onclick="openCompareFor('${ap.bssid}')">Compare</button>
            <button class="loc-btn" onclick="openLocateFor('${ap.bssid}')">Locate</button>
          </td>
        </tr>`;
    }).join('');

    document.getElementById('alertRows').innerHTML = alerts.length
      ? alerts.map(a => {
          const isMal = a.severity.includes('MALICIOUS');
          return `
            <tr class="${isMal ? 'twin-row' : 'susp-row'}">
              <td><span class="badge ${isMal ? 'spoofed' : 'suspicious'}">${a.severity}</span></td>
              <td><strong>${a.ssid}</strong><br><code>${a.bssid}</code></td>
              <td>${a.vendor}<br><small style="color:var(--dim)">Ch ${a.channel}</small></td>
              <td>${a.first_seen}</td>
              <td>${a.last_seen}<br><small style="color:var(--dim)">${a.seen_count} scans</small></td>
              <td><strong>${a.peak_signal_pct}%</strong> (${a.peak_rssi} dBm)</td>
              <td style="font-size:12px;">${a.reasons}</td>
            </tr>`;
        }).join('')
      : `<tr><td colspan="7" style="color:var(--dim); text-align:center; padding:20px;">No Suspicious or Malicious incidents recorded yet.</td></tr>`;

    document.getElementById('wlRows').innerHTML = (latestData.whitelist || []).map(w => `
      <tr><td>${w.ssid}</td><td><code>${w.bssid}</code></td><td><button class="del-btn" onclick="removeWhitelist('${w.bssid}')">Remove</button></td></tr>
    `).join('');

    document.getElementById('pfRows').innerHTML = (latestData.profiles || []).map(p => `
      <tr><td>${p.ssid}</td><td>${p.vendor}</td><td>${p.radio || ''}</td><td>${p.auth || ''}</td><td>${p.encryption || ''}</td><td>${p.channel || ''}</td><td><button class="del-btn" onclick="removeProfile('${p.ssid}')">Remove</button></td></tr>
    `).join('');

    updateCompareDropdowns();
    updateLocator();
    renderChannelMap();
  } catch (e) {
    document.getElementById('lastUpdate').textContent = 'Error: ' + e.message;
  }
}

async function removeWhitelist(bssid) {
  await fetch('/api/whitelist/' + encodeURIComponent(bssid), { method: 'DELETE' });
  toast('Removed from whitelist');
  refreshScan();
}

async function removeProfile(ssid) {
  await fetch('/api/profiles/' + encodeURIComponent(ssid), { method: 'DELETE' });
  toast('Profile removed');
  refreshScan();
}

document.getElementById('wlForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const bssid = document.getElementById('wlBssid').value.trim();
  const ssid = document.getElementById('wlSsid').value.trim();
  const res = await fetch('/api/whitelist', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bssid, ssid })
  });
  if (res.ok) {
    toast('Added "' + ssid + '" to whitelist');
    document.getElementById('wlForm').reset();
    refreshScan();
  }
});

document.getElementById('profileForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const payload = {
    ssid: document.getElementById('pfSsid').value.trim(),
    vendor: document.getElementById('pfVendor').value.trim(),
    radio: document.getElementById('pfRadio').value.trim(),
    auth: document.getElementById('pfAuth').value.trim(),
    encryption: document.getElementById('pfEnc').value.trim(),
    channel: document.getElementById('pfChannel').value.trim()
  };
  const res = await fetch('/api/profiles', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    toast('Profile saved for "' + payload.ssid + '"');
    document.getElementById('profileForm').reset();
    refreshScan();
  }
});

refreshScan();
setInterval(refreshScan, 2000);
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(PAGE)


if __name__ == "__main__":
    start_background_scanner()
    app.run(debug=True, port=5000, use_reloader=False)