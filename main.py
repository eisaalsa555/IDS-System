# main.py
"""
Intrusion Detection System - main entrypoint
- Loads config
- Starts packet sniffing (scapy)
- Uses detector.py for rule-based detection
- Optionally uses ml_model.py for anomaly detection
- Uses alert_system.py for logging/notifications
"""

import os
import signal
import threading
import time
import winsound
from collections import defaultdict

# imports (replace any previous get_windows_if_list import)
from scapy.arch.windows import get_windows_if_list
from scapy.all import sniff, IP, TCP, UDP, conf
# Local modules (make sure these files exist in src/)
from src.utils import load_config, ip_to_geo, current_timestamp
from src import detector       # must contain detect_attack(src_ip, packet_meta) or similar
from src import alert_system   # must contain log_attack(ip, details) and notify_telegram(...) etc.
from src import ml_model       # optional: train_model(), detect_anomaly()


# --- STATE HOUSED IN MAIN (keeps short-term stats) ---
# track last N seconds activity per IP for feature construction
activity_log = defaultdict(list)

# helper: safe get from config
def cfg(path, default=None):
    parts = path.split(".")
    node = CONFIG
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            return default
        node = node[p]
    return node

def build_packet_meta(packet):
    """Extract useful metadata from scapy packet for detector + ML"""
    try:
        src = packet[IP].src
        dst = packet[IP].dst
    except Exception:
        return None

    sport = None
    dport = None
    proto = "OTHER"
    pkt_len = len(packet)

    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    return {
        "src": src,
        "dst": dst,
        "proto": proto,
        "sport": sport,
        "dport": dport,
        "pkt_len": pkt_len,
        "timestamp": time.time()
    }

def update_activity_and_get_stats(src_ip, meta):
    """
    Keep a sliding window of timestamps & ports per IP and compute simple features:
    - packet_rate (pkts / window_seconds)
    - unique_ports (count)
    - avg_packet_size
    """
    now = meta["timestamp"]
    window = cfg("detection.portscan_window_seconds", 10)
    if window is None:
        window = 10

    # append (timestamp, port, size)
    activity_log[src_ip].append((now, meta.get("dport"), meta.get("pkt_len")))

    # prune old entries
    activity_log[src_ip] = [t for t in activity_log[src_ip] if now - t[0] <= window]

    entries = activity_log[src_ip]
    packet_rate = len(entries) / max(1.0, window)    # pkts per second
    unique_ports = len({p for (_, p, _) in entries if p is not None})
    avg_size = sum(s for (_, _, s) in entries) / max(1, len(entries))

    return {
        "packet_rate": packet_rate,
        "unique_ports": unique_ports,
        "avg_packet_size": avg_size
    }

def handle_packet(packet):
    """Callback for scapy.sniff"""
    meta = build_packet_meta(packet)
    if meta is None:
        return

    src = meta["src"]

    # 1) Use rule-based detector (detect_attack should return True/False and optional reason)
    #    detector.detect_attack signature expected: detect_attack(src_ip, meta) -> (bool, str)
    try:
        rule_result = detector.detect_attack(src, meta)
    except TypeError:
        # backward compatibility: if detect_attack only expects src_ip and returns bool
        try:
            rule_ok = detector.detect_attack(src)
            rule_reason = "rule-based threshold"
            rule_result = (rule_ok, rule_reason) if isinstance(rule_ok, tuple) else (rule_ok, rule_reason)
        except Exception:
            # if detector.detect_attack returns bool
            rule_result = (False, "")
    except Exception as e:
        print(f"[!] detector error: {e}")
        rule_result = (False, "")

    # 2) Update activity log and compute simple features for ML or more advanced rules
    packet_stats = update_activity_and_get_stats(src, meta)

    # 3) Optionally use ML model if enabled in config
    ml_enabled = cfg("ml.enable_ml_detection", False)
    ml_suspicious = False
    try:
        if ml_enabled:
            ml_suspicious = ml_model.detect_anomaly(packet_stats)
    except Exception as e:
        print(f"[!] ML detection error: {e}")
        ml_suspicious = False

    # 4) Decide final outcome (if either rule or ML says suspicious)
    rule_flag, rule_reason = False, ""
    if isinstance(rule_result, tuple):
        rule_flag, rule_reason = rule_result
    else:
        rule_flag = bool(rule_result)

    is_suspicious = rule_flag or ml_suspicious

    if is_suspicious:
        # gather enrichment data
        geo = ip_to_geo(src)
        timest = current_timestamp()
        details = {
            "timestamp": timest,
            "src": src,
            "dst": meta["dst"],
            "proto": meta["proto"],
            "sport": meta["sport"],
            "dport": meta["dport"],
            "pkt_len": meta["pkt_len"],
            "packet_stats": packet_stats,
            "geo": geo,
            "rule_reason": rule_reason,
            "ml_suspicious": ml_suspicious
        }
        # log & notify
        try:
            alert_system.log_attack(src, details)
        except Exception as e:
            print(f"[!] alert_system.log_attack failed: {e}")

        # ---- Beep alarm here ----
        try:
            if cfg("alerts.enable_sound_alarm", False):
                frequency = 1000  # Hz
                duration = 5000    # ms
                winsound.Beep(frequency, duration)
        except Exception:
            pass
        # optional: immediate telegram/email notify
        try:
            if cfg("alerts.enable_telegram", False) and hasattr(alert_system, "notify_telegram"):
                alert_system.notify_telegram(src, details)
        except Exception as e:
            print(f"[!] Telegram notify failed: {e}")

        try:
            if cfg("alerts.enable_email", False) and hasattr(alert_system, "notify_email"):
                alert_system.notify_email(src, details)
        except Exception as e:
            print(f"[!] Email notify failed: {e}")

    # small print to console for visibility during testing
    print(f"{current_timestamp()} | {meta['proto']} | {meta['src']} -> {meta['dst']} | len={meta['pkt_len']} | suspicious={is_suspicious}")

def choose_windows_iface(interactive=False):
    """
    Prefer Wi‑Fi first, then Ethernet, then other adapters.
    Returns the exact 'name' field from get_windows_if_list().
    """
    ifaces = get_windows_if_list()
    # Normalize list with (name, desc)
    norm = [(a.get("name"), (a.get("description") or "").lower()) for a in ifaces]

    # 1) Prefer Wi‑Fi by description or name
    for name, desc in norm:
        if name and ("wi-fi" in name.lower() or "wifi" in name.lower() or "wireless" in desc or "broadcom" in desc):
            return name

    # 2) Then prefer Ethernet by description
    for name, desc in norm:
        if name and ("ethernet" in name.lower() or "realtek" in desc or "intel" in desc):
            return name

    # 3) Then first non-loopback, non-virtual
    for name, desc in norm:
        if name and "loopback" not in name.lower() and "vmware" not in desc and "virtual" not in desc:
            return name

    # 4) fallback to conf.iface
    return conf.iface



def start_sniffer(interactive=False):
    iface = cfg("sniffer.interface", None)
    all_ifaces = get_windows_if_list()

    # if config provided and exact match exists, use it
    if iface:
        available_names = [a.get("name") for a in all_ifaces]
        if iface in available_names:
            chosen = iface
        else:
            print(f"[i] Config interface '{iface}' not found. Showing available interfaces:")
            for i, a in enumerate(all_ifaces):
                print(f"[{i}] {a.get('name')}  --  {a.get('description')}")
            # interactive choice
            try:
                idx = int(input("Choose interface index (or press Enter to auto-select): ") or -1)
                if 0 <= idx < len(all_ifaces):
                    chosen = all_ifaces[idx].get("name")
                else:
                    chosen = choose_windows_iface()
            except Exception:
                chosen = choose_windows_iface()
    else:
        if interactive:
            print("Available interfaces:")
            for i, a in enumerate(all_ifaces):
                print(f"[{i}] {a.get('name')}  --  {a.get('description')}")
            try:
                idx = int(input("Choose interface index (or press Enter to auto-select): ") or -1)
                if 0 <= idx < len(all_ifaces):
                    chosen = all_ifaces[idx].get("name")
                else:
                    chosen = choose_windows_iface()
            except Exception:
                chosen = choose_windows_iface()
        else:
            chosen = choose_windows_iface()

    if not chosen:
        print("[!] No interface chosen — aborting.")
        return

    print(f"[i] Starting sniffer on interface={chosen} (store={cfg('sniffer.store_packets', False)})")
    sniff(prn=handle_packet, store=cfg("sniffer.store_packets", False), iface=chosen)



def graceful_shutdown(signum, frame):
    print("\n[i] Received shutdown signal. Exiting gracefully...")
    # perform any cleanup if necessary (flush logs, close DB)
    try:
        if hasattr(alert_system, "shutdown"):
            alert_system.shutdown()
    except Exception:
        pass
    os._exit(0)

if __name__ == "__main__":
    # load config
    try:
        CONFIG = load_config()
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        raise SystemExit(1)

    # attach signal handlers
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    # If ML detection is enabled but model missing, warn
    if cfg("ml.enable_ml_detection", False):
        model_path = cfg("ml.model_path", "data/anomaly_model.joblib")
        if not os.path.exists(model_path):
            print(f"⚠️ ML enabled but model not found at {model_path}. Set ml.enable_ml_detection=False in config or train model first.")

    # Start sniffer (runs in main thread; scapy requires root)
    try:
        start_sniffer()
    except PermissionError:
        print("❗ Permission denied: run with root/Administrator privileges (scapy/sniff needs elevated rights).")
    except Exception as e:
        print(f"[!] Sniffer error: {e}")
