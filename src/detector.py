# src/detector.py
from collections import defaultdict
import time

traffic_log = defaultdict(list)
THRESHOLD = 50  # packets per 10 sec

def detect_attack(src_ip):
    now = time.time()
    traffic_log[src_ip] = [t for t in traffic_log[src_ip] if now - t < 10]
    traffic_log[src_ip].append(now)

    if len(traffic_log[src_ip]) > THRESHOLD:
        return True
    return False

#this is a temporary code for detecting attacks based on port usage
_last_seen = {}

def detect_attack(src_ip, meta=None):
    if meta is None:
        return False

    dport = meta.get("dport")
    now = time.time()

    # Agar port 139 ya 445 ho → suspicious
    if dport in (139, 445):
        return True, f"smb_target_port_{dport}"

    # simple portscan: agar ek IP last 10 sec me 3+ alag ports touch kare
    window = 10
    hits = _last_seen.setdefault(src_ip, [])
    hits.append((now, dport))
    _last_seen[src_ip] = [t for t in hits if now - t[0] <= window]
    unique_ports = len({p for (_, p) in _last_seen[src_ip] if p is not None})
    if unique_ports > 2:
        return True, f"portscan_unique_ports={unique_ports}"

    return False, ""