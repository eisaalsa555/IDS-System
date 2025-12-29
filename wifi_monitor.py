"""
wifi_monitor_nmap_telegram.py

Description:
- Continuous LAN scanner using nmap (must be installed on Windows)
- Discovers hosts with `nmap -sn` then runs full service/port scan `nmap -p- -sV --open -T4` per host
- Parses nmap XML output to list open ports and service names
- Sends a Telegram summary message after each scan (if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set)
- Plays a beep/alarm after each scan

Usage:
1. Install dependencies:
   pip install requests

2. Set environment variables (or edit the CONFIG section in the script):
   TELEGRAM_BOT_TOKEN - Bot token obtained from BotFather
   TELEGRAM_CHAT_ID  - Your chat id (or group id) for notifications

3. Run as administrator on Windows (nmap ARP/host discovery may require elevated privileges):
   py wifi_monitor_nmap_telegram.py

Notes:
- The script defaults to scanning the local /24 subnet discovered from the local IP.
- Change SCAN_INTERVAL_SECONDS to control how often scans run.
- The script is conservative about parallel scans to avoid hammering the network. It runs each host scan sequentially but spawns nmap subprocesses so nmap runs in background subprocesses.

"""

import os
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
import socket
import re
import threading
import logging
from datetime import datetime
import shutil

try:
    import requests
except ImportError:
    print("Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)

# ------------------ CONFIG ------------------
SCAN_INTERVAL_SECONDS = 60          # seconds between full discovery cycles
NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"                 # path to nmap executable if not in PATH, set full path
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')
# Whether to send Telegram notifications. If False, script will only log locally
USE_TELEGRAM = True if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID else False
# Beep settings (Windows winsound: frequency in Hz, duration in ms). If not windows, will print bell char.
BEEP_FREQUENCY = 1000
BEEP_DURATION_MS = 600
# Maximum time per host scan (seconds)
HOST_SCAN_TIMEOUT = 120
# Whether to do full port range (-p-) or just common ports (set False for speed)
FULL_PORT_SCAN = True
# Extra nmap flags
NMAP_EXTRA_FLAGS = ["-Pn"]  # -Pn avoids ping-check if you want to force scanning even if host didn't respond
# --------------------------------------------

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')


def get_local_ip():
    """Return the local IP address used for default route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def cidr_from_ip(ip):
    # naive assume /24 for home networks
    parts = ip.split('.')
    if len(parts) != 4:
        return '192.168.1.0/24'
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def run_nmap_discovery(subnet):
    """Run nmap -sn to discover hosts. Return list of IPs found."""
    cmd = [NMAP_PATH, '-sn', subnet, '-oX', '-']
    logging.info(f"Running discovery: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        logging.error('Discovery nmap timed out')
        return []

    if p.returncode != 0 and not p.stdout:
        logging.warning('nmap discovery returned non-zero code: %s', p.stderr.strip())

    xml = p.stdout
    ips = []
    try:
        root = ET.fromstring(xml)
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None:
                ips.append(addr.get('addr'))
    except ET.ParseError:
        logging.error('Failed to parse nmap discovery XML')
    logging.info(f"Discovered hosts: {ips}")
    return ips


def run_nmap_service_scan(ip):
    """Run nmap -p- -sV --open -oX - <ip> and parse open ports and services."""
    ports_flag = '-p-' if FULL_PORT_SCAN else '-F'
    cmd = [NMAP_PATH, ports_flag, '-sV', '--open', '-T4'] + NMAP_EXTRA_FLAGS + ['-oX', '-', ip]
    logging.info(f"Starting service scan for {ip}: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=HOST_SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        logging.error(f"Service scan for {ip} timed out")
        return {'ip': ip, 'ports': [], 'error': 'timeout'}

    if p.returncode != 0 and not p.stdout:
        logging.warning('nmap service scan returned non-zero code: %s', p.stderr.strip())

    xml = p.stdout
    result = {'ip': ip, 'ports': [], 'error': None}
    try:
        root = ET.fromstring(xml)
        for host in root.findall('host'):
            addr = host.find("address[@addrtype='ipv4']")
            if addr is not None and addr.get('addr') != ip:
                # sometimes nmap returns different formatting; still continue
                pass
            ports = host.find('ports')
            if ports is None:
                continue
            for port in ports.findall('port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                portid = port.get('portid')
                proto = port.get('protocol')
                service = port.find('service')
                service_name = service.get('name') if service is not None else ''
                product = service.get('product') if service is not None and 'product' in service.attrib else ''
                version = service.get('version') if service is not None and 'version' in service.attrib else ''
                result['ports'].append({
                    'port': int(portid),
                    'proto': proto,
                    'service': service_name,
                    'product': product,
                    'version': version
                })
    except ET.ParseError:
        logging.error('Failed to parse nmap service scan XML for %s', ip)
        result['error'] = 'parse_error'
    logging.info(f"Scan result for {ip}: {len(result['ports'])} open ports")
    return result


def beep_alarm():
    """Play a beep/alarm on Windows or print bell on other OS."""
    try:
        if sys.platform.startswith('win'):
            import winsound
            winsound.Beep(BEEP_FREQUENCY, BEEP_DURATION_MS)
            # additional short beeps
            winsound.Beep(int(BEEP_FREQUENCY*1.2), 200)
            winsound.Beep(int(BEEP_FREQUENCY*0.8), 200)
        else:
            # Unix: terminal bell
            print('\a')
    except Exception as e:
        logging.warning('Beep failed: %s', e)


def send_telegram_message(text):
    if not USE_TELEGRAM:
        logging.info('Telegram disabled or credentials missing; not sending message')
        return False
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'HTML'}
    try:
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            logging.info('Telegram message sent')
            return True
        else:
            logging.warning('Telegram send failed: %s %s', r.status_code, r.text)
            return False
    except Exception as e:
        logging.error('Telegram request exception: %s', e)
        return False


def summarize_scan_results(results):
    lines = []
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines.append(f'<b>WiFi Scan Result — {now}</b>')
    for r in results:
        ip = r.get('ip')
        ports = r.get('ports', [])
        if r.get('error'):
            lines.append(f'\n{ip} — ERROR: {r.get("error")}')
            continue
        if not ports:
            lines.append(f'\n{ip} — No open ports found')
            continue
        # Compose port/service summary
        port_summary = ', '.join([f"{p['port']}/{p['proto']} ({p['service'] or 'unknown'})" for p in ports])
        lines.append(f'\n{ip} — {port_summary}')
    return '\n'.join(lines)


def pretty_print_results(results):
    for r in results:
        ip = r.get('ip')
        logging.info('Device: %s', ip)
        if r.get('error'):
            logging.info('  Error: %s', r.get('error'))
            continue
        if not r.get('ports'):
            logging.info('  No open ports')
            continue
        for p in r['ports']:
            logging.info('  %s/%s — %s %s', p['port'], p['proto'], p['service'], f"({p['product']} {p['version']})" if p.get('product') else '')


def scan_cycle():
    local_ip = get_local_ip()
    subnet = cidr_from_ip(local_ip)
    logging.info(f'Local IP: {local_ip}  Subnet: {subnet}')

    hosts = run_nmap_discovery(subnet)
    if not hosts:
        logging.info('No hosts found in discovery. Sleeping...')
        return

    results = []
    # sequential scans (safer); you can parallelize but be careful
    for host in hosts:
        res = run_nmap_service_scan(host)
        results.append(res)

    pretty_print_results(results)

    # Send Telegram summary (if enabled)
    summary = summarize_scan_results(results)
    if USE_TELEGRAM:
        send_telegram_message(summary)

    # Beep after scan
    beep_alarm()


def main_loop():
    logging.info('Starting continuous WiFi LAN monitor with nmap')
    while True:
        try:
            scan_cycle()
        except KeyboardInterrupt:
            logging.info('User interrupted — exiting')
            break
        except Exception as e:
            logging.exception('Unexpected error during scan cycle: %s', e)
        logging.info(f'Waiting {SCAN_INTERVAL_SECONDS} seconds before next cycle...')
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == '__main__':
    # Quick sanity checks
    if not shutil.which(NMAP_PATH):
        logging.error('nmap executable not found. Please install nmap and ensure it is in PATH, or set NMAP_PATH.')
        sys.exit(1)

    # Allow overriding config via env
    if os.getenv('WIFI_SCAN_INTERVAL'):
        try:
            SCAN_INTERVAL_SECONDS = int(os.getenv('WIFI_SCAN_INTERVAL'))
        except:
            pass

    # Set USE_TELEGRAM according to presence of credentials
    USE_TELEGRAM = True if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID else False
    if not USE_TELEGRAM:
        logging.info('Telegram notifications disabled (TELEGRAM_BOT_TOKEN/CHAT_ID not set)')

    main_loop()
