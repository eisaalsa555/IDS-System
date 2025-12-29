#!/usr/bin/env python3
"""
background_scanner.py

What it does:
- Scans filesystem for suspicious files/folders based on heuristics:
  * suspicious extensions (.exe/.bat/.cmd/.scr/.js/.vbs/.ps1/.scr/.pif etc)
  * executable magic headers (PE/ELF/#!/bin)
  * double extensions like "invoice.pdf.exe"
  * filenames containing suspicious keywords (password, keylogger, ransomware, decrypt, crack)
  * hidden files in common user folders
  * large unknown binaries in Downloads or Temp
  * checks Windows Run registry keys and Startup folders (if running on Windows)
- Classifies findings as: SAFE, SUSPICIOUS, LIKELY_MALICIOUS
- Writes detailed report to output.log
- Runs an immediate scan, then repeats in background every INTERVAL_MINUTES

Notes:
- No network queries are made (no VirusTotal).
- For best results on Windows run with administrator privileges.
"""

import os
import sys
import hashlib
import time
import threading
import logging
import mimetypes
from datetime import datetime

# Windows-only imports guarded by try/except
try:
    import winreg
    import ctypes
    IS_WINDOWS = True
except Exception:
    IS_WINDOWS = False

# Configuration
ROOT_PATHS = []  # If empty, defaults will be used per platform
EXCLUDE_DIRS = {'$Recycle.Bin', 'node_modules', '__pycache__'}
SUSPICIOUS_EXTS = {
    '.exe', '.dll', '.scr', '.pif', '.bat', '.cmd', '.js', '.jse', '.vbs', '.vbe',
    '.ps1', '.psm1', '.msi', '.com', '.hta', '.wsf', '.jar'
}
SUSPICIOUS_KEYWORDS = {'password', 'passwd', 'keylogger', 'ransom', 'decrypt', 'steal', 'trojan', 'backdoor', 'crack', 'serial'}
DOUBLE_EXT_THRESHOLD = True
LARGE_FILE_MB = 100  # mark files > this as suspicious if in risky places
INTERVAL_MINUTES = 60  # repeat scan interval
LOGFILE = 'output.log'

# Setup logging
logger = logging.getLogger('bg_scanner')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOGFILE, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

console = logging.StreamHandler()
console.setFormatter(formatter)
console.setLevel(logging.INFO)
logger.addHandler(console)

def sha256_of_file(path, nbytes=None):
    """Compute SHA256 of file (optionally only first nbytes)."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            if nbytes:
                data = f.read(nbytes)
                h.update(data)
            else:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

def read_magic(path, n=4):
    try:
        with open(path, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''

def is_executable_by_magic(path):
    m = read_magic(path, n=4)
    if m.startswith(b'MZ'):  # Windows PE
        return True, 'PE (MZ)'
    if m.startswith(b'\x7fELF'):  # ELF
        return True, 'ELF'
    if m.startswith(b'#!'):  # script with shebang
        return True, 'Shebang script'
    return False, ''

def suspicious_double_ext(name):
    if '.' in name:
        parts = name.split('.')
        if len(parts) >= 3:
            # file.tar.gz is okay: treat known compressions as safe second ext
            second = parts[-2].lower()
            third = parts[-1].lower()
            # if final ext is executable-like, suspicious
            if '.' + third in SUSPICIOUS_EXTS:
                return True
    return False

def suspicious_name(name):
    l = name.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in l:
            return True
    return False

def human_size(bytesize):
    for unit in ['B','KB','MB','GB','TB']:
        if bytesize < 1024.0:
            return f"{bytesize:.1f}{unit}"
        bytesize /= 1024.0
    return f"{bytesize:.1f}PB"

def classify_item(path, stat, extra=None):
    """
    Return classification: 'SAFE' / 'SUSPICIOUS' / 'LIKELY_MALICIOUS' and reasons list.
    Uses heuristics — not definitive.
    """
    reasons = []
    name = os.path.basename(path)
    lower = name.lower()

    # If directory, look for suspicious patterns (e.g., hidden folder in temp)
    if os.path.isdir(path):
        if name.startswith('.') or name.startswith('temp') or 'tmp' in name.lower():
            reasons.append('Hidden or temp directory name')
    else:
        ext = os.path.splitext(name)[1].lower()
        size_mb = stat.st_size / (1024*1024)
        if ext in SUSPICIOUS_EXTS:
            reasons.append(f"Suspicious extension {ext}")
        is_exec, magic = is_executable_by_magic(path)
        if is_exec:
            reasons.append(f"Executable file detected ({magic})")
        if suspicious_double_ext(name):
            reasons.append("Double extension (e.g. file.pdf.exe)")
        if suspicious_name(name):
            reasons.append("Filename contains suspicious keyword")
        if size_mb >= LARGE_FILE_MB and ('downloads' in path.lower() or 'temp' in path.lower()):
            reasons.append(f"Large binary ({size_mb:.1f} MB) in Downloads/Temp")
        # hidden file (Windows attribute or dotfile)
        if name.startswith('.'):
            reasons.append('Hidden (dotfile)')
        # Unknown mimetype for non-binaries can be suspicious if executable by magic
        mime, _ = mimetypes.guess_type(path)
        if mime is None and is_exec:
            reasons.append('Unknown mimetype + executable magic')

    # Simple scoring
    score = 0
    for r in reasons:
        score += 1
    if len(reasons) == 0:
        return 'SAFE', reasons
    elif len(reasons) == 1:
        return 'SUSPICIOUS', reasons
    else:
        return 'LIKELY_MALICIOUS', reasons

def default_roots():
    if ROOT_PATHS:
        return ROOT_PATHS
    if IS_WINDOWS:
        # Scan user profile and program files reasonably
        roots = [os.path.expanduser('~')]
        # Common additional paths:
        pf = os.environ.get('ProgramFiles')
        pf86 = os.environ.get('ProgramFiles(x86)')
        if pf:
            roots.append(pf)
        if pf86:
            roots.append(pf86)
        return roots
    else:
        # Linux/macOS: home and /tmp and /opt
        return [os.path.expanduser('~'), '/tmp', '/opt']

def walk_and_scan(roots):
    findings = []
    for root in roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            # skip excluded directories
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            # Limit depth? (Optional) - for speed you could implement
            # examine files
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.stat(fpath)
                except Exception:
                    continue
                classification, reasons = classify_item(fpath, st)
                if classification != 'SAFE':
                    sha = sha256_of_file(fpath, nbytes=4096)  # partial hash for speed
                    findings.append({
                        'path': fpath,
                        'size': st.st_size,
                        'mtime': st.st_mtime,
                        'classification': classification,
                        'reasons': reasons,
                        'sha256_first4k': sha
                    })
    return findings

# Windows-specific functions
def get_windows_startup_folders():
    folders = []
    try:
        user = os.environ.get('USERPROFILE')
        if user:
            folders.append(os.path.join(user, r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
            folders.append(os.path.join(user, r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Startup'))
        # All users
        programdata = os.environ.get('ProgramData')
        if programdata:
            folders.append(os.path.join(programdata, r'Microsoft\Windows\Start Menu\Programs\StartUp'))
    except Exception:
        pass
    return [f for f in folders if os.path.exists(f)]

def read_run_registry():
    results = []
    try:
        # HKCU
        for hive, hive_name in [(winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')]:
            for subkey in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"):
                try:
                    key = winreg.OpenKey(hive, subkey)
                except FileNotFoundError:
                    continue
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        results.append({'hive': hive_name, 'key': subkey, 'name': name, 'value': value})
                        i += 1
                    except OSError:
                        break
    except Exception as e:
        logger.debug("Registry read error: %s", e)
    return results

def scan_windows_startup_entries():
    findings = []
    # registry Run keys
    reg_entries = read_run_registry()
    for e in reg_entries:
        val = e.get('value','')
        name = e.get('name','')
        # if value points to suspicious exe, classify
        path = val.strip('"')
        classification = 'SUSPICIOUS'
        reasons = ['Startup registry entry']
        if os.path.exists(path):
            try:
                st = os.stat(path)
                classification, reasons2 = classify_item(path, st)
                reasons = ['Startup registry entry'] + reasons2
            except Exception:
                pass
        findings.append({
            'path': path,
            'where': f"{e['hive']}\\{e['key']}\\{name}",
            'classification': classification,
            'reasons': reasons
        })
    # startup folders
    for folder in get_windows_startup_folders():
        try:
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                if os.path.isfile(fpath):
                    try:
                        st = os.stat(fpath)
                        classification, reasons = classify_item(fpath, st)
                        if classification != 'SAFE':
                            findings.append({
                                'path': fpath,
                                'where': f"StartupFolder:{folder}",
                                'classification': classification,
                                'reasons': reasons
                            })
                    except Exception:
                        continue
        except Exception:
            continue
    return findings

def summarize_and_log(findings, win_findings=None):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
    logger.info("=== Scan started: %s ===", now)
    totals = {'SAFE':0,'SUSPICIOUS':0,'LIKELY_MALICIOUS':0}
    for f in findings:
        totals[f['classification']] += 1
    if win_findings:
        for f in win_findings:
            totals[f.get('classification','SUSPICIOUS')] += 1
    logger.info("Summary: %d suspicious, %d likely malicious, %d safe (reported).",
                totals['SUSPICIOUS'], totals['LIKELY_MALICIOUS'], totals['SAFE'])
    # Detailed list
    for f in findings:
        logger.warning("Item: %s", f['path'])
        logger.warning("  Class: %s", f['classification'])
        logger.warning("  Size: %s", human_size(f['size']))
        logger.warning("  Reasons: %s", '; '.join(f['reasons']))
        logger.warning("  PartialSHA256: %s", f.get('sha256_first4k'))
    if win_findings:
        for f in win_findings:
            logger.warning("Windows-Startup Item: %s (where: %s)", f.get('path'), f.get('where'))
            logger.warning("  Class: %s", f.get('classification'))
            logger.warning("  Reasons: %s", '; '.join(f.get('reasons', [])))

def run_scan_once():
    roots = default_roots()
    logger.info("Roots to scan: %s", ', '.join(roots))
    findings = walk_and_scan(roots)
    win_findings = []
    if IS_WINDOWS:
        try:
            win_findings = scan_windows_startup_entries()
        except Exception as e:
            logger.debug("Windows startup scan error: %s", e)
    summarize_and_log(findings, win_findings)
    # return full details for potential further processing
    return findings, win_findings

def background_worker():
    while True:
        try:
            run_scan_once()
        except Exception as e:
            logger.exception("Scan error: %s", e)
        logger.info("Next scan in %d minutes.", INTERVAL_MINUTES)
        time.sleep(INTERVAL_MINUTES * 60)

def start_background_scanner():
    t = threading.Thread(target=background_worker, daemon=True)
    t.start()
    logger.info("Background scanner started. Logs will be appended to %s", LOGFILE)

def main():
    logger.info("Starting immediate scan...")
    run_scan_once()
    # start background scanner
    start_background_scanner()
    # keep main thread alive so background thread keeps running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("User requested stop. Exiting.")

if __name__ == '__main__':
    main()
