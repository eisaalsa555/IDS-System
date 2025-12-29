import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from config import cfg

def log_attack(ip, details):
    try:
        with open("data/alerts.log", "a") as f:
            f.write(f"[{datetime.datetime.now()}] ALERT: Suspicious activity from {ip}\n")
            f.write(f"   Reason: {details.get('rule_reason')}\n")
            f.write(f"   Protocol: {details.get('proto')}, DPort: {details.get('dport')}\n\n")
        print(f"🚨 ALERT: Suspicious activity detected from {ip}")
    except Exception as e:
        print(f"[!] Log write failed: {e}")

# --- Telegram Alert ---
BOT_TOKEN = "8242591827:AAE5KDQp0eorFaLQKKVipuG4za2PKrhQbDg"
CHAT_ID = "8288809692", "1783051037"

def notify_telegram(src, details):
    msg = f"⚠️ Suspicious: {src}\nReason: {details.get('rule_reason')}\nProto:{details.get('proto')} DPort:{details.get('dport')}"
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    requests.post(url, data={"chat_id": CHAT_ID, "text": msg})

# --- Email Notification ---
def notify_email(src_ip, details):
    smtp_server = cfg("email.smtp_server", "smtp.gmail.com")
    smtp_port = cfg("email.smtp_port", 587)
    username = cfg("email.username")
    password = cfg("email.password")
    to = cfg("email.to")

    if not (username and password and to):
        print("[!] Email credentials missing in settings.yaml")
        return False

    subject = f"🚨 Suspicious activity detected from {src_ip}"
    body = (
        f"Time: {details.get('timestamp')}\n"
        f"Source: {details.get('src')}\n"
        f"Destination: {details.get('dst')}\n"
        f"Proto: {details.get('proto')}\n"
        f"Sport: {details.get('sport')}\n"
        f"Dport: {details.get('dport')}\n"
        f"Reason: {details.get('rule_reason')}\n"
        f"ML suspicious: {details.get('ml_suspicious')}\n"
        f"Geo: {details.get('geo')}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = username
    msg["To"] = to

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
        print("✅ Email alert sent")
        return True
    except Exception as e:
        print(f"[!] Email send failed: {e}")
        return False