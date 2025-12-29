# src/utils.py
import yaml
import os
import json
from datetime import datetime

try:
    import geoip2.database  # GeoIP lookup ke liye
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


# 📥 CONFIG LOADER
def load_config():
    """YAML or JSON config file ko load karta hai"""
    config_path_yaml = os.path.join("config", "settings.yaml")
    config_path_json = os.path.join("config", "settings.json")

    if os.path.exists(config_path_yaml):
        with open(config_path_yaml, "r") as f:
            return yaml.safe_load(f)
    elif os.path.exists(config_path_json):
        with open(config_path_json, "r") as f:
            return json.load(f)
    else:
        raise FileNotFoundError("❌ No config file found in config/ folder")


# 🧭 IP TO GEO LOOKUP (optional)
def ip_to_geo(ip):
    """
    GeoIP lookup — IP ka country & city return karega.
    MaxMind GeoLite2-City.mmdb file lagti hai.
    """
    if not GEOIP_AVAILABLE:
        return {"country": "Unknown", "city": "Unknown"}

    db_path = os.path.join("data", "GeoLite2-City.mmdb")
    if not os.path.exists(db_path):
        return {"country": "Unknown", "city": "Unknown"}

    try:
        reader = geoip2.database.Reader(db_path)
        response = reader.city(ip)
        reader.close()
        return {
            "country": response.country.name or "Unknown",
            "city": response.city.name or "Unknown"
        }
    except Exception:
        return {"country": "Unknown", "city": "Unknown"}


# 📝 TIMESTAMP HELPER
def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
