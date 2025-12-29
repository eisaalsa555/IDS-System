# config.py
import yaml

with open("config/settings.yaml", "r") as f:
    _CFG = yaml.safe_load(f)

def cfg(path, default=None):
    """Get nested config value by dot.path (e.g. 'email.username')."""
    keys = path.split(".")
    cur = _CFG
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur
