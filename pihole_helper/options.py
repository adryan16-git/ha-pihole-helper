"""Read add-on configuration from /data/options.json."""

import json

_OPTIONS_FILE = "/data/options.json"
_opts = None


def _get():
    global _opts
    if _opts is None:
        try:
            with open(_OPTIONS_FILE) as f:
                _opts = json.load(f)
        except Exception:
            _opts = {}
    return _opts


def pihole_url():
    url = _get().get("pihole_url", "").strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def pihole_password():
    return _get().get("pihole_password", "")


def app_password():
    return _get().get("app_password", "")


def default_pause_minutes():
    return int(_get().get("default_pause_minutes") or 30)
