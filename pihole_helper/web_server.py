"""Pi-hole Helper — Flask web server and UI."""

import json
import logging
import os
import secrets
import time
from functools import wraps

from flask import Flask, request, jsonify, make_response

from pihole_helper import pihole_api, pause_manager
from pihole_helper.options import app_password, default_pause_minutes

logger = logging.getLogger("pihole_helper.web")

# In-memory session store: {token: expiry_timestamp}
_sessions: dict = {}
SESSION_LIFETIME = 8 * 3600  # 8 hours

INGRESS_PATH = os.environ.get("INGRESS_PATH", "").rstrip("/")

# Cloudflare upstream IPs that indicate external blocking (1.1.1.2/3, 1.0.0.2/3)
CLOUDFLARE_FAMILIES_UPSTREAMS = {"1.1.1.2", "1.1.1.3", "1.0.0.2", "1.0.0.3"}
CLOUDFLARE_RECATEGORIZE_URL = "https://radar.cloudflare.com/domains/feedback"


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_authenticated() -> bool:
    token = request.headers.get("X-Auth-Token") or request.cookies.get("ph_token")
    if not token:
        return False
    return time.time() < _sessions.get(token, 0)


def _require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({"ok": False, "message": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# HTML (single-page, embedded)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pi-hole Helper</title>
<base href="{{BASE}}/">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a; color: #cbd5e1; min-height: 100vh;
    display: flex; align-items: flex-start; justify-content: center;
    padding: 24px 16px;
  }
  .card {
    background: #1e293b; border-radius: 14px; padding: 28px 28px 32px;
    max-width: 500px; width: 100%; box-shadow: 0 8px 40px rgba(0,0,0,0.5);
  }
  h1 { font-size: 1.4rem; color: #a78bfa; margin-bottom: 4px; }
  .tagline { color: #64748b; font-size: 0.85rem; margin-bottom: 28px; }
  h2 {
    font-size: 0.8rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: #7c3aed; margin: 28px 0 14px;
    padding-bottom: 8px; border-bottom: 1px solid #334155;
  }
  .form-group { margin-bottom: 14px; }
  label { display: block; font-size: 0.82rem; color: #94a3b8; margin-bottom: 5px; }
  input[type=password], input[type=text], select {
    width: 100%; padding: 9px 13px; background: #0f172a;
    border: 1px solid #334155; border-radius: 8px; color: #e2e8f0;
    font-size: 0.92rem; outline: none; transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: #7c3aed; }
  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 9px 18px; border: none; border-radius: 8px; cursor: pointer;
    font-size: 0.88rem; font-weight: 500; transition: filter 0.15s; gap: 6px;
  }
  .btn:hover { filter: brightness(1.12); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-primary { background: #7c3aed; color: white; width: 100%; padding: 11px; }
  .btn-orange  { background: #d97706; color: white; }
  .btn-red     { background: #b91c1c; color: white; }
  .btn-green   { background: #047857; color: white; }
  .btn-blue    { background: #1d4ed8; color: white; }
  .btn-row { display: flex; gap: 10px; }
  .btn-row .btn { flex: 1; }
  .alert {
    padding: 11px 15px; border-radius: 8px; margin-top: 16px;
    font-size: 0.88rem; line-height: 1.5;
  }
  .alert a { color: inherit; font-weight: 600; }
  .alert-success { background: #052e16; color: #86efac; border: 1px solid #166534; }
  .alert-warn    { background: #431407; color: #fdba74; border: 1px solid #9a3412; }
  .alert-error   { background: #450a0a; color: #fca5a5; border: 1px solid #991b1b; }
  .alert-info    { background: #0c1a2e; color: #93c5fd; border: 1px solid #1e40af; }
  .pause-list { margin-top: 14px; }
  .pause-item {
    background: #0f172a; border-radius: 8px; padding: 9px 13px;
    margin-bottom: 7px; display: flex; justify-content: space-between;
    align-items: center; font-size: 0.84rem;
  }
  .pause-ip { color: #a78bfa; }
  .pause-time { color: #64748b; }
  .cancel-btn {
    background: none; border: 1px solid #475569; border-radius: 6px;
    color: #94a3b8; padding: 3px 9px; font-size: 0.78rem; cursor: pointer;
  }
  .cancel-btn:hover { border-color: #ef4444; color: #ef4444; }
  #login-section { }
  #app-section { display: none; }
  .spinner { display: none; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.3);
             border-top-color: white; border-radius: 50%; animation: spin 0.7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1>Pi-hole Helper</h1>
  <p class="tagline">Pause blocking or manage domains — no Pi-hole credentials needed</p>

  <!-- Login -->
  <div id="login-section">
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="pw" placeholder="Enter password"
             onkeydown="if(event.key==='Enter')login()">
    </div>
    <button class="btn btn-primary" onclick="login()">Sign In</button>
    <div id="login-msg"></div>
  </div>

  <!-- App -->
  <div id="app-section">

    <!-- Pause blocking -->
    <h2>Pause Blocking</h2>
    <div class="form-group">
      <label>Duration</label>
      <select id="pause-dur">
        <option value="900">15 minutes</option>
        <option value="1800" selected>30 minutes</option>
        <option value="3600">1 hour</option>
        <option value="7200">2 hours</option>
      </select>
    </div>
    <div class="btn-row">
      <button class="btn btn-orange" onclick="pauseDevice()">
        <span>My Device Only</span>
      </button>
      <button class="btn btn-red" onclick="pauseGlobal()">
        <span>Everyone</span>
      </button>
    </div>
    <div id="pause-result"></div>

    <!-- Active pauses -->
    <div id="active-pauses"></div>

    <!-- Whitelist -->
    <h2>Whitelist a Domain</h2>
    <div class="form-group">
      <label>Domain</label>
      <input type="text" id="whitelist-domain" placeholder="example.com"
             onkeydown="if(event.key==='Enter')whitelistDomain()">
    </div>
    <button class="btn btn-green" onclick="whitelistDomain()">Add to Allowlist</button>
    <div id="whitelist-result"></div>

    <!-- Troubleshoot -->
    <h2>Troubleshoot a Domain</h2>
    <div class="form-group">
      <label>Domain to check</label>
      <input type="text" id="check-domain" placeholder="example.com"
             onkeydown="if(event.key==='Enter')checkDomain()">
    </div>
    <button class="btn btn-blue" onclick="checkDomain()">Check Why It's Blocked</button>
    <div id="check-result"></div>

  </div>
</div>

<script>
const BASE = "{{BASE}}";
let authToken = null;

async function post(path, data) {
  const headers = {"Content-Type": "application/json"};
  if (authToken) headers["X-Auth-Token"] = authToken;
  const r = await fetch(path, {method: "POST", headers, body: JSON.stringify(data)});
  return r.json();
}

async function get(path) {
  const headers = {};
  if (authToken) headers["X-Auth-Token"] = authToken;
  const r = await fetch(path, {headers});
  return r.json();
}

function showMsg(elId, res, extra) {
  const el = document.getElementById(elId);
  const cls = res.ok ? "alert-success" : "alert-error";
  const msg = (res.message || "Unknown error") + (extra || "");
  el.innerHTML = `<div class="alert ${cls}">${msg}</div>`;
  if (res.ok) setTimeout(() => el.innerHTML = "", 6000);
}

async function login() {
  const pw = document.getElementById("pw").value;
  const res = await post("login", {password: pw});
  if (res.ok) {
    authToken = res.token;
    document.getElementById("login-section").style.display = "none";
    document.getElementById("app-section").style.display = "block";
    loadPauses();
  } else {
    document.getElementById("login-msg").innerHTML =
      '<div class="alert alert-error">Incorrect password</div>';
  }
}

async function pauseDevice() {
  const seconds = parseInt(document.getElementById("pause-dur").value);
  const res = await post("pause/device", {seconds});
  showMsg("pause-result", res);
  loadPauses();
}

async function pauseGlobal() {
  const seconds = parseInt(document.getElementById("pause-dur").value);
  const res = await post("pause/global", {seconds});
  showMsg("pause-result", res);
}

async function cancelPause(ip) {
  const res = await post("pause/cancel", {ip});
  showMsg("pause-result", res);
  loadPauses();
}

async function whitelistDomain() {
  const domain = document.getElementById("whitelist-domain").value.trim();
  if (!domain) return;
  const res = await post("whitelist", {domain});
  showMsg("whitelist-result", res);
  if (res.ok) document.getElementById("whitelist-domain").value = "";
}

async function checkDomain() {
  const domain = document.getElementById("check-domain").value.trim();
  if (!domain) return;
  const el = document.getElementById("check-result");
  el.innerHTML = '<div class="alert alert-info">Checking...</div>';
  const res = await post("check", {domain});
  el.innerHTML = "";

  if (!res.ok) {
    el.innerHTML = `<div class="alert alert-error">${res.message}</div>`;
    return;
  }

  const d = res.data;
  if (d.status === "not_blocked") {
    el.innerHTML = `<div class="alert alert-success">
      <strong>${domain}</strong> is not being blocked by Pi-hole.
    </div>`;
  } else if (d.status === "external_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by your upstream DNS provider
      (${d.upstream || "external"}), not by Pi-hole's blocklists.<br><br>
      This may be a miscategorization. You can request a correction here:<br>
      <a href="${d.recategorize_url}" target="_blank">${d.recategorize_url}</a>
    </div>`;
  } else if (d.status === "pihole_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by Pi-hole (gravity/blocklist).
      ${d.list_info ? "<br>List ID: " + d.list_info : ""}
      <br><br>Use the <em>Whitelist</em> section above to allow it.
    </div>`;
  } else if (d.status === "allowed") {
    el.innerHTML = `<div class="alert alert-success">
      <strong>${domain}</strong> is explicitly allowed (on your allowlist).
    </div>`;
  }
}

async function loadPauses() {
  const data = await get("status");
  const pauses = data.active_pauses || {};
  const el = document.getElementById("active-pauses");
  const keys = Object.keys(pauses);
  if (keys.length === 0) { el.innerHTML = ""; return; }

  let html = '<h2 style="margin-top:20px">Active Pauses</h2><div class="pause-list">';
  for (const ip of keys) {
    const mins = Math.ceil(pauses[ip].remaining_seconds / 60);
    html += `<div class="pause-item">
      <span class="pause-ip">${ip}</span>
      <span class="pause-time">${mins}m left</span>
      <button class="cancel-btn" onclick="cancelPause('${ip}')">Cancel</button>
    </div>`;
  }
  html += "</div>";
  el.innerHTML = html;
}

// Check if already logged in on load
get("status").then(d => {
  if (d.authenticated) {
    authToken = d.token;
    document.getElementById("login-section").style.display = "none";
    document.getElementById("app-section").style.display = "block";
    loadPauses();
  }
});
</script>
</body>
</html>"""


def _render_html():
    base = INGRESS_PATH if INGRESS_PATH else "."
    return HTML_TEMPLATE.replace("{{BASE}}", base)


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)

    @app.route("/", methods=["GET"])
    def index():
        return _render_html(), 200, {"Content-Type": "text/html; charset=utf-8"}

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        if data.get("password") == app_password():
            token = secrets.token_hex(32)
            _sessions[token] = time.time() + SESSION_LIFETIME
            return jsonify({"ok": True, "token": token})
        return jsonify({"ok": False, "message": "Incorrect password"}), 401

    @app.route("/status", methods=["GET"])
    def status():
        authed = _is_authenticated()
        resp = {"authenticated": authed}
        if authed:
            resp["token"] = request.headers.get("X-Auth-Token")
            resp["active_pauses"] = pause_manager.get_active_pauses()
        return jsonify(resp)

    @app.route("/pause/device", methods=["POST"])
    @_require_auth
    def pause_device():
        data = request.get_json() or {}
        seconds = int(data.get("seconds", default_pause_minutes() * 60))
        ip = _get_client_ip()
        try:
            pause_manager.pause_device(ip, seconds)
            mins = seconds // 60
            return jsonify({"ok": True,
                            "message": f"Blocking paused for your device ({ip}) for {mins} minutes."})
        except Exception as e:
            logger.exception("Failed to pause device %s", ip)
            return jsonify({"ok": False, "message": str(e)}), 500

    @app.route("/pause/global", methods=["POST"])
    @_require_auth
    def pause_global():
        data = request.get_json() or {}
        seconds = int(data.get("seconds", default_pause_minutes() * 60))
        try:
            pihole_api.set_global_blocking(False, timer_seconds=seconds)
            mins = seconds // 60
            return jsonify({"ok": True,
                            "message": f"Blocking paused for everyone for {mins} minutes. Pi-hole will re-enable automatically."})
        except Exception as e:
            logger.exception("Failed to pause global blocking")
            return jsonify({"ok": False, "message": str(e)}), 500

    @app.route("/pause/cancel", methods=["POST"])
    @_require_auth
    def cancel_pause():
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"ok": False, "message": "No IP provided"}), 400
        try:
            pause_manager.cancel_device_pause(ip)
            return jsonify({"ok": True, "message": f"Pause cancelled for {ip}."})
        except Exception as e:
            logger.exception("Failed to cancel pause for %s", ip)
            return jsonify({"ok": False, "message": str(e)}), 500

    @app.route("/whitelist", methods=["POST"])
    @_require_auth
    def whitelist():
        data = request.get_json() or {}
        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"ok": False, "message": "No domain provided"}), 400
        try:
            pihole_api.add_to_allowlist(domain)
            return jsonify({"ok": True,
                            "message": f"{domain} has been added to the Pi-hole allowlist."})
        except Exception as e:
            logger.exception("Failed to whitelist %s", domain)
            return jsonify({"ok": False, "message": str(e)}), 500

    @app.route("/check", methods=["POST"])
    @_require_auth
    def check_domain():
        data = request.get_json() or {}
        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"ok": False, "message": "No domain provided"}), 400
        try:
            result = _diagnose_domain(domain)
            return jsonify({"ok": True, "data": result})
        except Exception as e:
            logger.exception("Failed to check domain %s", domain)
            return jsonify({"ok": False, "message": str(e)}), 500

    return app


def _diagnose_domain(domain: str) -> dict:
    """Query Pi-hole logs to determine why a domain is blocked (or not)."""
    sid = pihole_api.get_sid()

    # Fetch the most recent queries for this domain
    import urllib.request
    url = pihole_api._url(f"/queries?domain={domain}&length=10")
    req = urllib.request.Request(url, headers={"sid": sid})
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = __import__("json").loads(resp.read())

    queries = result.get("queries", [])

    if not queries:
        return {"status": "not_blocked"}

    # Look at the most recent query for this domain
    latest = queries[0]
    status = latest.get("status", "")
    upstream = latest.get("upstream") or ""
    # upstream may include port like "1.1.1.3#53" — strip it
    upstream_ip = upstream.split("#")[0] if upstream else ""

    if status in ("GRAVITY", "GRAVITY_CNAME", "REGEX_GRAVITY", "DENYLIST"):
        list_id = latest.get("list_id")
        return {"status": "pihole_blocked", "list_info": list_id}

    if status in ("EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
                  "EXTERNAL_BLOCKED_IP"):
        recategorize_url = CLOUDFLARE_RECATEGORIZE_URL
        return {
            "status": "external_blocked",
            "upstream": upstream_ip or "external DNS",
            "recategorize_url": recategorize_url,
        }

    if status in ("ALLOW_LIST", "ALLOW_CNAME"):
        return {"status": "allowed"}

    # Forwarded, cached, etc. — not blocked
    return {"status": "not_blocked"}
