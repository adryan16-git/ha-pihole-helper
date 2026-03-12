"""Pi-hole Helper — Flask web server and UI."""

import logging
import os
import secrets
import time
from functools import wraps
from typing import List

from flask import Flask, request, jsonify

from pihole_helper import pihole_api, pause_manager
from pihole_helper.pihole_api import PiholeInstance
from pihole_helper.options import app_password, default_pause_minutes

logger = logging.getLogger("pihole_helper.web")

_sessions: dict = {}
SESSION_LIFETIME = 8 * 3600

INGRESS_PATH = os.environ.get("INGRESS_PATH", "").rstrip("/")

# Populated on startup by main.py
_instances: List[PiholeInstance] = []


def set_instances(instances: List[PiholeInstance]):
    global _instances
    _instances = instances


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_authenticated() -> bool:
    token = request.headers.get("X-Auth-Token") or request.cookies.get("ph_token")
    return bool(token) and time.time() < _sessions.get(token, 0)


def _require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_authenticated():
            return jsonify({"ok": False, "message": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pi-hole Helper</title>
<base href="{{BASE}}/">
<style>
  :root {
    --bg:          #f0f4f8;
    --card-bg:     #ffffff;
    --text:        #1e293b;
    --text-muted:  #64748b;
    --border:      #e2e8f0;
    --input-bg:    #f8fafc;
    --input-text:  #1e293b;
    --chip-bg:     #f1f5f9;
    --pause-bg:    #f1f5f9;
    --accent:      #7c3aed;
    --accent-soft: #ede9fe;
    --shadow:      0 4px 24px rgba(0,0,0,0.08);
    --alert-ok-bg: #f0fdf4; --alert-ok-text: #166534; --alert-ok-border: #bbf7d0;
    --alert-wn-bg: #fff7ed; --alert-wn-text: #9a3412; --alert-wn-border: #fed7aa;
    --alert-er-bg: #fef2f2; --alert-er-text: #991b1b; --alert-er-border: #fecaca;
    --alert-in-bg: #eff6ff; --alert-in-text: #1e40af; --alert-in-border: #bfdbfe;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:          #0f172a;
      --card-bg:     #1e293b;
      --text:        #cbd5e1;
      --text-muted:  #64748b;
      --border:      #334155;
      --input-bg:    #0f172a;
      --input-text:  #e2e8f0;
      --chip-bg:     #0f172a;
      --pause-bg:    #0f172a;
      --accent:      #a78bfa;
      --accent-soft: #3b1e6e;
      --shadow:      0 8px 40px rgba(0,0,0,0.5);
      --alert-ok-bg: #052e16; --alert-ok-text: #86efac; --alert-ok-border: #166534;
      --alert-wn-bg: #431407; --alert-wn-text: #fdba74; --alert-wn-border: #9a3412;
      --alert-er-bg: #450a0a; --alert-er-text: #fca5a5; --alert-er-border: #991b1b;
      --alert-in-bg: #0c1a2e; --alert-in-text: #93c5fd; --alert-in-border: #1e40af;
    }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh;
    display: flex; align-items: flex-start; justify-content: center;
    padding: 24px 16px;
  }
  .card {
    background: var(--card-bg); border-radius: 14px; padding: 28px 28px 32px;
    max-width: 500px; width: 100%; box-shadow: var(--shadow);
  }
  h1 { font-size: 1.4rem; color: var(--accent); margin-bottom: 4px; }
  .tagline { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 28px; }
  h2 {
    font-size: 0.78rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--accent); margin: 28px 0 14px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }
  .instances { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }
  .instance-chip {
    background: var(--chip-bg); border: 1px solid var(--border); border-radius: 20px;
    padding: 4px 12px; font-size: 0.78rem; color: var(--text-muted);
    display: flex; align-items: center; gap: 6px;
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; }
  .form-group { margin-bottom: 14px; }
  label { display: block; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px; }
  input[type=password], input[type=text], select {
    width: 100%; padding: 9px 13px; background: var(--input-bg);
    border: 1px solid var(--border); border-radius: 8px; color: var(--input-text);
    font-size: 0.92rem; outline: none; transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: var(--accent); }
  .btn {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 9px 18px; border: none; border-radius: 8px; cursor: pointer;
    font-size: 0.88rem; font-weight: 500; transition: filter 0.15s;
  }
  .btn:hover { filter: brightness(1.1); }
  .btn-primary { background: var(--accent); color: white; width: 100%; padding: 11px; }
  .btn-orange  { background: #d97706; color: white; }
  .btn-red     { background: #b91c1c; color: white; }
  .btn-green   { background: #047857; color: white; }
  .btn-blue    { background: #1d4ed8; color: white; }
  .btn-small { padding: 7px 13px; font-size: 0.82rem; }
  .btn-row { display: flex; gap: 10px; }
  .btn-row .btn { flex: 1; }
  .alert {
    padding: 11px 15px; border-radius: 8px; margin-top: 14px;
    font-size: 0.88rem; line-height: 1.6;
  }
  .alert a { color: inherit; font-weight: 600; }
  .alert-success { background: var(--alert-ok-bg); color: var(--alert-ok-text); border: 1px solid var(--alert-ok-border); }
  .alert-warn    { background: var(--alert-wn-bg); color: var(--alert-wn-text); border: 1px solid var(--alert-wn-border); }
  .alert-error   { background: var(--alert-er-bg); color: var(--alert-er-text); border: 1px solid var(--alert-er-border); }
  .alert-info    { background: var(--alert-in-bg); color: var(--alert-in-text); border: 1px solid var(--alert-in-border); }
  .pause-list { margin-top: 14px; }
  .pause-item {
    background: var(--pause-bg); border-radius: 8px; padding: 9px 13px;
    margin-bottom: 7px; display: flex; justify-content: space-between;
    align-items: center; font-size: 0.84rem;
  }
  .cancel-btn {
    background: none; border: 1px solid var(--border); border-radius: 6px;
    color: var(--text-muted); padding: 3px 9px; font-size: 0.78rem; cursor: pointer;
  }
  .cancel-btn:hover { border-color: #ef4444; color: #ef4444; }
  .action-row {
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px;
  }
  .action-row select {
    flex: 1; min-width: 120px; padding: 7px 10px; font-size: 0.84rem;
  }
  .divider {
    border: none; border-top: 1px solid var(--border); margin: 28px 0 0;
  }
  #login-section { }
  #app-section { display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Pi-hole Helper</h1>
  <p class="tagline">Having trouble reaching a website? Start below.</p>

  <div id="login-section">
    <div class="form-group">
      <label>Password</label>
      <input type="password" id="pw" placeholder="Enter password"
             onkeydown="if(event.key==='Enter')login()">
    </div>
    <button class="btn btn-primary" onclick="login()">Sign In</button>
    <div id="login-msg"></div>
  </div>

  <div id="app-section">

    <h2>Website not working? Start here.</h2>
    <div class="form-group">
      <label>Enter the domain you can't reach</label>
      <input type="text" id="check-domain" placeholder="example.com"
             onkeydown="if(event.key==='Enter')checkDomain()">
    </div>
    <button class="btn btn-blue" onclick="checkDomain()">Check</button>
    <div id="check-result"></div>

    <hr class="divider">

    <h2>Pause Blocking</h2>
    <p style="font-size:0.83rem;color:var(--text-muted);margin-bottom:12px">
      Need access to something that's blocked? Pause filtering temporarily.
    </p>
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
      <button class="btn btn-orange" onclick="pauseDevice()">My Device Only</button>
      <button class="btn btn-red" onclick="pauseGlobal()">Everyone</button>
    </div>
    <div id="pause-result"></div>
    <div id="active-pauses"></div>

    <hr class="divider">

    <h2>Permanently Allow a Domain</h2>
    <p style="font-size:0.83rem;color:var(--text-muted);margin-bottom:12px">
      Adds a domain to the allowlist on all Pi-hole instances.
    </p>
    <div class="form-group">
      <label>Domain</label>
      <input type="text" id="whitelist-domain" placeholder="example.com"
             onkeydown="if(event.key==='Enter')whitelistDomain()">
    </div>
    <button class="btn btn-green" onclick="whitelistDomain()">Add to Allowlist</button>
    <div id="whitelist-result"></div>

    <hr class="divider">

    <h2>Connected Instances</h2>
    <div class="instances" id="instances"></div>

  </div>
</div>

<script>
let authToken = null;

const NETWORK_ERR = {ok: false, message: "Could not reach the add-on — try refreshing the page."};

async function post(path, data) {
  const headers = {"Content-Type": "application/json"};
  if (authToken) headers["X-Auth-Token"] = authToken;
  try {
    const r = await fetch(path, {method: "POST", headers, body: JSON.stringify(data)});
    return r.json();
  } catch (e) {
    console.error("POST", path, e);
    return NETWORK_ERR;
  }
}

async function get(path) {
  const headers = {};
  if (authToken) headers["X-Auth-Token"] = authToken;
  try {
    const r = await fetch(path, {headers});
    return r.json();
  } catch (e) {
    console.error("GET", path, e);
    return {};
  }
}

function showMsg(elId, res) {
  const el = document.getElementById(elId);
  const cls = res.ok ? "alert-success" : "alert-error";
  el.innerHTML = `<div class="alert ${cls}">${res.message || "Unknown error"}</div>`;
  if (res.ok) setTimeout(() => el.innerHTML = "", 7000);
}

async function login() {
  const pw = document.getElementById("pw").value;
  const res = await post("login", {password: pw});
  if (res.ok) {
    authToken = res.token;
    document.getElementById("login-section").style.display = "none";
    document.getElementById("app-section").style.display = "block";
    loadStatus();
  } else {
    document.getElementById("login-msg").innerHTML =
      '<div class="alert alert-error">Incorrect password</div>';
  }
}

async function pauseFromCheck(seconds) {
  const res = await post("pause/device", {seconds});
  document.getElementById("check-result").innerHTML +=
    `<div class="alert ${res.ok ? "alert-success" : "alert-error"}" style="margin-top:8px">${res.message}</div>`;
}

async function whitelistFromCheck(domain) {
  const res = await post("whitelist", {domain});
  document.getElementById("check-result").innerHTML +=
    `<div class="alert ${res.ok ? "alert-success" : "alert-error"}" style="margin-top:8px">${res.message}</div>`;
}

async function checkDomain() {
  const domain = document.getElementById("check-domain").value.trim();
  if (!domain) return;
  const el = document.getElementById("check-result");
  el.innerHTML = '<div class="alert alert-info">Checking...</div>';
  const res = await post("check", {domain});
  if (!res.ok) {
    el.innerHTML = `<div class="alert alert-error">${res.message}</div>`;
    return;
  }
  const d = res.data;
  if (d.status === "not_blocked") {
    el.innerHTML = `<div class="alert alert-success">
      <strong>${domain}</strong> is not being blocked by Pi-hole.
      The issue may be something else (DNS cache, server down, etc.).
    </div>`;
  } else if (d.status === "external_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by your upstream DNS provider (${d.upstream}), not by Pi-hole's own lists.<br><br>
      This is likely a miscategorization. You can request a correction here:<br>
      <a href="${d.recategorize_url}" target="_blank">${d.recategorize_url}</a>
    </div>`;
  } else if (d.status === "pihole_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by Pi-hole. What would you like to do?
      <div class="action-row">
        <select id="quick-pause-dur">
          <option value="900">15 min</option>
          <option value="1800" selected>30 min</option>
          <option value="3600">1 hour</option>
          <option value="7200">2 hours</option>
        </select>
        <button class="btn btn-orange btn-small"
          onclick="pauseFromCheck(parseInt(document.getElementById('quick-pause-dur').value))">
          Pause my device
        </button>
        <button class="btn btn-green btn-small"
          onclick="whitelistFromCheck('${domain}')">
          Permanently allow
        </button>
      </div>
    </div>`;
  } else if (d.status === "allowed") {
    el.innerHTML = `<div class="alert alert-success">
      <strong>${domain}</strong> is explicitly allowed — Pi-hole isn't blocking it.
    </div>`;
  }
}

async function pauseDevice() {
  const seconds = parseInt(document.getElementById("pause-dur").value);
  showMsg("pause-result", await post("pause/device", {seconds}));
  loadStatus();
}

async function pauseGlobal() {
  const seconds = parseInt(document.getElementById("pause-dur").value);
  showMsg("pause-result", await post("pause/global", {seconds}));
}

async function cancelPause(ip) {
  showMsg("pause-result", await post("pause/cancel", {ip}));
  loadStatus();
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
  if (!res.ok) {
    el.innerHTML = `<div class="alert alert-error">${res.message}</div>`;
    return;
  }
  const d = res.data;
  if (d.status === "not_blocked") {
    el.innerHTML = `<div class="alert alert-success"><strong>${domain}</strong> is not being blocked by Pi-hole.</div>`;
  } else if (d.status === "external_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by your upstream DNS (${d.upstream}), not by Pi-hole's own blocklists.<br><br>
      This may be a miscategorization. Request a correction here:<br>
      <a href="${d.recategorize_url}" target="_blank">${d.recategorize_url}</a>
    </div>`;
  } else if (d.status === "pihole_blocked") {
    el.innerHTML = `<div class="alert alert-warn">
      <strong>${domain}</strong> is blocked by Pi-hole (gravity/blocklist).
      Use <em>Whitelist a Domain</em> above to allow it.
    </div>`;
  } else if (d.status === "allowed") {
    el.innerHTML = `<div class="alert alert-success"><strong>${domain}</strong> is explicitly allowed.</div>`;
  }
}

async function loadStatus() {
  const data = await get("status");

  // Instances
  const chips = (data.instances || []).map(i =>
    `<div class="instance-chip"><span class="dot"></span>${i}</div>`
  ).join("");
  document.getElementById("instances").innerHTML = chips || "<span style='color:#64748b;font-size:.85rem'>None discovered</span>";

  // Active pauses
  const pauses = data.active_pauses || {};
  const keys = Object.keys(pauses);
  const el = document.getElementById("active-pauses");
  if (keys.length === 0) { el.innerHTML = ""; return; }
  let html = '<h2 style="margin-top:20px">Active Pauses</h2><div class="pause-list">';
  for (const ip of keys) {
    const mins = Math.ceil(pauses[ip].remaining_seconds / 60);
    html += `<div class="pause-item">
      <span class="pause-ip">${ip}</span>
      <span style="color:#64748b">${mins}m left</span>
      <button class="cancel-btn" onclick="cancelPause('${ip}')">Cancel</button>
    </div>`;
  }
  el.innerHTML = html + "</div>";
}

// Check session on load
get("status").then(d => {
  if (d.authenticated) {
    authToken = d.token;
    document.getElementById("login-section").style.display = "none";
    document.getElementById("app-section").style.display = "block";
    loadStatus();
  }
});
</script>
</body>
</html>"""


def _render_html():
    base = INGRESS_PATH if INGRESS_PATH else "."
    return HTML_TEMPLATE.replace("{{BASE}}", base)


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
        logger.warning("Failed login attempt from %s", _get_client_ip())
        return jsonify({"ok": False, "message": "Incorrect password"}), 401

    @app.route("/status", methods=["GET"])
    def status():
        authed = _is_authenticated()
        resp = {"authenticated": authed}
        if authed:
            resp["token"] = request.headers.get("X-Auth-Token")
            resp["instances"] = [i.name for i in _instances]
            resp["active_pauses"] = pause_manager.get_active_pauses()
        return jsonify(resp)

    @app.route("/pause/device", methods=["POST"])
    @_require_auth
    def pause_device():
        if not _instances:
            return jsonify({"ok": False, "message": "No Pi-hole instances discovered"}), 503
        data = request.get_json() or {}
        seconds = int(data.get("seconds", default_pause_minutes() * 60))
        ip = _get_client_ip()
        try:
            pause_manager.pause_device(ip, seconds, _instances)
            mins = seconds // 60
            names = ", ".join(i.name for i in _instances)
            return jsonify({"ok": True,
                            "message": f"Blocking paused for your device ({ip}) for {mins} minutes on: {names}."})
        except Exception as e:
            logger.exception("Failed to pause device %s", ip)
            return jsonify({"ok": False, "message": str(e)}), 500

    @app.route("/pause/global", methods=["POST"])
    @_require_auth
    def pause_global():
        if not _instances:
            return jsonify({"ok": False, "message": "No Pi-hole instances discovered"}), 503
        data = request.get_json() or {}
        seconds = int(data.get("seconds", default_pause_minutes() * 60))
        errors = []
        for instance in _instances:
            try:
                pihole_api.set_global_blocking(instance, False, timer_seconds=seconds)
            except Exception as e:
                errors.append(f"{instance.name}: {e}")
        mins = seconds // 60
        if errors:
            return jsonify({"ok": False,
                            "message": f"Some instances failed: {'; '.join(errors)}"}), 500
        names = ", ".join(i.name for i in _instances)
        return jsonify({"ok": True,
                        "message": f"Blocking paused for everyone for {mins} minutes on: {names}."})

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
        if not _instances:
            return jsonify({"ok": False, "message": "No Pi-hole instances discovered"}), 503
        data = request.get_json() or {}
        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"ok": False, "message": "No domain provided"}), 400
        errors = []
        for instance in _instances:
            try:
                pihole_api.add_to_allowlist(instance, domain)
            except Exception as e:
                errors.append(f"{instance.name}: {e}")
        if errors:
            return jsonify({"ok": False,
                            "message": f"Some instances failed: {'; '.join(errors)}"}), 500
        names = ", ".join(i.name for i in _instances)
        return jsonify({"ok": True,
                        "message": f"{domain} added to allowlist on: {names}."})

    @app.route("/check", methods=["POST"])
    @_require_auth
    def check_domain():
        if not _instances:
            return jsonify({"ok": False, "message": "No Pi-hole instances discovered"}), 503
        data = request.get_json() or {}
        domain = data.get("domain", "").strip().lower()
        if not domain:
            return jsonify({"ok": False, "message": "No domain provided"}), 400
        try:
            # Use the first instance for diagnosis
            result = pihole_api.diagnose_domain(_instances[0], domain)
            return jsonify({"ok": True, "data": result})
        except Exception as e:
            logger.exception("Failed to check domain %s", domain)
            return jsonify({"ok": False, "message": str(e)}), 500

    return app
