"""Pi-hole v6 REST API client (stdlib only)."""

import json
import logging
import urllib.request
import urllib.error

from pihole_helper.options import pihole_url, pihole_password

logger = logging.getLogger("pihole_helper.api")

BYPASS_GROUP_NAME = "pihole_helper_bypass"


def _url(path):
    return f"{pihole_url()}/api{path}"


def _request(method, path, data=None, sid=None):
    url = _url(path)
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["sid"] = sid
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read()
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return json.loads(content)
        except Exception:
            raise RuntimeError(f"HTTP {e.code}: {content.decode(errors='replace')}")


def get_sid():
    """Authenticate with Pi-hole and return a session ID."""
    result = _request("POST", "/auth", {"password": pihole_password()})
    session = result.get("session", {})
    if not session.get("valid"):
        raise RuntimeError(f"Pi-hole authentication failed: {result}")
    return session["sid"]


def set_global_blocking(enabled, timer_seconds=None):
    """Enable or disable Pi-hole blocking globally.

    Pi-hole v6 natively handles the timer — it re-enables blocking automatically.
    """
    sid = get_sid()
    data = {"blocking": enabled}
    if timer_seconds is not None:
        data["timer"] = timer_seconds
    return _request("PATCH", "/dns/blocking", data, sid=sid)


def get_or_create_bypass_group(sid):
    """Return the ID of the bypass group, creating it if it doesn't exist.

    The bypass group has no blocklists assigned, so any client exclusively in
    this group bypasses all Pi-hole blocking.
    """
    result = _request("GET", "/groups", sid=sid)
    for group in result.get("groups", []):
        if group.get("name") == BYPASS_GROUP_NAME:
            return group["id"]

    # Create it
    result = _request("POST", "/groups", {
        "name": BYPASS_GROUP_NAME,
        "comment": "Pi-hole Helper — temporary bypass (no blocklists assigned)",
        "enabled": True,
    }, sid=sid)
    group = result.get("group") or result
    group_id = group.get("id")
    if group_id is None:
        raise RuntimeError(f"Failed to create bypass group: {result}")
    logger.info("Created bypass group with id=%s", group_id)
    return group_id


def get_client_groups(ip, sid):
    """Return the list of group IDs the client belongs to, or None if unknown."""
    try:
        result = _request("GET", f"/clients/{ip}", sid=sid)
        client = result.get("client") or (result.get("clients") or [{}])[0]
        groups = client.get("groups")
        return groups  # list of ints, or None
    except Exception:
        return None


def set_client_groups(ip, group_ids, sid, comment=""):
    """Assign a client to specific groups, creating the client record if needed."""
    existing_groups = get_client_groups(ip, sid)
    if existing_groups is None:
        return _request("POST", "/clients", {
            "client": ip,
            "groups": group_ids,
            "comment": comment,
        }, sid=sid)
    else:
        return _request("PUT", f"/clients/{ip}", {
            "groups": group_ids,
            "comment": comment,
        }, sid=sid)


def delete_client(ip, sid):
    """Remove a client record so it falls back to the Default group."""
    try:
        _request("DELETE", f"/clients/{ip}", sid=sid)
    except Exception as e:
        logger.warning("Could not delete client %s: %s", ip, e)


def add_to_allowlist(domain, comment="Added via Pi-hole Helper"):
    """Add a domain to the Pi-hole allowlist."""
    sid = get_sid()
    result = _request("POST", "/domains", {
        "domain": domain,
        "type": "allow",
        "kind": "exact",
        "comment": comment,
        "enabled": True,
        "groups": [0],
    }, sid=sid)
    if "error" in result:
        raise RuntimeError(result["error"].get("message", str(result["error"])))
    return result
