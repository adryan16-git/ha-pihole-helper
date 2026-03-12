"""Pi-hole v6 REST API client — supports multiple instances."""

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass

logger = logging.getLogger("pihole_helper.api")

BYPASS_GROUP_NAME = "pihole_helper_bypass"

CLOUDFLARE_RECATEGORIZE_URL = "https://radar.cloudflare.com/domains/feedback"

# Statuses that mean Pi-hole itself blocked the query
PIHOLE_BLOCK_STATUSES = {
    "GRAVITY", "GRAVITY_CNAME", "REGEX_GRAVITY", "DENYLIST", "REGEX_DENYLIST",
}

# Statuses that mean an upstream (external) DNS blocked it
EXTERNAL_BLOCK_STATUSES = {
    "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_IP",
}


@dataclass
class PiholeInstance:
    name: str
    url: str
    password: str

    def __str__(self):
        return f"{self.name} ({self.url})"


def _api_url(instance: PiholeInstance, path: str) -> str:
    return f"{instance.url.rstrip('/')}/api{path}"


def _request(instance: PiholeInstance, method: str, path: str,
             data=None, sid: str = None):
    url = _api_url(instance, path)
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


def get_sid(instance: PiholeInstance) -> str:
    result = _request(instance, "POST", "/auth", {"password": instance.password})
    session = result.get("session", {})
    if not session.get("valid"):
        raise RuntimeError(
            f"Pi-hole auth failed for {instance.name}: {session.get('message', result)}"
        )
    return session["sid"]


def set_global_blocking(instance: PiholeInstance, enabled: bool,
                        timer_seconds: int = None):
    sid = get_sid(instance)
    data = {"blocking": enabled}
    if timer_seconds is not None:
        data["timer"] = timer_seconds
    return _request(instance, "PATCH", "/dns/blocking", data, sid=sid)


def get_or_create_bypass_group(instance: PiholeInstance, sid: str) -> int:
    result = _request(instance, "GET", "/groups", sid=sid)
    for group in result.get("groups", []):
        if group.get("name") == BYPASS_GROUP_NAME:
            return group["id"]

    result = _request(instance, "POST", "/groups", {
        "name": BYPASS_GROUP_NAME,
        "comment": "Pi-hole Helper — temporary bypass (no blocklists assigned)",
        "enabled": True,
    }, sid=sid)
    group = result.get("group") or result
    group_id = group.get("id")
    if group_id is None:
        raise RuntimeError(f"Failed to create bypass group on {instance.name}: {result}")
    logger.info("Created bypass group on %s (id=%s)", instance.name, group_id)
    return group_id


def get_client_groups(instance: PiholeInstance, ip: str, sid: str):
    try:
        result = _request(instance, "GET", f"/clients/{ip}", sid=sid)
        clients = result.get("clients") or []
        if clients:
            return clients[0].get("groups")
        client = result.get("client")
        if client:
            return client.get("groups")
        return None
    except Exception:
        return None


def set_client_groups(instance: PiholeInstance, ip: str, group_ids: list,
                      sid: str, comment: str = ""):
    existing = get_client_groups(instance, ip, sid)
    if existing is None:
        return _request(instance, "POST", "/clients", {
            "client": ip, "groups": group_ids, "comment": comment,
        }, sid=sid)
    else:
        return _request(instance, "PUT", f"/clients/{ip}", {
            "groups": group_ids, "comment": comment,
        }, sid=sid)


def delete_client(instance: PiholeInstance, ip: str, sid: str):
    try:
        _request(instance, "DELETE", f"/clients/{ip}", sid=sid)
    except Exception as e:
        logger.warning("Could not delete client %s on %s: %s", ip, instance.name, e)


def add_to_allowlist(instance: PiholeInstance, domain: str,
                     comment: str = "Added via Pi-hole Helper"):
    sid = get_sid(instance)
    result = _request(instance, "POST", "/domains", {
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


def diagnose_domain(instance: PiholeInstance, domain: str) -> dict:
    """Query Pi-hole logs to determine why a domain is (or isn't) blocked."""
    sid = get_sid(instance)
    url = _api_url(instance, f"/queries?domain={domain}&length=10")
    req = urllib.request.Request(url, headers={"sid": sid})
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read())

    queries = result.get("queries", [])
    if not queries:
        return {"status": "not_blocked"}

    latest = queries[0]
    status = latest.get("status", "")
    upstream = (latest.get("upstream") or "").split("#")[0]

    if status in PIHOLE_BLOCK_STATUSES:
        return {"status": "pihole_blocked", "list_id": latest.get("list_id")}

    if status in EXTERNAL_BLOCK_STATUSES:
        return {
            "status": "external_blocked",
            "upstream": upstream or "external DNS",
            "recategorize_url": CLOUDFLARE_RECATEGORIZE_URL,
        }

    if status in ("ALLOW_LIST", "ALLOW_CNAME"):
        return {"status": "allowed"}

    return {"status": "not_blocked"}
