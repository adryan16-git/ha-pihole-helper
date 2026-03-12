"""Manage per-device pause timers across all Pi-hole instances."""

import json
import logging
import os
import threading
import time
from typing import List

from pihole_helper import pihole_api
from pihole_helper.pihole_api import PiholeInstance

logger = logging.getLogger("pihole_helper.pause")

DATA_FILE = "/data/active_pauses.json"

_lock = threading.Lock()
_timers: dict = {}


def _load() -> dict:
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


def _pause_on_instance(instance: PiholeInstance, ip: str) -> list:
    """Pause one instance and return the previous group IDs (or None)."""
    sid = pihole_api.get_sid(instance)
    bypass_id = pihole_api.get_or_create_bypass_group(instance, sid)
    previous_groups = pihole_api.get_client_groups(instance, ip, sid)
    pihole_api.set_client_groups(instance, ip, [bypass_id], sid,
                                 comment="Pi-hole Helper — temporary bypass")
    return previous_groups


def _restore_on_instance(instance: PiholeInstance, ip: str, previous_groups):
    """Restore one instance after a pause expires."""
    try:
        sid = pihole_api.get_sid(instance)
        if previous_groups is None:
            pihole_api.delete_client(instance, ip, sid)
        else:
            pihole_api.set_client_groups(instance, ip, previous_groups, sid)
        logger.info("Restored %s on %s", ip, instance.name)
    except Exception:
        logger.exception("Failed to restore %s on %s", ip, instance.name)


def pause_device(ip: str, seconds: int, instances: List[PiholeInstance]):
    """Pause blocking for a device IP across all instances."""
    per_instance_state = {}
    for instance in instances:
        try:
            previous_groups = _pause_on_instance(instance, ip)
            per_instance_state[instance.url] = {
                "name": instance.name,
                "password": instance.password,
                "previous_groups": previous_groups,
            }
        except Exception:
            logger.exception("Failed to pause %s on %s", ip, instance.name)

    expires_at = time.time() + seconds

    with _lock:
        pauses = _load()
        pauses[ip] = {
            "expires_at": expires_at,
            "instances": per_instance_state,
        }
        _save(pauses)

        if ip in _timers:
            _timers[ip].cancel()

        t = threading.Timer(seconds, _expire_pause, args=[ip])
        t.daemon = True
        t.start()
        _timers[ip] = t

    logger.info("Device %s paused for %ds across %d instance(s)",
                ip, seconds, len(per_instance_state))


def _expire_pause(ip: str):
    with _lock:
        pauses = _load()
        pause_info = pauses.pop(ip, None)
        if not pause_info:
            return
        _save(pauses)
        _timers.pop(ip, None)

    for url, state in pause_info.get("instances", {}).items():
        instance = PiholeInstance(
            name=state["name"],
            url=url,
            password=state["password"],
        )
        _restore_on_instance(instance, ip, state.get("previous_groups"))

    logger.info("Device %s pause expired — blocking restored on all instances", ip)


def cancel_device_pause(ip: str):
    with _lock:
        if ip in _timers:
            _timers[ip].cancel()
            _timers.pop(ip)
    _expire_pause(ip)


def get_active_pauses() -> dict:
    pauses = _load()
    now = time.time()
    return {
        ip: {"remaining_seconds": int(info["expires_at"] - now)}
        for ip, info in pauses.items()
        if info["expires_at"] > now
    }


def restore_on_startup():
    """Re-arm timers after an add-on restart."""
    pauses = _load()
    now = time.time()

    for ip, info in list(pauses.items()):
        remaining = info["expires_at"] - now
        if remaining <= 0:
            logger.info("Pause for %s expired while offline — restoring", ip)
            _expire_pause(ip)
        else:
            t = threading.Timer(remaining, _expire_pause, args=[ip])
            t.daemon = True
            t.start()
            _timers[ip] = t
            logger.info("Restored pause timer for %s: %ds remaining", ip, int(remaining))
