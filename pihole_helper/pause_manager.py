"""Manage per-device pause timers, persisted across add-on restarts."""

import json
import logging
import os
import threading
import time

from pihole_helper import pihole_api

logger = logging.getLogger("pihole_helper.pause")

DATA_FILE = "/data/active_pauses.json"

_lock = threading.Lock()
_timers: dict = {}  # ip -> threading.Timer


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


def pause_device(ip: str, seconds: int):
    """Temporarily assign a device to the bypass group."""
    sid = pihole_api.get_sid()
    bypass_group_id = pihole_api.get_or_create_bypass_group(sid)

    # Save current group membership so we can restore it later
    previous_groups = pihole_api.get_client_groups(ip, sid)

    pihole_api.set_client_groups(ip, [bypass_group_id], sid,
                                  comment="Pi-hole Helper — temporary bypass")

    expires_at = time.time() + seconds

    with _lock:
        pauses = _load()
        pauses[ip] = {
            "expires_at": expires_at,
            "previous_groups": previous_groups,  # None = client didn't exist before
        }
        _save(pauses)

        if ip in _timers:
            _timers[ip].cancel()

        t = threading.Timer(seconds, _expire_device_pause, args=[ip])
        t.daemon = True
        t.start()
        _timers[ip] = t

    logger.info("Device %s paused for %ds (expires %s)", ip, seconds,
                time.strftime("%H:%M:%S", time.localtime(expires_at)))


def _expire_device_pause(ip: str):
    """Called when a device pause timer fires."""
    with _lock:
        pauses = _load()
        pause_info = pauses.pop(ip, None)
        if not pause_info:
            return
        _save(pauses)
        _timers.pop(ip, None)

    try:
        sid = pihole_api.get_sid()
        previous_groups = pause_info.get("previous_groups")
        if previous_groups is None:
            # Client didn't exist before — delete it so it falls back to Default
            pihole_api.delete_client(ip, sid)
        else:
            pihole_api.set_client_groups(ip, previous_groups, sid)
        logger.info("Device %s pause expired — blocking restored", ip)
    except Exception:
        logger.exception("Failed to restore blocking for device %s", ip)


def cancel_device_pause(ip: str):
    """Manually cancel a device pause early."""
    with _lock:
        if ip in _timers:
            _timers[ip].cancel()
            _timers.pop(ip)
    _expire_device_pause(ip)


def get_active_pauses() -> dict:
    """Return active pauses with remaining seconds."""
    pauses = _load()
    now = time.time()
    active = {}
    for ip, info in pauses.items():
        remaining = info["expires_at"] - now
        if remaining > 0:
            active[ip] = {"remaining_seconds": int(remaining)}
    return active


def restore_on_startup():
    """Re-arm timers after an add-on restart."""
    pauses = _load()
    now = time.time()
    expired = [ip for ip, info in pauses.items() if info["expires_at"] <= now]

    for ip in expired:
        logger.info("Pause for %s expired while add-on was offline — restoring", ip)
        _expire_device_pause(ip)

    for ip, info in pauses.items():
        if ip in expired:
            continue
        remaining = info["expires_at"] - now
        t = threading.Timer(remaining, _expire_device_pause, args=[ip])
        t.daemon = True
        t.start()
        _timers[ip] = t
        logger.info("Restored pause timer for %s: %ds remaining", ip, int(remaining))
