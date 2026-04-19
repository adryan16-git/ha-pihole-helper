"""Discover Pi-hole instances from Home Assistant config entries."""

import json
import logging

logger = logging.getLogger("pihole_helper.discovery")

HA_CONFIG_ENTRIES = "/config/.storage/core.config_entries"


def discover_instances():
    """Read HA config entries and return a list of PiholeInstance objects."""
    # Import here to avoid circular import
    from pihole_helper.pihole_api import PiholeInstance

    try:
        with open(HA_CONFIG_ENTRIES) as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Could not read HA config entries: %s", e)
        return []

    instances = []
    for entry in data.get("data", {}).get("entries", []):
        if entry.get("domain") != "pi_hole_v6":
            continue

        d = entry.get("data", {})
        # pi_hole_v6 stores the full API URL (e.g. "http://pi-hole1.local/api")
        # pihole_api.py appends /api{path}, so strip the trailing /api
        url = d.get("url", "").rstrip("/")
        if url.endswith("/api"):
            url = url[:-4]
        password = d.get("password", "")
        name = d.get("name") or entry.get("title") or url

        instances.append(PiholeInstance(name=name, url=url, password=password))
        logger.info("Discovered Pi-hole: %s at %s", name, url)

    if not instances:
        logger.warning("No Pi-hole instances found in HA config entries")

    return instances
