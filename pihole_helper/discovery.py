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
        if entry.get("domain") != "pi_hole":
            continue

        d = entry.get("data", {})
        host = d.get("host", "")  # may be "192.168.1.6:80"
        ssl = d.get("ssl", False)
        api_key = d.get("api_key", "")
        name = d.get("name") or entry.get("title") or host

        scheme = "https" if ssl else "http"
        url = f"{scheme}://{host}"

        instances.append(PiholeInstance(name=name, url=url, password=api_key))
        logger.info("Discovered Pi-hole: %s at %s", name, url)

    if not instances:
        logger.warning("No Pi-hole instances found in HA config entries")

    return instances
