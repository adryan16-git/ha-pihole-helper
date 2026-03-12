"""Pi-hole Helper — entry point."""

import logging
import sys

from pihole_helper.discovery import discover_instances
from pihole_helper.web_server import create_app, set_instances
from pihole_helper import pause_manager
from pihole_helper import pihole_api

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("pihole_helper")

PORT = 8098


def _check_connectivity(instances):
    """Verify each Pi-hole instance is reachable at startup."""
    for instance in instances:
        try:
            pihole_api.get_sid(instance)
            logger.info("Connected to %s ✓", instance.name)
        except Exception as e:
            logger.error("Could not connect to %s: %s", instance.name, e)


def main():
    logger.info("Pi-hole Helper starting up...")

    instances = discover_instances()
    if instances:
        logger.info("Using %d Pi-hole instance(s): %s",
                    len(instances), ", ".join(i.name for i in instances))
    else:
        logger.warning("No Pi-hole instances found — check HA Pi-hole integration is configured")

    set_instances(instances)
    _check_connectivity(instances)
    pause_manager.restore_on_startup()

    app = create_app()
    logger.info("Listening on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()
