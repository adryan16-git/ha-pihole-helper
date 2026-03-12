"""Pi-hole Helper — entry point."""

import logging
import sys

from pihole_helper.web_server import create_app
from pihole_helper import pause_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("pihole_helper")

PORT = 8098


def main():
    logger.info("Pi-hole Helper starting up...")

    # Re-arm any pauses that survived an add-on restart
    pause_manager.restore_on_startup()

    app = create_app()
    logger.info("Listening on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)


if __name__ == "__main__":
    main()
