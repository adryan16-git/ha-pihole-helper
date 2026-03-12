#!/usr/bin/with-contenv bashio

bashio::log.info "Starting Pi-hole Helper add-on..."

export PYTHONPATH=/
exec python3 /pihole_helper/main.py
