"""Tests for Pi-hole instance discovery from HA config entries."""

import json
import os
import sys

import pytest

# Allow importing pihole_helper from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pihole_helper.discovery as discovery

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    return os.path.join(FIXTURES, name)


def test_discovers_both_pi_hole_v6_instances(monkeypatch, tmp_path):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_pi_hole_v6.json"))
    instances = discovery.discover_instances()

    assert len(instances) == 2
    names = {i.name for i in instances}
    assert names == {"Pi-hole Server", "Pi-hole RPi"}


def test_url_strips_api_suffix(monkeypatch):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_pi_hole_v6.json"))
    instances = discovery.discover_instances()

    for instance in instances:
        assert not instance.url.endswith("/api"), (
            f"URL should not include /api suffix (pihole_api.py appends it): {instance.url}"
        )


def test_url_is_correct_base(monkeypatch):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_pi_hole_v6.json"))
    instances = {i.name: i for i in discovery.discover_instances()}

    assert instances["Pi-hole Server"].url == "http://192.168.1.6"
    assert instances["Pi-hole RPi"].url == "http://192.168.1.20"


def test_password_is_extracted(monkeypatch):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_pi_hole_v6.json"))
    instances = {i.name: i for i in discovery.discover_instances()}

    assert instances["Pi-hole Server"].password == "test-app-password-server"
    assert instances["Pi-hole RPi"].password == "test-app-password-rpi"


def test_ignores_non_pihole_entries(monkeypatch):
    """mobile_app and other domains should be skipped."""
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_pi_hole_v6.json"))
    instances = discovery.discover_instances()
    assert len(instances) == 2  # only the two pi_hole_v6 entries


def test_returns_empty_when_no_pihole(monkeypatch):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_no_pihole.json"))
    instances = discovery.discover_instances()
    assert instances == []


def test_old_pi_hole_domain_not_discovered(monkeypatch):
    """Legacy pi_hole entries (pre-v6 migration) should NOT be discovered."""
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", _fixture("config_entries_old_pi_hole.json"))
    instances = discovery.discover_instances()
    assert instances == [], (
        "Old pi_hole domain entries should be ignored — only pi_hole_v6 is supported"
    )


def test_returns_empty_on_missing_file(monkeypatch):
    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", "/nonexistent/path.json")
    instances = discovery.discover_instances()
    assert instances == []


def test_name_falls_back_to_title(monkeypatch, tmp_path):
    """If data.name is absent, fall back to entry title."""
    fixture_data = {
        "data": {"entries": [{
            "domain": "pi_hole_v6",
            "entry_id": "abc123",
            "title": "My Pi-hole",
            "data": {
                "url": "http://192.168.1.6/api",
                "password": "secret"
                # no "name" key
            }
        }]}
    }
    fixture_path = tmp_path / "config_entries.json"
    fixture_path.write_text(json.dumps(fixture_data))

    monkeypatch.setattr(discovery, "HA_CONFIG_ENTRIES", str(fixture_path))
    instances = discovery.discover_instances()

    assert len(instances) == 1
    assert instances[0].name == "My Pi-hole"
