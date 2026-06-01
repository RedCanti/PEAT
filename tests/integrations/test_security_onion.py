"""
Tests for the Security Onion integration wrapper.

These cover ECS enrichment and dataset mapping without contacting a live
Security Onion deployment.
"""

from peat.integrations import SecurityOnion


def test_dataset_from_dated_index():
    assert SecurityOnion._dataset_from_index("peat-configs-2025.06.01") == "configs"
    assert SecurityOnion._dataset_from_index("ot-device-events-2025.06.01") == "events"


def test_dataset_from_undated_index():
    assert SecurityOnion._dataset_from_index("peat-configs") == "configs"
    assert SecurityOnion._dataset_from_index("ot-device-registers") == "registers"


def test_dataset_from_unknown_index_returns_none():
    assert SecurityOnion._dataset_from_index("totally-made-up-index") is None


def test_enrich_adds_ecs_fields():
    so = SecurityOnion("https://so.example.com/")
    enriched = so.enrich({"firmware": {"version": "1.2"}}, "peat-configs-2025.06.01")

    assert enriched["event"]["module"] == "peat"
    assert enriched["event"]["dataset"] == "peat.configs"
    assert enriched["event"]["kind"] == "asset"
    assert enriched["data_stream"]["type"] == "logs"
    assert enriched["data_stream"]["dataset"] == "peat.configs"
    assert enriched["data_stream"]["namespace"] == "default"
    # original content is preserved
    assert enriched["firmware"]["version"] == "1.2"


def test_enrich_preserves_existing_event_fields():
    so = SecurityOnion("https://so.example.com/")
    src = {"event": {"dataset": "custom.ds", "module": "elsewhere"}}
    enriched = so.enrich(src, "peat-configs-2025.06.01")

    # We must not overwrite caller-set values
    assert enriched["event"]["dataset"] == "custom.ds"
    assert enriched["event"]["module"] == "elsewhere"


def test_enrich_uses_configured_prefix():
    so = SecurityOnion("https://so.example.com/", dataset_prefix="ot-team")
    enriched = so.enrich({}, "peat-configs")
    assert enriched["event"]["dataset"] == "ot-team.configs"
    assert enriched["data_stream"]["dataset"] == "ot-team.configs"
