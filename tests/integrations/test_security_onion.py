"""
Tests for the Security Onion integration wrapper.

These cover ECS enrichment and dataset mapping without contacting a live
Security Onion deployment.
"""

from peat.elastic import Elastic
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


# --- in-band (live collection) enrichment via the _so_index_hint -------------


def test_gen_body_enriches_from_index_hint():
    so = SecurityOnion("https://so.example.com/")
    body = so.gen_body({"_so_index_hint": "ot-device-registers", "foo": "bar"})

    assert body["event"]["dataset"] == "peat.registers"
    assert body["data_stream"]["dataset"] == "peat.registers"
    assert body["foo"] == "bar"
    # The hint is an internal marker and must not leak into the stored doc
    assert "_so_index_hint" not in body


def test_gen_body_without_hint_is_not_enriched():
    so = SecurityOnion("https://so.example.com/")
    body = so.gen_body({"foo": "bar"})
    assert body.get("event", {}).get("dataset") is None


def test_push_injects_index_hint(monkeypatch):
    so = SecurityOnion("https://so.example.com/")
    captured = {}

    def fake_push(self, index, content, doc_id=None, no_date=False):
        captured["index"] = index
        captured["content"] = content
        return True

    monkeypatch.setattr(Elastic, "push", fake_push)
    original = {"foo": "bar"}

    assert so.push("ot-device-registers", original) is True
    assert captured["index"] == "ot-device-registers"
    assert captured["content"]["_so_index_hint"] == "ot-device-registers"
    # The caller's dict must not be mutated
    assert "_so_index_hint" not in original


def test_bulk_push_injects_index_hint(monkeypatch):
    so = SecurityOnion("https://so.example.com/")
    captured = {}

    def fake_bulk_push(self, index, contents):
        captured["index"] = index
        captured["contents"] = contents
        return True

    monkeypatch.setattr(Elastic, "bulk_push", fake_bulk_push)
    original = {"foo": "bar"}

    assert so.bulk_push("ot-device-tags", [("id1", original)]) is True
    assert captured["index"] == "ot-device-tags"
    assert captured["contents"][0][1]["_so_index_hint"] == "ot-device-tags"
    # The caller's dict must not be mutated
    assert "_so_index_hint" not in original
