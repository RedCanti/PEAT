"""
Tests for the offline run forwarder.

These build a fake ``peat_results/<run-dir>/elastic_data/`` tree, point the
forwarder at it, and verify that the right docs are read out and dispatched
to the target wrapper.
"""

import json
from pathlib import Path

import pytest

from peat import PeatError
from peat.integrations import forward_run, iter_run_docs


def _write_jsonl(path: Path, docs: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for doc in docs:
            fh.write(json.dumps(doc) + "\n")


def _make_run_dir(tmp_path: Path) -> Path:
    """
    Build a minimal run directory mirroring the structure produced by
    ``peat.Elastic._dump_docs_to_file``.
    """
    run_dir = tmp_path / "scan_default-config_2026-05-28_165532013980"
    elastic_data = run_dir / "elastic_data" / "165532013980"

    _write_jsonl(
        elastic_data / "peat-configs-2026.05.28.jsonl",
        [
            {
                "_index": "peat-configs-2026.05.28",
                "_id": "peat~1~001~9",
                "_source": {"firmware": {"version": "1.0"}},
            },
            {
                "_index": "peat-configs-2026.05.28",
                "_id": "peat~1~002~7",
                "_source": {"firmware": {"version": "1.1"}},
            },
        ],
    )
    _write_jsonl(
        elastic_data / "ot-device-registers-2026.05.28.jsonl",
        [
            {
                "_index": "ot-device-registers-2026.05.28",
                "_id": "peat~1~003~4",
                "_source": {"register": {"id": "DI-0001"}},
            }
        ],
    )

    # Mapping files should be skipped, not read as docs
    mappings_dir = run_dir / "elastic_data" / "mappings"
    mappings_dir.mkdir(parents=True, exist_ok=True)
    (mappings_dir / "peat-configs.jsonl").write_text('{"not": "a doc"}\n')

    return run_dir


def test_iter_run_docs_reads_all_jsonl(tmp_path):
    run_dir = _make_run_dir(tmp_path)
    docs = [doc for _, doc in iter_run_docs(run_dir)]

    assert len(docs) == 3
    ids = {doc["_id"] for doc in docs}
    assert ids == {"peat~1~001~9", "peat~1~002~7", "peat~1~003~4"}


def test_iter_run_docs_skips_mappings(tmp_path):
    run_dir = _make_run_dir(tmp_path)
    # The mappings/ entry would fail the required-key check, but it should be
    # skipped before that — so no warning about missing keys
    docs = list(iter_run_docs(run_dir))
    assert all("mappings" not in p.parts for p, _ in docs)


def test_iter_run_docs_missing_elastic_dir(tmp_path):
    empty_run = tmp_path / "empty-run"
    empty_run.mkdir()
    with pytest.raises(PeatError, match="elastic_data"):
        list(iter_run_docs(empty_run))


def test_iter_run_docs_skips_malformed_lines(tmp_path):
    run_dir = tmp_path / "run-with-junk"
    elastic_data = run_dir / "elastic_data" / "1"
    elastic_data.mkdir(parents=True)

    # mix of valid and malformed lines
    (elastic_data / "peat-configs.jsonl").write_text(
        '{"_index": "i", "_id": "1", "_source": {}}\n'
        "not-json-at-all\n"
        '{"missing": "required-keys"}\n'
        '{"_index": "i", "_id": "2", "_source": {}}\n'
    )

    docs = [doc for _, doc in iter_run_docs(run_dir)]
    assert [d["_id"] for d in docs] == ["1", "2"]


class _FakeTarget:
    """
    Minimal stand-in for Malcolm/SecurityOnion: records every bulk push.
    """

    def __init__(self):
        self.pushed: list[dict] = []
        self.push_calls = 0

    def bulk_push_raw(self, docs):
        self.push_calls += 1
        self.pushed.extend(docs)
        return True


def test_forward_run_dispatches_to_target(tmp_path):
    run_dir = _make_run_dir(tmp_path)
    target = _FakeTarget()

    assert forward_run(run_dir, target) is True
    assert len(target.pushed) == 3


def test_forward_run_batches(tmp_path):
    run_dir = _make_run_dir(tmp_path)
    target = _FakeTarget()

    assert forward_run(run_dir, target, batch_size=2) is True
    # 3 docs at batch=2 => two flushes (2 + 1)
    assert target.push_calls == 2
    assert len(target.pushed) == 3


def test_forward_run_propagates_failure(tmp_path):
    class _FailingTarget(_FakeTarget):
        def bulk_push_raw(self, docs):
            super().bulk_push_raw(docs)
            return False

    run_dir = _make_run_dir(tmp_path)
    target = _FailingTarget()
    assert forward_run(run_dir, target) is False


def test_forward_run_missing_dir_raises():
    with pytest.raises(PeatError, match="does not exist"):
        forward_run("/nonexistent-path-for-tests", _FakeTarget())
