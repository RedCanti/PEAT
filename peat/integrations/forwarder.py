from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from peat import PeatError, log
from peat.elastic import Elastic

from .malcolm import Malcolm
from .security_onion import SecurityOnion

TargetType = Literal["elastic", "malcolm", "security_onion"]


def iter_run_docs(run_dir: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    """
    Yield each saved Elasticsearch document from a PEAT run directory.

    Walks ``<run_dir>/elastic_data/**/*.jsonl`` (the artifacts produced by
    :meth:`peat.Elastic._dump_docs_to_file`) and yields ``(source_file, doc)``
    where ``doc`` is the bulk-action dict ``{"_index", "_id", "_source"}``.

    Skips index-mapping files in ``elastic_data/mappings/``; those describe how
    to create indices, not documents to push.

    Args:
        run_dir: Path to a ``peat_results/<run-dir>/`` directory.
    """
    elastic_dir = run_dir / "elastic_data"
    if not elastic_dir.is_dir():
        raise PeatError(
            f"Run directory '{run_dir.as_posix()}' has no elastic_data/ subdirectory. "
            f"Was PEAT run with file output enabled?"
        )

    for jsonl_path in sorted(elastic_dir.rglob("*.jsonl")):
        # mappings/ holds index-creation JSON, not docs
        if "mappings" in jsonl_path.parts:
            continue

        with jsonl_path.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError as ex:
                    log.warning(
                        f"Skipping malformed JSON at {jsonl_path.as_posix()}:{line_no}: {ex}"
                    )
                    continue

                if not all(k in doc for k in ("_index", "_id", "_source")):
                    log.warning(
                        f"Skipping doc without _index/_id/_source at "
                        f"{jsonl_path.as_posix()}:{line_no}"
                    )
                    continue

                yield jsonl_path, doc


def forward_run(
    run_dir: Path | str,
    target: Elastic | Malcolm | SecurityOnion,
    batch_size: int = 500,
) -> bool:
    """
    Replay a saved PEAT run into a SIEM target.

    Reads bulk-action documents from ``<run_dir>/elastic_data/`` and pushes
    them in batches via the target's bulk push API. The target wrapper applies
    any policy needed (e.g. ECS enrichment for Security Onion).

    Args:
        run_dir: Path to a PEAT run directory.
        target: Wrapper instance (:class:`Malcolm`, :class:`SecurityOnion`, or
            a plain :class:`peat.Elastic` for generic Elastic/OpenSearch).
        batch_size: Maximum number of docs per bulk push.

    Returns:
        If every batch was pushed successfully.
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise PeatError(f"Run directory does not exist: {run_dir.as_posix()}")

    pushed = 0
    failed = 0
    batch: list[dict[str, Any]] = []
    success = True

    def flush() -> None:
        nonlocal pushed, failed, success, batch
        if not batch:
            return
        if _bulk_push(target, batch):
            pushed += len(batch)
        else:
            failed += len(batch)
            success = False
        batch = []

    for _, doc in iter_run_docs(run_dir):
        batch.append(doc)
        if len(batch) >= batch_size:
            flush()

    flush()

    target_name = type(target).__name__
    log.info(
        f"Forwarded {pushed} docs from {run_dir.as_posix()} to {target_name} (failed: {failed})"
    )
    return success


def _bulk_push(
    target: Elastic | Malcolm | SecurityOnion,
    docs: list[dict[str, Any]],
) -> bool:
    """
    Dispatch to the right bulk-push method on the target.

    Wrappers expose ``bulk_push_raw`` for replay (pre-formed docs). Plain
    :class:`peat.Elastic` instances don't, so fall back to a minimal inline
    bulk push that bypasses :meth:`gen_body`.
    """
    if hasattr(target, "bulk_push_raw"):
        return target.bulk_push_raw(docs)

    # Bare Elastic — push docs as-is without re-running gen_body
    indices = {doc["_index"] for doc in docs}
    for index in indices:
        if not target.create_index(index):
            return False

    try:
        successful = True
        for es_success, _ in target.parallel_bulk(client=target.es, actions=docs):
            if not es_success:
                successful = False
        return successful
    except Exception as err:
        log.error(f"Forward bulk push failed: {err}")
        return False


__all__ = ["TargetType", "forward_run", "iter_run_docs"]
