from __future__ import annotations

from pathlib import Path

from peat import log
from peat.integrations import build_target, forward_run


def forward(
    run_dir: Path | str,
    target: str,
    server_url: str | None = None,
) -> bool:
    """
    Replay a saved PEAT run into Elasticsearch, Malcolm, or Security Onion.

    This is the offline counterpart to PEAT's normal in-band push: data was
    collected on (potentially isolated) hardware and saved to
    ``peat_results/<run-dir>/elastic_data/``, and now needs to land in an
    analyst SIEM. No device communication occurs.

    Args:
        run_dir: Path to a ``peat_results/<run-dir>/`` directory.
        target: Which SIEM to push to. Must be one of the registered target
            names (see :func:`peat.integrations.target_names`): ``elastic``,
            ``malcolm``, or ``security_onion``.
        server_url: Optional override of the target URL. If not given, the
            target's builder falls back to the relevant ``*_SERVER``
            configuration value (``ELASTIC_SERVER``, ``MALCOLM_SERVER``, or
            ``SO_SERVER``).

    Returns:
        If every document was forwarded successfully.

    Raises:
        PeatError: If ``target`` is unknown or no server URL is available.
    """
    run_dir = Path(run_dir)
    instance = build_target(target, server_url)
    log.info(f"Forwarding {run_dir.as_posix()} -> {target} ({instance.safe_url})")
    return forward_run(run_dir, instance)


__all__ = ["forward"]
