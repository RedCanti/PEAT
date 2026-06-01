"""
Registry of ``peat forward`` targets.

Maps each ``--target`` name to a builder that constructs the appropriate
transport wrapper. Builders are referenced as ``"module:function"`` strings and
imported lazily on use, so listing the available target names does not require
importing every target's client libraries.

To add a target: create a module under :mod:`peat.integrations` that exposes a
``build_target(server_url)`` function returning a configured transport, then add
one entry to :data:`_TARGETS` below. Removing a target is the reverse. No other
code (CLI ``--target`` choices, dispatch) needs to change.

A copy-and-edit starting point with step-by-step instructions lives in
``examples/integration_template.py``.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from peat import PeatError, config

if TYPE_CHECKING:
    from peat.elastic import Elastic

# Target name -> "module:function" path of its builder. Each builder takes an
# optional server_url override and returns a configured transport wrapper.
_TARGETS: dict[str, str] = {
    "elastic": "peat.integrations.registry:build_elastic",
    "malcolm": "peat.integrations.malcolm:build_target",
    "security_onion": "peat.integrations.security_onion:build_target",
}


def target_names() -> list[str]:
    """Sorted names of the available forward targets (for CLI ``--target``)."""
    return sorted(_TARGETS)


def build_target(name: str, server_url: str | None = None) -> Elastic:
    """
    Build the transport wrapper for the named forward target.

    Args:
        name: A registered target name (see :func:`target_names`).
        server_url: Optional URL override. If omitted, the target's builder uses
            the relevant ``*_SERVER`` configuration value.

    Returns:
        A configured :class:`peat.Elastic` (or subclass) instance.

    Raises:
        PeatError: If ``name`` is not a registered target, or its builder module
            cannot be imported.
    """
    try:
        dotted = _TARGETS[name]
    except KeyError:
        raise PeatError(
            f"Unknown forward target: {name!r}. Available: {', '.join(target_names())}"
        ) from None

    module_path, _, func_name = dotted.partition(":")
    try:
        module = import_module(module_path)
    except ImportError as ex:
        raise PeatError(f"Forward target {name!r} is unavailable: {ex}") from ex

    return getattr(module, func_name)(server_url)


def build_elastic(server_url: str | None = None) -> Elastic:
    """Build a plain Elasticsearch/OpenSearch target from ``ELASTIC_SERVER``."""
    from peat.elastic import Elastic

    from ._common import inject_credentials

    url = server_url or config.ELASTIC_SERVER
    if not url:
        raise PeatError("Elastic forward requires ELASTIC_SERVER")
    url = inject_credentials(url, config.ELASTIC_USER, config.ELASTIC_PASSWORD)
    return Elastic(url)


__all__ = ["build_elastic", "build_target", "target_names"]
