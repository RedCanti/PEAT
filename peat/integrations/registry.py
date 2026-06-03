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


# Flat-settings prefix for each target type. A profile's generic fields
# (``server``, ``user``, ``insecure``, ...) map onto ``<PREFIX>_<FIELD>``
# settings (``SO_SERVER``, ``MALCOLM_USER``, ...) which the builders already read.
_TYPE_PREFIX: dict[str, str] = {
    "security_onion": "so",
    "malcolm": "malcolm",
    "elastic": "elastic",
}


def resolve_integration(
    name: str, integrations: dict | None = None
) -> tuple[str, dict[str, object]]:
    """
    Resolve a ``--integration`` value to a target type and config overrides.

    ``name`` may be either a profile name defined under the ``integrations``
    config section, or a bare target type (see :func:`target_names`). For a
    profile, its fields (minus ``type``) are mapped to flat ``<prefix>_<field>``
    settings so the existing target builders can consume them unchanged.

    Args:
        name: A profile name or a bare target type.
        integrations: The ``integrations`` config mapping (``config.INTEGRATIONS``).

    Returns:
        ``(target_type, overrides)`` -- ``overrides`` is a dict of flat settings
        to apply before building (e.g. ``{"so_server": ..., "so_user": ...}``),
        empty for a bare type.

    Raises:
        PeatError: If ``name`` is neither a known profile nor a target type, or
            a profile is malformed (not a mapping, or missing/unknown ``type``).
    """
    integrations = integrations or {}

    if name in integrations:
        profile = integrations[name]
        if not isinstance(profile, dict):
            raise PeatError(
                f"Integration profile {name!r} must be a mapping, "
                f"got {type(profile).__name__}"
            )
        target_type = profile.get("type")
        if target_type not in _TYPE_PREFIX:
            raise PeatError(
                f"Integration profile {name!r} has missing/unknown type "
                f"{target_type!r}. Valid types: {', '.join(sorted(_TYPE_PREFIX))}"
            )
        prefix = _TYPE_PREFIX[target_type]
        overrides = {
            f"{prefix}_{key}": value for key, value in profile.items() if key != "type"
        }
        return target_type, overrides

    if name in _TYPE_PREFIX:
        return name, {}

    raise PeatError(
        f"Unknown integration {name!r}. Defined profiles: "
        f"{', '.join(sorted(integrations)) or '(none)'}; "
        f"target types: {', '.join(sorted(_TYPE_PREFIX))}"
    )


__all__ = ["build_elastic", "build_target", "resolve_integration", "target_names"]
