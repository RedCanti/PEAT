"""
SIEM integration wrappers for PEAT.

This package contains thin wrappers around :class:`peat.Elastic` that apply
target-specific policy (URL handling, ECS field additions, dashboard import)
for Security Onion and Malcolm, plus an offline ``forward`` flow that replays
a saved PEAT run into one of those targets without re-collecting from devices.

The transport layer (Elasticsearch/OpenSearch client, serialization, bulk push,
index caching) is inherited unchanged from :class:`peat.Elastic`. Only policy
that differs between targets lives here.
"""

from .forwarder import forward_run, iter_run_docs
from .malcolm import Malcolm
from .registry import build_target, resolve_integration, target_names
from .security_onion import SecurityOnion

__all__ = [
    "Malcolm",
    "SecurityOnion",
    "build_target",
    "forward_run",
    "iter_run_docs",
    "resolve_integration",
    "target_names",
]
