"""
Template for a new ``peat forward`` SIEM target.

``peat forward`` replays a saved PEAT run (the JSONL artifacts under
``peat_results/<run>/elastic_data/``) into a SIEM without re-collecting from
devices. Each target is a thin wrapper around :class:`peat.Elastic` that applies
only the policy that differs for that target (URL handling, field enrichment,
auth, dashboard import). The Elasticsearch/OpenSearch transport -- client,
serialization, bulk push, index caching -- is inherited unchanged.

Copy this file to ``peat/integrations/<your_target>.py`` and adapt it. The two
shipped targets, ``peat/integrations/malcolm.py`` and
``peat/integrations/security_onion.py``, are real, fuller examples worth reading
alongside this template.

------------------------------------------------------------------------------
HOW TO WIRE IN A NEW TARGET
------------------------------------------------------------------------------
1. Module: copy this file to ``peat/integrations/foobar.py`` and rename the
   class / docstrings. Implement only the policy your SIEM needs.

2. Registry: add ONE line to ``_TARGETS`` in
   ``peat/integrations/registry.py``:

       "foobar": "peat.integrations.foobar:build_target",

   That is the only change needed for ``--target foobar`` to appear in the CLI
   and dispatch correctly -- ``target_names()`` and dispatch read this dict.

3. Config fields: add settings to ``peat/settings.py`` (declare as
   ``FOOBAR_SERVER: str = None`` etc.). At minimum a ``FOOBAR_SERVER``; add
   ``FOOBAR_USER`` / ``FOOBAR_PASSWORD`` if it uses basic auth.

4. CLI flags (optional but recommended): add ``--foobar-server`` /
   ``--foobar-user`` / ``--foobar-password`` to the ``siem_group`` in
   ``peat/cli_args.py``. A flag's ``dest`` (e.g. ``foobar_server``) is
   uppercased and auto-loaded into the matching config field -- no other glue.

5. Secrets: operators put ``foobar_user`` / ``foobar_password`` in a gitignored
   config file (see ``examples/peat-credentials.example.yaml``) or
   ``PEAT_FOOBAR_*`` env vars. Never require secrets on the command line.

------------------------------------------------------------------------------
CREDENTIAL INJECTION
------------------------------------------------------------------------------
Use :func:`peat.integrations._common.inject_credentials` to fold a configured
username/password into the server URL's userinfo. It is a no-op when the
username is empty or when the URL already carries ``user:pass@`` (so an explicit
``--foobar-server`` URL always wins), and it percent-encodes the credentials so
special characters survive without the operator hand-encoding the URL.
"""

from __future__ import annotations

from typing import Any

from peat import PeatError, config
from peat.elastic import Elastic

from peat.integrations._common import inject_credentials


class Foobar(Elastic):
    """
    Wrapper for pushing PEAT data into a Foobar SIEM.

    Subclass :class:`peat.Elastic` and override only what differs for your
    target. Common things you might customize:

    - ``__init__``: normalize the URL (e.g. append a fixed API path) and set
      ``self.is_opensearch`` / ``self.type`` if you already know the backend,
      to skip the tagline auto-detection round-trip.
    - :meth:`enrich`: add target-specific fields to each ``_source`` before
      push (Security Onion adds ECS ``event.*`` / ``data_stream.*``).
    - :meth:`bulk_push_raw`: the replay entry point used by the forwarder for
      pre-formed ``{"_index", "_id", "_source"}`` docs. Implement it if you need
      per-doc enrichment or a non-Elasticsearch transport; otherwise the
      forwarder falls back to a plain bulk push (see
      ``peat/integrations/forwarder.py``).
    """

    def __init__(self, server_url: str = "https://localhost:9200/") -> None:
        super().__init__(server_url)
        # If you always know the backend, short-circuit tagline detection:
        # self.is_opensearch = True
        # self.type = "OpenSearch"

    def enrich(self, source: dict[str, Any], index: str) -> dict[str, Any]:
        """
        Add any target-specific fields to a single document's ``_source``.

        Preserve existing values (use ``setdefault``). Return the same dict.
        Remove this method if your target needs no enrichment.
        """
        return source

    def bulk_push_raw(self, docs: list[dict[str, Any]]) -> bool:
        """
        Push pre-built bulk-action docs during a ``forward`` replay.

        ``docs`` is a list of ``{"_index", "_id", "_source"}`` dicts read from
        the saved run. Apply :meth:`enrich`, ensure indices exist, then bulk
        push. Returns True only if every document was indexed successfully.

        Delete this override to accept the forwarder's generic bulk push.
        """
        if not docs:
            return True

        for doc in docs:
            self.enrich(doc["_source"], doc["_index"])

        indices = {doc["_index"] for doc in docs}
        for index in indices:
            if not self.create_index(index):
                return False

        self.log.info(f"Bulk pushing {len(docs)} raw docs to {self.type}")
        successful = True
        try:
            for es_success, _ in self.parallel_bulk(client=self.es, actions=docs):
                if not es_success:
                    successful = False
        except Exception as err:
            self.log.error(f"Raw bulk push to Foobar failed: {err}")
            successful = False

        return successful


def build_target(server_url: str | None = None) -> Foobar:
    """
    Build a :class:`Foobar` target from configuration.

    This is the function named in the registry's ``"module:function"`` entry.
    It must accept an optional ``server_url`` override (the CLI passes ``None``,
    so the ``FOOBAR_SERVER`` config value is used) and return a configured
    transport wrapper.
    """
    url = server_url or config.FOOBAR_SERVER  # add FOOBAR_SERVER to settings.py
    if not url:
        raise PeatError("Foobar forward requires FOOBAR_SERVER")

    # Fold configured basic-auth credentials into the URL. No-op if unset or if
    # the URL already has user:pass@.
    url = inject_credentials(url, config.FOOBAR_USER, config.FOOBAR_PASSWORD)
    return Foobar(url)


__all__ = ["Foobar", "build_target"]
