from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from peat import PeatError, config
from peat.elastic import Elastic
from peat.protocols import HTTP

from ._common import inject_credentials


class Malcolm(Elastic):
    """
    Wrapper for pushing PEAT data into a Malcolm instance.

    Malcolm fronts its OpenSearch cluster with nginx at a path prefix of
    ``/mapi/opensearch``. Operators frequently pass just the base URL
    (e.g. ``https://malcolm.example.com/``), so this wrapper auto-appends
    the path if missing. It also adds dashboard import support via Malcolm's
    saved-objects API.

    Args:
        server_url: Malcolm URL. Either the bare host
            (``https://user:pass@malcolm.example.com/``) or the full OpenSearch
            path (``https://user:pass@malcolm.example.com/mapi/opensearch/``).
    """

    OPENSEARCH_PATH: str = "/mapi/opensearch"
    # The saved-objects import API is OpenSearch Dashboards' own REST endpoint,
    # served by Malcolm's nginx under the /dashboards base path -- NOT under the
    # /mapi data proxy (an unknown /mapi route answers 200 with a JSON 404 body).
    SAVED_OBJECTS_PATH: str = "/dashboards/api/saved_objects/_import"

    def __init__(self, server_url: str = "https://localhost/mapi/opensearch/") -> None:
        super().__init__(self._normalize_url(server_url))

        # Malcolm is always OpenSearch — short-circuit the tagline auto-detection
        # in Elastic.es so we don't pay an extra HTTP round-trip.
        self.is_opensearch = True
        self.type = "OpenSearch"

    @classmethod
    def _normalize_url(cls, url: str) -> str:
        """
        Append ``/mapi/opensearch`` to a Malcolm URL if it is not already present.
        """
        if cls.OPENSEARCH_PATH in url:
            return url

        # Preserve userinfo (``user:pass@host``) when splitting on the host boundary
        if "://" not in url:
            return url

        scheme, _, rest = url.partition("://")
        host_part, _, path_part = rest.partition("/")
        normalized_path = f"{cls.OPENSEARCH_PATH}/{path_part}".rstrip("/") + "/"
        return f"{scheme}://{host_part}{normalized_path}"

    def import_dashboard(self, ndjson_path: str | Path, overwrite: bool = True) -> bool:
        """
        Upload a saved-objects NDJSON bundle to Malcolm's dashboard import API.

        Args:
            ndjson_path: Path to the saved-objects bundle (one JSON object per line).
                The PEAT-shipped bundle is at
                ``distribution/opensearch-files/peat-malcolm-dashboard.ndjson``.
            overwrite: If existing saved objects with matching IDs should be replaced.

        Returns:
            If the import was successful.
        """
        ndjson_path = Path(ndjson_path)
        if not ndjson_path.is_file():
            self.log.error(f"Dashboard NDJSON not found: {ndjson_path.as_posix()}")
            return False

        # The saved-objects endpoint lives under OpenSearch Dashboards
        # (/dashboards/api/...), not under the /mapi/opensearch data path.
        import_url = self._saved_objects_url()
        # Log the path only -- import_url carries userinfo (user:pass) and must
        # not leak into the log file.
        self.log.info(f"Importing dashboard {ndjson_path.name} to {self.SAVED_OBJECTS_PATH}")

        # The saved-objects API does NOT use the OpenSearch client; it's the
        # OpenSearch Dashboards REST API behind nginx, which wants a multipart
        # upload plus an anti-CSRF header. OpenSearch Dashboards requires
        # "osd-xsrf"; we also send "kbn-xsrf" for Kibana / older-OSD compatibility.
        with HTTP.gen_session() as sess:
            with ndjson_path.open("rb") as handle:
                files = {"file": (ndjson_path.name, handle, "application/ndjson")}
                params = {"overwrite": "true"} if overwrite else {}
                headers = {"osd-xsrf": "peat", "kbn-xsrf": "peat"}
                resp = sess.post(
                    import_url,
                    files=files,
                    params=params,
                    headers=headers,
                    timeout=config.ELASTIC_TIMEOUT,
                )

        if not resp or resp.status_code >= 400:
            self.log.error(
                f"Dashboard import failed: status={getattr(resp, 'status_code', '?')} "
                f"body={getattr(resp, 'text', '')[:500]}"
            )
            return False

        try:
            body = resp.json()
        except (ValueError, json.JSONDecodeError):
            body = {}

        # Require an explicit success flag: Malcolm's nginx can wrap an unknown
        # route in a 200 with a JSON error body (no "success" key), so checking
        # only "is not False" would mistake that for success.
        if body.get("success") is not True:
            self.log.error(f"Dashboard import did not report success: {body}")
            return False

        errors = body.get("errors") or []
        if errors:
            self.log.error(f"Dashboard import had {len(errors)} object error(s): {errors}")
            return False

        self.log.info(f"Dashboard import succeeded: {body.get('successCount', '?')} objects")
        return True

    def _saved_objects_url(self) -> str:
        """
        Build the saved-objects import URL by stripping ``/mapi/opensearch`` from the
        base URL and appending :data:`SAVED_OBJECTS_PATH`
        (``/dashboards/api/saved_objects/_import``).
        """
        base = self.unsafe_url.rstrip("/")
        if base.endswith(self.OPENSEARCH_PATH):
            base = base[: -len(self.OPENSEARCH_PATH)]
        return f"{base}{self.SAVED_OBJECTS_PATH}"

    def bulk_push_raw(self, docs: list[dict[str, Any]]) -> bool:
        """
        Push pre-built documents without re-running :meth:`Elastic.gen_body`.

        Used by the forwarder to replay JSONL artifacts produced by
        :meth:`peat.Elastic._dump_docs_to_file`. Each doc must be a dict in
        bulk-action form: ``{"_index": ..., "_id": ..., "_source": ...}``.
        """
        if not docs:
            return True

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
            self.log.error(f"Raw bulk push to Malcolm failed: {err}")
            successful = False

        return successful


def build_target(server_url: str | None = None) -> Malcolm:
    """
    Build a :class:`Malcolm` target from configuration.

    Uses ``server_url`` if given, otherwise falls back to ``MALCOLM_SERVER`` and
    then ``ELASTIC_SERVER``. Registered as the ``malcolm`` forward target in
    :mod:`peat.integrations.registry`.

    Basic-auth credentials come from ``MALCOLM_USER``/``MALCOLM_PASSWORD``,
    falling back to ``ELASTIC_USER``/``ELASTIC_PASSWORD`` (mirroring the server
    fallback). They are injected into the URL unless it already carries
    ``user:pass@``.
    """
    url = server_url or config.MALCOLM_SERVER or config.ELASTIC_SERVER
    if not url:
        raise PeatError("Malcolm forward requires MALCOLM_SERVER or ELASTIC_SERVER")
    user = config.MALCOLM_USER or config.ELASTIC_USER
    password = config.MALCOLM_PASSWORD or config.ELASTIC_PASSWORD
    url = inject_credentials(url, user, password)
    return Malcolm(url)


__all__ = ["Malcolm", "build_target"]
