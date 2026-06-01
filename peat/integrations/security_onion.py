from __future__ import annotations

from typing import Any, Literal, cast

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError, TransportError
from opensearchpy.exceptions import OpenSearchException

from peat import config, consts, state
from peat.elastic import Elastic

from ._common import inject_credentials

SOAuth = Literal["none", "basic", "apikey", "cert"]

# Mapping from PEAT index basenames to the dataset suffix used in
# ``event.dataset`` and ``data_stream.dataset``. Keys are the values of the
# corresponding ``ELASTIC_*_INDEX`` settings.
_INDEX_TO_DATASET: dict[str, str] = {
    "peat-logs": "logs",
    "peat-scan-summaries": "scan",
    "peat-pull-summaries": "pull",
    "peat-parse-summaries": "parse",
    "peat-configs": "configs",
    "peat-state": "state",
    "ot-device-hosts-timeseries": "hosts",
    "ot-device-files": "files",
    "ot-device-registers": "registers",
    "ot-device-tags": "tags",
    "ot-device-io": "io",
    "ot-device-events": "events",
    "ot-device-memory": "memory",
    "uefi-files": "uefi_files",
    "uefi-hashes": "uefi_hashes",
}

# event.kind value per dataset. Most PEAT data is "asset"-like (device state
# snapshots); device-emitted log/event records get "event".
# See: https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html
_DATASET_TO_KIND: dict[str, str] = {
    "logs": "event",
    "events": "event",
    "scan": "asset",
    "pull": "asset",
    "parse": "asset",
    "configs": "asset",
    "state": "state",
    "hosts": "asset",
    "files": "asset",
    "registers": "asset",
    "tags": "asset",
    "io": "asset",
    "memory": "asset",
    "uefi_files": "asset",
    "uefi_hashes": "asset",
}


class SecurityOnion(Elastic):
    """
    Wrapper for pushing PEAT data into a Security Onion deployment.

    Security Onion expects ECS records with ``event.dataset``, ``event.module``,
    ``event.kind``, and ``data_stream.*`` populated so that data is queryable
    from Hunt, Dashboards, and Cases without manual index-pattern setup.

    Documents are pushed straight to SO's Elasticsearch API. (Forwarding a saved
    run replays already-structured PEAT documents, so there is no benefit to
    routing them through SO's live Logstash ingestion pipeline.)

    Args:
        server_url: SO Elasticsearch URL (e.g. ``https://so-manager:9200/``).
        auth: Authentication mode (``none``, ``basic``, ``apikey``, or ``cert``).
            ``basic`` uses credentials in ``server_url``; ``apikey`` and ``cert``
            use the dedicated config options.
        api_key: API key for ``auth=apikey``. Must be the
            ``id:api_key`` form (the client will base64-encode it).
        client_cert: Client certificate path for ``auth=cert``.
        client_key: Client key path for ``auth=cert``.
        ca_cert: Path to a CA bundle for TLS verification.
        insecure: If True, disable TLS verification (default False).
        dataset_prefix: Prefix for ``event.dataset`` values (default ``peat``).
    """

    def __init__(
        self,
        server_url: str = "https://localhost:9200/",
        auth: SOAuth = "basic",
        api_key: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        ca_cert: str | None = None,
        insecure: bool = False,
        dataset_prefix: str = "peat",
    ) -> None:
        super().__init__(server_url)

        self.auth: SOAuth = auth
        self.api_key: str | None = api_key
        self.client_cert: str | None = client_cert
        self.client_key: str | None = client_key
        self.ca_cert: str | None = ca_cert
        self.insecure: bool = insecure
        self.dataset_prefix: str = dataset_prefix or "peat"

    # ------------------------------------------------------------------
    # Elasticsearch client
    # ------------------------------------------------------------------

    @property
    def es(self) -> Elasticsearch:
        """
        Elasticsearch client with SO-specific auth options applied.

        Overrides :attr:`peat.Elastic.es` so that ``api_key``, ``client_cert``,
        ``ca_certs``, and ``verify_certs`` are passed through. The base class
        already handles URL-embedded basic auth via ``self.unsafe_url``.
        """
        if self._es is not None:
            return self._es  # type: ignore[return-value]

        client_kwargs: dict[str, Any] = {
            "hosts": [self.unsafe_url],
            "timeout": config.ELASTIC_TIMEOUT,
            "serializer": self.serializer,
            "verify_certs": not self.insecure,
        }

        if self.insecure:
            client_kwargs["ssl_show_warn"] = False

        if self.ca_cert:
            client_kwargs["ca_certs"] = self.ca_cert

        if self.auth == "apikey" and self.api_key:
            client_kwargs["api_key"] = self.api_key
        elif self.auth == "cert":
            if self.client_cert:
                client_kwargs["client_cert"] = self.client_cert
            if self.client_key:
                client_kwargs["client_key"] = self.client_key

        try:
            self._es = Elasticsearch(**client_kwargs)
            if not self._es.ping():
                raise consts.PeatError(
                    f"Connected to Security Onion at {self.safe_url} but ping failed"
                )
        except (ApiError, TransportError, OpenSearchException) as err:
            self.log.exception(f"Failed to connect to Security Onion: {err}")
            raise

        self.log.info(f"Connected to Security Onion ({self.safe_url})")
        self._index_cache = set()
        return self._es  # type: ignore[return-value]

    @es.setter
    def es(self, instance: Elasticsearch) -> None:
        self._es = instance

    # ------------------------------------------------------------------
    # ECS enrichment for SO
    # ------------------------------------------------------------------

    @staticmethod
    def _dataset_from_index(index: str) -> str | None:
        """
        Strip a dated suffix (``-2025.06.01``) and return the dataset name
        for the resulting base index, or :obj:`None` if it's not a known
        PEAT index.
        """
        # ``peat-configs-2025.06.01`` -> ``peat-configs``; leave undated names alone
        if "." in index:
            base = index.rpartition("-")[0] or index
        else:
            base = index
        return _INDEX_TO_DATASET.get(base)

    def enrich(self, source: dict[str, Any], index: str) -> dict[str, Any]:
        """
        Add the ECS fields Security Onion needs to surface a PEAT doc in
        Hunt / Dashboards. Existing field values are preserved.
        """
        dataset = self._dataset_from_index(index)
        full_dataset = f"{self.dataset_prefix}.{dataset}" if dataset else self.dataset_prefix

        event = source.setdefault("event", {})
        event.setdefault("module", "peat")
        event.setdefault("dataset", full_dataset)
        if dataset:
            event.setdefault("kind", _DATASET_TO_KIND.get(dataset, "asset"))

        data_stream = source.setdefault("data_stream", {})
        data_stream.setdefault("type", "logs")
        data_stream.setdefault("dataset", full_dataset)
        data_stream.setdefault("namespace", "default")

        return source

    def gen_body(self, content: dict) -> dict[str, Any]:
        body = super().gen_body(content)
        # gen_body is called before bulk_push knows the dated index name, so the
        # dataset is derived from a hint placed on the content (or omitted).
        # The forwarder uses ``enrich(...)`` directly when replaying with a known index.
        index_hint = content.get("_so_index_hint")
        if index_hint:
            self.enrich(body, index_hint)
            body.pop("_so_index_hint", None)
        return body

    # ------------------------------------------------------------------
    # Bulk push
    # ------------------------------------------------------------------

    def bulk_push_raw(self, docs: list[dict[str, Any]]) -> bool:
        """
        Push pre-built bulk-action docs, applying SO ECS enrichment to each.
        ``docs`` is a list of ``{"_index", "_id", "_source"}`` dicts.
        """
        if not docs:
            return True

        for doc in docs:
            self.enrich(doc["_source"], doc["_index"])

        return self._push_direct(docs)

    def _push_direct(self, docs: list[dict[str, Any]]) -> bool:
        indices = {doc["_index"] for doc in docs}
        for index in indices:
            if not self.create_index(index):
                state.error = True
                return False

        self.log.info(f"Bulk pushing {len(docs)} docs to Security Onion")
        successful = True
        try:
            for es_success, _ in self.parallel_bulk(client=self.es, actions=docs):
                if not es_success:
                    successful = False
        except Exception as err:
            self.log.error(f"Push to Security Onion failed: {err}")
            successful = False

        return successful


def build_target(server_url: str | None = None) -> SecurityOnion:
    """
    Build a :class:`SecurityOnion` target from the ``SO_*`` configuration.

    Uses ``server_url`` if given, otherwise ``SO_SERVER``. Registered as the
    ``security_onion`` forward target in :mod:`peat.integrations.registry`.

    For ``SO_AUTH=basic``, credentials come from ``SO_USER``/``SO_PASSWORD`` and
    are injected into the URL unless it already carries ``user:pass@``.
    """
    url = server_url or config.SO_SERVER
    if not url:
        raise consts.PeatError("Security Onion forward requires SO_SERVER")
    url = inject_credentials(url, config.SO_USER, config.SO_PASSWORD)
    return SecurityOnion(
        url,
        auth=cast(SOAuth, config.SO_AUTH),
        api_key=config.SO_API_KEY,
        client_cert=config.SO_CLIENT_CERT,
        client_key=config.SO_CLIENT_KEY,
        ca_cert=config.SO_CA_CERT,
        insecure=config.SO_INSECURE,
        dataset_prefix=config.SO_DATASET_PREFIX,
    )


__all__ = ["SOAuth", "SecurityOnion", "build_target"]
