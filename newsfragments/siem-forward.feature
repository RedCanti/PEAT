Added ``peat forward`` subcommand and the :mod:`peat.integrations` package for
shipping a saved PEAT run into Security Onion or Malcolm without re-collecting
from devices. Security Onion documents are pushed straight to its Elasticsearch
API, with four auth modes (none, basic, apikey, mTLS) and ECS field enrichment
(``event.dataset``, ``event.module``, ``event.kind``, ``data_stream.*``) so PEAT
data is visible in Hunt and Dashboards. Malcolm support auto-normalizes the
``/mapi/opensearch`` proxy path and exposes a saved-objects dashboard importer.
