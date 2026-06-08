.. _siem-integrations:

*****************
SIEM integrations
*****************

PEAT ships data into analyst tooling through three target wrappers around
:class:`peat.Elastic`: a generic Elasticsearch/OpenSearch path (already
supported via ``-e``), a Malcolm wrapper that handles the ``/mapi/opensearch``
fronting proxy, and a Security Onion wrapper that adds the ECS fields
Hunt and Dashboards expect.

There are two flows: in-band push during a normal ``peat scan/pull/parse``
run (the long-standing ``-e`` behavior), and offline replay via
``peat forward``. Offline replay is the primary flow for OT operators whose
collection segment can't reach the analyst SIEM directly.

Forwarding a run
================

``peat forward`` reads the bulk-action documents PEAT writes to
``<run-dir>/elastic_data/`` and pushes them into the chosen target without
re-collecting anything. The wrapper for the chosen target applies any
required policy on top (URL normalization for Malcolm, ECS enrichment for
Security Onion).

Basic usage::

    peat forward ./peat_results/<run-dir> --target security_onion \
        --so-server https://so-manager:9200/ \
        --so-api-key id:secret --so-ca-cert /etc/so/ca.pem

    peat forward ./peat_results/<run-dir> --target malcolm \
        --malcolm-server https://user:pass@malcolm.example.com/

    peat forward ./peat_results/<run-dir> --target elastic \
        -e https://user:pass@localhost:9200/

Run ``peat forward --examples`` for more examples.

Credentials and config files
============================

Embedding ``user:pass@`` directly in a ``--*-server`` URL works, but passwords
with URL-significant characters (``@ : / ? # [ ]``) must be percent-encoded by
hand and are awkward to quote on a shell command line. Instead, supply
credentials separately and let PEAT inject them into the URL for you.

Each target has matching ``*_user`` / ``*_password`` settings:

- ``elastic_user`` / ``elastic_password`` (``--elastic-user`` / ``--elastic-password``)
- ``malcolm_user`` / ``malcolm_password`` — falls back to the ``elastic_*`` values
- ``so_user`` / ``so_password`` (used when ``so_auth=basic``)

PEAT percent-encodes these and folds them into the target URL at run time. A
``user:pass@`` already present in the URL always takes precedence, so an
explicit ``--*-server`` value is never overridden.

Because credentials are sensitive, the recommended place for them is a small,
**gitignored** config file loaded only on the run that needs it::

    peat -c peat-credentials.yaml forward ./peat_results/<run-dir> \
        --target security_onion

Copy ``examples/peat-credentials.example.yaml`` to ``peat-credentials.yaml``
(the ``peat-credentials.{yaml,yml}`` and ``.peat-credentials.*`` names are in
``.gitignore``) and fill in the targets you use. The file is an ordinary PEAT
config, so it supports the ``!ENV`` tag to pull a secret from an environment
variable at load time instead of storing it on disk:

.. code-block:: yaml

    so_server: "https://so-manager.example.com:9200/"
    so_auth: "basic"
    so_user: "so_elastic"
    so_password: !ENV "SO_PASSWORD"   # read from $SO_PASSWORD at load time

Both ``-c``/``--config-file`` and a dedicated ``--credentials-file`` (alias
``--creds-file``) can be given on the same run. The credentials file is loaded
after ``-c`` and layered on top, so its values win over the main config for
overlapping keys, and -- unlike ``-c`` -- it is never copied into the run's
metadata directory. This lets a shareable (committable) config and the secrets
it needs live in separate files::

    peat -c peat-config.yaml --credentials-file peat-credentials.yaml \
        scan 192.0.2.0/24 --integration soc-prod

Precedence, highest first: CLI flag (e.g. ``--so-password``) > ``PEAT_*``
environment variable (e.g. ``PEAT_SO_PASSWORD``) > ``--credentials-file`` value
> ``--config-file`` value. Avoid passing real passwords as CLI flags on shared
hosts, where they are visible in the process list and shell history.

Named integration profiles
===========================

The flat ``*_server`` settings describe at most one target of each type. To
define several targets at once -- including multiple of the *same* type, e.g.
two Malcolms with different credentials -- use the ``integrations`` config
section and select one by name on a live run with ``--integration <name>``.

.. code-block:: yaml

    integrations:
      job:
        type: malcolm
        server: "https://1.1.1.1/"
        user: Greg
        password: Gregpass
      soc-prod:
        type: security_onion
        server: "https://so-manager:9200/"
        auth: basic
        user: peat
        password: !ENV SO_PASSWORD
        insecure: true

::

    peat pull -d selrelay -i 192.0.2.10 --integration job -c peat-credentials.yaml

Each profile's ``type`` is a registered target (``security_onion``,
``malcolm``, ``elastic``). Its remaining fields map onto that type's settings --
``server`` → ``*_server``, ``user`` → ``*_user``, ``insecure`` → ``so_insecure``,
and so on -- so any option the flat settings accept works inside a profile too.

``--integration`` also accepts a bare target *type* (``--integration malcolm``),
which selects that type using the flat ``*_server`` settings. It takes
precedence over the flat ``--*-server`` flags and the config-file defaults.

Malcolm
=======

The :class:`peat.integrations.Malcolm` wrapper handles two Malcolm-specific
quirks:

1. **URL normalization.** Malcolm fronts its OpenSearch cluster at
   ``/mapi/opensearch``. If you pass just the base URL
   (``https://malcolm.example.com/``), PEAT auto-appends the path.
2. **Dashboard import.** PEAT ships an OpenSearch Dashboards bundle at
   ``distribution/opensearch-files/peat-malcolm-dashboard.ndjson`` that
   can be uploaded via :meth:`Malcolm.import_dashboard`.

Security Onion
==============

Authentication
--------------

Four auth modes are supported, selected by ``--so-auth``:

- ``none``: no credentials. Use only for lab deployments behind other access controls.
- ``basic``: HTTP basic auth via ``user:pass@`` in ``--so-server``.
- ``apikey``: API key in ``id:api_key`` form, passed via ``--so-api-key``.
- ``cert``: client certificate via ``--so-client-cert`` and ``--so-client-key``.

Use ``--so-ca-cert`` to point at the CA bundle that signs SO's API
certificate. ``--so-insecure`` disables verification entirely; previous PEAT
versions did this silently, but it must now be opted into explicitly.

Documents are pushed straight to Security Onion's Elasticsearch API.
``peat forward`` replays already-structured PEAT records, so there is no
benefit to routing them through SO's live Logstash ingestion pipeline.

ECS enrichment
--------------

When pushing to Security Onion, PEAT adds the following fields to every doc
(without overwriting any that are already set):

- ``event.module = "peat"``
- ``event.dataset = "<prefix>.<dataset>"`` (e.g. ``peat.configs``)
- ``event.kind`` — ``event`` for device-emitted records, ``asset`` for
  configuration/state snapshots
- ``data_stream.{type,dataset,namespace}``

The dataset suffix is derived from the index basename
(``peat-configs`` → ``configs``, ``ot-device-events`` → ``events``, …).
The prefix defaults to ``peat`` and is configurable via
``--so-dataset-prefix`` or the ``SO_DATASET_PREFIX`` setting.

Live vs. replay
---------------

The wire format is identical between live push and ``peat forward``. The
difference is timing:

- ``@timestamp`` carries the original observation time, not the ingestion
  time. Replayed docs land in the dated index for the day PEAT actually
  ran.
- Time-bounded Hunt queries and dashboards correlate fine across
  replay/live because they key on ``@timestamp``.
- **Detection rules with short lookback windows do not fire on replay.**
  Most Elastic SIEM rules use a 5–30 minute ``@timestamp`` lookback; by
  the time replayed docs arrive, that window has passed. Configure rules
  against PEAT data to schedule on ingest time, not ``@timestamp``.
- Dashboards default to "Last 15 minutes" in Kibana. For replayed runs,
  widen the time picker.

Adding a new target
===================

Targets are registered in :mod:`peat.integrations.registry`. Each entry maps a
``--target`` name to a ``"module:function"`` builder that is imported lazily, so
listing targets does not import every SIEM client library.

To add one:

1. Copy ``examples/integration_template.py`` to
   ``peat/integrations/<your_target>.py`` and adapt the wrapper class and
   ``build_target`` function. Override only the policy your SIEM needs
   (URL handling, enrichment, auth); the Elasticsearch/OpenSearch transport is
   inherited from :class:`peat.Elastic`.
2. Add one entry to ``_TARGETS`` in ``peat/integrations/registry.py``::

       "your_target": "peat.integrations.your_target:build_target",

3. Add the target's settings to ``peat/settings.py`` (e.g.
   ``YOUR_TARGET_SERVER``, ``YOUR_TARGET_USER``, ``YOUR_TARGET_PASSWORD``).
4. Optionally add ``--your-target-server`` / ``--your-target-user`` /
   ``--your-target-password`` flags to the SIEM argument group in
   ``peat/cli_args.py``. A flag's ``dest`` is uppercased and auto-loaded into
   the matching config field.

Use :func:`peat.integrations._common.inject_credentials` in ``build_target`` so
your target gets the same config-file / env-var credential handling as the
built-in targets. The template does this already.

Code documentation
==================

.. automodule:: peat.integrations
   :members:

.. automodule:: peat.integrations.malcolm
   :members:

.. automodule:: peat.integrations.security_onion
   :members:

.. automodule:: peat.integrations.forwarder
   :members:

.. automodule:: peat.api.forward_api
   :members:
