Added ``--credentials-file`` (alias ``--creds-file``) to load secrets -- SIEM
integration profiles and ``*_user``/``*_password`` settings -- from a file
separate from ``--config-file``. Both files may be given on the same run; the
credentials file is loaded after ``-c`` and layered on top, so its values win
over the main config for overlapping keys (CLI flags and ``PEAT_*`` environment
variables still take precedence over both). Unlike ``--config-file``, the
credentials file is deliberately NOT copied into the run's metadata directory,
so a shareable config and the sensitive credentials it needs can live apart.
