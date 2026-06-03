Added named SIEM integration profiles: define several targets (even multiple of
the same type) under an ``integrations`` config section and select one on a live
``scan``/``pull``/``parse`` run with ``--integration <name>``. ``--integration``
also accepts a bare target type (``security_onion``/``malcolm``/``elastic``) and
takes precedence over the flat ``--*-server`` options and config-file defaults.
