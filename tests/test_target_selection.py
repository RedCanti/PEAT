"""
Tests for live-upload target selection (peat.init._select_upload_target).

Covers the precedence rules: a target named on the command line wins over one
that only appears in a config file, and within each source the order is
Security Onion > Malcolm > Elastic.
"""

from peat.init import _select_upload_target


def _candidates(so=None, malcolm=None, elastic=None):
    return (
        ("security_onion", "so_server", so),
        ("malcolm", "malcolm_server", malcolm),
        ("elastic", "elastic_server", elastic),
    )


def test_none_configured_returns_none():
    assert _select_upload_target(_candidates(), {}) == (None, None)


def test_single_config_target_selected():
    cands = _candidates(elastic="http://es:9200/")
    # Came only from config (not in cli_args) -- second pass still picks it up.
    assert _select_upload_target(cands, {}) == ("elastic", "http://es:9200/")


def test_config_only_precedence_so_over_malcolm_over_elastic():
    cands = _candidates(so="https://so:9200/", malcolm="https://m/", elastic="http://es:9200/")
    assert _select_upload_target(cands, {}) == ("security_onion", "https://so:9200/")

    cands = _candidates(malcolm="https://m/", elastic="http://es:9200/")
    assert _select_upload_target(cands, {}) == ("malcolm", "https://m/")


def test_cli_target_beats_config_target():
    # so_server is in config (both the candidate value and would-be winner),
    # but --malcolm-server was given on the CLI, so Malcolm must win.
    cands = _candidates(so="https://so:9200/", malcolm="https://m/")
    cli_args = {"malcolm_server": "https://m/"}  # only malcolm came from the CLI
    assert _select_upload_target(cands, cli_args) == ("malcolm", "https://m/")


def test_cli_elastic_beats_config_so():
    cands = _candidates(so="https://so:9200/", elastic="http://es:9200/")
    cli_args = {"elastic_server": "http://es:9200/"}
    assert _select_upload_target(cands, cli_args) == ("elastic", "http://es:9200/")


def test_cli_precedence_so_over_malcolm_when_both_on_cli():
    cands = _candidates(so="https://so:9200/", malcolm="https://m/")
    cli_args = {"so_server": "https://so:9200/", "malcolm_server": "https://m/"}
    assert _select_upload_target(cands, cli_args) == ("security_onion", "https://so:9200/")


def test_cli_arg_present_but_empty_does_not_select():
    # A falsy server value (e.g. flag absent / unset) must not be selected even
    # if the key exists in cli_args.
    cands = _candidates(malcolm="https://m/")
    cli_args = {"so_server": None}
    assert _select_upload_target(cands, cli_args) == ("malcolm", "https://m/")
