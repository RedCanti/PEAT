"""
Tests for the forward-target registry.

These verify target discovery and builder dispatch without contacting a live
SIEM (constructing the wrappers does not open a connection).
"""

import pytest

from peat import PeatError, config
from peat.elastic import Elastic
from peat.integrations import Malcolm, SecurityOnion, build_target, target_names


def test_target_names_are_registered():
    assert target_names() == ["elastic", "malcolm", "security_onion"]


def test_build_elastic_returns_bare_elastic():
    inst = build_target("elastic", "https://es.example.com/")
    # Exactly Elastic, not a subclass
    assert type(inst) is Elastic
    assert inst.safe_url


def test_build_malcolm_applies_url_normalization():
    inst = build_target("malcolm", "https://malcolm.example.com/")
    assert isinstance(inst, Malcolm)
    assert inst.type == "OpenSearch"
    assert inst.unsafe_url.endswith("/mapi/opensearch/")


def test_build_security_onion_honors_url_override():
    inst = build_target("security_onion", "https://so.example.com/")
    assert isinstance(inst, SecurityOnion)
    assert "so.example.com" in inst.safe_url


def test_build_unknown_target_raises():
    with pytest.raises(PeatError, match="Unknown forward target"):
        build_target("not-a-real-target")


def test_build_elastic_requires_server_url():
    # With no override and no configured server, the builder should refuse.
    # ELASTIC_SERVER is a SettingsManager-managed field, so save/restore by
    # assignment rather than mock (whose teardown can't delattr it).
    original = config.ELASTIC_SERVER
    config.ELASTIC_SERVER = ""
    try:
        with pytest.raises(PeatError, match="ELASTIC_SERVER"):
            build_target("elastic")
    finally:
        config.ELASTIC_SERVER = original


def test_build_elastic_injects_configured_credentials():
    # Configured ELASTIC_USER/PASSWORD are folded into the URL's userinfo.
    orig_user, orig_pw = config.ELASTIC_USER, config.ELASTIC_PASSWORD
    config.ELASTIC_USER = "alice"
    config.ELASTIC_PASSWORD = "s3cret"
    try:
        inst = build_target("elastic", "https://es.example.com:9200/")
        assert inst.unsafe_url == "https://alice:s3cret@es.example.com:9200/"
        # Credentials must not leak into the safe (loggable) URL.
        assert "alice" not in inst.safe_url
        assert "s3cret" not in inst.safe_url
    finally:
        config.ELASTIC_USER = orig_user
        config.ELASTIC_PASSWORD = orig_pw


def test_url_embedded_credentials_beat_config():
    # An explicit user:pass@ in the override URL wins over configured creds.
    orig_user, orig_pw = config.ELASTIC_USER, config.ELASTIC_PASSWORD
    config.ELASTIC_USER = "alice"
    config.ELASTIC_PASSWORD = "s3cret"
    try:
        inst = build_target("elastic", "https://bob:hunter2@es.example.com:9200/")
        assert inst.unsafe_url == "https://bob:hunter2@es.example.com:9200/"
    finally:
        config.ELASTIC_USER = orig_user
        config.ELASTIC_PASSWORD = orig_pw


def test_build_malcolm_injects_credentials_with_path_normalization():
    orig_user, orig_pw = config.MALCOLM_USER, config.MALCOLM_PASSWORD
    config.MALCOLM_USER = "analyst"
    config.MALCOLM_PASSWORD = "p@ss"
    try:
        inst = build_target("malcolm", "https://malcolm.example.com/")
        # Credentials injected AND the /mapi/opensearch path appended.
        assert inst.unsafe_url == ("https://analyst:p%40ss@malcolm.example.com/mapi/opensearch/")
        assert "analyst" not in inst.safe_url
    finally:
        config.MALCOLM_USER = orig_user
        config.MALCOLM_PASSWORD = orig_pw


def test_build_malcolm_falls_back_to_elastic_credentials():
    orig_mu, orig_mp = config.MALCOLM_USER, config.MALCOLM_PASSWORD
    orig_eu, orig_ep = config.ELASTIC_USER, config.ELASTIC_PASSWORD
    config.MALCOLM_USER = None
    config.MALCOLM_PASSWORD = None
    config.ELASTIC_USER = "shared"
    config.ELASTIC_PASSWORD = "secret"
    try:
        inst = build_target("malcolm", "https://malcolm.example.com/")
        assert inst.unsafe_url.startswith("https://shared:secret@malcolm.example.com")
    finally:
        config.MALCOLM_USER = orig_mu
        config.MALCOLM_PASSWORD = orig_mp
        config.ELASTIC_USER = orig_eu
        config.ELASTIC_PASSWORD = orig_ep


def test_build_security_onion_injects_credentials():
    orig_user, orig_pw = config.SO_USER, config.SO_PASSWORD
    config.SO_USER = "so_elastic"
    config.SO_PASSWORD = "pa#ss?word"
    try:
        inst = build_target("security_onion", "https://so.example.com:9200/")
        assert inst.unsafe_url == ("https://so_elastic:pa%23ss%3Fword@so.example.com:9200/")
        assert "so_elastic" not in inst.safe_url
        assert "pa#ss?word" not in inst.unsafe_url  # raw special chars encoded
    finally:
        config.SO_USER = orig_user
        config.SO_PASSWORD = orig_pw
