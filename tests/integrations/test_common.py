"""
Tests for the shared integration helpers.

These cover :func:`peat.integrations._common.inject_credentials`, which folds
configured basic-auth credentials into a target server URL.
"""

from peat.integrations._common import inject_credentials


def test_injects_user_and_password():
    url = inject_credentials("https://es.example.com:9200/", "alice", "s3cret")
    assert url == "https://alice:s3cret@es.example.com:9200/"


def test_injects_username_only():
    url = inject_credentials("https://es.example.com:9200/", "alice", None)
    assert url == "https://alice@es.example.com:9200/"


def test_noop_when_username_falsy():
    base = "https://es.example.com:9200/"
    assert inject_credentials(base, None, "s3cret") == base
    assert inject_credentials(base, "", "s3cret") == base


def test_existing_url_credentials_win():
    # An explicit user:pass@ in the URL must never be overridden.
    base = "https://bob:hunter2@es.example.com:9200/"
    assert inject_credentials(base, "alice", "s3cret") == base


def test_percent_encodes_special_characters():
    # The motivating case: passwords with URL-significant characters must be
    # encoded so they survive in the userinfo and decode back correctly.
    pw = "qK9hK([grt(.6?BBDk#,Hp|)~B"
    url = inject_credentials("https://so-manager:9200/", "so_elastic", pw)

    # Special chars are percent-encoded, not left raw in the authority.
    assert "#" not in url.split("@", 1)[0].replace("%23", "")
    assert "?" not in url.split("@", 1)[0].replace("%3F", "")
    assert url.startswith("https://so_elastic:")
    assert url.endswith("@so-manager:9200/")

    # And it round-trips: urlsplit + unquote recovers the original password,
    # mirroring what the ES client / requests do.
    from urllib.parse import unquote, urlsplit

    parts = urlsplit(url)
    assert unquote(parts.password) == pw
    assert unquote(parts.username) == "so_elastic"


def test_preserves_path_query_and_fragment():
    url = inject_credentials("https://host.example.com/mapi/opensearch/?x=1#frag", "u", "p")
    assert url == "https://u:p@host.example.com/mapi/opensearch/?x=1#frag"


def test_encodes_username_special_characters():
    url = inject_credentials("https://host:9200/", "user@domain", "pw")
    assert url == "https://user%40domain:pw@host:9200/"
