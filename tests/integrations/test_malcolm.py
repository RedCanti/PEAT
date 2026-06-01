"""
Tests for the Malcolm integration wrapper.

These exercise URL normalization, the saved-objects import endpoint
construction, and the dashboard-import success handling without touching a live
Malcolm instance.
"""

import json
from contextlib import contextmanager

from peat.integrations import Malcolm
from peat.protocols import HTTP


class _FakeResp:
    """Minimal stand-in for a requests.Response."""

    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> dict:
        return self._payload


class _FakeSession:
    """Records POST calls and returns a canned response."""

    def __init__(self, resp: _FakeResp) -> None:
        self._resp = resp
        self.calls: list[tuple[str, dict]] = []

    def post(self, url: str, **kwargs) -> _FakeResp:
        self.calls.append((url, kwargs))
        return self._resp


def _patch_session(monkeypatch, resp: _FakeResp) -> _FakeSession:
    """Patch HTTP.gen_session() so import_dashboard talks to a fake server."""
    sess = _FakeSession(resp)

    @contextmanager
    def fake_gen_session(*_a, **_k):
        yield sess

    monkeypatch.setattr(HTTP, "gen_session", fake_gen_session)
    return sess


def test_normalize_url_adds_opensearch_path():
    # Bare base URL gets the OpenSearch path appended
    assert (
        Malcolm._normalize_url("https://malcolm.example.com/")
        == "https://malcolm.example.com/mapi/opensearch/"
    )


def test_normalize_url_preserves_userinfo():
    assert (
        Malcolm._normalize_url("https://user:pass@malcolm.example.com/")
        == "https://user:pass@malcolm.example.com/mapi/opensearch/"
    )


def test_normalize_url_no_op_when_path_present():
    url = "https://malcolm.example.com/mapi/opensearch/"
    assert Malcolm._normalize_url(url) == url


def test_normalize_url_no_op_when_path_present_no_trailing_slash():
    # Should NOT double-add the path if the user already gave it
    url = "https://malcolm.example.com/mapi/opensearch"
    assert Malcolm._normalize_url(url) == url


def test_malcolm_marks_self_as_opensearch():
    m = Malcolm("https://malcolm.example.com/")
    assert m.is_opensearch
    assert m.type == "OpenSearch"


def test_saved_objects_url_strips_opensearch_path():
    m = Malcolm("https://malcolm.example.com/")
    # The import API is OpenSearch Dashboards' REST endpoint under /dashboards,
    # not the /mapi/opensearch data proxy.
    assert (
        m._saved_objects_url()
        == "https://malcolm.example.com/dashboards/api/saved_objects/_import"
    )


def test_saved_objects_url_with_userinfo():
    m = Malcolm("https://user:pass@malcolm.example.com/")
    # unsafe_url retains creds; saved-objects URL should too so requests can auth
    assert (
        m._saved_objects_url()
        == "https://user:pass@malcolm.example.com/dashboards/api/saved_objects/_import"
    )


def test_import_dashboard_success(monkeypatch, tmp_path):
    bundle = tmp_path / "dash.ndjson"
    bundle.write_text('{"type":"index-pattern","id":"x"}\n', encoding="utf-8")
    sess = _patch_session(monkeypatch, _FakeResp(200, {"success": True, "successCount": 9}))

    m = Malcolm("https://user:pass@malcolm.example.com/")
    assert m.import_dashboard(bundle) is True

    # It must POST to the OpenSearch Dashboards endpoint with the osd-xsrf header.
    url, kwargs = sess.calls[0]
    assert url.endswith("/dashboards/api/saved_objects/_import")
    assert "osd-xsrf" in kwargs["headers"]


def test_import_dashboard_rejects_200_wrapped_error(monkeypatch, tmp_path):
    # Malcolm's nginx answers an unknown route with HTTP 200 wrapping a JSON 404
    # body that has no "success" key -- this must NOT be treated as a success.
    bundle = tmp_path / "dash.ndjson"
    bundle.write_text('{"type":"index-pattern","id":"x"}\n', encoding="utf-8")
    _patch_session(monkeypatch, _FakeResp(200, {"error": "NotFound: 404 Not Found"}))

    m = Malcolm("https://malcolm.example.com/")
    assert m.import_dashboard(bundle) is False


def test_import_dashboard_surfaces_object_errors(monkeypatch, tmp_path):
    # A real OSD response can report success=True overall while individual
    # objects failed; treat any per-object errors as an import failure.
    bundle = tmp_path / "dash.ndjson"
    bundle.write_text('{"type":"index-pattern","id":"x"}\n', encoding="utf-8")
    _patch_session(
        monkeypatch,
        _FakeResp(200, {"success": True, "successCount": 0, "errors": [{"id": "x"}]}),
    )

    m = Malcolm("https://malcolm.example.com/")
    assert m.import_dashboard(bundle) is False


def test_import_dashboard_missing_file(monkeypatch, tmp_path):
    # A non-existent bundle should fail fast without ever opening a session.
    sess = _patch_session(monkeypatch, _FakeResp(200, {"success": True}))

    m = Malcolm("https://malcolm.example.com/")
    assert m.import_dashboard(tmp_path / "nope.ndjson") is False
    assert sess.calls == []
