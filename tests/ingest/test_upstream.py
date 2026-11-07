import email.message
import io
import json
import urllib.error

import pytest

from stig_mcp import github_auth, tls
from stig_mcp.ingest import upstream


class _Opener:
    """Stands in for urllib.request.urlopen: bytes, a response object, or an exception to raise."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.requested = []

    def __call__(self, request, timeout=None):
        self.requested.append(request.full_url)
        body = self.bodies[request.full_url]
        if isinstance(body, Exception):
            raise body
        return io.BytesIO(body)


def _index(*versions):
    """An index.json body listing Enterprise versions in exactly the order given."""
    return {
        "collections": [
            {"name": "Mobile ATT&CK", "versions": [{"version": "99.0", "url": "https://example.invalid/x"}]},
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": v,
                        "url": f"{upstream.ATTACK_URL_PREFIX}master/enterprise-attack/enterprise-attack-{v}.json",
                        "modified": f"2026-0{i + 1}-15T14:00:00.188Z",
                    }
                    for i, v in enumerate(versions)
                ],
            },
        ]
    }


def test_parse_attack_index__lower_version_listed_first__picks_the_numerically_highest():
    # Listed low to high so "take the first entry" (what the live file happens to allow) fails.
    parsed = upstream.parse_attack_index(_index("9.0", "16.1", "19.2"))
    assert parsed.latest.version == "19.2"
    assert parsed.latest.url.endswith("enterprise-attack-19.2.json")


def test_parse_attack_index__release_dates__keyed_by_version_as_date_part():
    parsed = upstream.parse_attack_index(_index("16.1", "19.2"))
    assert parsed.release_dates == {"16.1": "2026-01-15", "19.2": "2026-02-15"}


def test_parse_attack_index__malformed_version_entry__is_skipped_not_fatal():
    doc = _index("19.1")
    doc["collections"][1]["versions"].append({"version": "20.0; rm -rf", "url": "https://example.invalid"})
    assert upstream.parse_attack_index(doc).latest.version == "19.1"


def test_parse_attack_index__no_version_entry_in_major_minor_form__raises_upstream_error():
    doc = _index()
    doc["collections"][1]["versions"] = [{"version": "20.0; rm -rf", "url": "https://example.invalid"}]
    with pytest.raises(upstream.UpstreamError, match="MAJOR.MINOR"):
        upstream.parse_attack_index(doc)


def test_parse_attack_index__no_enterprise_collection__raises_upstream_error():
    with pytest.raises(upstream.UpstreamError, match="Enterprise ATT&CK"):
        upstream.parse_attack_index({"collections": []})


def test_version_key__two_digit_minor_and_major__orders_numerically():
    assert upstream.version_key("9.0") < upstream.version_key("16.1") < upstream.version_key("16.10")


def test_date_part__not_a_date__returns_none():
    assert upstream.date_part("yesterday") is None
    assert upstream.date_part(None) is None


def test_attack_latest__served_index__requests_only_the_index_url():
    opener = _Opener({upstream.ATTACK_INDEX_URL: json.dumps(_index("19.1", "19.2")).encode()})
    assert upstream.attack_latest(opener).latest.version == "19.2"
    assert opener.requested == [upstream.ATTACK_INDEX_URL]


def test_get_json__not_json__raises_upstream_error_naming_the_url():
    opener = _Opener({upstream.ATTACK_INDEX_URL: b"<html>rate limited</html>"})
    with pytest.raises(upstream.UpstreamError, match="index.json"):
        upstream.get_json(upstream.ATTACK_INDEX_URL, opener)


def _dir(name):
    return {"name": name, "type": "dir", "sha": "0" * 40}


def test_parse_ctid_listing__newest_folder_listed_first__still_picks_the_highest_version():
    # Newest first so "take the last entry" fails; a stray file and a non-matching dir are ignored.
    listing = [_dir("attack-16.1"), _dir("attack-9.0"), {"name": "README.md", "type": "file"}, _dir("drafts")]
    release = upstream.parse_ctid_listing(listing)
    assert release.attack_version == "16.1"
    assert release.folder == "attack-16.1"
    assert release.url == upstream.CTID_FILE_URL.format(folder="attack-16.1")


def test_parse_ctid_listing__no_attack_folder__raises_upstream_error():
    with pytest.raises(upstream.UpstreamError, match="attack-"):
        upstream.parse_ctid_listing([_dir("drafts")])


def test_parse_catalog_listing__catalog_present__returns_its_blob_sha():
    sha = "81c55f5c652bf2c6ccd5de0afe3ebe4618c6af91"
    listing = [
        {"name": "other.json", "type": "file", "sha": "1" * 40},
        {"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": sha},
    ]
    assert upstream.parse_catalog_listing(listing) == sha


def test_parse_catalog_listing__catalog_missing__raises_upstream_error_naming_it():
    with pytest.raises(upstream.UpstreamError, match=upstream.CATALOG_FILE_NAME):
        upstream.parse_catalog_listing([])


def test_git_blob_sha__known_content__matches_git_hash_object(tmp_path):
    # `printf 'hello\n' | git hash-object --stdin` prints this value.
    path = tmp_path / "f"
    path.write_bytes(b"hello\n")
    assert upstream.git_blob_sha(path) == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_ctid_latest__served_listing__sends_the_github_accept_header():
    seen = {}

    def opener(request, timeout=None):
        seen["accept"] = request.get_header("Accept")
        return io.BytesIO(json.dumps([_dir("attack-16.1")]).encode())

    assert upstream.ctid_latest(opener).attack_version == "16.1"
    assert seen["accept"] == upstream.GITHUB_ACCEPT


def test_catalog_state__served_listing__sends_the_github_accept_header():
    seen = {}
    sha = "81c55f5c652bf2c6ccd5de0afe3ebe4618c6af91"

    def opener(request, timeout=None):
        seen["accept"] = request.get_header("Accept")
        return io.BytesIO(json.dumps([{"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": sha}]).encode())

    assert upstream.catalog_state(opener) == sha
    assert seen["accept"] == upstream.GITHUB_ACCEPT


class _Reached(Exception):
    """Raised by the patched tls opener, so reaching it is observable."""


def _refusing_opener(*_handlers):
    def open_url(request, timeout=None):
        raise _Reached(request.full_url)

    return open_url


def test_get_json__no_opener_given__opens_through_the_truststore_opener(monkeypatch):
    monkeypatch.setattr(tls, "opener", _refusing_opener)
    with pytest.raises(_Reached, match="attack-stix-data"):
        upstream.get_json(upstream.ATTACK_INDEX_URL)


class _Recorder:
    def __init__(self, body=b"[]", error=None):
        self.body = body
        self.error = error
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return io.BytesIO(self.body)


def _http_error(url, code, headers=None):
    message = email.message.Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return urllib.error.HTTPError(url, code, "error", message, None)


def test_ctid_latest__github_token_set__sends_it_to_the_api(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    recorder = _Recorder(json.dumps([{"name": "attack-16.1", "type": "dir"}]).encode())
    upstream.ctid_latest(recorder)
    assert recorder.requests[0].get_header("Authorization") == "Bearer t0k"


def test_attack_latest__github_token_set__sends_no_authorization_to_raw_githubusercontent(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    recorder = _Recorder(json.dumps(_index("16.1")).encode())
    upstream.attack_latest(recorder)
    assert not recorder.requests[0].has_header("Authorization")


def test_get_json__github_token_unset__sends_exactly_the_original_headers(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    recorder = _Recorder()
    upstream.get_json(upstream.CTID_LISTING_URL, recorder, accept=upstream.GITHUB_ACCEPT)
    assert sorted(recorder.requests[0].header_items()) == [
        ("Accept", upstream.GITHUB_ACCEPT),
        ("User-agent", upstream.USER_AGENT),
    ]


def test_get_json__no_opener_given__opens_with_the_auth_stripping_redirect_handler(monkeypatch):
    seen = []

    def fake_opener(*handlers):
        seen.extend(handlers)
        return _Recorder()

    monkeypatch.setattr(tls, "opener", fake_opener)
    upstream.get_json(upstream.CTID_LISTING_URL)
    assert [type(handler) for handler in seen] == [github_auth.StripAuthOffApi]


def test_get_json__rate_limited_without_token__names_github_token_once(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    error = _http_error(upstream.CTID_LISTING_URL, 403, {"X-RateLimit-Remaining": "0"})
    with pytest.raises(upstream.UpstreamError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    message = str(excinfo.value)
    assert "Set GITHUB_TOKEN" in message
    assert message.count("unauthenticated") == 1
    assert excinfo.value.__cause__ is error


def test_get_json__rate_limited_with_token__reports_the_token_limit_not_to_set_it(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = _http_error(upstream.CTID_LISTING_URL, 429, {"X-RateLimit-Remaining": "0"})
    with pytest.raises(upstream.UpstreamError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    message = str(excinfo.value)
    assert "rate limit for your GITHUB_TOKEN is used up" in message
    assert "Set GITHUB_TOKEN" not in message
    assert "unauthenticated" not in message


def test_get_json__401_with_token__says_the_token_was_rejected(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = _http_error(upstream.CTID_LISTING_URL, 401)
    with pytest.raises(upstream.UpstreamError, match="GITHUB_TOKEN was rejected") as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert excinfo.value.__cause__ is error


def test_get_json__401_without_token__propagates_unchanged(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    error = _http_error(upstream.CTID_LISTING_URL, 401)
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert excinfo.value is error


@pytest.mark.parametrize("code", [404, 500])
def test_get_json__other_http_error__propagates_unchanged(monkeypatch, code):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = _http_error(upstream.CTID_LISTING_URL, code)
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert excinfo.value is error


def test_get_json__forbidden_without_rate_limit_header__propagates_unchanged(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = _http_error(upstream.CTID_LISTING_URL, 403, {"X-RateLimit-Remaining": "12"})
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert excinfo.value is error


def test_get_json__url_error__propagates_unchanged(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = urllib.error.URLError(OSError("refused"))
    with pytest.raises(urllib.error.URLError) as excinfo:
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert excinfo.value is error


def test_get_json__rate_limited__says_when_the_limit_resets(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790559566"}
    error = _http_error(upstream.CTID_LISTING_URL, 403, headers)
    with pytest.raises(upstream.UpstreamError, match="it resets at 2026-09-28"):
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))


def test_get_json__rate_limited_without_reset_header__says_it_resets_within_the_hour(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    error = _http_error(upstream.CTID_LISTING_URL, 403, {"X-RateLimit-Remaining": "0"})
    with pytest.raises(upstream.UpstreamError, match="it resets within the hour"):
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))


@pytest.mark.parametrize(
    ("code", "headers"),
    [(403, {"X-RateLimit-Remaining": "0"}), (401, {})],
    ids=["rate_limited", "401_with_token"],
)
def test_get_json__replaced_http_error__closes_its_body(monkeypatch, code, headers):
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    body = io.BytesIO(b"{}")
    message = email.message.Message()
    for name, value in headers.items():
        message[name] = value
    error = urllib.error.HTTPError(upstream.CTID_LISTING_URL, code, "error", message, body)
    with pytest.raises(upstream.UpstreamError):
        upstream.get_json(upstream.CTID_LISTING_URL, _Recorder(error=error))
    assert body.closed
