import email.message
import hashlib
import http.client
import ssl
import urllib.error
import urllib.request

import pytest

from stig_mcp.kb import releases
from stig_mcp.kb.releases import ReleaseError
from tests.kb.fake_github import FakeGitHub, http_error


def _asset(tag, name, size=10):
    return {"name": name, "size": size, "browser_download_url": f"{releases.DOWNLOAD_PREFIX}{tag}/{name}"}


def _entry(tag, schema="6", draft=False, prerelease=False, extra=()):
    date = tag.removeprefix("kb-")
    names = [f"stig_kb-schema{schema}-{date}.sqlite.xz", "SHA256SUMS", "release.json", *extra]
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": [_asset(tag, n) for n in names]}


def test_parse_listing__published_kb_release__reads_tag_date_schema_and_assets():
    [release] = releases.parse_listing([_entry("kb-2026-10-04")])
    assert (release.tag, release.date, release.schema) == ("kb-2026-10-04", "2026-10-04", "6")
    assert release.kb_asset == "stig_kb-schema6-2026-10-04.sqlite.xz"
    assert release.sqlite_name == "stig_kb-schema6-2026-10-04.sqlite"
    assert release.url("SHA256SUMS") == f"{releases.DOWNLOAD_PREFIX}kb-2026-10-04/SHA256SUMS"


def test_parse_listing__package_release_draft_and_prerelease__are_skipped():
    package = {"tag_name": "v0.2.0", "draft": False, "prerelease": False, "assets": []}
    found = releases.parse_listing(
        [
            package,
            _entry("kb-2026-10-11", draft=True),
            _entry("kb-2026-10-18", prerelease=True),
            _entry("kb-2026-10-04"),
        ]
    )
    assert [r.tag for r in found] == ["kb-2026-10-04"]


def test_parse_listing__kb_asset_dated_differently_from_its_tag__is_skipped():
    entry = _entry("kb-2026-10-04")
    entry["assets"][0] = _asset("kb-2026-10-04", "stig_kb-schema6-2026-09-27.sqlite.xz")
    assert releases.parse_listing([entry]) == []


def test_parse_listing__not_a_list__refuses():
    with pytest.raises(ReleaseError, match="list of releases"):
        releases.parse_listing({"message": "Not Found"})


def test_release_url__asset_absent__names_the_release_and_the_asset():
    entry = _entry("kb-2026-10-04")
    entry["assets"] = [a for a in entry["assets"] if a["name"] != "SHA256SUMS"]
    [release] = releases.parse_listing([entry])
    with pytest.raises(ReleaseError, match=r"kb-2026-10-04 has no SHA256SUMS"):
        release.url("SHA256SUMS")


def test_choose__several_schemas__picks_newest_compatible_and_newest_higher():
    found = releases.parse_listing(
        [
            _entry("kb-2026-10-18", schema="7"),
            _entry("kb-2026-10-11"),
            _entry("kb-2026-10-04"),
            _entry("kb-2026-09-27", schema="5"),
        ]
    )
    choice = releases.choose(found, "6")
    assert choice.compatible.tag == "kb-2026-10-11"
    assert choice.newer_schema.tag == "kb-2026-10-18"


def test_choose__listing_order_puts_the_older_release_first__still_picks_by_date():
    found = releases.parse_listing([_entry("kb-2026-10-04"), _entry("kb-2026-10-11")])
    assert releases.choose(found, "6").compatible.tag == "kb-2026-10-11"


def test_choose__tag_given__picks_exactly_that_release():
    found = releases.parse_listing([_entry("kb-2026-10-11"), _entry("kb-2026-10-04")])
    choice = releases.choose(found, "6", tag="kb-2026-10-04")
    assert choice.compatible.tag == "kb-2026-10-04"


def test_choose__nothing_for_this_schema__returns_no_compatible_release():
    found = releases.parse_listing([_entry("kb-2026-10-11", schema="5")])
    assert releases.choose(found, "6") == releases.Choice(compatible=None, newer_schema=None)


def test_parse_sums__sha256sum_format__maps_names_to_digests():
    text = f"{'a' * 64}  stig_kb-schema6-2026-10-04.sqlite.xz\n{'b' * 64} *stig_kb-schema6-2026-10-04.sqlite\n"
    assert releases.parse_sums(text) == {
        "stig_kb-schema6-2026-10-04.sqlite.xz": "a" * 64,
        "stig_kb-schema6-2026-10-04.sqlite": "b" * 64,
    }


def test_parse_sums__malformed_line__refuses():
    with pytest.raises(ReleaseError, match="SHA256SUMS"):
        releases.parse_sums("not a checksum line\n")


def test_parse_sums__blank_line_between_entries__is_skipped():
    text = f"{'a' * 64}  stig_kb-schema6-2026-10-04.sqlite.xz\n\n{'b' * 64} *stig_kb-schema6-2026-10-04.sqlite\n"
    assert releases.parse_sums(text) == {
        "stig_kb-schema6-2026-10-04.sqlite.xz": "a" * 64,
        "stig_kb-schema6-2026-10-04.sqlite": "b" * 64,
    }


def test_parse_release_json__well_formed__keeps_the_contract_fields():
    [release] = releases.parse_listing([_entry("kb-2026-10-04")])
    doc = {
        "schema": "6",
        "built_with": "0.2.0",
        "sha256": {"xz": "a" * 64, "sqlite": "b" * 64},
        "upstream": {"attack": "19.2", "stig_library": "U_SRG-STIG_Library_July_2026.zip", "loose_stigs": 3},
        "ignored": True,
    }
    assert releases.parse_release_json(doc, release) == {
        "schema": "6",
        "built_with": "0.2.0",
        "sha256": {"xz": "a" * 64, "sqlite": "b" * 64},
        "upstream": {"attack": "19.2", "stig_library": "U_SRG-STIG_Library_July_2026.zip", "loose_stigs": 3},
    }


def test_parse_release_json__schema_disagrees_with_the_asset_name__refuses():
    [release] = releases.parse_listing([_entry("kb-2026-10-04")])
    doc = {"schema": "7", "built_with": "0.2.0", "sha256": {"xz": "a" * 64, "sqlite": "b" * 64}, "upstream": {}}
    with pytest.raises(ReleaseError, match="release.json"):
        releases.parse_release_json(doc, release)


def test_parse_release_json__built_with_has_a_stray_character__refuses():
    [release] = releases.parse_listing([_entry("kb-2026-10-04")])
    doc = {"schema": "6", "built_with": "0.2.0 ", "sha256": {"xz": "a" * 64, "sqlite": "b" * 64}, "upstream": {}}
    with pytest.raises(ReleaseError, match="release.json"):
        releases.parse_release_json(doc, release)


def test_parse_release_json__sha256_is_not_a_mapping__refuses():
    [release] = releases.parse_listing([_entry("kb-2026-10-04")])
    doc = {"schema": "6", "built_with": "0.2.0", "sha256": "not-a-mapping", "upstream": {}}
    with pytest.raises(ReleaseError, match="release.json"):
        releases.parse_release_json(doc, release)


def test_list_releases__published_release__reads_the_listing_url():
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    assert [r.tag for r in releases.list_releases(github)] == ["kb-2026-10-04"]
    assert github.requested == [releases.LISTING_URL]


def test_list_releases__tag_given__reads_only_that_release():
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"old")
    github.publish("kb-2026-10-11", b"new")
    assert [r.tag for r in releases.list_releases(github, tag="kb-2026-10-04")] == ["kb-2026-10-04"]
    assert github.requested == [releases.TAG_URL.format(tag="kb-2026-10-04")]


def test_list_releases__tag_not_of_the_kb_form__refuses_before_any_request():
    github = FakeGitHub()
    with pytest.raises(ReleaseError, match="kb-YYYY-MM-DD"):
        releases.list_releases(github, tag="v0.2.0")
    assert github.requested == []


def test_list_releases__pinned_tag_not_found__says_so_and_how_to_recover():
    github = FakeGitHub()
    with pytest.raises(ReleaseError, match=r"No published release kb-2026-10-04.*check_sources"):
        releases.list_releases(github, tag="kb-2026-10-04")


def test_list_releases__tag_lookup_answers_a_non_404_error__propagates_it_unchanged():
    github = FakeGitHub()
    url = releases.TAG_URL.format(tag="kb-2026-10-04")
    github.bodies[url] = http_error(url, 500)
    with pytest.raises(ReleaseError, match="HTTP 500"):
        releases.list_releases(github, tag="kb-2026-10-04")


def test_list_releases__repository_private_or_absent__says_404_and_how_to_build_locally():
    github = FakeGitHub()
    github.bodies.pop(releases.LISTING_URL)
    with pytest.raises(ReleaseError, match=r"HTTP 404.*stig-mcp-fetch"):
        releases.list_releases(github)


def test_metadata__published_release__returns_the_parsed_release_json():
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes", built_with="0.2.0", upstream={"attack": "19.2"})
    [release] = releases.list_releases(github)
    meta = releases.metadata(release, github)
    assert meta["built_with"] == "0.2.0"
    assert meta["upstream"] == {"attack": "19.2"}


def test_download_to__asset__writes_it_and_returns_its_sha256(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    dest = tmp_path / "x.xz"
    digest = releases.download_to(release.url(release.kb_asset), dest, github)
    assert digest == hashlib.sha256(dest.read_bytes()).hexdigest()


def test_checksums__published_release__matches_the_downloaded_assets_digest(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    digest = releases.download_to(release.url(release.kb_asset), tmp_path / "x.xz", github)
    sums = releases.checksums(release, github)
    assert sums[release.kb_asset] == digest


def test_list_releases__body_is_not_json__refuses():
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = b"not json"
    with pytest.raises(ReleaseError, match="did not return JSON"):
        releases.list_releases(github)


def test_default_opener__builds_an_opener_with_the_allowlist_redirect_handler():
    opener = releases.default_opener()
    handlers = opener.__self__.handlers
    assert any(isinstance(handler, releases._AllowlistRedirects) for handler in handlers)


def test_default_opener__redirect_within_the_allowlist__follows_it():
    handler = releases._AllowlistRedirects()
    request = urllib.request.Request("https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x")
    newurl = "https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/y"
    result = handler.redirect_request(request, None, 302, "Found", {}, newurl)
    assert result.full_url == newurl


class _DroppedMidStream:
    """A response whose headers arrived but whose body read fails, like a reset connection."""

    def __init__(self, url):
        self._url = url

    def geturl(self):
        return self._url

    def read(self, size):
        raise OSError("connection reset")

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_download_to__connection_drops_mid_stream__is_reported_via_explain(tmp_path):
    url = releases.DOWNLOAD_PREFIX + "kb-2026-10-04/x"

    def dropping_opener(request, timeout=None):
        return _DroppedMidStream(request.full_url)

    with pytest.raises(ReleaseError, match="Could not reach"):
        releases.download_to(url, tmp_path / "x", dropping_opener)


class _IncompleteReadStream:
    """A response whose body read raises an http.client exception, not an OSError."""

    def __init__(self, url):
        self._url = url

    def geturl(self):
        return self._url

    def read(self, size):
        raise http.client.IncompleteRead(b"abc", 100)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_download_to__body_read_raises_an_http_client_exception__is_reported_via_explain(tmp_path):
    url = releases.DOWNLOAD_PREFIX + "kb-2026-10-04/x"

    def incomplete_opener(request, timeout=None):
        return _IncompleteReadStream(request.full_url)

    with pytest.raises(ReleaseError) as excinfo:
        releases.download_to(url, tmp_path / "x", incomplete_opener)
    assert str(excinfo.value).endswith(releases.OFFLINE)


def test_list_releases__opener_itself_raises_an_http_client_exception__is_reported_via_explain():
    # The other catch site: the failure happens opening the connection, in _open, not in
    # _stream's body read.
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = http.client.BadStatusLine("garbage")
    with pytest.raises(ReleaseError) as excinfo:
        releases.list_releases(github)
    assert str(excinfo.value).endswith(releases.OFFLINE)


class _TimesOutMidRead:
    """A bare TimeoutError raised from read(), not wrapped in URLError, like a real socket
    timeout after headers arrived."""

    def __init__(self, url):
        self._url = url

    def geturl(self):
        return self._url

    def read(self, size):
        raise TimeoutError("timed out")

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_download_to__read_times_out_mid_stream__says_timed_out_not_could_not_reach(tmp_path):
    url = releases.DOWNLOAD_PREFIX + "kb-2026-10-04/x"

    def timing_out_opener(request, timeout=None):
        return _TimesOutMidRead(request.full_url)

    with pytest.raises(ReleaseError, match="timed out") as excinfo:
        releases.download_to(url, tmp_path / "x", timing_out_opener)
    # str(TimeoutError("timed out")) already contains "timed out", so the match above would
    # pass even without the isinstance(reason, TimeoutError) branch; this pins the branch itself.
    assert "Could not reach" not in str(excinfo.value)


def test_download_to__sink_write_fails__names_the_destination_not_the_host(tmp_path, monkeypatch):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    url = release.url(release.kb_asset)
    dest = tmp_path / "x.xz"
    real_open = open

    class _FailingFile:
        def __init__(self, handle):
            self._handle = handle

        def write(self, data):
            raise OSError(28, "No space left on device")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self._handle.close()
            return False

    monkeypatch.setattr(releases, "open", lambda path, mode: _FailingFile(real_open(path, mode)), raising=False)

    with pytest.raises(ReleaseError) as excinfo:
        releases.download_to(url, dest, github)
    message = str(excinfo.value)
    assert str(dest) in message
    assert "No space left on device" in message
    assert "Could not reach" not in message
    assert releases.OFFLINE not in message


def test_download_to__body_of_exactly_the_cap__succeeds_but_one_byte_more_is_refused(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    url = release.url(release.kb_asset)
    cap = releases.CHUNK * 2

    github.bodies[url] = b"\0" * cap
    digest = releases.download_to(url, tmp_path / "at-cap.xz", github, cap=cap)
    assert digest == hashlib.sha256(b"\0" * cap).hexdigest()

    github.bodies[url] = b"\0" * (cap + 1)
    with pytest.raises(ReleaseError, match="cap"):
        releases.download_to(url, tmp_path / "over-cap.xz", github, cap=cap)


def test_explain__forbidden_without_rate_limit__reports_the_status_not_a_limit():
    message = releases.explain(http_error(releases.LISTING_URL, 403), releases.LISTING_URL)
    assert "HTTP 403" in message
    assert "requests per hour" not in message


def test_explain__rate_limited_with_no_reset_header__says_within_the_hour_not_at_within():
    exc = http_error(releases.LISTING_URL, 403, {"X-RateLimit-Remaining": "0"})
    message = releases.explain(exc, releases.LISTING_URL)
    assert "it resets within the hour" in message
    assert "at within the hour" not in message


def test_reset_time__gmtime_rejects_a_value_this_platform_cannot_hold__is_unknown(monkeypatch):
    # A 10-digit value never overflows gmtime on Linux; simulate a platform (e.g. Windows) whose
    # time_t range is narrower, since _reset_time's except clause exists for exactly that case.
    def raising_gmtime(value):
        raise OverflowError("timestamp out of range for platform time_t")

    monkeypatch.setattr(releases.time, "gmtime", raising_gmtime)
    assert releases._reset_time("9999999999") is None


def test_reset_time__millisecond_value__is_unknown_not_a_wrong_far_future_date():
    # 13 ASCII digits parse and gmtime accepts them without raising, but as a reset time this is
    # milliseconds, not GitHub's seconds, and would silently print a date around the year 58710
    # if the length check did not reject it first.
    assert releases._reset_time("1790559566000") is None


def test_explain__connection_times_out__says_timed_out_not_could_not_reach():
    exc = urllib.error.URLError(TimeoutError("timed out"))
    message = releases.explain(exc, releases.LISTING_URL)
    assert "timed out" in message
    assert "Could not reach" not in message


def test_explain__remote_reason_is_huge__quotes_at_most_120_characters_and_keeps_the_guidance():
    exc = urllib.error.URLError(OSError("x" * 5000))
    message = releases.explain(exc, releases.LISTING_URL)
    assert "x" * 121 not in message
    assert message.endswith(releases.OFFLINE)


def test_explain__remote_reason_is_huge__quotes_to_exactly_120_characters():
    exc = urllib.error.URLError(OSError("x" * 5000))
    message = releases.explain(exc, releases.LISTING_URL)
    assert ("x" * 117 + "...") in message
    assert ("x" * 118) not in message


def test_explain__tls_failure_with_huge_reason__quotes_to_exactly_120_characters():
    exc = urllib.error.URLError(ssl.SSLError(1, "x" * 5000))
    message = releases.explain(exc, releases.LISTING_URL)
    assert ("x" * 117 + "...") in message
    assert ("x" * 118) not in message


class _TrackedHTTPError(urllib.error.HTTPError):
    closed = False

    def close(self):
        self.closed = True
        super().close()


def test_list_releases__http_error_response__closes_its_body():
    github = FakeGitHub()
    error = _TrackedHTTPError(releases.LISTING_URL, 500, "error", email.message.Message(), None)
    github.bodies[releases.LISTING_URL] = error
    with pytest.raises(ReleaseError, match="HTTP 500"):
        releases.list_releases(github)
    assert error.closed
