import contextlib
import hashlib
import http.client
import io
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from stig_mcp import tls
from stig_mcp.ingest import catalog, config, fetch, inventory, upstream
from stig_mcp.ingest.fetch import _TARGET_FILENAMES, SOURCE_URLS, manual_sources

FIX = Path(__file__).parent.parent / "fixtures"
INDEX = (FIX / "disa_index.html").read_text()


def test_source_urls__the_three_automated_sources__are_named_and_are_https():
    assert upstream.ATTACK_INDEX_URL.startswith("https://") and upstream.CTID_LISTING_URL.startswith("https://")
    assert set(SOURCE_URLS) == {"catalog"} and SOURCE_URLS["catalog"].startswith("https://")


def test_manual_sources__the_downloads_disa_puts_behind_a_login__are_named_in_the_instructions():
    manual = " ".join(manual_sources()).lower()
    assert "cci" in manual
    assert "stig" in manual


def test_manual_sources__loose_product_stigs__are_offered_as_an_optional_third_source():
    manual = " ".join(manual_sources()).lower()
    assert "loose product stig" in manual
    assert "optional" in manual


def test_manual_sources__a_relocated_data_dir__names_that_dir_not_a_hardcoded_path(tmp_path, monkeypatch):
    # stig-mcp-fetch prints these and stig-mcp-ingest then reports config.SOURCES_DIR, so
    # both must name the same directory, including under STIG_MCP_DATA.
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "relocated" / "sources")
    manual = " ".join(manual_sources())
    assert str(config.SOURCES_DIR) in manual


def test_target_filenames__ctid_and_attack__match_ingester_expected_names():
    assert _TARGET_FILENAMES["ctid"] == "ctid_mappings.json"
    assert _TARGET_FILENAMES["attack"] == "enterprise-attack.json"


def test_fetch__imported_before_catalog_in_a_fresh_interpreter__has_no_import_cycle():
    # catalog imports require_web_url from this module, so a module-level `import catalog`
    # in fetch is a cycle that fires only when fetch is imported FIRST. Every test module
    # here imports catalog first, so no in-process test can see it, while stig-mcp-fetch
    # and `python -m stig_mcp.ingest.fetch` do exactly this on every real invocation.
    # S603: argv is sys.executable plus a literal import statement, not external input.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import stig_mcp.ingest.fetch"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _entry(name, size_bytes=5, date="10-Jul-2026", href=None):
    return catalog.Entry(name=name, href=href or name, date=date, size_bytes=size_bytes)


def _url(name):
    return urllib.parse.urljoin(catalog.INDEX_URL, name)


def _plenty(_path):
    return SimpleNamespace(total=99 * 1024**3, used=0, free=99 * 1024**3)


def _tiny(_path):
    return SimpleNamespace(total=1024, used=0, free=1024)


@pytest.fixture(autouse=True)
def _plenty_of_disk(monkeypatch):
    """fetch_disa preflights the real filesystem it is writing to. Without this every
    fetch_disa test below would pass here and fail on a machine whose tmp volume holds less
    than REQUIRED_FREE_BYTES. The preflight tests inject their own usage and are unaffected.

    This fixture disarms the guard it is describing, so the tests that must SEE the guard
    override it with their own monkeypatch: a per-test setattr wins over this one, and
    test_fetch_disa__a_volume_too_small_for_the_downloads__refuses_before_requesting_anything
    is what stops the preflight call becoming dead code.
    """
    monkeypatch.setattr(fetch.shutil, "disk_usage", _plenty)


# Derived from the buffer rather than hardcoded, because a body that fits in one read is handed
# over whole and leaves a COMPLETE file, which would make every name and comment below about
# truncation false while the tests still passed. COPY_BUFSIZE differs by platform and Python
# version, so read it at import instead of guessing. Windows 11 is a supported platform here,
# so a constant that is only large enough on Linux is a test that stops testing.
_TRUNCATING_BODY = b"\xa5" * (2 * shutil.COPY_BUFSIZE)


class _HalfBody(io.BytesIO):
    """A response that hands over one read and then drops, the way a cut connection does.

    shutil.copyfileobj has written that first chunk to the target by then, so a body longer
    than its buffer leaves a genuinely truncated file for the cleanup to remove.
    """

    def __init__(self, data):
        super().__init__(data)
        self._reads = 0

    def read(self, size=-1):
        self._reads += 1
        if self._reads > 1:
            raise OSError("connection reset mid-body")
        return super().read(size)


class _Opener:
    """Stands in for urllib.request.urlopen and records every URL asked for.

    Recording the requests is what lets a test see a skip at all: the skipped path and the
    downloaded path both end with the target in the returned list, so only the absence of a
    request distinguishes them.

    A body may be bytes, an already-built response object, or an exception to raise instead
    of answering. A body may also be a list of any of those, consumed one entry per request in
    order, for a URL a retry asks for more than once.
    """

    def __init__(self, bodies):
        self.bodies = bodies
        self.requested = []

    def __call__(self, request, timeout=None):
        self.requested.append(request.full_url)
        body = self.bodies[request.full_url]
        if isinstance(body, list):
            body = body.pop(0)
        if isinstance(body, Exception):
            raise body
        return body if isinstance(body, io.BytesIO) else io.BytesIO(body)


def test_selection__the_real_index__takes_library_sunset_cci_and_loose():
    chosen = fetch.selection(catalog.parse_index(INDEX))
    names = {e.name for e in chosen}
    assert "U_SRG-STIG_Library_July_2026.zip" in names
    assert "U_Rev_4_SRG-STIG_Sunset_Compilation.zip" in names
    assert "U_CCI_List.zip" in names
    assert "U_MS_Windows_Server_2019_V3R9_STIG.zip" in names
    assert not any("SCAP" in n for n in names)
    assert len(chosen) == len(names), "a name selected twice would be downloaded twice"


def test_selection__the_cci_near_miss_on_the_real_index__takes_only_the_u_prefixed_one():
    # The index publishes both U_CCI_List.zip (417792 bytes) and CCI_List.zip (434176).
    # An exact-name match separates them; a substring or startswith test would not.
    names = {e.name for e in fetch.selection(catalog.parse_index(INDEX))}
    assert "U_CCI_List.zip" in names
    assert "CCI_List.zip" not in names


def test_selection__an_index_with_no_sunset_and_no_cci__takes_the_library_and_the_loose_stigs():
    entries = [
        _entry("U_SRG-STIG_Library_July_2026.zip"),
        _entry("U_Foo_V1R1_STIG.zip"),
    ]
    names = [e.name for e in fetch.selection(entries)]
    assert names == ["U_SRG-STIG_Library_July_2026.zip", "U_Foo_V1R1_STIG.zip"]


def test_preflight__less_free_space_than_required__refuses_and_names_the_shortfall(tmp_path):
    def tiny(_path):
        return SimpleNamespace(total=0, used=0, free=1024)

    with pytest.raises(RuntimeError) as excinfo:
        fetch.preflight(tmp_path, [], disk_usage=tiny)
    message = str(excinfo.value)
    assert "0.0 GiB free" in message
    assert "2.0 GiB needed" in message


def test_preflight__entries_larger_than_the_floor__demands_twice_their_downloaded_size(tmp_path):
    def five_gib(_path):
        return SimpleNamespace(total=0, used=0, free=5 * 1024**3)

    with pytest.raises(RuntimeError) as excinfo:
        fetch.preflight(tmp_path, [_entry("big.zip", size_bytes=3 * 1024**3)], disk_usage=five_gib)
    assert "6.0 GiB needed" in str(excinfo.value)


def test_preflight__enough_free_space__returns_quietly(tmp_path):
    assert fetch.preflight(tmp_path, [], disk_usage=_plenty) is None


def test_manifest__written_then_read__round_trips_name_date_and_size(tmp_path):
    entries = [catalog.Entry(name="a.zip", href="a.zip", date="10-Jul-2026", size_bytes=5)]
    fetch.write_manifest(tmp_path, entries)
    stored = fetch.read_manifest(tmp_path)
    assert stored["entries"]["a.zip"]["date"] == "10-Jul-2026"
    assert stored["entries"]["a.zip"]["size_bytes"] == 5


def test_manifest__a_file_whose_length_differs_from_the_index__records_both_sizes_apart(tmp_path):
    # The index's size column is rounded, so these two are different questions: what DISA
    # advertised, and what was actually stored.
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, [_entry("a.zip", size_bytes=999)])
    stored = fetch.read_manifest(tmp_path)["entries"]["a.zip"]
    assert stored["size_bytes"] == 999
    assert stored["on_disk_bytes"] == 5
    assert stored["sha256"] == hashlib.sha256(b"12345").hexdigest()


def test_manifest__an_entry_with_no_file_on_disk__records_no_on_disk_size_and_no_digest(tmp_path):
    fetch.write_manifest(tmp_path, [_entry("a.zip")])
    stored = fetch.read_manifest(tmp_path)["entries"]["a.zip"]
    assert stored["on_disk_bytes"] is None
    assert stored["sha256"] is None


def test_manifest__a_file_longer_than_one_digest_chunk__hashes_every_chunk(tmp_path):
    # Two and a bit megabytes, so the 1 MiB read loop runs more than once. A body that fits
    # in a single chunk would pass even if the loop stopped after its first read.
    body = bytes(range(256)) * 8192 + b"tail"
    assert len(body) > 2 * 1024 * 1024
    (tmp_path / "a.zip").write_bytes(body)
    fetch.write_manifest(tmp_path, [_entry("a.zip")])
    stored = fetch.read_manifest(tmp_path)["entries"]["a.zip"]
    assert stored["sha256"] == hashlib.sha256(body).hexdigest()


def test_manifest__no_manifest_yet__reads_as_empty(tmp_path):
    assert fetch.read_manifest(tmp_path) == {"entries": {}, "public": {}}


def test_manifest__a_manifest_that_is_not_json__reads_as_empty(tmp_path):
    (tmp_path / fetch.MANIFEST_NAME).write_text("{ truncated")
    assert fetch.read_manifest(tmp_path) == {"entries": {}, "public": {}}


@pytest.mark.parametrize("body", ['{"entries": []}', "{}", "[]", '"a string"', '{"entries": {"a.zip": 5}}'])
def test_manifest__valid_json_of_the_wrong_shape__reads_as_empty_rather_than_failing_its_caller(tmp_path, body):
    # Callers are promised an "entries" dict, and fetch_disa indexes it unguarded, so a
    # manifest that parses but carries the wrong shape must not be handed back as it is.
    (tmp_path / fetch.MANIFEST_NAME).write_text(body)
    assert fetch.read_manifest(tmp_path) == {"entries": {}, "public": {}}


def test_manifest__one_unusable_row__costs_that_row_and_not_the_rest_of_the_manifest(tmp_path):
    # A row is only ever read on its own, so one bad row is one archive re-fetched. Discarding
    # the whole file for it would re-fetch the entire selection.
    (tmp_path / fetch.MANIFEST_NAME).write_text(
        json.dumps({"entries": {"a.zip": {"on_disk_bytes": 5}, "b.zip": 5, "c.zip": {"on_disk_bytes": 7}}})
    )
    stored = fetch.read_manifest(tmp_path)["entries"]
    assert set(stored) == {"a.zip", "c.zip"}
    assert stored["a.zip"]["on_disk_bytes"] == 5


def test_write_public__then_write_manifest__keeps_the_public_record(tmp_path):
    record = {"version": "19.2", "url": "https://x", "sha256": "ab", "release_date": "2026-08-05"}
    fetch.write_public(tmp_path, "attack", record)
    fetch.write_manifest(tmp_path, [])
    assert fetch.read_manifest(tmp_path)["public"] == {"attack": record}


def test_write_public__existing_entries__are_preserved(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, [_entry("a.zip")])
    fetch.write_public(tmp_path, "catalog", {"version": "5.2.0", "url": "u", "sha256": "s", "git_blob_sha": "g"})
    assert set(fetch.read_manifest(tmp_path)["entries"]) == {"a.zip"}


def test_read_manifest__malformed_public_records__drops_only_those(tmp_path):
    good = {"attack_version": "16.1", "url": "u", "sha256": "s", "attack_release_date": None}
    body = {
        "entries": {},
        "public": {"ctid": good, "attack": ["not", "a", "record"], "catalog": {"version": 5}, "evil": {"x": "y"}},
    }
    (tmp_path / fetch.MANIFEST_NAME).write_text(json.dumps(body))
    assert fetch.read_manifest(tmp_path)["public"] == {"ctid": good}


def test_read_manifest__no_public_section__returns_an_empty_one(tmp_path):
    (tmp_path / fetch.MANIFEST_NAME).write_text(json.dumps({"entries": {}}))
    assert fetch.read_manifest(tmp_path)["public"] == {}


def test_fetch_disa__a_manifest_with_one_unusable_row__refetches_only_that_entry(tmp_path):
    entries = [_entry("a.zip"), _entry("b.zip")]
    for name in ("a.zip", "b.zip"):
        (tmp_path / name).write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    body = json.loads((tmp_path / fetch.MANIFEST_NAME).read_text())
    body["entries"]["b.zip"] = "corrupted"
    (tmp_path / fetch.MANIFEST_NAME).write_text(json.dumps(body))
    opener = _Opener({_url("b.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("b.zip")]


def test_manifest__vouched_for_passed_positionally__is_refused_rather_than_taken_as_a_third_argument(tmp_path):
    # Keyword-only on purpose: the default vouches for everything, so a caller that meant to
    # narrow it and passed it positionally would silently get the opposite of what it asked.
    with pytest.raises(TypeError, match="positional"):
        fetch.write_manifest(tmp_path, [_entry("a.zip")], {"a.zip"})


def test_manifest__an_entry_the_caller_does_not_vouch_for__records_no_size_even_with_a_file_there(tmp_path):
    (tmp_path / "a.zip").write_bytes(b"12345")
    (tmp_path / "b.zip").write_bytes(b"STALE-MANUAL-COPY")
    fetch.write_manifest(tmp_path, [_entry("a.zip"), _entry("b.zip")], vouched_for={"a.zip"})
    stored = fetch.read_manifest(tmp_path)["entries"]
    assert stored["a.zip"]["on_disk_bytes"] == 5
    assert stored["a.zip"]["sha256"] == hashlib.sha256(b"12345").hexdigest()
    assert stored["b.zip"]["on_disk_bytes"] is None
    assert stored["b.zip"]["sha256"] is None
    assert stored["b.zip"]["size_bytes"] == 5


def test_manifest__written_from_a_subset_of_entries__drops_the_entries_it_was_not_given(tmp_path):
    # fetch_disa(entries=<subset>) REPLACES the manifest, it does not merge into it, so a
    # refresh must pass the full selection or merge the result itself.
    fetch.write_manifest(tmp_path, [_entry("a.zip"), _entry("b.zip")])
    fetch.write_manifest(tmp_path, [_entry("b.zip")])
    assert set(fetch.read_manifest(tmp_path)["entries"]) == {"b.zip"}


def test_manifest_name__is_ignored_by_the_ingest(tmp_path):
    # The manifest lives in sources/, which classify walks. A .json is not an artifact kind,
    # so it must not appear as one.
    (tmp_path / fetch.MANIFEST_NAME).write_text("{}")
    assert inventory.classify(tmp_path) == []


def test_fetch_disa__a_file_still_the_length_the_manifest_recorded__is_not_downloaded_again(tmp_path):
    # The index size (999) deliberately disagrees with the file's real length (5): a skip
    # that compared against the index size instead of the manifest would never fire.
    entries = [_entry("a.zip", size_bytes=999)]
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    opener = _Opener({})
    written = fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == []
    assert written == [tmp_path / "a.zip"]
    assert (tmp_path / "a.zip").read_bytes() == b"12345"


def test_fetch_disa__a_file_shorter_than_the_manifest_recorded__is_downloaded_again(tmp_path):
    entries = [_entry("a.zip")]
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    (tmp_path / "a.zip").write_bytes(b"12")
    opener = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("a.zip")]
    assert (tmp_path / "a.zip").read_bytes() == b"12345"


def test_fetch_disa__a_file_on_disk_with_no_manifest__is_downloaded_anyway(tmp_path):
    # The first run has nothing to trust, so it takes everything. Whatever is sitting in the
    # directory was not put there by the fetch, and nothing is known about its length.
    entries = [_entry("a.zip")]
    (tmp_path / "a.zip").write_bytes(b"12345")
    opener = _Opener({_url("a.zip"): b"fresh"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("a.zip")]
    assert (tmp_path / "a.zip").read_bytes() == b"fresh"


def test_fetch_disa__a_recorded_file_deleted_since__is_downloaded_again(tmp_path):
    entries = [_entry("a.zip")]
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    (tmp_path / "a.zip").unlink()
    opener = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("a.zip")]
    assert (tmp_path / "a.zip").read_bytes() == b"12345"


def test_fetch_disa__a_manifest_written_while_the_file_was_absent__downloads_it(tmp_path):
    # on_disk_bytes is None here, and the file that later appeared happens to be exactly the
    # index's advertised length, so only a None-aware comparison re-fetches it.
    entries = [_entry("a.zip", size_bytes=5)]
    fetch.write_manifest(tmp_path, entries)
    (tmp_path / "a.zip").write_bytes(b"12345")
    opener = _Opener({_url("a.zip"): b"fresh"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("a.zip")]


def test_fetch_disa__two_downloads__pauses_once_between_them(tmp_path):
    entries = [_entry("a.zip"), _entry("b.zip")]
    opener = _Opener({_url("a.zip"): b"12345", _url("b.zip"): b"12345"})
    pauses = []
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, delay=0.25, sleep=pauses.append)
    assert pauses == [0.25]


def test_fetch_disa__a_skipped_entry_before_a_download__does_not_pause_for_it(tmp_path):
    # The delay is politeness between REQUESTS. A skip makes no request, so counting it
    # would make the first real download wait for a host it has not touched yet.
    entries = [_entry("a.zip"), _entry("b.zip")]
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    opener = _Opener({_url("b.zip"): b"12345"})
    pauses = []
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, delay=0.25, sleep=pauses.append)
    assert opener.requested == [_url("b.zip")]
    assert pauses == []


def test_fetch_disa__an_entry_resolving_to_cui__refuses_before_requesting_anything(tmp_path):
    entries = [_entry("CUI_Something_V1R1_STIG.zip")]
    opener = _Opener({})
    with pytest.raises(RuntimeError, match="CUI"):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == []


def test_fetch_disa__an_href_with_a_non_web_scheme__refuses_before_requesting_anything(tmp_path):
    entries = [_entry("a.zip", href="file:///etc/passwd")]
    opener = _Opener({})
    with pytest.raises(ValueError, match="only http/https"):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == []


def test_fetch_disa__no_entries_given__reads_the_index_and_takes_what_selection_chose(tmp_path):
    index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
        '<A HREF="U_Foo_V1R0_STIG.zip">old</A> 10-Jan-2026 12:00  1k\n'
    )
    opener = _Opener(
        {
            catalog.INDEX_URL: index.encode(),
            _url("U_SRG-STIG_Library_July_2026.zip"): b"library",
            _url("U_Foo_V1R1_STIG.zip"): b"newest",
        }
    )
    written = fetch.fetch_disa(tmp_path, opener=opener, sleep=lambda _seconds: None)
    assert opener.requested[0] == catalog.INDEX_URL
    assert opener.requested[1:] == [_url("U_SRG-STIG_Library_July_2026.zip"), _url("U_Foo_V1R1_STIG.zip")]
    assert [p.name for p in written] == ["U_SRG-STIG_Library_July_2026.zip", "U_Foo_V1R1_STIG.zip"]


def test_fetch_disa__no_entries_given_and_the_index_read_resets_once__retries_it(tmp_path):
    # The index read itself can fail transiently (errno 101), not only a download.
    # fetch_disa's OWN index read (taken when entries is None) must retry it, distinct from
    # _run_refresh's separately wrapped index read.
    index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
        '<A HREF="U_Foo_V1R0_STIG.zip">old</A> 10-Jan-2026 12:00  1k\n'
    )
    opener = _Opener(
        {
            catalog.INDEX_URL: [urllib.error.URLError(OSError(101, "Network is unreachable")), index.encode()],
            _url("U_SRG-STIG_Library_July_2026.zip"): b"library",
            _url("U_Foo_V1R1_STIG.zip"): b"newest",
        }
    )
    pauses = []
    written = fetch.fetch_disa(tmp_path, opener=opener, sleep=pauses.append)
    assert opener.requested[:2] == [catalog.INDEX_URL, catalog.INDEX_URL]
    assert opener.requested[2:] == [_url("U_SRG-STIG_Library_July_2026.zip"), _url("U_Foo_V1R1_STIG.zip")]
    assert pauses[:1] == [5]
    assert [p.name for p in written] == ["U_SRG-STIG_Library_July_2026.zip", "U_Foo_V1R1_STIG.zip"]


def test_fetch_disa__a_third_run_after_a_download_and_a_skip__still_skips(tmp_path):
    # The manifest a run leaves must keep vouching for the files it SKIPPED, not only for the
    # ones it downloaded. Two runs cannot see this: the second would skip on the first run's
    # record even if it then wrote that record away, and the third is what notices.
    entries = [_entry("a.zip")]
    first = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=first, entries=entries, sleep=lambda _seconds: None)
    second = _Opener({})
    fetch.fetch_disa(tmp_path, opener=second, entries=entries, sleep=lambda _seconds: None)
    third = _Opener({})
    fetch.fetch_disa(tmp_path, opener=third, entries=entries, sleep=lambda _seconds: None)
    assert first.requested == [_url("a.zip")]
    assert second.requested == []
    assert third.requested == []


def test_fetch_disa__a_volume_too_small_for_the_downloads__refuses_before_requesting_anything(tmp_path, monkeypatch):
    # The preflight only protects a real user through this call. Tested in isolation it is
    # green whether or not fetch_disa ever calls it.
    monkeypatch.setattr(fetch.shutil, "disk_usage", _tiny)
    opener = _Opener({_url("a.zip"): b"12345"})
    with pytest.raises(RuntimeError, match="Not enough free space"):
        fetch.fetch_disa(tmp_path, opener=opener, entries=[_entry("a.zip")], sleep=lambda _seconds: None)
    assert opener.requested == []
    assert not (tmp_path / fetch.MANIFEST_NAME).exists()


def test_fetch_disa__a_selection_already_fully_downloaded__is_not_refused_for_lack_of_room(tmp_path, monkeypatch):
    # Nothing will be transferred, so there is nothing to guard and refusing would be a
    # refusal of a no-op. The volume here is far too small for the selection's nominal size.
    entries = [_entry("a.zip")]
    (tmp_path / "a.zip").write_bytes(b"12345")
    fetch.write_manifest(tmp_path, entries)
    monkeypatch.setattr(fetch.shutil, "disk_usage", _tiny)
    opener = _Opener({})
    written = fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == []
    assert written == [tmp_path / "a.zip"]


def test_fetch_disa__room_for_the_remainder_but_not_the_whole_selection__downloads_the_remainder(tmp_path, monkeypatch):
    # The preflight sizes what this run will fetch, not what the selection weighs: one 3 GiB
    # entry already on disk must not make a 5 byte download impossible.
    entries = [_entry("big.zip", size_bytes=3 * 1024**3), _entry("a.zip")]
    (tmp_path / "big.zip").write_bytes(b"cached")
    fetch.write_manifest(tmp_path, entries)
    monkeypatch.setattr(fetch.shutil, "disk_usage", lambda _path: SimpleNamespace(total=0, used=0, free=3 * 1024**3))
    opener = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == [_url("a.zip")]


def test_fetch_disa__a_download_failing_partway__records_what_arrived_and_not_what_did_not(tmp_path):
    # c.zip is never reached, and something unrelated is already sitting at its path, which is
    # exactly what manual_sources tells operators to do. Recording that file's length would
    # credit this run with a download it never made, and the real c.zip would never arrive.
    entries = [_entry("a.zip"), _entry("b.zip"), _entry("c.zip")]
    (tmp_path / "c.zip").write_bytes(b"STALE-MANUAL-COPY")
    opener = _Opener({_url("a.zip"): b"12345", _url("b.zip"): OSError("connection reset")})
    with pytest.raises(OSError, match="connection reset"):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    stored = fetch.read_manifest(tmp_path)["entries"]
    assert stored["a.zip"]["on_disk_bytes"] == 5
    assert stored["b.zip"]["on_disk_bytes"] is None
    assert stored["c.zip"]["on_disk_bytes"] is None
    assert stored["c.zip"]["sha256"] is None
    assert opener.requested == [_url("a.zip"), _url("b.zip")]


def test_fetch_disa__the_run_after_a_failure__refetches_only_what_did_not_arrive(tmp_path):
    entries = [_entry("a.zip"), _entry("b.zip"), _entry("c.zip")]
    (tmp_path / "c.zip").write_bytes(b"STALE-MANUAL-COPY")
    failing = _Opener({_url("a.zip"): b"12345", _url("b.zip"): OSError("connection reset")})
    with pytest.raises(OSError, match="connection reset"):
        fetch.fetch_disa(tmp_path, opener=failing, entries=entries, sleep=lambda _seconds: None)
    retry = _Opener({_url("b.zip"): b"bbbbb", _url("c.zip"): b"ccccc"})
    fetch.fetch_disa(tmp_path, opener=retry, entries=entries, sleep=lambda _seconds: None)
    assert retry.requested == [_url("b.zip"), _url("c.zip")]
    assert (tmp_path / "c.zip").read_bytes() == b"ccccc"


def _reset(errno=104, message="Connection reset by peer"):
    return urllib.error.URLError(ConnectionResetError(errno, message))


class _CutShortBody(io.BytesIO):
    """A response whose first read raises http.client.IncompleteRead, the way a connection cut
    partway through a body does. Distinct from _HalfBody: that one leaves a truncated file on
    disk from a completed first chunk, while this one never returns any bytes at all."""

    def read(self, size=-1):
        raise http.client.IncompleteRead(b"", 10)


def test_fetch_disa__a_download_reset_twice__retries_and_stores_the_file(tmp_path, capsys):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): [_reset(), _reset(), b"12345"]})
    pauses = []
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=pauses.append)
    assert (tmp_path / "U_Foo_V1R1_STIG.zip").read_bytes() == b"12345"
    stored = fetch.read_manifest(tmp_path)["entries"]["U_Foo_V1R1_STIG.zip"]
    assert stored["on_disk_bytes"] == 5
    assert pauses == [5, 15]
    err = capsys.readouterr().err
    assert "U_Foo_V1R1_STIG.zip" in err
    assert "attempt 2 of 4" in err


def test_fetch_disa__a_download_that_always_resets__gives_up_after_four_attempts_and_leaves_no_partial_file(
    tmp_path,
):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): [_reset(), _reset(), _reset(), _reset()]})
    with pytest.raises(urllib.error.URLError):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert len(opener.requested) == fetch.RETRY_ATTEMPTS
    assert not (tmp_path / "U_Foo_V1R1_STIG.zip").exists()
    stored = fetch.read_manifest(tmp_path)["entries"]["U_Foo_V1R1_STIG.zip"]
    assert stored["on_disk_bytes"] is None


def test_fetch_disa__a_404__is_not_retried(tmp_path):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    error = urllib.error.HTTPError(_url("U_Foo_V1R1_STIG.zip"), 404, "Not Found", {}, None)
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): error})
    with pytest.raises(urllib.error.HTTPError):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert len(opener.requested) == 1


def test_fetch_disa__a_503__is_retried(tmp_path):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    error = urllib.error.HTTPError(_url("U_Foo_V1R1_STIG.zip"), 503, "Service Unavailable", {}, None)
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): [error, b"12345"]})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert (tmp_path / "U_Foo_V1R1_STIG.zip").read_bytes() == b"12345"
    assert len(opener.requested) == 2


def test_fetch_disa__a_certificate_error__is_not_retried(tmp_path):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    error = urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): error})
    with pytest.raises(urllib.error.URLError):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert len(opener.requested) == 1


def test_fetch_disa__a_body_cut_short_mid_read__is_retried(tmp_path):
    entries = [_entry("U_Foo_V1R1_STIG.zip")]
    opener = _Opener({_url("U_Foo_V1R1_STIG.zip"): [_CutShortBody(b""), b"12345"]})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert (tmp_path / "U_Foo_V1R1_STIG.zip").read_bytes() == b"12345"
    assert len(opener.requested) == 2


_TRANSIENT_AND_NOT = [
    (TimeoutError("timed out"), True),
    (ConnectionResetError(104, "reset"), True),
    (ConnectionAbortedError(103, "aborted"), True),
    (ConnectionRefusedError(111, "refused"), True),
    (BrokenPipeError(32, "broken pipe"), True),
    (http.client.RemoteDisconnected("Remote end closed connection"), True),
    (http.client.IncompleteRead(b"", 10), True),
    (urllib.error.HTTPError("http://x", 429, "Too Many Requests", {}, None), True),
    (urllib.error.HTTPError("http://x", 500, "Internal Server Error", {}, None), True),
    (urllib.error.HTTPError("http://x", 502, "Bad Gateway", {}, None), True),
    (urllib.error.HTTPError("http://x", 503, "Service Unavailable", {}, None), True),
    (urllib.error.HTTPError("http://x", 504, "Gateway Timeout", {}, None), True),
    (urllib.error.URLError(OSError(101, "Network is unreachable")), True),
    (urllib.error.URLError(socket.gaierror(-2, "Name or service not known")), True),
    (urllib.error.HTTPError("http://x", 404, "Not Found", {}, None), False),
    (urllib.error.HTTPError("http://x", 400, "Bad Request", {}, None), False),
    (urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed")), False),
    (RuntimeError("Refusing to fetch: it resolves to CUI content"), False),
    (ValueError("bad value"), False),
]


@pytest.mark.parametrize(("exc", "expected"), _TRANSIENT_AND_NOT)
def test_is_transient__each_class__is_classified(exc, expected):
    assert fetch.is_transient(exc) is expected


def test_fetch_disa__a_connection_dropped_mid_body__leaves_no_truncated_file_behind(tmp_path):
    # A truncated archive in the sources directory is not harmless even though the manifest
    # will not credit it: the ingest walks that directory and would open it as a real zip.
    entries = [_entry("a.zip", size_bytes=len(_TRUNCATING_BODY))]
    opener = _Opener({_url("a.zip"): _HalfBody(_TRUNCATING_BODY)})
    with pytest.raises(OSError, match="mid-body"):
        fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert not (tmp_path / "a.zip").exists()
    assert fetch.read_manifest(tmp_path)["entries"]["a.zip"]["on_disk_bytes"] is None
    retry = _Opener({_url("a.zip"): _TRUNCATING_BODY})
    fetch.fetch_disa(tmp_path, opener=retry, entries=entries, sleep=lambda _seconds: None)
    assert retry.requested == [_url("a.zip")]
    assert (tmp_path / "a.zip").read_bytes() == _TRUNCATING_BODY


def test_half_body__a_body_larger_than_the_copy_buffer__is_truncated_on_disk(tmp_path):
    # Guards the fixture itself: if _TRUNCATING_BODY ever shrinks below shutil's buffer, the
    # test above stops exercising a partial file while still passing, and every name and
    # comment about truncation here becomes false.
    target = tmp_path / "a.zip"
    with pytest.raises(OSError, match="mid-body"), _HalfBody(_TRUNCATING_BODY) as body, target.open("wb") as handle:
        shutil.copyfileobj(body, handle)
    assert 0 < target.stat().st_size < len(_TRUNCATING_BODY)


def test_fetch_disa__a_completed_run__leaves_a_manifest_naming_what_it_took(tmp_path):
    entries = [_entry("a.zip", size_bytes=999)]
    opener = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    stored = fetch.read_manifest(tmp_path)["entries"]["a.zip"]
    assert stored["size_bytes"] == 999
    assert stored["on_disk_bytes"] == 5
    assert stored["date"] == "10-Jul-2026"


# A real CCI list root element, small enough to read at a glance. extract_cci never parses
# what it copies, so the size and the content of the member are beside the point here; what
# these tests read is whether the right bytes reached the right path.
_CCI_XML = b"<?xml version='1.0'?><cci_list><cci_items/></cci_list>"


def _cci_zip(members):
    """A zip built in memory from member name to bytes.

    zipfile.writestr stores the name it is handed without sanitizing it, which is what lets a
    test carry a member called ../U_CCI_List.xml. Built in code rather than checked in as a
    binary fixture, because the member names are the whole point and a fixture file's names
    cannot be read in a diff.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_cci_zip__a_member_named_to_escape__is_stored_under_that_name(tmp_path):
    # Guards the helper above. If zipfile ever normalized the name away, the escape test
    # below would be handing extract_cci an ordinary archive and passing for that reason.
    path = tmp_path / "hostile.zip"
    path.write_bytes(_cci_zip({"../U_CCI_List.xml": b"escaped"}))
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == ["../U_CCI_List.xml"]


def test_extract_cci__the_archive_the_fetch_takes__leaves_the_xml_the_ingest_reads(tmp_path):
    # source_status is the ingest's own answer to "is the CCI list here", so this cannot pass
    # while the ingest still cannot see the file: a member written under any other name fails.
    path = tmp_path / "U_CCI_List.zip"
    path.write_bytes(_cci_zip({"U_CCI_List.html": b"<html>", "U_CCI_List.xml": _CCI_XML, "README.TXT": b"read me"}))
    written = fetch.extract_cci(tmp_path)
    assert inventory.source_status(tmp_path)["DISA CCI list"] is True
    assert written.read_bytes() == _CCI_XML


def test_extract_cci__no_archive_in_the_directory__leaves_a_hand_placed_xml_untouched(tmp_path):
    # The manual path is first class: someone who never runs the fetch must be unaffected.
    (tmp_path / "U_CCI_List.xml").write_bytes(b"placed by hand")
    assert fetch.extract_cci(tmp_path) is None
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == b"placed by hand"


def test_extract_cci__an_xml_left_by_an_earlier_release__is_replaced_by_the_archives_copy(tmp_path):
    # The archive is the file the manifest vouches for, so it is the authority on the XML's
    # contents. An XML from an older release surviving a fetch that took a newer archive is
    # the worse failure, because nothing would ever report it.
    (tmp_path / "U_CCI_List.xml").write_bytes(b"an older release")
    (tmp_path / "U_CCI_List.zip").write_bytes(_cci_zip({"U_CCI_List.xml": _CCI_XML}))
    fetch.extract_cci(tmp_path)
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == _CCI_XML


def test_extract_cci__a_member_named_to_escape_the_directory__writes_no_file_outside_it(tmp_path):
    # The destination is built from module constants alone and the member is read by exact
    # key, so this archive holds nothing extract_cci asks for. Resolving the member by
    # searching the namelist and writing to the path it names would fail this test.
    #
    # The refusal is a SEPARATE test and this one suppresses it deliberately, so that the only
    # thing able to fail here is a file appearing where none may. Asserted together, the
    # pytest.raises would fail first against a variant that writes the escaping member
    # happily, and the two paths below would never be looked at at all.
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_CCI_List.zip").write_bytes(_cci_zip({"../U_CCI_List.xml": b"escaped"}))
    with contextlib.suppress(RuntimeError):
        fetch.extract_cci(sources)
    assert not (tmp_path / "U_CCI_List.xml").exists()
    assert not (sources / "U_CCI_List.xml").exists()


def test_extract_cci__a_member_named_to_escape_the_directory__refuses_and_names_the_member(tmp_path):
    # The other half of the test above: the archive carries no member under the name asked
    # for, so the operator is told rather than left with a silently absent XML.
    (tmp_path / "U_CCI_List.zip").write_bytes(_cci_zip({"../U_CCI_List.xml": b"escaped"}))
    with pytest.raises(RuntimeError, match="U_CCI_List.xml"):
        fetch.extract_cci(tmp_path)


def test_extract_cci__an_archive_that_will_not_open__names_the_file_and_the_manual_remedy(tmp_path):
    (tmp_path / "U_CCI_List.zip").write_bytes(b"not a zip at all")
    with pytest.raises(RuntimeError) as excinfo:
        fetch.extract_cci(tmp_path)
    message = str(excinfo.value)
    assert str(tmp_path / "U_CCI_List.zip") in message
    assert "by hand" in message


def test_fetch_disa__the_cci_archive_downloaded__leaves_the_xml_and_reports_it(tmp_path):
    entries = [_entry("U_CCI_List.zip")]
    opener = _Opener({_url("U_CCI_List.zip"): _cci_zip({"U_CCI_List.xml": _CCI_XML})})
    written = fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert inventory.source_status(tmp_path)["DISA CCI list"] is True
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == _CCI_XML
    # main() prints what this returns, so the operator sees the XML arrive rather than
    # having to trust that the zip was unpacked.
    assert tmp_path / "U_CCI_List.xml" in written


def test_fetch_disa__the_archive_skipped_but_the_xml_gone__restores_it_without_a_request(tmp_path):
    # The second run of the two-command flow, with the XML deleted in between. The manifest
    # still matches the zip, so nothing is downloaded and only the extraction can restore it.
    entries = [_entry("U_CCI_List.zip")]
    (tmp_path / "U_CCI_List.zip").write_bytes(_cci_zip({"U_CCI_List.xml": _CCI_XML}))
    fetch.write_manifest(tmp_path, entries)
    opener = _Opener({})
    fetch.fetch_disa(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    assert opener.requested == []
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == _CCI_XML


def test_fetch_disa__a_subset_that_does_not_name_the_cci_archive__still_extracts_the_one_on_disk(tmp_path):
    # --refresh passes the entries the index carries and most runs have no CCI change in
    # them, while the archive sits in the directory throughout. Keying the extraction on the
    # archive rather than on this run's entries is what covers those runs.
    (tmp_path / "U_CCI_List.zip").write_bytes(_cci_zip({"U_CCI_List.xml": _CCI_XML}))
    opener = _Opener({_url("a.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=opener, entries=[_entry("a.zip")], sleep=lambda _seconds: None)
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == _CCI_XML


def test_fetch_disa__a_download_failing_after_the_cci_archive_arrived__extracts_on_the_retry(tmp_path):
    # The extraction runs only after every download has succeeded, so a run that raises leaves
    # no XML however far it got. Nothing is lost by that: the retry skips the archive on the
    # manifest and extracts from it. Pinned because the docstring rules on it.
    entries = [_entry("U_CCI_List.zip"), _entry("b.zip")]
    archive = _cci_zip({"U_CCI_List.xml": _CCI_XML})
    failing = _Opener({_url("U_CCI_List.zip"): archive, _url("b.zip"): OSError("connection reset")})
    with pytest.raises(OSError, match="connection reset"):
        fetch.fetch_disa(tmp_path, opener=failing, entries=entries, sleep=lambda _seconds: None)
    assert not (tmp_path / "U_CCI_List.xml").exists()
    retry = _Opener({_url("b.zip"): b"12345"})
    fetch.fetch_disa(tmp_path, opener=retry, entries=entries, sleep=lambda _seconds: None)
    assert retry.requested == [_url("b.zip")]
    assert (tmp_path / "U_CCI_List.xml").read_bytes() == _CCI_XML


def test_fetch_disa_or_advise__a_cci_archive_that_will_not_open__prints_the_manual_fallback(tmp_path, capsys):
    # An extraction failure must reach the operator the way a download failure does. BadZipFile
    # subclasses Exception rather than OSError, so raising it unconverted would leave the
    # command with a traceback and no advice at all.
    entries = [_entry("U_CCI_List.zip")]
    opener = _Opener({_url("U_CCI_List.zip"): b"not a zip at all"})
    with pytest.raises(RuntimeError):
        fetch._fetch_disa_or_advise(tmp_path, opener=opener, entries=entries, sleep=lambda _seconds: None)
    printed = capsys.readouterr().out
    assert "Fetch these sources by hand instead:" in printed
    assert "U_CCI_List.xml" in printed


def _manifest(tmp_path, *entries):
    """A manifest shaped exactly as write_manifest produces, built by calling it and reading
    the result back rather than hand-assembling a dict. A hand-written record can drift from
    the real shape (write_manifest also carries on_disk_bytes) without anything noticing; this
    cannot drift because it is the same function every real run calls."""
    fetch.write_manifest(tmp_path, entries)
    return fetch.read_manifest(tmp_path)


def test_diff__a_bulk_reupload_moving_every_date__reports_nothing_changed(tmp_path):
    # THE test for this function. Most entries on the live index share one bulk re-upload
    # date, so if change detection used dates, another bulk re-upload would report nearly
    # every entry as changed. DISA encodes the release in the filename, so a real change is
    # a NEW NAME.
    before = [catalog.Entry(name="a.zip", href="a.zip", date="28-Apr-2026", size_bytes=10)]
    after = [catalog.Entry(name="a.zip", href="a.zip", date="01-Dec-2026", size_bytes=10)]
    assert fetch.diff(after, _manifest(tmp_path, *before)) == {"new": [], "resized": [], "withdrawn": []}


def test_diff__a_new_release_filename__is_reported_as_new(tmp_path):
    before = [catalog.Entry(name="U_X_V1R1_STIG.zip", href="a", date="10-Jul-2026", size_bytes=10)]
    after = [*before, catalog.Entry(name="U_X_V1R2_STIG.zip", href="b", date="27-Jul-2026", size_bytes=11)]
    assert fetch.diff(after, _manifest(tmp_path, *before))["new"] == ["U_X_V1R2_STIG.zip"]


def test_diff__a_name_the_index_no_longer_carries__is_reported_as_withdrawn(tmp_path):
    before = [catalog.Entry(name="gone.zip", href="a", date="10-Jul-2026", size_bytes=10)]
    assert fetch.diff([], _manifest(tmp_path, *before))["withdrawn"] == ["gone.zip"]


def test_diff__the_same_name_at_a_different_size__is_reported_as_resized(tmp_path):
    before = [catalog.Entry(name="a.zip", href="a", date="10-Jul-2026", size_bytes=10)]
    after = [catalog.Entry(name="a.zip", href="a", date="10-Jul-2026", size_bytes=99)]
    assert fetch.diff(after, _manifest(tmp_path, *before))["resized"] == ["a.zip"]


def test_diff__every_state_at_once__reports_only_the_names_that_actually_changed(tmp_path):
    # Enumerates the state space in one pass: unchanged, date-moved-only, resized, withdrawn
    # and new all together, so a diff that mishandles one state cannot hide behind the others
    # each being tested alone.
    before = [
        catalog.Entry(name="unchanged.zip", href="a", date="10-Jul-2026", size_bytes=10),
        catalog.Entry(name="date_moved.zip", href="a", date="10-Jul-2026", size_bytes=10),
        catalog.Entry(name="resized.zip", href="a", date="10-Jul-2026", size_bytes=10),
        catalog.Entry(name="withdrawn.zip", href="a", date="10-Jul-2026", size_bytes=10),
    ]
    after = [
        catalog.Entry(name="unchanged.zip", href="a", date="10-Jul-2026", size_bytes=10),
        catalog.Entry(name="date_moved.zip", href="a", date="28-Apr-2026", size_bytes=10),
        catalog.Entry(name="resized.zip", href="a", date="10-Jul-2026", size_bytes=99),
        catalog.Entry(name="new.zip", href="a", date="10-Jul-2026", size_bytes=10),
    ]
    assert fetch.diff(after, _manifest(tmp_path, *before)) == {
        "new": ["new.zip"],
        "resized": ["resized.zip"],
        "withdrawn": ["withdrawn.zip"],
    }


def test_diff__the_manifests_on_disk_bytes_disagreeing_with_index_size__is_never_consulted(tmp_path):
    # size_bytes and on_disk_bytes answer different questions (see write_manifest's docstring):
    # size_bytes is what the index advertised, on_disk_bytes is what a run actually stored.
    # Writing a real 5-byte file under a 999-byte index entry makes the two disagree on
    # purpose; a diff that read on_disk_bytes instead of size_bytes would misreport this as
    # resized even though the index side never changed.
    (tmp_path / "a.zip").write_bytes(b"12345")
    entries = [catalog.Entry(name="a.zip", href="a", date="10-Jul-2026", size_bytes=999)]
    fetch.write_manifest(tmp_path, entries)
    manifest = fetch.read_manifest(tmp_path)
    assert manifest["entries"]["a.zip"]["on_disk_bytes"] == 5  # sanity: the two sizes disagree
    after = [catalog.Entry(name="a.zip", href="a", date="10-Jul-2026", size_bytes=999)]
    assert fetch.diff(after, manifest)["resized"] == []


def test_run_check__sources_matching_the_manifest__reports_current_and_returns_zero(tmp_path, capsys):
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    entries = catalog.parse_index(INDEX)
    fetch.write_manifest(tmp_path, fetch.selection(entries))
    opener = _Opener({**_public_bodies(), catalog.INDEX_URL: INDEX.encode()})
    assert fetch._run_check(tmp_path, opener=opener) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "All sources are current."


def test_run_check__a_newer_release_on_the_index__reports_new_and_the_superseded_release_as_withdrawn(tmp_path, capsys):
    before_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
    )
    after_index = before_index + '<A HREF="U_Foo_V1R2_STIG.zip">foo2</A> 27-Jul-2026 12:00  1k\n'
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode()})
    code = fetch._run_check(tmp_path, opener=opener)
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert code == 10
    assert "  new: U_Foo_V1R2_STIG.zip" in lines
    # selection keeps only the newest release per product, so the superseded V1R1 falls out
    # of the tracked selection in the same run V1R2 enters it. Checked as an EXACT line, not
    # a substring: "withdrawn: U_Foo_V1R1_STIG.zip" is also a prefix of the qualified line
    # below, so a substring check would pass even if the qualifier were silently dropped.
    assert "  withdrawn: U_Foo_V1R1_STIG.zip (superseded by U_Foo_V1R2_STIG.zip)" in lines
    # The command --check tells an operator to run must be one argparse accepts, and must be
    # the one that downloads the new release rather than the plain fetch.
    assert "Run stig-mcp-fetch --refresh, then stig-mcp-ingest." in out


def test_run_check__a_withdrawal_unrelated_to_any_new_release__is_reported_without_a_superseded_note(tmp_path, capsys):
    # Two products change at once: Bar bumps version (superseded), Foo simply disappears from
    # the index (a real withdrawal). The matcher must not cross-wire the two.
    before_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
        '<A HREF="U_Bar_V1R1_STIG.zip">bar</A> 10-Jul-2026 12:00  1k\n'
    )
    after_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Bar_V2R1_STIG.zip">bar2</A> 27-Jul-2026 12:00  1k\n'
    )
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode()})
    fetch._run_check(tmp_path, opener=opener)
    lines = capsys.readouterr().out.splitlines()
    assert "  new: U_Bar_V2R1_STIG.zip" in lines
    assert "  withdrawn: U_Bar_V1R1_STIG.zip (superseded by U_Bar_V2R1_STIG.zip)" in lines
    # No U_Foo entry exists anywhere on the after index: DISA genuinely dropped it, so the
    # line must stay bare rather than borrowing Bar's replacement.
    assert "  withdrawn: U_Foo_V1R1_STIG.zip" in lines


def test_run_check__a_withdrawal_sharing_a_product_but_not_a_version_scheme__is_not_marked_superseded(tmp_path, capsys):
    # U_Widget publishes under both schemes at once, as real products on the live index do
    # (catalog.newest_per_product's docstring). release_of's own rule is that a V/R release and
    # a Y/M release of the same product are not comparable, so a V/R withdrawal must never be
    # reported as superseded by an unrelated Y/M release just because the name text overlaps.
    before_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Widget_V1R1_STIG.zip">w1</A> 10-Jul-2026 12:00  1k\n'
        '<A HREF="U_Widget_Y23M04_STIG.zip">w2</A> 10-Jul-2026 12:00  1k\n'
    )
    after_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Widget_Y26M01_STIG.zip">w3</A> 27-Jul-2026 12:00  1k\n'
    )
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode()})
    fetch._run_check(tmp_path, opener=opener)
    lines = capsys.readouterr().out.splitlines()
    assert "  withdrawn: U_Widget_V1R1_STIG.zip" in lines
    assert "  withdrawn: U_Widget_Y23M04_STIG.zip (superseded by U_Widget_Y26M01_STIG.zip)" in lines


def test_run_check__a_withdrawn_name_with_no_version_pattern__is_reported_without_a_superseded_note(tmp_path, capsys):
    # U_CCI_List.zip carries no _V#R#_ or _Y##M##_ suffix at all, unlike a benchmark filename,
    # so it can never be matched to a replacement even while an unrelated product bumps
    # version in the same run.
    before_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_CCI_List.zip">cci</A> 10-Jul-2026 12:00  400k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
    )
    after_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R2_STIG.zip">foo2</A> 27-Jul-2026 12:00  1k\n'
    )
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode()})
    fetch._run_check(tmp_path, opener=opener)
    lines = capsys.readouterr().out.splitlines()
    assert "  withdrawn: U_CCI_List.zip" in lines
    assert "  withdrawn: U_Foo_V1R1_STIG.zip (superseded by U_Foo_V1R2_STIG.zip)" in lines


def test_run_check__only_a_withdrawal__does_not_claim_sources_are_current(tmp_path, capsys):
    before_index = (
        '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
        '<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n'
    )
    after_index = '<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n'
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(before_index)))
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    opener = _Opener({**_public_bodies(), catalog.INDEX_URL: after_index.encode()})
    code = fetch._run_check(tmp_path, opener=opener)
    out = capsys.readouterr().out
    assert code == 0
    assert "unknown" not in out
    assert "  withdrawn: U_Foo_V1R1_STIG.zip" in out.splitlines()
    assert "sources are current" not in out.lower()


def _new_entry(name):
    """An arriving entry whose advertised size CANNOT be the length that lands on disk.

    The index's size column is a rounded display value that almost never equals the stored
    length (_already_downloaded's docstring). A prune that verified an arrival against
    size_bytes would therefore verify nothing on a real run, so every test below must FAIL
    in that case rather than quietly agree with it.
    """
    return _entry(name, size_bytes=999_999)


def _fetched(tmp_path, *entries):
    """The state a completed fetch_disa leaves behind: every entry on disk, and a manifest
    recording the length actually stored there.

    Written through write_manifest, the same call fetch_disa makes, so the recorded length and
    the file agree because the code made them agree and not because a test picked a number
    that matched.
    """
    for entry in entries:
        (tmp_path / entry.name).write_bytes(entry.name.encode())
    fetch.write_manifest(tmp_path, entries)


def _armed_pair(tmp_path):
    """A genuinely superseded file plus the arrival that replaces it, for the tests whose real
    subject is a RETENTION. Without a deletion happening in the same call, "retained" would
    hold just as well for a prune whose deletion path never fired at all.
    """
    (tmp_path / "U_Armed_V1R1_STIG.zip").write_bytes(b"superseded")
    return _entry("U_Armed_V1R1_STIG.zip"), _new_entry("U_Armed_V1R2_STIG.zip")


def test_prune__a_superseded_loose_release__is_deleted(tmp_path):
    old = tmp_path / "U_X_V1R1_STIG.zip"
    old.write_bytes(b"old")
    before = _manifest(tmp_path, _entry(old.name))
    entries = [_new_entry("U_X_V1R2_STIG.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert not old.exists()
    assert result == {"deleted": [old.name], "retained": [], "dropped": []}


def test_prune__an_index_that_regressed_to_an_older_release__keeps_the_newer_local_file(tmp_path):
    # An older arrival supersedes nothing: the rule prune rests on is that a superseded file is
    # strictly worse than the one replacing it. DISA pulling a release, or one bad read of the
    # index page, must not cost the newer local copy.
    newer = tmp_path / "U_Foo_V2R5_STIG.zip"
    newer.write_bytes(b"the release the operator already has")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(newer.name), armed_old)
    entries = [_new_entry("U_Foo_V1R1_STIG.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert newer.exists()
    assert result == {"deleted": [armed_old.name], "retained": [newer.name], "dropped": []}


def test_prune__an_older_library_compilation_on_the_index__still_replaces_the_newer_local_one(tmp_path):
    # The deliberate asymmetry with the test above. inventory.classify refuses two library
    # compilations at once, so exactly one may exist and the index is the only authority on
    # which; keeping the newer local one would mean deleting the copy this very run downloaded.
    newer = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    newer.write_bytes(b"the quarter the operator already has")
    before = _manifest(tmp_path, _entry(newer.name))
    entries = [_new_entry("U_SRG-STIG_Library_April_2026.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert not newer.exists()
    assert result == {"deleted": [newer.name], "retained": [], "dropped": []}


def test_prune__a_file_the_manifest_never_recorded__is_left_alone(tmp_path):
    # manual_sources() tells operators to drop loose product STIG zips straight into this
    # directory, so a file no run recorded is an expected state rather than a hypothetical.
    # Iterating the manifest instead of the directory is the ENTIRE bound on what prune can
    # unlink: it is also why a manifest name is the only string that reaches unlink() at all,
    # so nothing prune has not previously written is reachable through it.
    hand_placed = tmp_path / "U_Hand_V1R1_STIG.zip"
    hand_placed.write_bytes(b"placed by the operator")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, armed_old)
    entries = [_new_entry("U_Hand_V1R2_STIG.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    # The arrival IS a later release of the hand-placed file's product, so a prune that read
    # the directory rather than the manifest would delete it, and fail this test.
    assert hand_placed.exists()
    assert result == {"deleted": [armed_old.name], "retained": [], "dropped": []}


def test_prune__the_xml_extracted_from_the_cci_archive__survives_a_call_that_deletes(tmp_path):
    # The XML is not an index entry, so no manifest ever names it and prune cannot reach it.
    # The armed pair makes the deletion branch fire in this same call, so the survival is not
    # the survival of a loop that never ran.
    extracted = tmp_path / "U_CCI_List.xml"
    extracted.write_bytes(_CCI_XML)
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry("U_CCI_List.zip"), armed_old)
    entries = [_new_entry("U_CCI_List.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert extracted.read_bytes() == _CCI_XML
    assert result == {"deleted": [armed_old.name], "retained": [], "dropped": []}


def test_prune__a_product_withdrawn_from_the_index__is_retained_while_a_superseded_one_is_deleted(tmp_path):
    # Coverage is the goal and a withdrawn STIG cannot be re-fetched once deleted. The server
    # already labels what it yields: _provenance_notes says the answer came from a local
    # artifact that is not in the current library compilation.
    gone = tmp_path / "U_Old_Product_V1R1_STIG.zip"
    gone.write_bytes(b"still useful")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(gone.name), armed_old)
    _fetched(tmp_path, armed_new)
    result = fetch.prune(tmp_path, [armed_new], before)
    assert gone.exists()
    assert result == {"deleted": [armed_old.name], "retained": [gone.name], "dropped": []}


def test_prune__a_release_in_the_other_version_scheme__does_not_supersede_the_one_on_disk(tmp_path):
    # U_IBM_HMC publishes under both schemes, and catalog.release_of measured that the Y/M
    # archive carries a benchmark dated 2015 while the V/R one carries 2024. Matching on the
    # product text alone would delete the NEWER file here and keep the older one.
    old = tmp_path / "U_IBM_HMC_V2R1_STIG.zip"
    old.write_bytes(b"newer content, older label")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(old.name), armed_old)
    entries = [_new_entry("U_IBM_HMC_Y23M04_STIG.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert old.exists()
    assert result == {"deleted": [armed_old.name], "retained": [old.name], "dropped": []}


def test_prune__an_unversioned_withdrawal__is_not_superseded_by_an_unversioned_arrival(tmp_path):
    # Neither name carries a version pattern, so neither has a product key at all. Treating
    # "no key" as a key every other unversioned name matches would delete the four unversioned
    # benchmarks catalog.newest_per_product deliberately keeps on today's index.
    gone = tmp_path / "U_Old_Bundle_STIG.zip"
    gone.write_bytes(b"still useful")
    before = _manifest(tmp_path, _entry(gone.name))
    entries = [_new_entry("U_Other_Bundle_STIG.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert gone.exists()
    assert result == {"deleted": [], "retained": [gone.name], "dropped": []}


def test_prune__a_superseded_library_compilation__is_deleted_once_the_new_one_is_verified(tmp_path):
    # The one file that MUST go rather than sit beside its replacement: inventory.classify
    # refuses two library compilations at once, so keeping both is the state the ingest
    # cannot handle.
    old = tmp_path / "U_SRG-STIG_Library_April_2026.zip"
    old.write_bytes(b"old")
    before = _manifest(tmp_path, _entry(old.name))
    entries = [_new_entry("U_SRG-STIG_Library_July_2026.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert not old.exists()
    assert result == {"deleted": [old.name], "retained": [], "dropped": []}


def test_prune__a_new_compilation_not_at_the_length_the_manifest_recorded__keeps_the_old_one(tmp_path):
    # Verify before deleting. A truncated download that replaced a good compilation would cost
    # the operator the quarter, and classify refuses two compilations so the old one cannot
    # simply be left beside it either.
    old = tmp_path / "U_SRG-STIG_Library_April_2026.zip"
    old.write_bytes(b"old")
    before = _manifest(tmp_path, _entry(old.name))
    entries = [_new_entry("U_SRG-STIG_Library_July_2026.zip")]
    _fetched(tmp_path, *entries)
    (tmp_path / entries[0].name).write_bytes(b"truncated")
    result = fetch.prune(tmp_path, entries, before)
    assert old.exists()
    assert result == {"deleted": [], "retained": [old.name], "dropped": []}


def test_prune__a_verified_library__does_not_authorize_deleting_a_superseded_sunset(tmp_path):
    # Both are COMPILATION tier and neither replaces the other, so a library arrival must not
    # count as the sunset archive's replacement. Unreachable until DISA publishes a Rev 5
    # sunset, which is exactly when a rule that pairs any compilation with any other bites.
    sunset = tmp_path / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"
    sunset.write_bytes(b"retired products live only here")
    old_library = tmp_path / "U_SRG-STIG_Library_April_2026.zip"
    old_library.write_bytes(b"old")
    before = _manifest(tmp_path, _entry(sunset.name), _entry(old_library.name))
    entries = [_new_entry("U_SRG-STIG_Library_July_2026.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert sunset.exists()
    assert result == {"deleted": [old_library.name], "retained": [sunset.name], "dropped": []}


def test_prune__a_verified_sunset_archive__does_not_authorize_deleting_an_old_library(tmp_path):
    # The other direction of the same rule, and the one only the compilation KIND protects,
    # since a sunset is never pruned: a sunset arrival must not be read as the library's
    # replacement, or a run that fetched only a new sunset would delete the library the ingest
    # builds from.
    old_library = tmp_path / "U_SRG-STIG_Library_April_2026.zip"
    old_library.write_bytes(b"the library the ingest builds from")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(old_library.name), armed_old)
    entries = [_new_entry("U_Rev_5_SRG-STIG_Sunset_Compilation.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert old_library.exists()
    assert result == {"deleted": [armed_old.name], "retained": [old_library.name], "dropped": []}


def test_prune__a_newer_sunset_archive_on_the_index__does_not_delete_the_local_one(tmp_path):
    # inventory.classify refuses two LIBRARY compilations and tolerates two sunsets, ingesting
    # both through _from_compilation, so nothing forces a choice here. The sunset archive is
    # the only place several retired products exist at all, which makes keeping both the
    # cheaper side of the trade.
    old = tmp_path / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"
    old.write_bytes(b"retired products live only here")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(old.name), armed_old)
    entries = [_new_entry("U_Rev_5_SRG-STIG_Sunset_Compilation.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert old.exists()
    assert result == {"deleted": [armed_old.name], "retained": [old.name], "dropped": []}


def test_prune__an_older_sunset_archive_on_the_index__does_not_delete_the_newer_local_one(tmp_path):
    # The reachable half: catalog.sunset() takes the FIRST match in index order rather than the
    # newest, so during an overlap window a refresh genuinely fetches Rev 4 while Rev 5 is on
    # disk. Deleting Rev 5 for it would be a coverage loss that cannot be re-fetched.
    newer = tmp_path / "U_Rev_5_SRG-STIG_Sunset_Compilation.zip"
    newer.write_bytes(b"the archive the operator already has")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(newer.name), armed_old)
    entries = [_new_entry("U_Rev_4_SRG-STIG_Sunset_Compilation.zip"), armed_new]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before)
    assert newer.exists()
    assert result == {"deleted": [armed_old.name], "retained": [newer.name], "dropped": []}


def test_prune__an_arrival_the_manifest_does_not_record__deletes_nothing(tmp_path):
    # prune verifies against the manifest fetch_disa writes, so a file it cannot confirm
    # authorizes no deletion, however plausible the name on disk looks.
    old = tmp_path / "U_X_V1R1_STIG.zip"
    old.write_bytes(b"old")
    before = _manifest(tmp_path, _entry(old.name))
    entries = [_new_entry("U_X_V1R2_STIG.zip")]
    (tmp_path / entries[0].name).write_bytes(b"arrived but unrecorded")
    result = fetch.prune(tmp_path, entries, before)
    assert old.exists()
    assert result == {"deleted": [], "retained": [old.name], "dropped": []}


def test_prune__a_recorded_name_no_longer_on_disk__is_neither_deleted_nor_retained(tmp_path):
    # Nothing to delete and nothing to protect: reporting it as retained would tell an
    # operator a local copy survived when none is there.
    entries = [_new_entry("U_X_V1R2_STIG.zip")]
    before = _manifest(tmp_path, _entry("U_X_V1R1_STIG.zip"))
    _fetched(tmp_path, *entries)
    assert fetch.prune(tmp_path, entries, before) == {"deleted": [], "retained": [], "dropped": []}


def test_prune__a_name_the_index_still_carries__is_never_deleted(tmp_path):
    # The file every other rule is protecting: it is in the current selection, so nothing
    # supersedes it and it must survive its own product's key being present in the arrivals.
    keep = tmp_path / "U_X_V1R2_STIG.zip"
    entries = [_new_entry(keep.name)]
    before = _manifest(tmp_path, _entry(keep.name))
    _fetched(tmp_path, *entries)
    assert fetch.prune(tmp_path, entries, before) == {"deleted": [], "retained": [], "dropped": []}
    assert keep.exists()


def test_prune__drop_withdrawn_a_product_the_index_no_longer_carries__is_dropped(tmp_path):
    gone = tmp_path / "U_Old_Product_V1R1_STIG.zip"
    gone.write_bytes(b"withdrawn")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(gone.name), armed_old)
    _fetched(tmp_path, armed_new)
    result = fetch.prune(tmp_path, [armed_new], before, drop_withdrawn=True)
    assert not gone.exists()
    assert result == {"deleted": [armed_old.name], "retained": [], "dropped": [gone.name]}


def test_prune__drop_withdrawn_the_cci_list_withdrawn__keeps_it(tmp_path):
    # The ingest cannot run without the CCI list, and _product_key cannot key it, so it is the
    # one withdrawal the flag must not act on. A second withdrawal is dropped in the same call.
    cci = tmp_path / "U_CCI_List.zip"
    cci.write_bytes(b"cci")
    gone = tmp_path / "U_Old_Product_V1R1_STIG.zip"
    gone.write_bytes(b"withdrawn")
    armed_old, armed_new = _armed_pair(tmp_path)
    before = _manifest(tmp_path, _entry(cci.name), _entry(gone.name), armed_old)
    _fetched(tmp_path, armed_new)
    result = fetch.prune(tmp_path, [armed_new], before, drop_withdrawn=True)
    assert cci.exists()
    assert result == {"deleted": [armed_old.name], "retained": [cci.name], "dropped": [gone.name]}


def test_prune__drop_withdrawn_a_file_the_manifest_never_recorded__is_left_alone(tmp_path):
    hand_placed = tmp_path / "U_Hand_V1R1_STIG.zip"
    hand_placed.write_bytes(b"placed by the operator")
    gone = tmp_path / "U_Old_Product_V1R1_STIG.zip"
    gone.write_bytes(b"withdrawn")
    before = _manifest(tmp_path, _entry(gone.name))
    _fetched(tmp_path)
    result = fetch.prune(tmp_path, [], before, drop_withdrawn=True)
    assert hand_placed.exists()
    assert result["dropped"] == [gone.name]


def test_prune__drop_withdrawn_an_index_that_regressed__drops_the_newer_local_release(tmp_path):
    # Without the flag the newer local copy is retained (the regression test above this one).
    # With it, CI builds from what DISA publishes now, which is the older release just fetched.
    newer = tmp_path / "U_Foo_V2R5_STIG.zip"
    newer.write_bytes(b"pulled by DISA")
    before = _manifest(tmp_path, _entry(newer.name))
    entries = [_new_entry("U_Foo_V2R4_STIG.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before, drop_withdrawn=True)
    assert not newer.exists()
    assert result == {"deleted": [], "retained": [], "dropped": [newer.name]}


def test_prune__drop_withdrawn_a_replaced_sunset_archive__is_dropped(tmp_path):
    # Without the flag a sunset archive is never deleted (_supersedes). With it, only the one
    # the index carries now survives.
    old = tmp_path / "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"
    old.write_bytes(b"old sunset")
    before = _manifest(tmp_path, _entry(old.name))
    entries = [_new_entry("U_Rev_5_SRG-STIG_Sunset_Compilation.zip")]
    _fetched(tmp_path, *entries)
    result = fetch.prune(tmp_path, entries, before, drop_withdrawn=True)
    assert not old.exists()
    assert result["dropped"] == [old.name]


def _index_rows(*rows):
    return "".join(['<A HREF="U_SRG-STIG_Library_July_2026.zip">lib</A> 13-Jul-2026 12:00  5k\n', *rows])


def test_run_refresh__an_index_read_that_resets_once__retries_it(tmp_path, monkeypatch, capsys):
    # _run_refresh has no injectable sleep of its own (unlike fetch_disa), so the pause between
    # its own retried index read goes through time.sleep directly; the test silences that sleep
    # rather than waiting out the real 5 seconds.
    monkeypatch.setattr(fetch.time, "sleep", lambda _seconds: None)
    index = _index_rows()
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(index)))
    unreachable = urllib.error.URLError(OSError(101, "Network is unreachable"))
    opener = _Opener({catalog.INDEX_URL: [unreachable, index.encode()]})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    disa_requests = [u for u in opener.requested if u.startswith(catalog.INDEX_URL)]
    assert disa_requests == [catalog.INDEX_URL, catalog.INDEX_URL]
    assert "already current" in out


def test_run_refresh__a_new_release__downloads_it_and_deletes_what_it_supersedes(tmp_path, capsys):
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    after_index = _index_rows('<A HREF="U_Foo_V1R2_STIG.zip">foo2</A> 27-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode(), _url("U_Foo_V1R2_STIG.zip"): b"new release"})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    assert (tmp_path / "U_Foo_V1R2_STIG.zip").read_bytes() == b"new release"
    assert not (tmp_path / "U_Foo_V1R1_STIG.zip").exists()
    # The library was already on disk at its recorded length, so only the new release is
    # requested; the index read is the other DISA request. Public checks add their own
    # discovery requests ahead of these, so only the DISA-hosted URLs are compared here.
    disa_requests = [u for u in opener.requested if u.startswith(catalog.INDEX_URL)]
    assert disa_requests == [catalog.INDEX_URL, _url("U_Foo_V1R2_STIG.zip")]
    assert "fetched 1 changed artifact(s)" in out
    assert "deleted 1 superseded file(s)" in out
    assert "stig-mcp-ingest" in out


def test_run_refresh__a_completed_run__leaves_a_manifest_naming_exactly_what_the_index_carries(tmp_path):
    # fetch_disa writes the manifest from the entries it was given, so a pruned name is
    # already absent from it. A second write_manifest call here would re-hash roughly a
    # gigabyte to produce the same file, against write_manifest's own "call it once" rule.
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    after_index = _index_rows('<A HREF="U_Foo_V1R2_STIG.zip">foo2</A> 27-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode(), _url("U_Foo_V1R2_STIG.zip"): b"new release"})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    stored = fetch.read_manifest(tmp_path)["entries"]
    assert set(stored) == {"U_SRG-STIG_Library_July_2026.zip", "U_Foo_V1R2_STIG.zip"}
    assert stored["U_Foo_V1R2_STIG.zip"]["on_disk_bytes"] == len(b"new release")


def test_run_refresh__a_withdrawn_product__is_reported_as_retained_rather_than_deleted(tmp_path, capsys):
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: _index_rows().encode()})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    assert (tmp_path / "U_Foo_V1R1_STIG.zip").exists()
    assert "1 product(s) no longer published" in capsys.readouterr().out


def test_run_refresh__drop_withdrawn__deletes_and_names_the_withdrawn_file(tmp_path, capsys):
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: _index_rows().encode()})
    fetch._run_refresh(tmp_path, 0, opener=opener, drop_withdrawn=True)
    out = capsys.readouterr().out
    assert not (tmp_path / "U_Foo_V1R1_STIG.zip").exists()
    assert "dropped 1 withdrawn file(s): U_Foo_V1R1_STIG.zip" in out
    assert "no longer published" not in out
    assert "Sources changed" in out


def test_run_refresh__an_index_that_has_not_moved__does_not_claim_the_sources_changed(tmp_path, capsys):
    # The commonest run of all: a quarterly refresh against an index that has not moved. Saying
    # the sources changed here costs the operator a full knowledge base rebuild for nothing,
    # and _run_check already refuses to misdescribe a run for the same reason.
    index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(index)))
    opener = _Opener({catalog.INDEX_URL: index.encode()})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    # Public checks add their own discovery requests ahead of the DISA ones; only the
    # DISA-hosted URL is compared here.
    disa_requests = [u for u in opener.requested if u.startswith(catalog.INDEX_URL)]
    assert disa_requests == [catalog.INDEX_URL]
    assert "Sources changed" not in out
    assert "already current" in out


def test_run_refresh__the_delay_it_was_given__is_the_one_the_downloads_are_spaced_by(monkeypatch, tmp_path):
    # A gigabyte from one government host: an operator lengthening the delay to be polite must
    # get the delay they asked for, not the default.
    spacing = []
    monkeypatch.setattr(
        fetch, "fetch_disa", lambda dest_dir, opener=None, delay=0.25, entries=None: spacing.append(delay)
    )
    opener = _Opener({catalog.INDEX_URL: _index_rows().encode()})
    fetch._run_refresh(tmp_path, 7.5, opener=opener)
    assert spacing == [7.5]


def test_run_refresh__a_download_that_fails__names_the_manual_fallback(monkeypatch, tmp_path, capsys):
    # A quarterly refresh that fails is exactly when an operator needs to be told they can
    # fetch by hand instead, which is what the default fetch path says.
    def fail(*_args, **_kwargs):
        raise RuntimeError("simulated DISA outage")

    monkeypatch.setattr(fetch, "fetch_disa", fail)
    opener = _Opener({catalog.INDEX_URL: _index_rows().encode()})
    with pytest.raises(RuntimeError, match="simulated DISA outage"):
        fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    for reminder in manual_sources():
        assert reminder in out


def test_run_refresh__a_download_that_fails__never_reaches_prune(monkeypatch, tmp_path):
    # Deciding what is superseded from a half-completed fetch is exactly how a good file gets
    # deleted for a replacement that never arrived. Pinned so a later reordering cannot make
    # prune run on the failure path.
    def fail(*_args, **_kwargs):
        raise RuntimeError("simulated DISA outage")

    calls = []
    monkeypatch.setattr(fetch, "fetch_disa", fail)
    monkeypatch.setattr(fetch, "prune", lambda *args: calls.append(args))
    opener = _Opener({catalog.INDEX_URL: _index_rows().encode()})
    with pytest.raises(RuntimeError, match="simulated DISA outage"):
        fetch._run_refresh(tmp_path, 0, opener=opener)
    assert calls == []


def test_main__default_action__also_fetches_from_disa(monkeypatch, tmp_path, capsys):
    # The default command fetches DISA content too, not only the three small public sources,
    # and this is the test that pins fetch_disa being wired to a caller at all.
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(fetch, "fetch_public", lambda dest_dir: [tmp_path / "enterprise-attack.json"])
    calls = []

    def fake_fetch_disa(dest_dir, delay=0.25):
        calls.append((dest_dir, delay))
        return [tmp_path / "U_CCI_List.zip"]

    monkeypatch.setattr(fetch, "fetch_disa", fake_fetch_disa)
    fetch.main()
    assert calls == [(tmp_path, 0.25)]
    out = capsys.readouterr().out
    assert "enterprise-attack.json" in out
    assert "U_CCI_List.zip" in out


def test_main__disa_fetch_fails__prints_manual_sources_and_reraises(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(fetch, "fetch_public", lambda dest_dir: [])

    def fail(dest_dir, delay=0.25):
        raise RuntimeError("simulated DISA outage")

    monkeypatch.setattr(fetch, "fetch_disa", fail)
    with pytest.raises(RuntimeError, match="simulated DISA outage"):
        fetch.main()
    out = capsys.readouterr().out
    for reminder in manual_sources():
        assert reminder in out


def test_main__disa_fetch_succeeds__does_not_print_manual_sources(monkeypatch, tmp_path, capsys):
    # manual_sources() is the fallback for a fetch that did not complete; printing it after a
    # clean run reads oddly since there is then nothing left to do by hand.
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(fetch, "fetch_public", lambda dest_dir: [])
    monkeypatch.setattr(fetch, "fetch_disa", lambda dest_dir, delay=0.25: [])
    fetch.main()
    assert "manual" not in capsys.readouterr().out.lower()


def test_main__the_check_flag__exits_with_run_checks_code_for_the_configured_sources_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--check"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    calls = []

    def fake_run_check(dest_dir):
        calls.append(dest_dir)
        return 10

    monkeypatch.setattr(fetch, "_run_check", fake_run_check)
    with pytest.raises(SystemExit) as excinfo:
        fetch.main()
    assert excinfo.value.code == 10
    assert calls == [tmp_path]


def test_main__the_check_flag__never_reaches_fetch_public_or_fetch_disa(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--check"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(fetch, "_run_check", lambda dest_dir: 0)

    def refuse(*_args, **_kwargs):
        raise AssertionError("--check must not fetch or download anything")

    monkeypatch.setattr(fetch, "fetch_public", refuse)
    monkeypatch.setattr(fetch, "fetch_disa", refuse)
    with pytest.raises(SystemExit):
        fetch.main()


def test_main__the_refresh_flag__refreshes_the_configured_sources_dir_at_the_requested_delay(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--refresh", "--delay", "0.5"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    calls = []
    # main() passes drop_withdrawn by keyword (the next test pins the value); this lambda
    # only cares about dest_dir and delay, so it absorbs the keyword and ignores it.
    monkeypatch.setattr(fetch, "_run_refresh", lambda dest_dir, delay, **kwargs: calls.append((dest_dir, delay)))
    fetch.main()
    assert calls == [(tmp_path, 0.5)]


def test_main__the_refresh_flag__never_reaches_the_plain_fetch_path(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--refresh"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    monkeypatch.setattr(fetch, "_run_refresh", lambda dest_dir, delay, **kwargs: None)

    def refuse(*_args, **_kwargs):
        raise AssertionError("--refresh must not run the plain fetch as well")

    monkeypatch.setattr(fetch, "fetch_public", refuse)
    monkeypatch.setattr(fetch, "fetch_disa", refuse)
    fetch.main()


def test_main__drop_withdrawn_without_refresh__exits_2_naming_refresh(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--drop-withdrawn"])
    with pytest.raises(SystemExit) as exit_info:
        fetch.main()
    assert exit_info.value.code == 2
    assert "--drop-withdrawn only applies with --refresh" in capsys.readouterr().err


def test_main__refresh_with_drop_withdrawn__passes_the_flag_through(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--refresh", "--drop-withdrawn"])
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path)
    calls = []
    monkeypatch.setattr(fetch, "_run_refresh", lambda *a, **kw: calls.append((a, kw)))
    fetch.main()
    assert calls == [((tmp_path, 0.25), {"drop_withdrawn": True})]


def test_main__check_and_refresh_together__is_refused_rather_than_silently_ignoring_one(monkeypatch, capsys):
    # A cron job asking for both means the operator does not know which it wants. Silently
    # running one of them would download or delete on a run that meant to only report.
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--check", "--refresh"])
    with pytest.raises(SystemExit) as excinfo:
        fetch.main()
    assert excinfo.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_main__the_help_flag__names_the_check_exit_codes(monkeypatch, capsys):
    # A scheduled quarterly check is the point of this flag; the exit code it scripts against
    # belongs where an operator will look for it, not only in a docstring.
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--help"])
    with pytest.raises(SystemExit):
        fetch.main()
    out = " ".join(capsys.readouterr().out.split())
    assert "exits 10 if updates are available" in out
    assert f"{fetch.EXIT_COULD_NOT_CHECK} if nothing is to take but a source printed as unknown" in out
    assert "could not be checked, else 0" in out


def test_main__the_help_flag__names_the_public_sources_check_and_refresh_cover(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["stig-mcp-fetch", "--help"])
    with pytest.raises(SystemExit):
        fetch.main()
    out = " ".join(capsys.readouterr().out.split())
    out = out[out.index("options:") :]  # past the usage line, which names both flags bare
    check_help = out[out.index("--check") : out.index("--refresh")]
    refresh_help = out[out.index("--refresh") : out.index("--delay")]
    for help_text in (check_help, refresh_help):
        assert "ATT&CK" in help_text and "CTID" in help_text and "catalog" in help_text
    assert "unknown" in check_help


_ATTACK_192 = upstream.ATTACK_URL_PREFIX + "master/enterprise-attack/enterprise-attack-19.2.json"
_CTID_161 = upstream.CTID_FILE_URL.format(folder="attack-16.1")


def _public_bodies(attack=b'{"objects": []}', ctid=b'{"mapping_objects": []}', catalog_body=None):
    """Upstream as it stands for the public sources: ATT&CK 19.2 (released 2026-08-05), CTID 16.1
    (ATT&CK 16.1 released 2024-11-12), and a catalog whose listing sha matches catalog_body."""
    catalog_body = catalog_body or json.dumps({"catalog": {"metadata": {"version": "5.2.0"}, "groups": []}}).encode()
    index = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": "16.1",
                        "url": upstream.ATTACK_URL_PREFIX + "x-16.1.json",
                        "modified": "2024-11-12T14:00:00Z",
                    },
                    {"version": "19.2", "url": _ATTACK_192, "modified": "2026-08-05T21:33:58Z"},
                ],
            }
        ]
    }
    blob = hashlib.sha1(b"blob %d\0" % len(catalog_body) + catalog_body, usedforsecurity=False).hexdigest()
    return {
        upstream.ATTACK_INDEX_URL: json.dumps(index).encode(),
        _ATTACK_192: attack,
        upstream.CTID_LISTING_URL: json.dumps([{"name": "attack-16.1", "type": "dir"}]).encode(),
        _CTID_161: ctid,
        upstream.CATALOG_LISTING_URL: json.dumps(
            [{"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": blob}]
        ).encode(),
        fetch.SOURCE_URLS["catalog"]: catalog_body,
    }


def test_fetch_public__current_upstream__writes_pinned_files_index_and_public_records(tmp_path):
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    public = fetch.read_manifest(tmp_path)["public"]
    assert public["attack"]["version"] == "19.2" and public["attack"]["url"] == _ATTACK_192
    assert public["attack"]["release_date"] == "2026-08-05"
    assert public["ctid"]["attack_version"] == "16.1" and public["ctid"]["attack_release_date"] == "2024-11-12"
    assert public["catalog"]["version"] == "5.2.0"
    for name in ("enterprise-attack.json", "ctid_mappings.json", "nist_800_53_rev5_catalog.json", "attack_index.json"):
        assert (tmp_path / name).is_file()


def test_take_public__download_drops_midway__keeps_the_previous_file(tmp_path):
    # A refresh that fails must not cost the operator the file they had.
    (tmp_path / "enterprise-attack.json").write_bytes(b"previous good bundle")
    bodies = _public_bodies(attack=_HalfBody(_TRUNCATING_BODY))
    with pytest.raises(OSError, match="connection reset"):
        fetch.take_public(tmp_path, ["attack"], opener=_Opener(bodies))
    assert (tmp_path / "enterprise-attack.json").read_bytes() == b"previous good bundle"
    assert not list(tmp_path.glob("*.part"))


def test_take_public__malformed_attack_index__keeps_the_previous_index(tmp_path, capsys):
    (tmp_path / fetch.ATTACK_INDEX_NAME).write_bytes(b"previous good index")
    bodies = _public_bodies()
    bodies[upstream.ATTACK_INDEX_URL] = b"<html>not an index</html>"
    with pytest.raises(ValueError):
        fetch.take_public(tmp_path, ["attack"], opener=_Opener(bodies))
    assert (tmp_path / fetch.ATTACK_INDEX_NAME).read_bytes() == b"previous good index"
    assert not list(tmp_path.glob("*.part"))
    assert capsys.readouterr().out.startswith("ATT&CK download failed: any previous enterprise-attack.json was kept")


def test_take_public__catalog_without_a_catalog_body__keeps_the_previous_catalog(tmp_path, capsys):
    target = tmp_path / fetch._TARGET_FILENAMES["catalog"]
    target.write_bytes(b"previous good catalog")
    bodies = _public_bodies()
    bodies[fetch.SOURCE_URLS["catalog"]] = b'{"not": "a catalog"}'
    with pytest.raises(KeyError):
        fetch.take_public(tmp_path, ["catalog"], opener=_Opener(bodies))
    assert target.read_bytes() == b"previous good catalog"
    assert not list(tmp_path.glob("*.part"))
    assert capsys.readouterr().out.startswith("NIST catalog download failed:")


def test_take_public__second_source_fails_after_the_first_succeeds__names_the_second(tmp_path, capsys):
    # take_public takes ATT&CK before CTID, so a message naming the first source requested, or
    # the last one to succeed, would name ATT&CK here.
    bodies = _public_bodies()
    bodies[_CTID_161] = urllib.error.HTTPError(_CTID_161, 500, "Internal Server Error", {}, None)
    with pytest.raises(urllib.error.HTTPError):
        fetch.take_public(tmp_path, ["attack", "ctid"], opener=_Opener(bodies))
    out = capsys.readouterr().out
    assert out.startswith("CTID mapping download failed: any previous ctid_mappings.json was kept")
    assert "ATT&CK" not in out


def test_take_public__ctid_folder_without_the_expected_file__names_folder_and_path(tmp_path):
    bodies = _public_bodies()
    bodies[_CTID_161] = urllib.error.HTTPError(_CTID_161, 404, "Not Found", {}, None)
    with pytest.raises(RuntimeError, match="attack-16.1") as excinfo:
        fetch.take_public(tmp_path, ["ctid"], opener=_Opener(bodies))
    assert "nist_800_53-rev5_attack-16.1-enterprise.json" in str(excinfo.value)


def test_take_public__ctid_download_fails_for_a_reason_other_than_404__is_not_converted(tmp_path):
    # Only a missing file (404) is CTID moving its layout, which is the one case worth a message
    # of its own. Anything else (a server error, a rate limit) must reach the operator as what it
    # actually is, not be folded into the "CTID may have changed its layout" text.
    bodies = _public_bodies()
    bodies[_CTID_161] = urllib.error.HTTPError(_CTID_161, 500, "Internal Server Error", {}, None)
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        fetch.take_public(tmp_path, ["ctid"], opener=_Opener(bodies))
    assert excinfo.value.code == 500


def test_take_public__ctid_alone_with_no_saved_attack_index__reads_the_release_date_from_upstream(tmp_path):
    # take_public(["ctid"]) on a directory that never took "attack" leaves no attack_index.json
    # on disk, so _release_date must fall back to a fresh upstream.attack_latest read rather than
    # silently recording no date at all.
    bodies = _public_bodies()
    opener = _Opener(bodies)
    fetch.take_public(tmp_path, ["ctid"], opener=opener)
    assert not (tmp_path / fetch.ATTACK_INDEX_NAME).is_file()
    assert upstream.ATTACK_INDEX_URL in opener.requested
    public = fetch.read_manifest(tmp_path)["public"]
    assert public["ctid"]["attack_release_date"] == "2024-11-12"


def test_take_public__ctid_alone_and_the_fallback_index_read_fails__records_no_release_date(tmp_path):
    # The fallback itself can fail (upstream unreachable, a malformed index): that must cost the
    # ctid record its release_date field, never the whole take.
    bodies = _public_bodies()
    bodies[upstream.ATTACK_INDEX_URL] = b"not json at all"
    opener = _Opener(bodies)
    fetch.take_public(tmp_path, ["ctid"], opener=opener)
    assert upstream.ATTACK_INDEX_URL in opener.requested
    public = fetch.read_manifest(tmp_path)["public"]
    assert public["ctid"]["attack_release_date"] is None


def test_run_check__newer_attack_upstream__prints_it_and_returns_ten(tmp_path, capsys):
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(INDEX)))
    fetch.write_public(tmp_path, "attack", {"version": "19.1", "url": "u", "sha256": "s", "release_date": None})
    opener = _Opener({**_public_bodies(), catalog.INDEX_URL: INDEX.encode()})
    code = fetch._run_check(tmp_path, opener=opener)
    lines = capsys.readouterr().out.splitlines()
    assert code == 10
    assert "  ATT&CK: 19.2 available (have 19.1)" in lines


def test_run_check__public_sources_unreachable_but_disa_current__returns_could_not_check_and_says_unknown(
    tmp_path, capsys
):
    entries = catalog.parse_index(INDEX)
    fetch.write_manifest(tmp_path, fetch.selection(entries))
    opener = _Opener({catalog.INDEX_URL: INDEX.encode()})
    assert fetch._run_check(tmp_path, opener=opener) == fetch.EXIT_COULD_NOT_CHECK
    assert "  ATT&CK: unknown" in capsys.readouterr().out


def test_run_check__attack_current__prints_current_with_the_version(tmp_path, capsys):
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(INDEX)))
    fetch.write_public(tmp_path, "attack", {"version": "19.2", "url": "u", "sha256": "s", "release_date": None})
    opener = _Opener({**_public_bodies(), catalog.INDEX_URL: INDEX.encode()})
    fetch._run_check(tmp_path, opener=opener)
    assert "  ATT&CK: current (19.2)" in capsys.readouterr().out.splitlines()


def test_run_check__disa_index_unreachable_but_public_sources_current__prints_unknown_and_returns_could_not_check(
    tmp_path, capsys
):
    fetch.write_manifest(tmp_path, fetch.selection(catalog.parse_index(INDEX)))
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    opener = _Opener(_public_bodies())  # no catalog.INDEX_URL entry, so the DISA listing fails
    code = fetch._run_check(tmp_path, opener=opener)
    lines = capsys.readouterr().out.splitlines()
    assert code == fetch.EXIT_COULD_NOT_CHECK
    assert any(line.startswith("  DISA: unknown (") for line in lines)
    assert lines[-1] == (
        "Nothing new to download from the sources that could be checked. Could not check: DISA (reason above)."
    )


def test_run_check__every_source_unreachable__never_says_current_and_names_all_four(tmp_path, capsys):
    code = fetch._run_check(tmp_path, opener=_Opener({}))
    out = capsys.readouterr().out
    assert code == fetch.EXIT_COULD_NOT_CHECK
    assert "current" not in out.lower()
    assert out.splitlines()[-1] == (
        "Nothing new to download from the sources that could be checked. "
        "Could not check: DISA, ATT&CK, CTID mapping, NIST catalog (reason above)."
    )


def test_run_check__long_failure_message__prints_the_whole_reason(tmp_path, capsys):
    remedy = "Download the compilation by hand and place it in the sources directory."

    def failing(request, timeout=None):
        raise RuntimeError("y" * 400 + " " + remedy)

    fetch._run_check(tmp_path, opener=failing)
    disa_line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("  DISA: unknown ("))
    assert disa_line == f"  DISA: unknown (RuntimeError: {'y' * 400} {remedy})"


def test_run_check__exit_codes__are_distinct_from_each_other_and_from_argparse():
    # argparse exits 2 on a usage error; a script must never read that as "could not check".
    assert len({0, 2, 10, fetch.EXIT_COULD_NOT_CHECK}) == 4  # noqa: PLR2004


def test_run_check__newer_attack_but_disa_unreachable__asks_for_a_refresh_and_names_disa(tmp_path, capsys):
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    fetch.write_public(tmp_path, "attack", {"version": "19.1", "url": "u", "sha256": "s", "release_date": None})
    code = fetch._run_check(tmp_path, opener=_Opener(_public_bodies()))
    assert code == 10
    assert capsys.readouterr().out.splitlines()[-1] == (
        "Run stig-mcp-fetch --refresh, then stig-mcp-ingest. Could not check: DISA (reason above)."
    )


def test_run_check__catalog_on_disk_but_unrecorded__does_not_call_it_current(tmp_path, capsys):
    # An upgrade from a release without public records: the catalog file matches upstream's
    # blob sha, so the sha alone says current, but nothing records its version yet.
    fetch.fetch_public(tmp_path, opener=_Opener(_public_bodies()))
    path = tmp_path / fetch.MANIFEST_NAME
    body = json.loads(path.read_text())
    del body["public"]
    path.write_text(json.dumps(body))
    fetch.write_public(tmp_path, "attack", {"version": "19.2", "url": "u", "sha256": "s", "release_date": None})
    fetch.write_public(
        tmp_path, "ctid", {"attack_version": "16.1", "url": "u", "sha256": "s", "attack_release_date": None}
    )
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(INDEX)))
    code = fetch._run_check(tmp_path, opener=_Opener({**_public_bodies(), catalog.INDEX_URL: INDEX.encode()}))
    lines = capsys.readouterr().out.splitlines()
    catalog_line = next(line for line in lines if line.startswith("  NIST catalog:"))
    assert catalog_line == "  NIST catalog: matches upstream, but no version is recorded; --refresh will record it"
    assert code == 10


def test_run_refresh__newer_attack_upstream__downloads_it_and_says_to_ingest(tmp_path, capsys):
    before = _index_rows()
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before)))
    fetch.write_public(tmp_path, "attack", {"version": "19.1", "url": "u", "sha256": "s", "release_date": None})
    opener = _Opener({**_public_bodies(attack=b'{"objects": ["new"]}'), catalog.INDEX_URL: before.encode()})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    assert (tmp_path / "enterprise-attack.json").read_bytes() == b'{"objects": ["new"]}'
    assert fetch.read_manifest(tmp_path)["public"]["attack"]["version"] == "19.2"
    assert "updated public source(s): ATT&CK" in out
    assert "Sources changed. Now run stig-mcp-ingest." in out


def test_run_refresh__public_source_unreachable__still_refreshes_disa_and_names_it(tmp_path, capsys):
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    after_index = _index_rows('<A HREF="U_Foo_V1R2_STIG.zip">foo2</A> 27-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    opener = _Opener({catalog.INDEX_URL: after_index.encode(), _url("U_Foo_V1R2_STIG.zip"): b"new release"})
    fetch._run_refresh(tmp_path, 0, opener=opener)
    out = capsys.readouterr().out
    assert (tmp_path / "U_Foo_V1R2_STIG.zip").read_bytes() == b"new release"
    assert "ATT&CK: not refreshed (" in out


def test_run_refresh__public_source_fails_with_a_long_message__prints_the_whole_reason(tmp_path, capsys):
    before_index = _index_rows('<A HREF="U_Foo_V1R1_STIG.zip">foo</A> 10-Jul-2026 12:00  1k\n')
    _fetched(tmp_path, *fetch.selection(catalog.parse_index(before_index)))
    disa = _Opener({catalog.INDEX_URL: before_index.encode()})
    remedy = "Check the proxy settings and run the refresh again."

    def github_refused(request, timeout=None):
        if request.full_url.startswith(catalog.INDEX_URL):
            return disa(request, timeout)
        raise OSError("z" * 400 + " " + remedy)

    fetch._run_refresh(tmp_path, 0, opener=github_refused)
    out = capsys.readouterr().out.splitlines()
    assert f"  ATT&CK: not refreshed (OSError: {'z' * 400} {remedy})" in out


def test_run_refresh__public_download_fails__stops_before_disa_and_keeps_the_previous_file(tmp_path, capsys):
    # The check reports ATT&CK 19.2 available (so take_public is asked to refresh it), but the
    # bundle download itself drops mid-transfer. A refresh stops on a failed download and a
    # half-finished fetch prunes nothing, so this must stop before the DISA phase ever requests
    # the index, not merely leave the previous ATT&CK file alone, and must say which source
    # failed rather than end in a bare traceback.
    (tmp_path / "enterprise-attack.json").write_bytes(b"previous good bundle")
    fetch.write_public(tmp_path, "attack", {"version": "19.1", "url": "u", "sha256": "s", "release_date": None})
    before_names = {p.name for p in tmp_path.iterdir()}
    opener = _Opener(_public_bodies(attack=_HalfBody(_TRUNCATING_BODY)))
    with pytest.raises(OSError, match="connection reset"):
        fetch._run_refresh(tmp_path, 0, opener=opener)
    assert capsys.readouterr().out.splitlines()[-1] == (
        "ATT&CK download failed: any previous enterprise-attack.json was kept and nothing was pruned. "
        "Re-run the same stig-mcp-fetch command once the error that follows is fixed."
    )
    assert (tmp_path / "enterprise-attack.json").read_bytes() == b"previous good bundle"
    assert not list(tmp_path.glob("*.part"))
    # The check itself never touches DISA (currency.public_report checks only the public
    # sources); this asserts the DOWNLOAD failure stopped _run_refresh before it reached the
    # `selection(...)` line that would have made the first DISA request.
    assert not any(u.startswith(catalog.INDEX_URL) for u in opener.requested)
    after_names = {p.name for p in tmp_path.iterdir()}
    assert before_names <= after_names


class _Reached(Exception):
    """Raised by the patched tls opener, so reaching it is observable."""


def _refusing_opener(*_handlers):
    def open_url(request, timeout=None):
        raise _Reached(request.full_url)

    return open_url


def test_take_public__no_opener_given__opens_through_the_truststore_opener(tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "opener", _refusing_opener)
    with pytest.raises(_Reached, match=re.escape(upstream.ATTACK_INDEX_URL)):
        fetch.take_public(tmp_path, {"attack"})


def test_fetch_disa__no_opener_given__downloads_through_the_truststore_opener(tmp_path, monkeypatch):
    monkeypatch.setattr(tls, "opener", _refusing_opener)
    with pytest.raises(_Reached, match=re.escape(_url("a.zip"))):
        fetch.fetch_disa(tmp_path, entries=[_entry("a.zip")], sleep=lambda _seconds: None)
