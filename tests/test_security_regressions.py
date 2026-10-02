"""Security regression tests for the ruff flake8-bandit (S-rule) hardening.

Each test feeds the previously-flagged insecure input and asserts the code now
rejects or neutralizes it:
  - S314: XML parsers must refuse entity-bearing (XXE / billion-laughs) documents.
  - S310: the fetcher must refuse non-http(s) source URLs before any retrieval.
  - S608: a malicious stig_id must be bound as a literal, never injected into SQL.
  - no S rule: a caller-supplied digit run must not crash the resolver on int() conversion.
  - no S rule: a remote index entry or a manifest key must not name a path, since every
    caller joins it onto the sources directory to write to and to unlink.
  - no S rule: a remote version, folder name or date written in non-ASCII digits must not
    outrank a real release or pass as a date.
  - no S rule: a CUI_-named source file or archive member must be refused at ingest, never
    silently rolled into a knowledge base that could be published.
  - no S rule: a release listing's tag, asset name or asset URL must not point a knowledge-base
    install outside this repository's own release downloads.
  - no S rule: a redirect, a landed response, or a downloaded asset over its cap must not carry
    a knowledge-base install off this repository's releases or past the size it was told to stop at.
  - no S rule: a remote rate-limit reset header must not crash the error path, whatever digits,
    length or script it is written in.
  - no S rule: a checksum mismatch, an oversized decompression, a corrupt SQLite file or a
    knowledge base built for another schema must refuse the install and leave the installed
    knowledge base untouched.
  - no S rule: an xz asset's hash is checked before anything is decompressed; release.json and
    SHA256SUMS disagreeing on a release's own hashes refuses it; and a pinned tag's lookup
    answering with a different release, rather than the one asked for, refuses the mismatch.
  - no S rule: a local file install refused over MCP must not tell the caller the file's SHA-256,
    its expanded path, or whether it exists, is readable or is a knowledge base, since a
    prompt-injected caller could otherwise fingerprint credential files such as ~/.pgpass.
"""

import contextlib
import email.message
import errno
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import shutil
import sqlite3
import ssl
import urllib.error
import urllib.request
import zipfile

import pytest
from defusedxml.common import DefusedXmlException

from stig_mcp.ingest import catalog, config, fetch, inventory, library, upstream
from stig_mcp.ingest.cci_parser import parse_cci_list
from stig_mcp.ingest.stig_parser import parse_stig
from stig_mcp.kb import install, releases
from stig_mcp.kb.db import SCHEMA_VERSION
from stig_mcp.kb.queries import findings_for_control
from stig_mcp.resolver.resolver import resolve
from stig_mcp.server import app as app_module
from stig_mcp.server import tools
from tests.conftest import FIX, open_db_for_test
from tests.kb.fake_github import FakeGitHub, http_error, refuse_network

_EXTERNAL_ENTITY_XML = """<?xml version="1.0"?>
<!DOCTYPE payload [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<cci_list>&xxe;</cci_list>
"""

_BILLION_LAUGHS_XML = """<?xml version="1.0"?>
<!DOCTYPE payload [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<cci_list>&lol3;</cci_list>
"""


@pytest.mark.parametrize("payload", [_EXTERNAL_ENTITY_XML, _BILLION_LAUGHS_XML])
def test_parse_cci_list__xml_declaring_entities__raises_DefusedXmlException(tmp_path, payload):
    path = tmp_path / "malicious_cci.xml"
    path.write_text(payload)
    with pytest.raises(DefusedXmlException):
        parse_cci_list(path)


@pytest.mark.parametrize("payload", [_EXTERNAL_ENTITY_XML, _BILLION_LAUGHS_XML])
def test_parse_stig__xml_declaring_entities__raises_DefusedXmlException(tmp_path, payload):
    path = tmp_path / "malicious_stig.xml"
    path.write_text(payload)
    with pytest.raises(DefusedXmlException):
        parse_stig(path)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "data:text/plain,x"])
def test_require_web_url__non_web_scheme__raises_ValueError(url):
    with pytest.raises(ValueError, match="http/https"):
        fetch.require_web_url(url)


@pytest.mark.parametrize("url", ["https://example.gov/a.json", "http://example.gov/a.json"])
def test_require_web_url__web_scheme__is_accepted(url):
    fetch.require_web_url(url)  # no exception


def test_take_public__non_https_source_url__raises_before_any_download(tmp_path, monkeypatch):
    # "catalog" is the one public source whose URL still comes from SOURCE_URLS; "attack" and
    # "ctid" are resolved through upstream instead.
    requested = []
    monkeypatch.setattr(fetch, "SOURCE_URLS", {"catalog": "file:///etc/passwd"})
    with pytest.raises(ValueError, match="http/https"):
        fetch.take_public(tmp_path, ["catalog"], opener=lambda *args, **kwargs: requested.append(args))
    assert requested == []  # the scheme guard fired before the opener was ever reached


_ESCAPING_NAMES = [
    "../ESCAPED.zip",  # the plain parent step, exercised for both the write and the delete
    "../../ESCAPED.zip",
    "/etc/ESCAPED.zip",  # absolute: joining it DISCARDS the destination entirely
    "sub/ESCAPED.zip",  # a separator in the middle, which escapes into a directory below
    "..\\ESCAPED.zip",  # one ordinary filename to POSIX, a parent step to Windows
    "C:ESCAPED.zip",  # drive-relative, likewise invisible to a POSIX-only check
    "\\\\server\\share\\ESCAPED.zip",
    # The three pure-dot names, none of which pathlib rejects on its own: "" and "." have a
    # .name of "", but CPython 3.14 returns ".." from PurePath("..").name, where older versions
    # returned "". Enumerated deliberately rather than left to the version in use.
    "..",
    ".",
    "",
]

# Every one of these is on the live DISA index, spaces, brackets and all: the guard must not
# cost a single real archive.
_REAL_NAMES = [
    "U_MS_Windows_Server_2019_V3R9_STIG.zip",
    "U_CCI_List.zip",
    "U_SRG-STIG_Library_July_2026.zip",
    "U_Splunk_Enterprise_8-x_for Linux_V2R1_STIG.zip",
    "U_CAN_Ubuntu_22-04_LTS_V2R4_STIG_SCAP_1-3_Benchmark (1).zip",
]


class _PlentyOfDisk:
    """fetch_disa preflights the real volume. Without this the escape test below could refuse
    on free space on a small tmp volume, which is not the assertion it exists to make."""

    total = used = 0
    free = 99 * 1024**3


_PLENTY_OF_DISK = _PlentyOfDisk()


def _always_serving(payload):
    """An opener that answers every URL, so a request that escapes is served rather than
    raising a KeyError before the write it is meant to demonstrate."""

    def open_url(_request, timeout=None):
        return io.BytesIO(payload)

    return open_url


def _row(on_disk_bytes):
    return {"date": "10-Jul-2026", "size_bytes": 1024, "on_disk_bytes": on_disk_bytes, "sha256": None}


@pytest.mark.parametrize("name", _ESCAPING_NAMES)
def test_require_bare_name__a_name_that_is_not_a_plain_filename__raises_ValueError(name):
    with pytest.raises(ValueError, match="plain filename"):
        fetch.require_bare_name(name)


@pytest.mark.parametrize("name", _REAL_NAMES)
def test_require_bare_name__a_name_the_real_index_publishes__is_accepted(name):
    fetch.require_bare_name(name)  # no exception


def test_parse_index__a_row_whose_href_leaves_the_directory__refuses_the_page():
    text = '<A HREF="../ESCAPED.zip">x</A>  13-Aug-2026 10:00  1k\n'
    with pytest.raises(ValueError, match="plain filename"):
        catalog.parse_index(text)


def test_parse_index__a_percent_encoded_traversal__is_refused_after_unquoting():
    # The name is unquoted before the guard sees it, so an encoded separator cannot slip past
    # the way it would past a check on the raw href.
    text = '<A HREF="%2e%2e%2fESCAPED.zip">x</A>  13-Aug-2026 10:00  1k\n'
    with pytest.raises(ValueError, match="plain filename"):
        catalog.parse_index(text)


def test_fetch_disa__an_index_row_that_leaves_the_destination__writes_nothing_outside_it(tmp_path, monkeypatch):
    """The ESCAPE assertion is what must fail when the guard is gone, so the raise is tolerated.

    Its sibling above pins the raise itself. Here the guard is removed from catalog.parse_index
    and the last line fails on the file that appeared outside dest, rather than on a DID NOT
    RAISE that would never reach it. tmp_path itself is the escape target, so the write an
    unguarded run makes lands inside this test's own directory and nowhere else, and the
    directory exists, so it fails on the assertion rather than on a FileNotFoundError.
    """
    monkeypatch.setattr(fetch.shutil, "disk_usage", lambda _path: _PLENTY_OF_DISK)
    dest = tmp_path / "sources"
    dest.mkdir()
    escaped = tmp_path / "ESCAPED.zip"
    text = '<A HREF="../ESCAPED.zip">x</A>  13-Aug-2026 10:00  1k\n'
    opener = _always_serving(b"payload an unguarded run would write outside dest")
    with contextlib.suppress(ValueError):
        # The parse is inside the suppression because the guard is what raises; without it
        # the whole call runs and the download lands outside dest.
        fetch.fetch_disa(dest, opener=opener, entries=catalog.parse_index(text))
    assert not escaped.exists(), f"fetch_disa wrote {escaped}, outside the destination {dest}"


def test_fetch_disa__a_server_that_never_stops_resetting__is_asked_a_bounded_number_of_times(tmp_path, monkeypatch):
    """A hostile or merely broken host that resets every connection must not hold fetch_disa in
    an unbounded retry loop: fetch._with_retry stops after fetch.RETRY_ATTEMPTS tries and the
    total time spent waiting between them is bounded by fetch.RETRY_BACKOFF, no matter how many
    times the host keeps failing."""
    monkeypatch.setattr(fetch.shutil, "disk_usage", lambda _path: _PLENTY_OF_DISK)
    requested = []
    paused = []

    def always_resetting(request, timeout=None):
        requested.append(request.full_url)
        raise urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))

    entries = catalog.parse_index('<A HREF="U_Foo_V1R1_STIG.zip">x</A> 10-Jul-2026 12:00  1k\n')
    with pytest.raises(urllib.error.URLError):
        fetch.fetch_disa(tmp_path, opener=always_resetting, entries=entries, sleep=paused.append)
    assert len(requested) == fetch.RETRY_ATTEMPTS
    assert sum(paused) == sum(fetch.RETRY_BACKOFF)


def test_read_manifest__a_key_that_is_not_a_plain_filename__drops_that_row_and_keeps_the_rest(tmp_path):
    body = {
        "entries": {
            "U_Foo_V1R1_STIG.zip": _row(11),
            "../victim/U_Foo_V1R1_STIG.zip": _row(11),
        }
    }
    (tmp_path / fetch.MANIFEST_NAME).write_text(json.dumps(body))
    assert set(fetch.read_manifest(tmp_path)["entries"]) == {"U_Foo_V1R1_STIG.zip"}


def test_prune__a_manifest_key_that_leaves_the_destination__deletes_nothing_outside_it(tmp_path):
    """The delete half of the same escape, and the one a validated index cannot close.

    prune iterates the manifest's own keys, which are JSON read off disk and so may name
    anything an earlier run or a hand edit put there. Both names key the same product under
    _prune_key, so an unguarded run reads V1R2 as superseding V1R1 and unlinks a file outside
    dest. prune raises in neither direction, so the surviving file is the only assertion that
    can fail, and it fails on the escape.
    """
    dest = tmp_path / "sources"
    dest.mkdir()
    outside = tmp_path / "victim"
    outside.mkdir()
    victim = outside / "U_Foo_V1R1_STIG.zip"
    victim.write_bytes(b"local coverage")
    arrival = outside / "U_Foo_V1R2_STIG.zip"
    arrival.write_bytes(b"newer release")
    body = {
        "entries": {
            "../victim/U_Foo_V1R1_STIG.zip": _row(len(b"local coverage")),
            "../victim/U_Foo_V1R2_STIG.zip": _row(len(b"newer release")),
        }
    }
    (dest / fetch.MANIFEST_NAME).write_text(json.dumps(body))
    entries = [catalog.Entry(name="../victim/U_Foo_V1R2_STIG.zip", href="x", date="27-Jul-2026", size_bytes=1024)]
    fetch.prune(dest, entries, fetch.read_manifest(dest))
    assert victim.is_file(), f"prune unlinked {victim}, outside the destination {dest}"


def test_prune__drop_withdrawn_with_a_manifest_key_that_leaves_the_destination__deletes_nothing_outside_it(tmp_path):
    """The drop path unlinks on withdrawal alone, with no arrival needed, so it is the easier
    escape of the two. read_manifest drops the key; this pins that the drop path goes through it."""
    dest = tmp_path / "sources"
    dest.mkdir()
    victim = tmp_path / "victim.zip"
    victim.write_bytes(b"outside")
    body = {"entries": {"../victim.zip": _row(len(b"outside"))}}
    (dest / fetch.MANIFEST_NAME).write_text(json.dumps(body))
    fetch.prune(dest, [], fetch.read_manifest(dest), drop_withdrawn=True)
    assert victim.is_file(), f"prune unlinked {victim}, outside the destination {dest}"


@pytest.mark.parametrize("injection", ["RHEL_9_STIG'); DROP TABLE stigs; --", "RHEL_9_STIG' OR '1'='1"])
def test_findings_for_control__malicious_stig_id__bound_as_literal_not_injected(kb_path, injection):
    conn = open_db_for_test(kb_path)
    baseline = findings_for_control(conn, "AC-2(1)", [("RHEL_9_STIG", "1")])
    assert baseline  # sanity: the parameterized query returns real rows

    result = findings_for_control(conn, "AC-2(1)", [(injection, "1")])
    assert result == []  # the payload matched no stig_id literally
    surviving_stigs = conn.execute("SELECT COUNT(*) AS n FROM stigs").fetchone()["n"]
    assert surviving_stigs > 0  # the DROP TABLE never executed


def test_resolve__a_digit_run_too_long_for_int_conversion__still_answers(wide_kb):
    """A caller-supplied digit run longer than CPython's int_max_str_digits (4300) must not
    abort the call. Such a token reaches int() in two places: the coverage key on the silence
    path and the version sort on the verdict path. Either would raise ValueError out of
    resolve(), through both mitigations_for_technique and resolve_system.

    wide_kb, not kb_path: with two benchmarks nothing is distinctive, so _version_coverage
    returns at its first gate and neither conversion is ever reached, and the test would pass
    with the defect reinstated."""
    conn = open_db_for_test(wide_kb)
    covered = resolve(conn, "RHEL 9 " + "9" * 4301)  # a held major: the silence path
    assert covered[0]["stig_id"] == "RHEL_9_STIG"
    assert covered[0]["version_coverage"] == []

    uncovered = resolve(conn, "RHEL " + "9" * 4301)  # no held major: the verdict path
    assert uncovered[0]["version_coverage"][0]["verdict"] == "uncovered"


def test_parse_attack_index__latest_url_off_host__is_refused():
    # index.json chooses the URL fetch downloads from; an entry pointing anywhere but MITRE's
    # own repository must never be fetched.
    doc = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [{"version": "19.2", "url": "https://evil.example/enterprise-attack-19.2.json"}],
            }
        ]
    }
    with pytest.raises(upstream.UpstreamError, match="Refusing"):
        upstream.parse_attack_index(doc)


def test_require_url_under__dot_dot_segment_or_http__is_refused():
    for url in (
        upstream.ATTACK_URL_PREFIX + "master/../../other-org/x.json",
        upstream.ATTACK_URL_PREFIX.replace("https://", "http://") + "master/x.json",
    ):
        with pytest.raises(upstream.UpstreamError):
            upstream.require_url_under(url, upstream.ATTACK_URL_PREFIX)


@pytest.mark.parametrize("encoded", ["%2e%2e", "%2E%2e"])
def test_require_url_under__percent_encoded_dot_dot_segment__is_refused(encoded):
    # The same bypass class catalog.py:65 already unquotes href against: a percent-encoded
    # ".." step is still a parent-directory step once decoded, in either letter case.
    url = upstream.ATTACK_URL_PREFIX + f"master/{encoded}/{encoded}/other-org/x.json"
    with pytest.raises(upstream.UpstreamError):
        upstream.require_url_under(url, upstream.ATTACK_URL_PREFIX)


def test_version_key__injected_version_string__is_refused():
    with pytest.raises(upstream.UpstreamError):
        upstream.version_key("19.2; rm")


def test_parse_ctid_listing__traversal_folder_with_higher_version__is_ignored():
    # attack-99.0/../../evil starts with a higher-version match, so a .match() in place of the
    # required .fullmatch() would accept it and wrongly return attack-99.0 instead of attack-16.1.
    listing = [
        {"name": "attack-99.0/../../evil", "type": "dir"},
        {"name": "attack-16.1", "type": "dir"},
    ]
    assert upstream.parse_ctid_listing(listing).folder == "attack-16.1"


@pytest.mark.parametrize(
    "sha",
    [
        "../../" + "a" * 40 + "/etc/passwd",  # a genuine 40-hex run buried mid-string
        "a" * 40 + "/../x",  # a genuine 40-hex run only as a prefix
    ],
)
def test_parse_catalog_listing__sha_with_embedded_40_hex_run__is_refused(sha):
    # Neither fixture is itself 40 hex characters, but each contains a real 40-hex run, so a
    # .search() (mid-string) or .match() (prefix-only) in place of .fullmatch() would wrongly
    # accept one of them.
    with pytest.raises(upstream.UpstreamError):
        upstream.parse_catalog_listing([{"name": upstream.CATALOG_FILE_NAME, "type": "file", "sha": sha}])


# Arabic-Indic digits: a bare \d matches them and int() converts them, so an unguarded
# pattern reads "٩٩.٠" as version 99.0. Every hostile value below carries the HIGHER
# apparent version or the later apparent date, so a pattern that accepts it changes the answer.
_NON_ASCII_VERSION = "٩٩.٠"  # 99.0
_NON_ASCII_DATE = "٢٠٢٦-٠٨-٠٥"  # 2026-08-05


def test_version_key__non_ascii_digits__is_refused():
    with pytest.raises(upstream.UpstreamError):
        upstream.version_key(_NON_ASCII_VERSION)


def test_parse_ctid_listing__non_ascii_digit_folder_with_higher_version__is_ignored():
    listing = [
        {"name": f"attack-{_NON_ASCII_VERSION}", "type": "dir"},
        {"name": "attack-16.1", "type": "dir"},
    ]
    assert upstream.parse_ctid_listing(listing).folder == "attack-16.1"


def test_parse_attack_index__non_ascii_digit_version_with_higher_value__is_ignored():
    doc = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {"version": _NON_ASCII_VERSION, "url": upstream.ATTACK_URL_PREFIX + "master/x-99.json"},
                    {"version": "19.2", "url": upstream.ATTACK_URL_PREFIX + "master/x-19.2.json"},
                ],
            }
        ]
    }
    index = upstream.parse_attack_index(doc)
    assert index.latest.version == "19.2"
    assert set(index.release_dates) == {"19.2"}


def test_parse_attack_index__non_ascii_digit_release_date__records_none():
    doc = {
        "collections": [
            {
                "name": "Enterprise ATT&CK",
                "versions": [
                    {
                        "version": "19.2",
                        "url": upstream.ATTACK_URL_PREFIX + "master/x-19.2.json",
                        "modified": _NON_ASCII_DATE + "T21:33:58Z",
                    }
                ],
            }
        ]
    }
    assert upstream.parse_attack_index(doc).release_dates == {"19.2": None}


def test_parse_attack__non_ascii_digit_created__records_none(tmp_path):
    # Stored, this would compare after every ASCII release date ("٢" sorts above "2"), so
    # the technique would always read as newer than the mapping.
    from stig_mcp.ingest.attack_parser import parse_attack  # noqa: PLC0415

    bundle = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Hostile Date",
                "created": _NON_ASCII_DATE + "T12:00:00.000Z",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1997"}],
            }
        ]
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    assert parse_attack(path).techniques[0].created is None


def _zip_bytes(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_classify__cui_named_file_in_sources__refuses_and_names_it(tmp_path):
    (tmp_path / "U_Public_V1R1_STIG.zip").write_bytes(_zip_bytes({"a.txt": b"x"}))
    (tmp_path / "CUI_Secret_V1R1_STIG.zip").write_bytes(_zip_bytes({"a.txt": b"x"}))
    with pytest.raises(inventory.CuiContentError, match="CUI_Secret_V1R1_STIG.zip"):
        inventory.classify(tmp_path)


def test_classify__cui_loose_xccdf__refuses_regardless_of_case(tmp_path):
    (tmp_path / "cui_thing-xccdf.xml").write_text("<Benchmark/>")
    with pytest.raises(inventory.CuiContentError, match="cui_thing-xccdf.xml"):
        inventory.classify(tmp_path)


def test_collect__cui_inner_zip_inside_a_public_compilation__refuses_naming_both(tmp_path):
    inner = _zip_bytes({"U_X/U_X-xccdf.xml": b"<Benchmark/>"})
    library = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    library.write_bytes(_zip_bytes({"CUI_X_V1R1_STIG.zip": inner}))
    artifacts = [inventory.Artifact(kind="library", path=library)]
    with pytest.raises(inventory.CuiContentError, match=r"CUI_X_V1R1_STIG\.zip.*U_SRG-STIG_Library_July_2026\.zip"):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__cui_member_inside_a_public_inner_zip__refuses_naming_the_chain(tmp_path):
    inner = _zip_bytes({"U_Y/CUI_Y-xccdf.xml": b"<Benchmark/>"})
    library = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    library.write_bytes(_zip_bytes({"U_Y_V1R1_STIG.zip": inner}))
    artifacts = [inventory.Artifact(kind="library", path=library)]
    with pytest.raises(
        inventory.CuiContentError,
        match=r"CUI_Y-xccdf\.xml.*U_Y_V1R1_STIG\.zip in U_SRG-STIG_Library_July_2026\.zip",
    ):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__cui_member_inside_a_public_product_zip__refuses_naming_both(tmp_path):
    product = tmp_path / "U_Public_V1R1_STIG.zip"
    product.write_bytes(_zip_bytes({"U_Public/CUI_Public-xccdf.xml": b"<Benchmark/>"}))
    artifacts = [inventory.Artifact(kind="product_zip", path=product)]
    with pytest.raises(inventory.CuiContentError, match=r"CUI_Public-xccdf\.xml.*U_Public_V1R1_STIG\.zip"):
        inventory.collect(artifacts, tmp_path / "out")


def test_source_status__cui_file_in_sources__reports_instead_of_raising(tmp_path):
    (tmp_path / "CUI_Secret_V1R1_STIG.zip").write_bytes(_zip_bytes({"a.txt": b"x"}))
    status = inventory.source_status(tmp_path)
    assert status["STIG benchmarks"] is True


def test_collect__cui_member_with_backslash_separator_in_product_zip__refuses(tmp_path):
    # A POSIX Path splits a name only on "/"; a zip member written on Windows can use "\", and
    # Path(name).name would then return the whole string, hiding the CUI_ prefix.
    member = "U_Public\\CUI_Public-xccdf.xml"
    product = tmp_path / "U_Public_V1R1_STIG.zip"
    product.write_bytes(_zip_bytes({member: b"<Benchmark/>"}))
    artifacts = [inventory.Artifact(kind="product_zip", path=product)]
    with pytest.raises(inventory.CuiContentError, match=re.escape(member)):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__cui_member_with_backslash_separator_in_compilation__refuses(tmp_path):
    member = "U_Y\\CUI_Y-xccdf.xml"
    inner = _zip_bytes({member: b"<Benchmark/>"})
    library = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    library.write_bytes(_zip_bytes({"U_Y_V1R1_STIG.zip": inner}))
    artifacts = [inventory.Artifact(kind="library", path=library)]
    with pytest.raises(inventory.CuiContentError, match=re.escape(member)):
        inventory.collect(artifacts, tmp_path / "out")


def _public_library_holding(tmp_path, name, inner_members):
    library_path = tmp_path / name
    library_path.write_bytes(_zip_bytes({"U_RHEL_9_V1R1_STIG.zip": _zip_bytes(inner_members)}))
    return library_path


def test_extract_stig_xccdfs__public_benchmark_inside_a_cui_inner_zip__refuses_and_writes_nothing(tmp_path):
    # The inner zip's name is the only CUI marking here; its benchmark member is named like
    # public content, so a check on benchmark members alone extracts it into sources/.
    inner = _zip_bytes({"U_RHEL_9/U_RHEL_9_V1R1_Manual-xccdf.xml": (FIX / "rhel9_xccdf.xml").read_bytes()})
    compilation = tmp_path / "U_SRG-STIG_Library_July_2026.zip"
    compilation.write_bytes(_zip_bytes({"CUI_RHEL_9_V1R1_STIG.zip": inner}))
    dest = tmp_path / "sources"
    with pytest.raises(inventory.CuiContentError, match=r"CUI_RHEL_9_V1R1_STIG\.zip"):
        library.extract_stig_xccdfs(compilation, dest)
    assert list(dest.iterdir()) == []


def test_extract_main__cui_named_compilation_argument__exits_naming_it(tmp_path, monkeypatch):
    compilation = _public_library_holding(
        tmp_path,
        "CUI_SRG-STIG_Library_July_2026.zip",
        {"U_RHEL_9/U_RHEL_9_V1R1_Manual-xccdf.xml": (FIX / "rhel9_xccdf.xml").read_bytes()},
    )
    monkeypatch.setattr(config, "SOURCES_DIR", tmp_path / "sources")
    monkeypatch.setattr("sys.argv", ["stig-mcp-extract", str(compilation)])
    with pytest.raises(SystemExit) as excinfo:
        library.main()
    assert excinfo.value.code not in (0, None)
    assert "CUI_SRG-STIG_Library_July_2026.zip" in str(excinfo.value.code)
    assert not (tmp_path / "sources").exists()


def test_collect__cui_document_beside_a_benchmark_in_a_product_zip__refuses_naming_it(tmp_path):
    product = tmp_path / "U_RHEL_9_V1R1_STIG.zip"
    product.write_bytes(
        _zip_bytes(
            {
                "U_RHEL_9/U_RHEL_9_V1R1_Manual-xccdf.xml": b"<Benchmark/>",
                "U_RHEL_9/CUI_RHEL_9_Overview.pdf": b"%PDF",
            }
        )
    )
    artifacts = [inventory.Artifact(kind="product_zip", path=product)]
    with pytest.raises(inventory.CuiContentError, match=r"CUI_RHEL_9_Overview\.pdf"):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__benchmark_under_a_cui_directory_in_a_product_zip__refuses(tmp_path):
    member = "CUI_RHEL_9/U_RHEL_9_V1R1_Manual-xccdf.xml"
    product = tmp_path / "U_RHEL_9_V1R1_STIG.zip"
    product.write_bytes(_zip_bytes({member: b"<Benchmark/>"}))
    artifacts = [inventory.Artifact(kind="product_zip", path=product)]
    with pytest.raises(inventory.CuiContentError, match=re.escape(member)):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__unc_shaped_cui_member_in_a_product_zip__refuses(tmp_path):
    # PureWindowsPath reads "\\srv\..." as a UNC drive and anchor, so its .name is empty and
    # a check on .name alone never sees the CUI_ component.
    member = "\\\\srv\\CUI_RHEL-xccdf.xml"
    product = tmp_path / "U_RHEL_9_V1R1_STIG.zip"
    product.write_bytes(_zip_bytes({member: b"<Benchmark/>"}))
    artifacts = [inventory.Artifact(kind="product_zip", path=product)]
    with pytest.raises(inventory.CuiContentError, match=re.escape(member)):
        inventory.collect(artifacts, tmp_path / "out")


def test_collect__cui_file_that_is_not_a_benchmark_in_a_public_inner_zip__refuses(tmp_path):
    compilation = _public_library_holding(
        tmp_path,
        "U_SRG-STIG_Library_July_2026.zip",
        {"U_RHEL_9/U_RHEL_9_V1R1_Manual-xccdf.xml": b"<Benchmark/>", "U_RHEL_9/CUI_notes.txt": b"notes"},
    )
    artifacts = [inventory.Artifact(kind="library", path=compilation)]
    with pytest.raises(
        inventory.CuiContentError, match=r"CUI_notes\.txt.*U_RHEL_9_V1R1_STIG\.zip in U_SRG-STIG_Library_July_2026\.zip"
    ):
        inventory.collect(artifacts, tmp_path / "out")


def test_parse_listing__tag_with_path_traversal__is_not_a_kb_release():
    entry = {
        "tag_name": "kb-2026-10-04/../../evil",
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": "stig_kb-schema6-2026-10-04.sqlite.xz",
                "size": 1,
                "browser_download_url": f"{releases.DOWNLOAD_PREFIX}kb-2026-10-04/../../evil/x",
            }
        ],
    }
    assert releases.parse_listing([entry]) == []


def test_parse_listing__asset_name_with_path_traversal__is_ignored():
    tag = "kb-2026-10-04"
    name = "../stig_kb-schema6-2026-10-04.sqlite.xz"
    entry = {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [{"name": name, "size": 1, "browser_download_url": f"{releases.DOWNLOAD_PREFIX}{tag}/{name}"}],
    }
    assert releases.parse_listing([entry]) == []


def test_parse_listing__asset_url_outside_the_repository__refuses_the_listing():
    tag = "kb-2026-10-04"
    name = "stig_kb-schema6-2026-10-04.sqlite.xz"
    entry = {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [{"name": name, "size": 1, "browser_download_url": f"https://evil.example/{tag}/{name}"}],
    }
    with pytest.raises(releases.ReleaseError, match="evil.example"):
        releases.parse_listing([entry])


def test_require_allowed__url_outside_the_project_releases__refuses():
    for url in (
        "https://evil.example/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x",
        "http://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x",
        "https://github.com/someone/else/releases/download/kb-2026-10-04/x",
        "https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/%2e%2e/%2e%2e/x",
        "https://api.github.com/repos/jeneric/STIG-MCP/issues",
        "https://user@release-assets.githubusercontent.com/x",
        # "releases" as a path-segment prefix, not the whole segment, is a different endpoint.
        "https://api.github.com/repos/jeneric/STIG-MCP/releasesX/foo",
        # A backslash, raw or percent-encoded, is still a separator on a server that treats it as one.
        "https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/..\\x",
        "https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/%5c..%5cx",
    ):
        with pytest.raises(releases.ReleaseError, match="contacts only"):
            releases.require_allowed(url)


def test_default_opener__redirect_off_the_allowlist__refuses_to_follow():
    handler = releases._AllowlistRedirects()
    request = urllib.request.Request("https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x")
    with pytest.raises(releases.ReleaseError, match="evil.example"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/payload")


class _TrackedFp:
    """A response object whose close() call the test can observe."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_default_opener__redirect_off_the_allowlist__closes_the_response_first():
    handler = releases._AllowlistRedirects()
    request = urllib.request.Request("https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x")
    fp = _TrackedFp()
    with pytest.raises(releases.ReleaseError, match="evil.example"):
        handler.redirect_request(request, fp, 302, "Found", {}, "https://evil.example/payload")
    assert fp.closed


def test_default_opener__protocol_relative_location_header__refuses():
    handler = releases._AllowlistRedirects()
    request = urllib.request.Request("https://github.com/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x")
    headers = email.message.Message()
    headers["Location"] = "//evil.example/x"
    with pytest.raises(releases.ReleaseError, match="evil.example"):
        handler.http_error_302(request, None, 302, "Found", headers)


def test_download_to__response_landed_off_the_allowlist__refuses(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    url = release.url(release.kb_asset)
    github.redirects[url] = "https://evil.example/payload"
    with pytest.raises(releases.ReleaseError, match="evil.example") as excinfo:
        releases.download_to(url, tmp_path / "x.xz", github)
    # The request landed (unlike require_allowed's pre-request refusal), so the message must
    # not claim nothing was requested.
    assert "nothing was requested there" not in str(excinfo.value)


def test_download_to__asset_larger_than_the_cap__stops_and_refuses(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    url = release.url(release.kb_asset)
    github.bodies[url] = b"\0" * (releases.CHUNK * 3)
    with pytest.raises(releases.ReleaseError, match=r"2\.0 MB cap") as excinfo:
        releases.download_to(url, tmp_path / "x.xz", github, cap=releases.CHUNK * 2)
    # Only the caller staging the file knows whether anything was ultimately installed.
    assert "nothing was installed" not in str(excinfo.value)


def test_download_to__asset_larger_than_a_sub_megabyte_cap__reports_bytes_not_0_mb(tmp_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    url = release.url(release.kb_asset)
    github.bodies[url] = b"\0" * 100
    with pytest.raises(releases.ReleaseError, match=r"10 bytes cap"):
        releases.download_to(url, tmp_path / "x.xz", github, cap=10)


def test_list_releases__rate_limited__says_so_with_the_reset_time():
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = http_error(
        releases.LISTING_URL, 403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790559566"}
    )
    with pytest.raises(releases.ReleaseError, match="resets at 2026-09-28"):
        releases.list_releases(github)


@pytest.mark.parametrize(
    "reset",
    [
        "99999999999999999",  # too large for gmtime on some platforms: OSError
        "²",  # str.isdigit() but int() rejects it: ValueError
        "9" * 400,  # digits, but far too large for gmtime: OverflowError
    ],
)
def test_list_releases__rate_limit_reset_header_is_hostile__still_names_the_limit(reset):
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = http_error(
        releases.LISTING_URL, 403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset}
    )
    with pytest.raises(releases.ReleaseError, match="60 unauthenticated requests"):
        releases.list_releases(github)


def test_explain__rate_limited__names_the_reset_time_and_the_offline_route():
    exc = http_error(releases.LISTING_URL, 403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790559566"})
    message = releases.explain(exc, releases.LISTING_URL)
    assert "60 unauthenticated requests" in message
    assert "2026-09-28" in message
    assert "--file" in message


def test_explain__tls_failure_inside_urlerror__names_the_os_store():
    exc = urllib.error.URLError(ssl.SSLError(1, "CERTIFICATE_VERIFY_FAILED"))
    message = releases.explain(exc, releases.LISTING_URL)
    assert "operating system's certificate store" in message
    assert "inspecting proxy" in message
    assert "SSL_CERT_FILE" in message
    assert "HTTPS_PROXY" not in message


def test_explain__unreachable__names_the_host_and_the_offline_route():
    exc = urllib.error.URLError(OSError("Name or service not known"))
    message = releases.explain(exc, releases.LISTING_URL)
    assert "Could not reach api.github.com" in message
    assert "--file" in message


def test_explain__tls_verification_fails__points_at_the_os_store_not_python():
    # The old advice sent a corporate user to edit Python's store, which truststore never reads.
    exc = urllib.error.URLError(ssl.SSLError(1, "CERTIFICATE_VERIFY_FAILED"))
    message = releases.explain(exc, releases.LISTING_URL)
    assert "operating system's certificate store" in message
    assert "Python's trust store" not in message
    assert "HTTPS_PROXY" not in message
    assert "TLS connection to api.github.com failed" in message
    assert message.endswith(releases.OFFLINE)


def _installed_state(data_dir):
    return {p.name: p.read_bytes() for p in data_dir.iterdir()}


def _data_dir_with_a_kb(tmp_path, kb_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    shutil.copyfile(kb_path, data_dir / "stig_kb.sqlite")
    return data_dir


def test_install_file__checksum_mismatch__refuses_and_leaves_the_installed_kb(tmp_path, kb_path):
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(kb_path.read_bytes()))
    with pytest.raises(install.InstallError, match="Re-download"):
        install.install_file(source, "0" * 64, data_dir / "stig_kb.sqlite")
    assert _installed_state(data_dir) == before


def test_install_file__xz_bomb_over_the_cap__refuses_and_leaves_nothing_behind(tmp_path, kb_path, monkeypatch):
    monkeypatch.setattr(install, "DECOMPRESSED_CAP", 1024 * 1024)
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    bomb = tmp_path / "bomb.sqlite.xz"
    bomb.write_bytes(lzma.compress(b"\0" * (3 * 1024 * 1024)))
    with pytest.raises(install.InstallError, match="512 MB|cap"):
        install.install_file(bomb, hashlib.sha256(bomb.read_bytes()).hexdigest(), data_dir / "stig_kb.sqlite")
    assert _installed_state(data_dir) == before


def test_install_file__corrupt_sqlite__refuses_and_leaves_the_installed_kb(tmp_path, kb_path):
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(install.SQLITE_MAGIC + b"\xff" * 8192)
    with pytest.raises(install.InstallError, match="not an intact"):
        install.install_file(corrupt, hashlib.sha256(corrupt.read_bytes()).hexdigest(), data_dir / "stig_kb.sqlite")
    assert _installed_state(data_dir) == before


def test_install_file__knowledge_base_for_another_schema__refuses_naming_both(tmp_path, kb_path):
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    old = tmp_path / "old.sqlite"
    shutil.copyfile(kb_path, old)
    with sqlite3.connect(old) as conn:
        conn.execute("UPDATE ingest_meta SET schema_version = '5'")
    conn.close()
    with pytest.raises(install.InstallError, match=r"schema 5.*schema 6"):
        install.install_file(old, hashlib.sha256(old.read_bytes()).hexdigest(), data_dir / "stig_kb.sqlite")
    assert _installed_state(data_dir) == before


def test_install_file__index_corruption_detected_by_integrity_check__refuses_and_leaves_the_installed_kb(
    tmp_path, kb_path
):
    """A real corrupted knowledge base, not a hand-built one: an autoindex root page has one byte
    of a row's key flipped, so integrity_check reports the row missing from its index without
    sqlite3 raising DatabaseError first (as the header-garbage corrupt_sqlite test above does)."""
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    corrupt = tmp_path / "corrupt.sqlite"
    shutil.copyfile(kb_path, corrupt)
    with sqlite3.connect(corrupt) as conn:
        rootpage = conn.execute(
            "SELECT rootpage FROM sqlite_master WHERE name='sqlite_autoindex_ingest_meta_1'"
        ).fetchone()[0]
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        source_name = conn.execute("SELECT source_name FROM ingest_meta LIMIT 1").fetchone()[0]
    conn.close()
    raw = bytearray(corrupt.read_bytes())
    start, end = (rootpage - 1) * page_size, rootpage * page_size
    at = raw.find(source_name.encode(), start, end)
    assert at != -1
    raw[at] ^= 0x20
    corrupt.write_bytes(bytes(raw))
    with pytest.raises(install.InstallError, match=r"integrity_check: .*missing from index"):
        install.install_file(corrupt, hashlib.sha256(corrupt.read_bytes()).hexdigest(), data_dir / "stig_kb.sqlite")
    assert _installed_state(data_dir) == before


def _retag_sha256(github, release, name, hexdigest):
    """Set release.json's sha256[name] to hexdigest, keeping it self-consistent so the
    manifest-agreement check (which runs before any download) does not preempt a test aimed
    at a later check."""
    meta = json.loads(github.bodies[release.url(releases.RELEASE_JSON_NAME)])
    meta["sha256"][name] = hexdigest
    github.bodies[release.url(releases.RELEASE_JSON_NAME)] = json.dumps(meta).encode()


def test_install_release__xz_asset_is_not_xz_at_all__refuses_before_decompressing(tmp_path, kb_path, monkeypatch):
    """Pins the check order in _download_verified: the xz asset's hash is checked against
    SHA256SUMS before anything is fed to the decompressor. release.json and SHA256SUMS are left
    exactly as published (mutually consistent); only the served asset bytes are swapped for
    non-xz junk, so the only way to catch this is the download hash check, and _decompress must
    never be reached."""
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    [release] = releases.list_releases(github)
    github.bodies[release.url(release.kb_asset)] = b"this is not xz data at all"

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("must not decompress before the xz hash is verified")

    monkeypatch.setattr(install, "_decompress", _must_not_be_called)
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    with pytest.raises(install.InstallError, match="downloaded with SHA-256"):
        install.install_release(data_dir / "stig_kb.sqlite", opener=github)
    assert _installed_state(data_dir) == before


def test_install_release__release_json_sha256_disagrees_with_sha256sums__refuses(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    [release] = releases.list_releases(github)
    _retag_sha256(github, release, "xz", "0" * 64)
    with pytest.raises(install.InstallError, match="inconsistent"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)
    assert release.url(release.kb_asset) not in github.requested


def test_install_release__sha256sums_disagrees_with_the_download__refuses_and_leaves_the_kb(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    [release] = releases.list_releases(github)
    sqlite_sha = hashlib.sha256(kb_path.read_bytes()).hexdigest()
    github.bodies[release.url(releases.SUMS_NAME)] = (
        f"{'0' * 64}  {release.kb_asset}\n{sqlite_sha}  {release.sqlite_name}\n".encode()
    )
    _retag_sha256(github, release, "xz", "0" * 64)
    data_dir = _data_dir_with_a_kb(tmp_path, kb_path)
    before = _installed_state(data_dir)
    with pytest.raises(install.InstallError, match="downloaded with SHA-256"):
        install.install_release(data_dir / "stig_kb.sqlite", opener=github)
    assert _installed_state(data_dir) == before


def test_install_release__decompressed_file_disagrees_with_sha256sums__refuses(tmp_path, kb_path):
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    [release] = releases.list_releases(github)
    xz_sha = hashlib.sha256(github.bodies[release.url(release.kb_asset)]).hexdigest()
    github.bodies[release.url(releases.SUMS_NAME)] = (
        f"{xz_sha}  {release.kb_asset}\n{'0' * 64}  {release.sqlite_name}\n".encode()
    )
    _retag_sha256(github, release, "sqlite", "0" * 64)
    with pytest.raises(install.InstallError, match=r"decompressed.*report it if it repeats"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", opener=github)


def test_install_release__pinned_tag_github_answers_404__refuses_naming_the_tag(tmp_path):
    with pytest.raises(releases.ReleaseError, match=r"No published release kb-2099-01-01"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", release="kb-2099-01-01", opener=FakeGitHub())


def test_install_release__tag_url_answers_with_a_different_release__refuses_the_mismatch(tmp_path, kb_path):
    """list_releases's tag branch must re-check the release it got back against the tag it
    asked for, not just trust that the URL it fetched named that tag."""
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    other = github.publish("kb-2026-10-11", kb_path.read_bytes())
    github.bodies[releases.TAG_URL.format(tag="kb-2026-10-04")] = json.dumps(other).encode()
    with pytest.raises(releases.ReleaseError, match=r"kb-2026-10-04.*kb-2026-10-11"):
        install.install_release(tmp_path / "data" / "stig_kb.sqlite", release="kb-2026-10-04", opener=github)


def test_install_file__source_swapped_after_it_was_verified__installs_the_verified_bytes(
    tmp_path, kb_path, monkeypatch
):
    """The file whose SHA-256 was checked must be the file installed. The source is replaced
    with another valid knowledge base right after the first hash, as a writer racing the install
    would; reading the source again after that hash would install the unverified replacement."""
    verified = kb_path.read_bytes()
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(verified))
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    other = tmp_path / "other.sqlite"
    shutil.copyfile(kb_path, other)
    with contextlib.closing(sqlite3.connect(other)) as conn, conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'swapped in after the hash'")
    swapped = lzma.compress(other.read_bytes())
    real_sha256 = install.file_sha256
    calls = []

    def hash_then_swap(path):
        digest = real_sha256(path)
        if not calls:
            source.write_bytes(swapped)
        calls.append(path)
        return digest

    monkeypatch.setattr(install, "file_sha256", hash_then_swap)
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_file(source, expected, target)
    assert calls
    assert target.read_bytes() == verified


def test_install_file__source_changed_back_after_it_was_copied__refuses_the_unverified_copy(
    tmp_path, kb_path, monkeypatch
):
    """The other side of the same race: the copy holds unverified bytes and the source is put back
    to the verified ones before the hash. Hashing the source rather than the copy passes it."""
    verified = lzma.compress(kb_path.read_bytes())
    other = tmp_path / "other.sqlite"
    shutil.copyfile(kb_path, other)
    with contextlib.closing(sqlite3.connect(other)) as conn, conn:
        conn.execute("UPDATE ingest_meta SET ingested_at = 'copied before the hash'")
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(lzma.compress(other.read_bytes()))
    real_copy = install.shutil.copyfileobj

    def copy_then_restore(fsrc, fdst, *args):
        real_copy(fsrc, fdst, *args)
        source.write_bytes(verified)

    monkeypatch.setattr(install.shutil, "copyfileobj", copy_then_restore)
    target = tmp_path / "data" / "stig_kb.sqlite"
    with pytest.raises(install.InstallError, match="Re-download"):
        install.install_file(source, hashlib.sha256(verified).hexdigest(), target)
    assert not target.exists()


def test_list_releases__tag_lookup_answers_a_draft_under_another_tag__reports_the_mismatch(tmp_path, kb_path):
    """A draft is dropped by parse_listing, so comparing tags only after parsing would find no
    release at all and say the tag holds no knowledge base, hiding that GitHub answered for
    another tag."""
    github = FakeGitHub()
    github.publish("kb-2026-10-04", kb_path.read_bytes())
    draft = github.publish("kb-2026-10-11", kb_path.read_bytes(), draft=True)
    github.bodies[releases.TAG_URL.format(tag="kb-2026-10-04")] = json.dumps(draft).encode()
    with pytest.raises(releases.ReleaseError, match=r"lookup for kb-2026-10-04 answered with 'kb-2026-10-11'"):
        releases.list_releases(github, tag="kb-2026-10-04")


def test_list_releases__tls_failure__names_the_os_store_and_the_offline_route():
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = urllib.error.URLError(ssl.SSLError(1, "CERTIFICATE_VERIFY_FAILED"))
    with pytest.raises(releases.ReleaseError, match=r"operating system's certificate store.*--file PATH --sha256 HEX"):
        releases.list_releases(github)


def test_list_releases__host_unreachable__names_the_host_and_the_offline_route():
    github = FakeGitHub()
    github.bodies[releases.LISTING_URL] = urllib.error.URLError(OSError("Name or service not known"))
    with pytest.raises(releases.ReleaseError, match=r"Could not reach api\.github\.com.*--file PATH --sha256 HEX"):
        releases.list_releases(github)


def test_require_allowed__allowed_host_with_an_explicit_port__refuses():
    with pytest.raises(releases.ReleaseError, match="contacts only"):
        releases.require_allowed("https://github.com:443/jeneric/STIG-MCP/releases/download/kb-2026-10-04/x")


def test_decompress__trailing_data_after_a_stream_ending_on_a_chunk_boundary__refuses(tmp_path, monkeypatch):
    """With the stream ending exactly where a read ends, the trailing bytes are never handed to
    the decompressor, so unused_data is empty and only reading past the stream finds them."""
    stream = lzma.compress(b"hello world" * 1000)
    source = tmp_path / "kb.sqlite.xz"
    source.write_bytes(stream + b"GARBAGE")
    monkeypatch.setattr(install, "CHUNK", len(stream))
    with pytest.raises(install.InstallError, match="holds data after its xz stream"):
        install._decompress(source, tmp_path / "candidate.sqlite")


def test_parse_release_json__upstream_value_over_the_limit__is_dropped():
    github = FakeGitHub()
    github.publish("kb-2026-10-04", b"kb bytes")
    [release] = releases.list_releases(github)
    doc = {
        "schema": "6",
        "built_with": "0.2.0",
        "sha256": {"xz": "a" * 64, "sqlite": "b" * 64},
        "upstream": {"kept": "k" * 100, "dropped": "d" * 101},
    }
    assert releases.parse_release_json(doc, release)["upstream"] == {"kept": "k" * 100}


@pytest.mark.parametrize("name", ["kb#1.sqlite", "kb%41.sqlite", "kb?x.sqlite"])
def test_install_file__file_name_with_uri_characters__installs_it(tmp_path, kb_path, name):
    """The candidate is opened through a SQLite file: URI, where # ends the path, ? starts the
    query and % escapes a byte; a name holding one must still install, not be refused or crash."""
    source = tmp_path / name
    shutil.copyfile(kb_path, source)
    target = tmp_path / "data" / "stig_kb.sqlite"
    install.install_file(source, hashlib.sha256(kb_path.read_bytes()).hexdigest(), target)
    assert target.read_bytes() == kb_path.read_bytes()


def test_install_file__data_directory_with_uri_characters__installs_it(tmp_path, kb_path):
    target = tmp_path / "data#1 %41?x" / "stig_kb.sqlite"
    install.install_file(kb_path, hashlib.sha256(kb_path.read_bytes()).hexdigest(), target)
    assert target.read_bytes() == kb_path.read_bytes()


def test_install_file__refusals_after_staging__name_the_operators_file(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_bytes(b"hello")
    with pytest.raises(install.InstallError, match=r"notes\.txt is neither"):
        install.install_file(notes, hashlib.sha256(b"hello").hexdigest(), tmp_path / "data" / "stig_kb.sqlite")
    garbage = tmp_path / "mine.sqlite.xz"
    garbage.write_bytes(lzma.compress(b"hello") + b"GARBAGE")
    with pytest.raises(install.InstallError, match=r"mine\.sqlite\.xz holds data after its xz stream"):
        install.install_file(
            garbage, hashlib.sha256(garbage.read_bytes()).hexdigest(), tmp_path / "data" / "stig_kb.sqlite"
        )


_PGPASS = b"db.internal:5432:*:app:hunter2\n"
_NO_SUCH_ACCOUNT = "~nosuchuser-stig-mcp/.pgpass"


def _pgpass(tmp_path):
    secret = tmp_path / ".pgpass"
    secret.write_bytes(_PGPASS)
    return secret


def _is_file_raising(code):
    """Path.is_file as Python 3.11 to 3.13 ship it: an errno outside ENOENT, ENOTDIR, EBADF and
    ELOOP propagates instead of answering False. 3.14 swallows it, so CI would never see it."""
    real = pathlib.Path.is_file

    def is_file(self, *args, **kwargs):
        if self.parent.name == "private":
            raise OSError(code, os.strerror(code), str(self))
        return real(self, *args, **kwargs)

    return is_file


def _probe_wrong_sha(tmp_path, monkeypatch):
    return str(_pgpass(tmp_path)), "0" * 64


def _probe_right_sha_not_a_kb(tmp_path, monkeypatch):
    return str(_pgpass(tmp_path)), hashlib.sha256(_PGPASS).hexdigest()


def _probe_directory(tmp_path, monkeypatch):
    (tmp_path / ".pgpass").mkdir()
    return str(tmp_path / ".pgpass"), "0" * 64


def _probe_unreadable(tmp_path, monkeypatch):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("needs a POSIX user that file permissions apply to")
    secret = _pgpass(tmp_path)
    secret.chmod(0)
    return str(secret), "0" * 64


def _probe_stat_permission_denied(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "is_file", _is_file_raising(errno.EACCES))
    return str(tmp_path / "private" / ".pgpass"), "0" * 64


def _probe_stat_name_too_long(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "is_file", _is_file_raising(errno.ENAMETOOLONG))
    return str(tmp_path / "private" / ".pgpass"), "0" * 64


def _probe_no_such_account(tmp_path, monkeypatch):
    try:
        pathlib.Path(_NO_SUCH_ACCOUNT).expanduser()
    except RuntimeError:
        return _NO_SUCH_ACCOUNT, "0" * 64
    pytest.skip("expanduser does not raise for an unknown account on this platform")


def _probe_embedded_null_in_account(tmp_path, monkeypatch):
    return "~\x00/.pgpass", "0" * 64


def _probe_read_fails_midway(tmp_path, monkeypatch):
    def copy_failing(source, out, *args, **kwargs):
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(install.shutil, "copyfileobj", copy_failing)
    return str(_pgpass(tmp_path)), "0" * 64


_PROBE_SHAS = ("0" * 64, hashlib.sha256(_PGPASS).hexdigest())


def _mcp_refusal(tmp_path, path, sha256):
    kb = app_module.KnowledgeBase(tmp_path / "data" / "stig_kb.sqlite")
    with pytest.raises(tools.CallerError) as refused:
        tools.install_knowledge_base(kb, path=path, sha256=sha256, opener=refuse_network)
    return str(refused.value)


@pytest.mark.parametrize(
    "probe",
    [
        _probe_wrong_sha,
        _probe_right_sha_not_a_kb,
        _probe_directory,
        _probe_unreadable,
        _probe_stat_permission_denied,
        _probe_stat_name_too_long,
        _probe_no_such_account,
        _probe_embedded_null_in_account,
        _probe_read_fails_midway,
    ],
)
def test_install_knowledge_base__probing_a_credential_file__refuses_exactly_as_for_a_missing_file(
    tmp_path, monkeypatch, probe
):
    # The baseline is tmp_path/.pgpass before the probe creates anything there: the same path
    # for every probe that puts something on disk, and the same basename for the four that
    # cannot use it (the stat probes key on a "private" parent, the account probes need a ~).
    baselines = {sha: _mcp_refusal(tmp_path, str(tmp_path / ".pgpass"), sha) for sha in _PROBE_SHAS}
    path, sha256 = probe(tmp_path, monkeypatch)
    refusal = _mcp_refusal(tmp_path, path, sha256)
    assert refusal == baselines[sha256]
    assert str(tmp_path) not in refusal
    assert str(pathlib.Path.home()) not in refusal


def test_install_knowledge_base__data_directory_cannot_be_staged_in__says_so_alike_for_present_and_absent_files(
    tmp_path,
):
    """Staging never reads the caller's file, so its failure can name the data directory without
    telling the caller anything about the path it passed."""
    blocker = tmp_path / "data"
    blocker.write_bytes(b"a file where the data directory should be")
    kb = app_module.KnowledgeBase(blocker / "stig_kb.sqlite")
    refusals = []
    for path in (_pgpass(tmp_path), tmp_path / "absent" / ".pgpass"):
        with pytest.raises(tools.CallerError) as refused:
            tools.install_knowledge_base(kb, path=str(path), sha256="0" * 64, opener=refuse_network)
        refusals.append(str(refused.value))
    assert refusals[0] == refusals[1]
    assert "Could not create a staging directory" in refusals[0]


def test_main__checksum_mismatch__still_tells_the_operator_the_files_actual_sha256(tmp_path, monkeypatch, capsys):
    """The MCP caller gets one fixed refusal; the operator at the CLI keeps the detail, since
    whoever can run the CLI can already run sha256sum on the file."""
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    assert install.main(["--file", str(_pgpass(tmp_path)), "--sha256", "0" * 64]) == 1
    assert f"has SHA-256 {hashlib.sha256(_PGPASS).hexdigest()}" in capsys.readouterr().err


def test_main__unknown_account_in_the_path__refuses_instead_of_crashing(tmp_path, monkeypatch, capsys):
    _probe_no_such_account(tmp_path, monkeypatch)
    monkeypatch.setattr(install.config, "KB_PATH", tmp_path / "data" / "stig_kb.sqlite")
    assert install.main(["--file", _NO_SUCH_ACCOUNT, "--sha256", "0" * 64]) == 1
    assert "nosuchuser-stig-mcp" in capsys.readouterr().err


def test_package__a_notice_name_that_leaves_the_output_directory__is_written_inside_it(tmp_path, kb_path):
    """Notice names come from the database, which a release consumer never trusts; the packager
    must not either. The name is flattened to its last component."""
    from tools import kb_package  # noqa: PLC0415

    built = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, built)
    conn = sqlite3.connect(built)
    # The fixture's licenses/apache-2.0.txt also has a "/" in its name; unflattened, its write
    # would raise FileNotFoundError before the escape assertion below ever ran, which would
    # make an unguarded name look refused for the wrong reason. Removed so the only "/"-bearing
    # name left is the one this test is about.
    conn.execute("DELETE FROM notices WHERE name LIKE '%/%'")
    conn.execute("INSERT INTO notices(name, text) VALUES ('../../escaped.txt', 'x')")
    conn.commit()
    conn.close()
    kb_package.package(built, tmp_path / "out" / "release", "kb-2026-09-28", "0.1.0", tmp_path)
    assert not (tmp_path / "escaped.txt").exists()
    assert (tmp_path / "out" / "release" / "escaped.txt").read_text() == "x"


def test_package__two_notices_with_one_flat_name__are_refused(tmp_path, kb_path):
    from tools import kb_package  # noqa: PLC0415

    built = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, built)
    conn = sqlite3.connect(built)
    conn.execute("INSERT INTO notices(name, text) VALUES ('other/NOTICE', 'shadow')")
    conn.commit()
    conn.close()
    with pytest.raises(kb_package.PackageError, match="NOTICE"):
        kb_package.package(built, tmp_path / "release", "kb-2026-09-28", "0.1.0", tmp_path)


_XZ_ASSET_NAME = f"stig_kb-schema{SCHEMA_VERSION}-2026-09-28.sqlite.xz"  # matches the "kb-2026-09-28" tag below


_RESERVED_NOTICE_NAMES = ["SHA256SUMS", "release.json", "other/release.json", _XZ_ASSET_NAME, "notes.md", "assets.txt"]


@pytest.mark.parametrize("name", ["..", ".", "", *_RESERVED_NOTICE_NAMES])
def test_package__a_notice_name_whose_flat_form_is_dot_empty_or_reserved__is_refused(tmp_path, kb_path, name):
    """Path(name).name can itself be "", "." or "..": none of those is writable as a release
    asset's file name, so the same guard that stops a shadowing name must also stop these.

    A notice flattening to SHA256SUMS, release.json or the .sqlite.xz asset is the same threat
    with a real payoff. package() writes SHA256SUMS, and the .xz itself, before it writes
    notices, so an unguarded notice of either name would silently overwrite that file with notice
    text after its hash was already recorded in SHA256SUMS and release.json; release.json is
    written after notices, so the same rule covers its name too rather than depending on write
    order. notes.md and assets.txt are written by kb_release.build into the same directory after
    package() returns, so a notice of either name would be overwritten, or would itself become
    the upload list. _RESERVED, plus the xz asset's own name passed in for this build, is what
    stops all of them."""
    from tools import kb_package  # noqa: PLC0415

    built = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, built)
    conn = sqlite3.connect(built)
    conn.execute("INSERT INTO notices(name, text) VALUES (?, 'x')", (name,))
    conn.commit()
    conn.close()
    with pytest.raises(kb_package.PackageError, match="empty or already"):
        kb_package.package(built, tmp_path / "release", "kb-2026-09-28", "0.1.0", tmp_path)


def test_verify__a_hand_placed_cui_archive_in_the_sources__refuses_the_release(tmp_path, kb_path):
    """The ingest refuses CUI_ names itself (library.refuse_cui); this is the release's own line:
    nothing the fetch did not record may reach a published knowledge base."""
    from stig_mcp.ingest import catalog, fetch  # noqa: PLC0415
    from tools import kb_verify  # noqa: PLC0415

    copy = tmp_path / "kb.sqlite"
    shutil.copyfile(kb_path, copy)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_Foo_V1R1_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(sources, [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)])
    (sources / "CUI_Something_V1R1_STIG.zip").write_bytes(b"z")
    with pytest.raises(kb_verify.VerifyError, match="CUI_Something_V1R1_STIG.zip"):
        kb_verify.verify(copy, sources, golden=())


def test_decide__a_draft_whose_tag_is_not_a_kb_tag__is_never_scheduled_for_deletion():
    """delete_drafts feeds a DELETE call in the workflow. Only kb-YYYY-MM-DD drafts qualify,
    matched in full, so a package draft or a crafted tag name cannot be swept up. Nor can a
    non-positive-int id: True and False are ints in Python (bool subclasses int), and 0 or a
    negative id is never a real release id, so each must be refused the same as a string id."""
    from tools import kb_release  # noqa: PLC0415

    listing = [
        {"id": 1, "tag_name": "kb-2026-09-29", "draft": True, "prerelease": False, "assets": []},
        {"id": 2, "tag_name": "kb-2026-09-29/../v0.1.0", "draft": True, "prerelease": False, "assets": []},
        {"id": 3, "tag_name": "v0.1.0", "draft": True, "prerelease": False, "assets": []},
        {"id": 4, "tag_name": "kb-2026-09-28", "draft": False, "prerelease": False, "assets": []},
        {"id": "5; rm", "tag_name": "kb-2026-09-27", "draft": True, "prerelease": False, "assets": []},
        {"id": True, "tag_name": "kb-2026-09-26", "draft": True, "prerelease": False, "assets": []},
        {"id": 0, "tag_name": "kb-2026-09-25", "draft": True, "prerelease": False, "assets": []},
        {"id": -1, "tag_name": "kb-2026-09-24", "draft": True, "prerelease": False, "assets": []},
    ]
    decision = kb_release.decide(listing, 10, "schedule", None, "2026-10-05", "0.1.0")
    assert decision["delete_drafts"] == [1]
