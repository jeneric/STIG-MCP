import copy
import json
import urllib.parse
from pathlib import Path

import pytest

from stig_mcp.ingest import catalog
from tools import corpus_manifest


@pytest.mark.parametrize(
    "name,expected",
    [
        # Real filenames taken verbatim from the published directory listing.
        ("U_A10_Networks_ADC_Y24M07_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_Apple_macOS_15_V1R7_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_Kubernetes_V2R6_STIG.zip", corpus_manifest.BENCHMARK),
        ("U_SRG-STIG_Library_July_2026.zip", corpus_manifest.COMPILATION),
        ("U_Rev_4_SRG-STIG_Sunset_Compilation.zip", corpus_manifest.COMPILATION),
        ("U_MS_Windows_11_V2R9_STIG_SCAP_1-3_Benchmark.zip", corpus_manifest.ADVERSARIAL),
        ("U_CAN_Ubuntu_22-04_LTS_V2R9_STIG_Ansible.zip", corpus_manifest.ADVERSARIAL),
        ("U_CAN_Ubuntu_24-04_LTS_V1R6_STIG_Chef.zip", corpus_manifest.ADVERSARIAL),
        ("U_MS_Windows_Server_2016_V1R3_STIG_PowerShell_DSC.zip", corpus_manifest.ADVERSARIAL),
        ("U_AAA_Services_V2R2_SRG.zip", corpus_manifest.ADVERSARIAL),
        ("U_Intune_Policy_Package_July_2026.zip", corpus_manifest.ADVERSARIAL),
        ("U_July 2024 Quarterly Release Automated Benchmarks.zip", corpus_manifest.ADVERSARIAL),
        ("OneDrive_1_7-10-2026.zip", corpus_manifest.JUNK),
        ("CCI_List.zip", corpus_manifest.JUNK),
        ("RPM-GPG-KEY-SCC-5.11", None),
        ("SCC_5.11_UNIX_Remote_Scanning_Plugin.scc", None),
    ],
)
def test_tier_of__a_published_filename__lands_in_the_right_tier(name, expected):
    assert corpus_manifest.tier_of(name) == expected


def test_tier_of__a_cui_filename__refuses_with_the_credential_reason():
    with pytest.raises(ValueError) as excinfo:
        corpus_manifest.tier_of("CUI_Some_Restricted_V1R1_STIG.zip")
    message = str(excinfo.value)
    assert "CUI" in message
    assert "CAC" in message


@pytest.mark.parametrize(
    "name",
    ["U_Rev_4_SRG-STIG_Sunset_Compilation.zip", "U_SRG-STIG_Library_July_2026.zip"],
)
def test_tier_of__a_compilation_named_with_srg_stig__is_a_compilation_not_adversarial(name):
    # Both compilations are named with the hyphenated pair "SRG-STIG". That contains "_srg",
    # which is an adversarial marker, and it does NOT contain "_stig", because the g is
    # followed by a hyphen. So both the marker check and the "_stig" check get these wrong,
    # and the compilation check has to run before either. Getting this backwards discards
    # the two richest sources in the corpus as requirements guides.
    assert corpus_manifest.tier_of(name) == corpus_manifest.COMPILATION


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
LISTING_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"


def _listing_html():
    return (FIXTURES / "corpus_autoindex.html").read_text(encoding="utf-8")


def test_parse_listing__an_autoindex_page__returns_files_and_skips_navigation():
    entries = corpus_manifest.parse_listing(_listing_html())
    names = [name for name, _ in entries]
    assert "U_Apple_macOS_15_V1R7_STIG.zip" in names
    # Column-sort links and the parent link are not files.
    assert not any(name.startswith("?") for name in names)
    assert "Parent Directory" not in names
    assert not any(name.endswith("/") for name in names)


def test_parse_listing__a_percent_encoded_name__decodes_the_name_and_keeps_the_href():
    # The published directory really does contain a filename with spaces in it. The decoded
    # name is what the tier rules read; the encoded href is what has to go back on the wire.
    entries = dict(corpus_manifest.parse_listing(_listing_html()))
    assert "U_July 2024 Quarterly Release Automated Benchmarks.zip" in entries
    assert entries["U_July 2024 Quarterly Release Automated Benchmarks.zip"] == (
        "U_July%202024%20Quarterly%20Release%20Automated%20Benchmarks.zip"
    )


def test_build_manifest__a_parsed_listing__tiers_every_entry_and_drops_non_archives():
    manifest = corpus_manifest.build_manifest(LISTING_URL, corpus_manifest.parse_listing(_listing_html()))
    assert manifest["source_url"] == LISTING_URL
    tiers = {entry["name"]: entry["tier"] for entry in manifest["entries"]}
    assert tiers["U_Apple_macOS_15_V1R7_STIG.zip"] == corpus_manifest.BENCHMARK
    assert tiers["U_MS_Windows_11_V2R9_STIG_SCAP_1-3_Benchmark.zip"] == corpus_manifest.ADVERSARIAL
    assert tiers["OneDrive_1_7-10-2026.zip"] == corpus_manifest.JUNK
    # Not an archive, so it is not in the manifest at all.
    assert "RPM-GPG-KEY-SCC-5.11" not in tiers
    assert all(entry["sha256"] is None and entry["size"] is None for entry in manifest["entries"])


def test_build_manifest__a_cui_entry_in_the_listing__is_skipped_and_counted_not_aborted():
    # tier_of() itself stays fail-closed and raises; main() fetches the listing over HTTP, so
    # an operator cannot "remove it from the listing input" the way the raise's message
    # suggests. One CUI_ entry must not discard every other entry in the directory.
    entries = [
        ("U_Apple_macOS_15_V1R7_STIG.zip", "U_Apple_macOS_15_V1R7_STIG.zip"),
        ("CUI_Restricted_V1R1_STIG.zip", "CUI_Restricted_V1R1_STIG.zip"),
    ]
    manifest = corpus_manifest.build_manifest(LISTING_URL, entries)
    names = {entry["name"] for entry in manifest["entries"]}
    assert "U_Apple_macOS_15_V1R7_STIG.zip" in names
    assert "CUI_Restricted_V1R1_STIG.zip" not in names
    assert manifest["cui_skipped"] == 1


def test_fetch_listing__a_web_url__sends_a_named_user_agent():
    seen = {}

    class _Response:
        def read(self):
            return _listing_html().encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(request, timeout=None):
        seen["url"] = request.full_url
        seen["agent"] = request.get_header("User-agent")
        return _Response()

    html = corpus_manifest.fetch_listing(LISTING_URL, opener=opener, user_agent=corpus_manifest.USER_AGENT)
    assert "U_Apple_macOS_15_V1R7_STIG.zip" in html
    assert seen["url"] == LISTING_URL
    assert seen["agent"] == corpus_manifest.USER_AGENT


def test_fetch_listing__a_non_web_scheme__is_refused_before_any_request():
    def opener(request, timeout=None):
        raise AssertionError("must not be called")

    with pytest.raises(ValueError):
        corpus_manifest.fetch_listing("file:///etc/passwd", opener=opener)


def test_write_manifest__a_manifest__round_trips_as_json(tmp_path):
    manifest = corpus_manifest.build_manifest(LISTING_URL, corpus_manifest.parse_listing(_listing_html()))
    written = corpus_manifest.write_manifest(manifest, tmp_path / "manifest.json")
    assert json.loads(written.read_text(encoding="utf-8")) == manifest


def test_parse_listing__an_anchor_with_a_non_href_attribute__ignores_that_attribute():
    # Apache's own markup only ever emits href, but the parser walks every attribute pair
    # on the tag, so a page that also sets class or title must not be mistaken for a link.
    html = '<html><body><a class="icon" href="U_Kubernetes_V2R6_STIG.zip">K8s</a></body></html>'
    entries = corpus_manifest.parse_listing(html)
    assert entries == [("U_Kubernetes_V2R6_STIG.zip", "U_Kubernetes_V2R6_STIG.zip")]


def test_parse_listing__a_subdirectory_link__is_skipped_as_not_a_file():
    html = '<html><body><a href="subdir/">subdir/</a></body></html>'
    entries = corpus_manifest.parse_listing(html)
    assert entries == []


def test_entry_url__a_manifest_entry__joins_the_href_to_the_source_url():
    manifest = corpus_manifest.build_manifest(LISTING_URL, corpus_manifest.parse_listing(_listing_html()))
    entry = next(entry for entry in manifest["entries"] if entry["name"] == "U_Apple_macOS_15_V1R7_STIG.zip")
    assert corpus_manifest.entry_url(manifest, entry) == LISTING_URL + "U_Apple_macOS_15_V1R7_STIG.zip"


def test_main__a_cli_invocation__writes_the_manifest_and_prints_the_tier_counts(monkeypatch, tmp_path, capsys):
    out_path = tmp_path / "manifest.json"
    seen = {}

    def fake_fetch_listing(url, user_agent=None):
        seen["user_agent"] = user_agent
        return _listing_html()

    monkeypatch.setattr(corpus_manifest, "fetch_listing", fake_fetch_listing)
    monkeypatch.setattr("sys.argv", ["corpus_manifest", "--url", LISTING_URL, "--out", str(out_path)])

    corpus_manifest.main()

    # main() must identify itself as the corpus tool, not silently inherit catalog's own
    # identity: the two callers keep separate user agents so each is distinguishable in logs.
    assert seen["user_agent"] == corpus_manifest.USER_AGENT
    manifest = json.loads(out_path.read_text(encoding="utf-8"))
    assert manifest["source_url"] == LISTING_URL
    captured = capsys.readouterr()
    assert str(out_path) in captured.out
    assert f"{len(manifest['entries'])} entries" in captured.out


def _base(*entries):
    return {"source_url": catalog.ZIP_BASE, "entries": [dict(entry) for entry in entries], "cui_skipped": 0}


def _staged(name, size=100, sha256="aa", href=None):
    return {"name": name, "href": href or name, "tier": corpus_manifest.BENCHMARK, "sha256": sha256, "size": size}


def _cat(name):
    return catalog.Entry(name=name, href=urllib.parse.quote(name), date="2026-11-01", size_bytes=None)


def _merged(manifest, name):
    return next(entry for entry in manifest["entries"] if entry["name"] == name)


def test_merge__a_base_only_entry__is_kept_unchanged():
    base = _base(_staged("U_MarkLogic_Server_v9_V3R2_STIG.zip", size=10))
    manifest, report = corpus_manifest.merge(base, [], {})
    assert manifest["entries"] == [_staged("U_MarkLogic_Server_v9_V3R2_STIG.zip", size=10)]
    assert report["kept"] == 1


def test_merge__a_new_catalog_name__is_added_tiered_with_no_checksum():
    manifest, report = corpus_manifest.merge(_base(), [_cat("U_Kubernetes_V2R6_STIG.zip")], {})
    assert manifest["entries"] == [
        {
            "name": "U_Kubernetes_V2R6_STIG.zip",
            "href": "U_Kubernetes_V2R6_STIG.zip",
            "tier": corpus_manifest.BENCHMARK,
            "sha256": None,
            "size": None,
        }
    ]
    assert report["added"] == ["U_Kubernetes_V2R6_STIG.zip"]


def test_merge__a_shared_name_whose_length_changed__clears_sha256_and_size():
    name = "U_RHEL_9_V2R10_STIG.zip"
    manifest, report = corpus_manifest.merge(_base(_staged(name)), [_cat(name)], {name: 101})
    entry = _merged(manifest, name)
    assert entry["sha256"] is None
    assert entry["size"] is None
    assert report["restaged"] == [name]
    assert report["added"] == []


def test_merge__a_shared_name_whose_length_matches__keeps_sha256_and_size():
    name = "U_RHEL_9_V2R10_STIG.zip"
    manifest, report = corpus_manifest.merge(_base(_staged(name)), [_cat(name)], {name: 100})
    assert _merged(manifest, name) == _staged(name)
    assert report["restaged"] == []


def test_merge__a_shared_name_never_staged__is_kept_with_no_restage():
    name = "U_RHEL_9_V2R10_STIG.zip"
    unstaged = _staged(name, size=None, sha256=None)
    manifest, report = corpus_manifest.merge(_base(unstaged), [_cat(name)], {})
    assert _merged(manifest, name) == unstaged
    assert report["restaged"] == []


def test_merge__a_shared_name_with_a_space__keeps_the_base_href():
    name = "U_July 2024 Quarterly Release Automated Benchmarks.zip"
    href = "U_July%202024%20Quarterly%20Release%20Automated%20Benchmarks.zip"
    base = _base(_staged(name, href=href))
    manifest, _report = corpus_manifest.merge(base, [_cat(name)], {name: 100})
    assert _merged(manifest, name)["href"] == href


def test_merge__a_cui_catalog_name__is_skipped_and_counted():
    manifest, report = corpus_manifest.merge(_base(), [_cat("CUI_Restricted_V1R1_STIG.zip")], {})
    assert manifest["entries"] == []
    assert manifest["cui_skipped"] == 1
    assert report["added"] == []


def test_merge__a_non_archive_catalog_name__is_left_out():
    manifest, report = corpus_manifest.merge(_base(), [_cat("RPM-GPG-KEY-SCC-5.11")], {})
    assert manifest["entries"] == []
    assert report["added"] == []


def test_merge__unsorted_inputs__writes_entries_sorted_by_name():
    base = _base(_staged("U_Zebra_V1R1_STIG.zip"), _staged("U_Beta_V1R1_STIG.zip"))
    catalog_entries = [_cat("U_Yak_V1R1_STIG.zip"), _cat("U_Alpha_V1R1_STIG.zip")]
    manifest, _report = corpus_manifest.merge(base, catalog_entries, {})
    assert [entry["name"] for entry in manifest["entries"]] == [
        "U_Alpha_V1R1_STIG.zip",
        "U_Beta_V1R1_STIG.zip",
        "U_Yak_V1R1_STIG.zip",
        "U_Zebra_V1R1_STIG.zip",
    ]


def test_merge__a_restage__does_not_mutate_the_base():
    name = "U_RHEL_9_V2R10_STIG.zip"
    base = _base(_staged(name))
    before = copy.deepcopy(base)
    corpus_manifest.merge(base, [_cat(name), _cat("U_Kubernetes_V2R6_STIG.zip")], {name: 101})
    assert base == before


def test_merge__the_base_source_url__is_carried_over():
    manifest, _report = corpus_manifest.merge(_base(), [], {})
    assert manifest["source_url"] == catalog.ZIP_BASE


class _HeadResponse:
    def __init__(self, length):
        self.headers = {"Content-Length": str(length)}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _recording_opener(seen, length=7):
    def opener(request, timeout=None):
        seen.append(request)
        return _HeadResponse(length)

    return opener


def test_measure__only_staged_shared_names__are_requested():
    staged, unstaged, new = "U_RHEL_9_V2R10_STIG.zip", "U_TOSS_4_V2R2_STIG.zip", "U_Kubernetes_V2R6_STIG.zip"
    base = _base(_staged(staged, size=5), _staged(unstaged, size=None, sha256=None))
    seen, sleeps = [], []
    lengths = corpus_manifest.measure(
        [_cat(staged), _cat(unstaged), _cat(new)], base, _recording_opener(seen), sleep=sleeps.append
    )
    assert lengths == {staged: 7}
    assert [request.full_url for request in seen] == [catalog.ZIP_BASE + staged]
    assert sleeps == [1.0]


def test_measure__the_request__carries_the_corpus_tool_user_agent():
    name = "U_RHEL_9_V2R10_STIG.zip"
    seen = []
    corpus_manifest.measure([_cat(name)], _base(_staged(name)), _recording_opener(seen), sleep=lambda _s: None)
    assert seen[0].get_method() == "HEAD"
    assert seen[0].get_header("User-agent") == corpus_manifest.USER_AGENT
