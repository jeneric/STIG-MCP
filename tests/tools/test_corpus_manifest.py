import json
from pathlib import Path

import pytest

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
