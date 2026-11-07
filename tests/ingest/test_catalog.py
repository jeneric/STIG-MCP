import json
import re
import urllib.parse
from pathlib import Path

import pytest

from stig_mcp import tls
from stig_mcp.ingest import catalog

FIX = Path(__file__).parent.parent / "fixtures"
# Hand-checked against the fixture: the plain STIG of each product, with every SCAP, Ansible and
# Chef variant, CCI_List.zip and both compilations left out.
EXPECTED_SELECTION = {
    "U_Anduril_NixOS_V1R3_STIG.zip",
    "U_Apple_iOS-iPadOS_17_V2R2_STIG.zip",
    "U_Apache_Server_2-4_Unix_Y26M07_STIG.zip",
    "U_Cisco_IOS_Router_Y26M10_STIG.zip",
    "U_Google_Android_14_BYOAD_Y25M10_STIG.zip",
    "U_IBM_HMC_V2R2_STIG.zip",
    "U_MS_IIS_10-0_Y26M10_STIG.zip",
    "U_MS_Windows_Server_2019_V3R9_STIG.zip",
    "U_Omnissa_Horizon_Y26M09_STIG.zip",
    "U_RHEL_10_V1R3_STIG.zip",
    "U_RHEL_7_V3R15_STIG.zip",
    "U_RHEL_9_V2R10_STIG.zip",
    "U_Splunk_Enterprise_8-x_for Linux_V2R3_STIG.zip",
}
CATALOG = (FIX / "cyber_mil_catalog.json").read_text(encoding="utf-8")


def _row(link, date="2026-10-05", title="A title"):
    return {"DownloadLink": link, "UploadDate": date, "FileName": title, "DocumentLibrary": "STIGs"}


def _body(*rows):
    return json.dumps({"returnValue": list(rows)})


def test_parse_catalog__the_saved_response__keeps_every_zip_row_on_the_zip_path():
    entries = catalog.parse_catalog(CATALOG)
    names = {e.name for e in entries}
    assert all("/" not in e.href for e in entries)
    assert all(e.size_bytes is None for e in entries)
    assert {"CCI_List.zip", "U_SRG-STIG_Library_October_2026.zip", "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"} <= names
    assert "U_Apple_iOS-iPadOS_17_V2R2_STIG.zip" in names  # the S3 mirror host
    assert "U_Omnissa_Horizon_Y26M09_STIG.zip" in names  # a doubled slash after the host
    assert "u_draft_cci_specification_v2r0.2.zip" in names  # dl.cyber.mil, on the same zip path
    assert not any(name.lower().endswith((".pdf", ".txt")) for name in names)
    assert len(entries) == 27


def test_parse_catalog__the_saved_response__is_sorted_by_name():
    names = [e.name for e in catalog.parse_catalog(CATALOG)]
    assert names == sorted(names)


def test_parse_catalog__the_saved_response__carries_upload_date():
    by_name = {e.name: e for e in catalog.parse_catalog(CATALOG)}
    assert by_name["U_RHEL_9_V2R10_STIG.zip"].date == "2026-10-05"
    assert by_name["U_RHEL_9_V2R10_STIG_Ansible.zip"].date == "2026-10-06"


def test_parse_catalog__a_link_with_a_space__quotes_the_href_and_keeps_the_name():
    by_name = {e.name: e for e in catalog.parse_catalog(CATALOG)}
    entry = by_name["U_Splunk_Enterprise_8-x_for Linux_V2R3_STIG.zip"]
    assert entry.href == "U_Splunk_Enterprise_8-x_for%20Linux_V2R3_STIG.zip"


def test_parse_catalog__the_saved_response__every_href_is_the_quoted_name():
    entries = catalog.parse_catalog(CATALOG)
    assert [e.href for e in entries] == [urllib.parse.quote(e.name) for e in entries]


def test_parse_catalog__a_percent_encoded_link__decodes_name_but_not_href():
    link = catalog.ZIP_BASE + "U_July%202024%20Quarterly%20Release.zip"
    (entry,) = catalog.parse_catalog(_body(_row(link)))
    assert entry.name == "U_July 2024 Quarterly Release.zip"
    assert entry.href == "U_July%202024%20Quarterly%20Release.zip"


def test_parse_catalog__an_upper_case_zip_extension__is_kept():
    (entry,) = catalog.parse_catalog(_body(_row(catalog.ZIP_BASE + "U_Foo_V1R1_STIG.ZIP")))
    assert entry.name == "U_Foo_V1R1_STIG.ZIP"


def test_parse_catalog__the_same_name_listed_twice__keeps_the_newest_upload_date():
    link = catalog.ZIP_BASE + "U_Foo_V1R1_STIG.zip"
    older, newer = _row(link, "2026-07-10"), _row(link, "2026-10-05")
    for rows in ((older, newer), (newer, older)):
        (entry,) = catalog.parse_catalog(_body(*rows))
        assert entry.date == "2026-10-05"


@pytest.mark.parametrize("body", ["{}", '{"returnValue": {}}', "<html>"])
def test_parse_catalog__body_without_return_value__names_the_classname(body):
    with pytest.raises(RuntimeError, match=re.escape(catalog.CATALOG_CLASSNAME)):
        catalog.parse_catalog(body)


def test_parse_catalog__a_doubled_slash_in_the_path__is_kept_under_zip_base():
    link = "https://dl.dod.cyber.mil//wp-content/uploads//stigs/zip/U_Foo_V1R1_STIG.zip"
    (entry,) = catalog.parse_catalog(_body(_row(link)))
    assert (entry.name, entry.href) == ("U_Foo_V1R1_STIG.zip", "U_Foo_V1R1_STIG.zip")


def test_parse_catalog__a_mirror_host_on_the_zip_path__keeps_the_name_only():
    link = "https://s3.us-gov-west-1.amazonaws.com/dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Foo V1R1_STIG.zip"
    (entry,) = catalog.parse_catalog(_body(_row(link)))
    assert (entry.name, entry.href) == ("U_Foo V1R1_STIG.zip", "U_Foo%20V1R1_STIG.zip")


def test_parse_catalog__a_zip_off_the_zip_path__is_skipped_and_named_in_one_warning(caplog):
    good = _row(catalog.ZIP_BASE + "U_Bar_V1R1_STIG.zip")
    elsewhere = _row("https://files.example/downloads/U_Foo_V1R1_STIG.zip")
    other = _row("https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_Baz_V1R1_STIG.ZIP")
    pdf = _row("https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_Qux.pdf")
    with caplog.at_level("WARNING", logger=catalog.__name__):
        entries = catalog.parse_catalog(_body(good, elsewhere, other, pdf))
    assert [e.name for e in entries] == ["U_Bar_V1R1_STIG.zip"]
    (record,) = caplog.records
    assert record.levelname == "WARNING"
    assert elsewhere["DownloadLink"] in record.getMessage()
    assert other["DownloadLink"] in record.getMessage()
    assert "U_Qux.pdf" not in record.getMessage()


def test_parse_catalog__the_zip_path_only_in_the_query__is_skipped_and_named(caplog):
    link = "https://files.example/a.zip?u=/wp-content/uploads/stigs/zip/U_Foo_V1R1_STIG.zip"
    good = _row(catalog.ZIP_BASE + "U_Bar_V1R1_STIG.zip")
    with caplog.at_level("WARNING", logger=catalog.__name__):
        entries = catalog.parse_catalog(_body(_row(link), good))
    assert [e.name for e in entries] == ["U_Bar_V1R1_STIG.zip"]
    (record,) = caplog.records
    assert link in record.getMessage()


def test_parse_catalog__a_mirror_link_with_a_query__keeps_it_in_the_name_and_escapes_it():
    link = "https://s3.example/dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Foo_V1R1_STIG.zip?x=1#y.zip"
    (entry,) = catalog.parse_catalog(_body(_row(link)))
    assert entry.name == "U_Foo_V1R1_STIG.zip?x=1#y.zip"
    assert entry.href == "U_Foo_V1R1_STIG.zip%3Fx%3D1%23y.zip"


def test_parse_catalog__every_zip_on_the_zip_path__warns_nothing(caplog):
    with caplog.at_level("WARNING", logger=catalog.__name__):
        catalog.parse_catalog(_body(_row(catalog.ZIP_BASE + "U_Bar_V1R1_STIG.zip")))
    assert caplog.records == []


@pytest.mark.parametrize("link", [None, 42, ["x.zip"]])
def test_parse_catalog__a_download_link_that_is_not_a_string__skips_the_row(link):
    good = _row(catalog.ZIP_BASE + "U_Bar_V1R1_STIG.zip")
    assert [e.name for e in catalog.parse_catalog(_body(_row(link), good))] == ["U_Bar_V1R1_STIG.zip"]


@pytest.mark.parametrize("date", [None, 20261005])
def test_parse_catalog__an_upload_date_that_is_not_a_string__becomes_empty(date):
    (entry,) = catalog.parse_catalog(_body(_row(catalog.ZIP_BASE + "U_Bar_V1R1_STIG.zip", date=date)))
    assert entry.date == ""


def test_parse_catalog__no_zip_rows__blames_the_row_shape_not_the_classname():
    pdf = _row("https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_Foo.pdf")
    with pytest.raises(RuntimeError, match="no zip") as raised:
        catalog.parse_catalog(_body(pdf))
    assert catalog.CATALOG_CLASSNAME not in str(raised.value)
    assert "DownloadLink" in str(raised.value)


def test_fetch_catalog__sends_the_pinned_post():
    requests = []

    class _Response:
        def read(self):
            return b'{"returnValue": []}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(request, timeout=None):
        requests.append(request)
        return _Response()

    assert catalog.fetch_catalog(opener=opener) == '{"returnValue": []}'
    (request,) = requests
    assert request.get_method() == "POST"
    assert request.full_url == catalog.CATALOG_URL
    assert json.loads(request.data) == {
        "namespace": "",
        "classname": catalog.CATALOG_CLASSNAME,
        "method": catalog.CATALOG_METHOD,
        "isContinuation": False,
        "params": {"documentLibrary": catalog.CATALOG_LIBRARY},
        "cacheable": False,
    }
    assert request.get_header("User-agent") == "stig-mcp"
    assert request.get_header("Content-type") == "application/json"


class _HeadResponse:
    def __init__(self, headers):
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _head_opener(headers, seen):
    def opener(request, timeout=None):
        seen.append(request)
        return _HeadResponse(headers)

    return opener


def _entry(name="U_RHEL_9_V2R10_STIG.zip"):
    return catalog.Entry(name=name, href=name, date="2026-10-05", size_bytes=None)


def test_head_length__content_length_present__returns_it():
    seen = []
    length = catalog.head_length(_entry(), _head_opener({"Content-Length": "2282653"}, seen))
    assert length == 2282653
    (request,) = seen
    assert request.get_method() == "HEAD"
    assert request.full_url == catalog.ZIP_BASE + "U_RHEL_9_V2R10_STIG.zip"
    assert request.get_header("User-agent") == "stig-mcp"


def test_head_length__an_entry_from_the_mirror_host__requests_zip_base():
    seen = []
    by_name = {e.name: e for e in catalog.parse_catalog(CATALOG)}
    catalog.head_length(by_name["U_Apple_iOS-iPadOS_17_V2R2_STIG.zip"], _head_opener({"Content-Length": "1"}, seen))
    assert seen[0].full_url == catalog.ZIP_BASE + "U_Apple_iOS-iPadOS_17_V2R2_STIG.zip"


def test_head_length__a_name_with_a_space__requests_the_quoted_url():
    seen = []
    by_name = {e.name: e for e in catalog.parse_catalog(CATALOG)}
    entry = by_name["U_Splunk_Enterprise_8-x_for Linux_V2R3_STIG.zip"]
    catalog.head_length(entry, _head_opener({"Content-Length": "1"}, seen))
    assert seen[0].full_url.endswith("for%20Linux_V2R3_STIG.zip")


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "abc"}])
def test_head_length__content_length_missing__names_the_file(headers):
    with pytest.raises(RuntimeError, match="U_RHEL_9_V2R10_STIG.zip"):
        catalog.head_length(_entry(), _head_opener(headers, []))


def test_tier_of__the_saved_response__classifies_the_known_tiers():
    tiers = {e.name: catalog.tier_of(e.name) for e in catalog.parse_catalog(CATALOG)}
    assert tiers["U_SRG-STIG_Library_October_2026.zip"] == catalog.COMPILATION
    assert tiers["U_Rev_4_SRG-STIG_Sunset_Compilation.zip"] == catalog.COMPILATION
    assert tiers["U_MS_Windows_Server_2019_V3R9_STIG.zip"] == catalog.BENCHMARK
    assert tiers["U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-3_Benchmark.zip"] == catalog.ADVERSARIAL


def test_tier_of__cui_content__is_refused_outright():
    with pytest.raises(ValueError, match="CUI"):
        catalog.tier_of("CUI_Something_STIG.zip")


def test_tier_of__the_stig_viewer_desktop_app__is_junk_not_a_stig():
    # The name contains "_stig" only by coincidence of spelling: lowered, "U_STIGViewer-..."
    # decomposes as "u" + "_stig" + "viewer-...". The archive ships an Electron desktop
    # application (v8_context_snapshot.bin, chrome_200_percent.pak, a locales/ tree), not a
    # STIG. Checked against the real index: all nine live STIG Viewer archives begin
    # "U_STIGViewer-".
    assert catalog.tier_of("U_STIGViewer-linux_x64-3-7-0.zip") == catalog.JUNK
    assert catalog.tier_of("U_STIGViewer-win32_x64-3-7-0_msi.zip") == catalog.JUNK


def _named(*names):
    return [catalog.Entry(name=n, href=n, date="2026-07-10", size_bytes=None) for n in names]


def test_newest_library__month_names__are_not_sorted_lexically():
    # inventory.classify records why this matters: month names do not sort chronologically.
    # This test pins that a later year wins even though its month word ("January") sorts
    # lower than the others ("July", "October"). The same-year test below is the one that
    # pins the month-word-to-number table itself; this input is decided by year alone.
    entries = _named(
        "U_SRG-STIG_Library_July_2026.zip",
        "U_SRG-STIG_Library_January_2027.zip",
        "U_SRG-STIG_Library_October_2026.zip",
    )
    assert catalog.newest_library(entries).name == "U_SRG-STIG_Library_January_2027.zip"


def test_newest_library__two_legacy_numeric_releases__are_ordered_by_year_then_month():
    # An entry whose _LIBRARY_NUMERIC match fails falls to (0, 0), and ties there resolve
    # to whichever entry came first in the input, so the later entry winning here requires
    # the year and month to be extracted from the right groups and compared correctly, not
    # merely present. 2020_09 sorts higher by month (9 > 1) than 2021_01 does, so a regex
    # that swaps the year and month groups would also pick the wrong winner.
    entries = _named("U_SRG-STIG_Library_2020_09.zip", "U_SRG-STIG_Library_2021_01.zip")
    assert catalog.newest_library(entries).name == "U_SRG-STIG_Library_2021_01.zip"


def test_newest_library__a_later_legacy_numeric_release__beats_an_earlier_month_name():
    # "U_SRG-STIG_Library_2027_01.zip" sorts lexically BELOW "U_SRG-STIG_Library_April_2025.zip"
    # ('2' < 'A'), so a lexical-sort regression picks April 2025 here, the wrong answer.
    entries = _named("U_SRG-STIG_Library_April_2025.zip", "U_SRG-STIG_Library_2027_01.zip")
    assert catalog.newest_library(entries).name == "U_SRG-STIG_Library_2027_01.zip"


def test_newest_library__two_month_names_in_the_same_year__are_ordered_by_month_number():
    # Both names also sort correctly as plain strings ("April" < "July"), so this does not
    # discriminate a lexical-sort regression. It pins one pairwise relationship in the
    # month-word-to-number table: if that mapping is dropped, every month scores 0 and the
    # two entries tie, and max() returns whichever came first in the input rather than the
    # later month. The test below pins the table itself, all twelve entries, in order.
    entries = _named("U_SRG-STIG_Library_April_2026.zip", "U_SRG-STIG_Library_July_2026.zip")
    assert catalog.newest_library(entries).name == "U_SRG-STIG_Library_July_2026.zip"


def test_MONTHS__names_every_calendar_month_to_its_one_based_number_in_order():
    assert list(catalog._MONTHS.items()) == [
        ("january", 1),
        ("february", 2),
        ("march", 3),
        ("april", 4),
        ("may", 5),
        ("june", 6),
        ("july", 7),
        ("august", 8),
        ("september", 9),
        ("october", 10),
        ("november", 11),
        ("december", 12),
    ]


def test_newest_library__only_a_sunset_archive__raises_as_though_it_were_absent():
    # The sunset archive is COMPILATION tier and must never be mistaken for the current
    # library. If the sunset exclusion in newest_library were removed, this input would
    # instead reach the unreadable-release branch, whose message does not contain "no
    # SRG-STIG Library", so the match= below would fail. That is what makes this test catch
    # the exclusion being dropped rather than passing regardless; if the two messages are
    # ever reworded to share that phrase, this test goes vacuous silently.
    with pytest.raises(ValueError, match="no SRG-STIG Library"):
        catalog.newest_library(_named("U_Rev_4_SRG-STIG_Sunset_Compilation.zip"))


def test_newest_library__the_saved_response__picks_october_2026():
    assert catalog.newest_library(catalog.parse_catalog(CATALOG)).name == "U_SRG-STIG_Library_October_2026.zip"


def test_newest_library__no_compilation_entries__raises_rather_than_returning_none():
    # Selecting nothing must be loud. If DISA changes the page format this is the failure
    # that says so, instead of a fetch that quietly downloads no benchmarks.
    with pytest.raises(ValueError, match="no SRG-STIG Library"):
        catalog.newest_library(_named("U_Some_Product_V1R1_STIG.zip"))


def test_newest_library__the_winner_has_no_readable_release__raises_rather_than_guessing():
    # "Spring_Edition" is COMPILATION tier (it contains "srg-stig") but matches neither
    # release pattern, so a plain max() would return it anyway, tied with itself at (0, 0).
    # That is the same silent wrong answer this function exists to prevent, so it must raise.
    with pytest.raises(ValueError, match="Could not read a release"):
        catalog.newest_library(_named("U_SRG-STIG_Library_Spring_Edition.zip"))


def test_sunset__the_saved_response__is_the_rev_4_archive():
    assert catalog.sunset(catalog.parse_catalog(CATALOG)).name == "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"


def test_newest_per_product__several_releases_of_one_product__keeps_only_the_newest():
    entries = _named(
        "U_MS_Windows_Server_2019_V3R5_STIG.zip",
        "U_MS_Windows_Server_2019_V3R9_STIG.zip",
        "U_MS_Windows_Server_2019_V3R8_STIG.zip",
    )
    assert [e.name for e in catalog.newest_per_product(entries)] == ["U_MS_Windows_Server_2019_V3R9_STIG.zip"]


def test_newest_per_product__a_year_month_version__is_ordered_too():
    entries = _named("U_Google_Android_17_Y26M03_STIG.zip", "U_Google_Android_17_Y26M06_STIG.zip")
    assert [e.name for e in catalog.newest_per_product(entries)] == ["U_Google_Android_17_Y26M06_STIG.zip"]


def test_newest_per_product__a_product_publishing_both_version_schemes__keeps_the_newest_of_each():
    # U_IBM_HMC, a real name on the live index, publishes under both V(major)R(minor) and
    # Y(year)M(month), and the Y/M name is NOT the newer content: Y23M04 carries a 2015
    # benchmark while V2R1 carries a 2024 one. The two schemes are not comparable, so one
    # release per scheme is kept rather than one scheme's tuple winning the other's slot.
    entries = _named(
        "U_IBM_HMC_V2R1_STIG.zip",
        "U_IBM_HMC_Y23M04_STIG.zip",
    )
    assert {e.name for e in catalog.newest_per_product(entries)} == {
        "U_IBM_HMC_V2R1_STIG.zip",
        "U_IBM_HMC_Y23M04_STIG.zip",
    }


def test_newest_per_product__filenames_with_no_parseable_version__are_all_kept():
    # THE test for this function. A filename rule that silently drops a product is a
    # coverage loss, which is this project's worst failure mode: silence a caller cannot
    # tell apart from "nothing applies". These four real names do not match the version
    # pattern, and they are the whole such set on the live index once the STIG Viewer
    # archives are excluded as JUNK rather than BENCHMARK. Each was checked by hand to
    # contain at least one XCCDF document, so keeping them is correct, not merely permissive.
    entries = _named(
        "U_Ivanti_MI_Sentry_9-x_STIG.zip",
        "U_MS_IE11_V1R17_STIG-1.zip",
        "U_MS_Office_365_ProPlus_V1R1_STIG-1.zip",
        "U_MS_Word_2010_V1R11_Manual_STIG.zip",
    )
    kept = {e.name for e in catalog.newest_per_product(entries)}
    assert kept == {e.name for e in entries}


def test_newest_per_product__the_saved_response__keeps_the_newest_of_each_product_and_scheme():
    selected = {e.name for e in catalog.newest_per_product(catalog.parse_catalog(CATALOG))}
    assert selected == EXPECTED_SELECTION


def test_newest_per_product__scap_and_ansible_variants__are_excluded():
    entries = _named(
        "U_MS_Windows_Server_2019_V3R9_STIG.zip",
        "U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-3_Benchmark.zip",
        "U_MS_Windows_Server_2019_V1R2_STIG_Ansible.zip",
    )
    assert [e.name for e in catalog.newest_per_product(entries)] == ["U_MS_Windows_Server_2019_V3R9_STIG.zip"]


def test_release_of__both_version_schemes_and_a_nameless_one__reports_scheme_position_and_ordinal():
    # fetch.prune reads the ordinal to decide whether an arrival supersedes a file on disk, and
    # that decision is wired to unlink(). start() is asserted, not `match.group() in name`,
    # because prune reads the product prefix off the match and containment cannot see WHERE
    # it matched. The scheme tag is asserted here because both returns are pinned to literals,
    # so a separate test comparing the schemes could not fail while this passes.
    match, scheme, release = catalog.release_of("U_IBM_HMC_V2R1_STIG.zip")
    assert (scheme, release) == ("VR", (2, 1))
    assert match.start() == len("U_IBM_HMC")

    match, scheme, release = catalog.release_of("U_IBM_HMC_Y23M04_STIG.zip")
    assert (scheme, release) == ("YM", (23, 4))
    assert match.start() == len("U_IBM_HMC")

    assert catalog.release_of("U_CCI_List.zip") == (None, None, None)
    # Pins VERSION_RE's `_STIG\.zip$` anchor. The no-match case above cannot reach it, because
    # U_CCI_List.zip carries no version pattern at all and fails earlier.
    assert catalog.release_of("U_Foo_V1R1_STIG.zip.bak") == (None, None, None)


class _Reached(Exception):
    """Raised by the patched tls opener, so reaching it is observable."""


def _refusing_opener(*_handlers):
    def open_url(request, timeout=None):
        raise _Reached(request.full_url)

    return open_url


def test_fetch_catalog__no_opener_given__opens_through_the_truststore_opener(monkeypatch):
    monkeypatch.setattr(tls, "opener", _refusing_opener)
    with pytest.raises(_Reached, match=re.escape(catalog.CATALOG_URL)):
        catalog.fetch_catalog()


def test_parse_catalog__a_link_with_a_malformed_ipv6_host__refuses_naming_the_link():
    bad = "https://[dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Foo_V1R1_STIG.zip"
    good = catalog.ZIP_BASE + "U_Kubernetes_V2R6_STIG.zip"
    with pytest.raises(RuntimeError, match=re.escape(bad)):
        catalog.parse_catalog(_body(_row(good), _row(bad)))
