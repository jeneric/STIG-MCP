import re
from pathlib import Path

import pytest

from stig_mcp import tls
from stig_mcp.ingest import catalog

FIX = Path(__file__).parent.parent / "fixtures"
INDEX = (FIX / "disa_index.html").read_text()


def test_parse_index__the_real_index__reads_name_href_date_and_size():
    entries = catalog.parse_index(INDEX)
    assert len(entries) > 1000
    by_name = {e.name: e for e in entries}
    # Derived from the fetched fixture itself, not guessed ahead of time:
    # the newest DISA library compilation row as of the fixture's fetch date.
    entry = by_name["U_SRG-STIG_Library_July_2026.zip"]
    assert entry.date == "13-Jul-2026"
    assert entry.size_bytes > 300_000_000


def test_parse_index__a_percent_encoded_row_in_the_real_index__decodes_name_but_not_href():
    # A real row from the fetched fixture whose href carries %20. name and href must differ,
    # or a mutation that stops decoding (or swaps the two fields) would pass unnoticed.
    entries = catalog.parse_index(INDEX)
    by_href = {e.href: e for e in entries}
    entry = by_href["U_July%202024%20Quarterly%20Release%20Automated%20Benchmarks.zip"]
    assert entry.name == "U_July 2024 Quarterly Release Automated Benchmarks.zip"
    assert entry.href == "U_July%202024%20Quarterly%20Release%20Automated%20Benchmarks.zip"


def test_parse_index__a_size_in_k_and_in_m__both_become_bytes():
    text = '<A HREF="a.zip">a.zip</A> 10-Jul-2026 12:00  665k\n<A HREF="b.zip">b.zip</A> 10-Jul-2026 12:00  1.1M\n'
    sizes = {e.name: e.size_bytes for e in catalog.parse_index(text)}
    assert sizes["a.zip"] == pytest.approx(665 * 1024, rel=0.01)
    assert sizes["b.zip"] == pytest.approx(1.1 * 1024 * 1024, rel=0.01)


def test_parse_index__a_page_with_no_rows__returns_empty_rather_than_raising():
    assert catalog.parse_index("<html><body>nothing here</body></html>") == []


def test_fetch_listing__a_non_web_scheme__is_refused():
    with pytest.raises(ValueError, match="http/https"):
        catalog.fetch_listing("file:///etc/passwd")


def test_tier_of__the_real_index__classifies_the_known_tiers():
    tiers = {e.name: catalog.tier_of(e.name) for e in catalog.parse_index(INDEX)}
    assert tiers["U_SRG-STIG_Library_July_2026.zip"] == catalog.COMPILATION
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
    return [catalog.Entry(name=n, href=n, date="10-Jul-2026", size_bytes=1) for n in names]


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


def test_newest_library__the_real_index__picks_july_2026():
    # The lexical maximum of the real index's nine library names is
    # "U_SRG-STIG_Library_October_2025.zip" ("October" sorts above "July"), so a regression
    # to max(names) or to sorting these strings fails this test on real data. It does not
    # pin a date-column sort too: July 2026 is the only entry whose index date differs from
    # 28-Apr-2026, so sorting by that date would pick the same winner here by accident.
    assert catalog.newest_library(catalog.parse_index(INDEX)).name == "U_SRG-STIG_Library_July_2026.zip"


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


def test_sunset__the_real_index__is_the_rev_4_archive():
    assert catalog.sunset(catalog.parse_index(INDEX)).name == "U_Rev_4_SRG-STIG_Sunset_Compilation.zip"


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


def test_newest_per_product__the_real_index__keeps_every_unversioned_name():
    selected = {e.name for e in catalog.newest_per_product(catalog.parse_index(INDEX))}
    assert "U_Ivanti_MI_Sentry_9-x_STIG.zip" in selected
    # The exact count for tests/fixtures/disa_index.html, not a range: a range wide enough to
    # pass both 275 (STIG Viewer included) and 266 (viewer excluded, one scheme per product)
    # cannot tell whether the viewer archives are selected.
    assert len(selected) == 269


def test_newest_per_product__the_stig_viewer_desktop_app__is_not_selected():
    # Without this assertion, a revert of the tier_of
    # viewer exclusion goes unnoticed by this module's own tests.
    selected = {e.name for e in catalog.newest_per_product(catalog.parse_index(INDEX))}
    assert not any(name.startswith("U_STIGViewer-") for name in selected)


def test_newest_per_product__scap_and_ansible_variants__are_excluded():
    entries = _named(
        "U_MS_Windows_Server_2019_V3R9_STIG.zip",
        "U_MS_Windows_Server_2019_V3R9_STIG_SCAP_1-3_Benchmark.zip",
        "U_MS_Windows_Server_2019_V1R2_STIG_Ansible.zip",
    )
    assert [e.name for e in catalog.newest_per_product(entries)] == ["U_MS_Windows_Server_2019_V3R9_STIG.zip"]


def test_fetch_listing__a_web_url__sends_a_named_user_agent_and_a_timeout():
    seen = {}

    class _Response:
        def read(self):
            return b"the page body"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(request, timeout=None):
        seen["url"] = request.full_url
        seen["agent"] = request.get_header("User-agent")
        seen["timeout"] = timeout
        return _Response()

    text = catalog.fetch_listing("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/", opener=opener)
    assert text == "the page body"
    assert seen["url"] == "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
    assert seen["agent"] == "stig-mcp"
    assert seen["timeout"] == 60


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


def test_bytes_of__a_size_carrying_no_unit_suffix__is_read_as_plain_bytes():
    # Every size on the real DISA index carries a K, M or G suffix, so this branch is
    # unreachable from tests/fixtures/disa_index.html.
    assert catalog._bytes_of("1024") == 1024
    assert catalog._bytes_of("1.5K") == 1536
    assert catalog._bytes_of("2M") == 2 * 1024**2


class _Reached(Exception):
    """Raised by the patched tls opener, so reaching it is observable."""


def _refusing_opener(*_handlers):
    def open_url(request, timeout=None):
        raise _Reached(request.full_url)

    return open_url


def test_fetch_listing__no_opener_given__opens_through_the_truststore_opener(monkeypatch):
    monkeypatch.setattr(tls, "opener", _refusing_opener)
    with pytest.raises(_Reached, match=re.escape(catalog.INDEX_URL)):
        catalog.fetch_listing()
