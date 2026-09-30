import pytest

from stig_mcp.kb.db import create_db
from stig_mcp.resolver.resolver import distinctiveness_margin, resolve
from stig_mcp.server import tools
from tests.conftest import open_db_for_test

_FILLER_COUNT = 24
_DISTINCTIVE_STIG_ID = "ZORPTECH_APPLIANCE_5_STIG"


def _insert_stig(conn, stig_id, title, product_keywords=""):
    """One row of the stigs-only KB shape `_build_gate_kb` and the margin tests below share:
    `_corpus` reads title and product_keywords straight from this table, so a raw INSERT is
    enough to control document frequency without an XCCDF fixture or a `build_kb` run."""
    conn.execute(
        "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (stig_id, "1", title, product_keywords, "loose", "test fixture"),
    )


def _build_gate_kb(path):
    """A purpose-built minimal KB (stigs table only) with N=25 benchmarks: one has a
    product token ('zorptech') unique to it, clearing the <=5%-of-N distinctiveness
    cutoff; the rest are generic filler so no other token is ever distinctive.
    Exercises the keyword path (not aliases) since no alias is defined for this id."""
    conn = create_db(path)
    _insert_stig(
        conn,
        _DISTINCTIVE_STIG_ID,
        "Zorptech Appliance 5 Security Technical Implementation Guide",
        "zorptech appliance 5",
    )
    for i in range(_FILLER_COUNT):
        _insert_stig(conn, f"FILLER_{i}_STIG", "Filler Generic Appliance Guide", "generic appliance software")
    conn.commit()
    conn.close()


def test_resolve__keyword_path_with_distinctive_product_token__is_high_confidence(tmp_path):
    kb = tmp_path / "gate_kb.sqlite"
    _build_gate_kb(kb)
    conn = open_db_for_test(kb)

    hits = resolve(conn, "zorptech 5")

    top = next(h for h in hits if h["stig_id"] == _DISTINCTIVE_STIG_ID)
    assert top["high_confidence"] is True
    assert top["matched_on"] == "keyword"


def test_resolve_scope__keyword_path_with_distinctive_product_token__auto_scopes(tmp_path):
    kb = tmp_path / "gate_kb.sqlite"
    _build_gate_kb(kb)
    conn = open_db_for_test(kb)

    scope, _resolved, _notes = tools._resolve_scope(conn, "zorptech 5", None)

    assert scope == [(_DISTINCTIVE_STIG_ID, "1")]


def test_distinctiveness_margin__a_token_one_document_inside_the_gate__is_reported_as_losing(wide_kb):
    # wide_kb: n=29, gate 1.45, so a df of 1 sits inside the gate and one more benchmark
    # holding the token would put it outside. 'chrome' is held by Google_Chrome_Current_Windows
    # alone.
    conn = open_db_for_test(wide_kb)
    band = distinctiveness_margin(conn)
    assert band.n == 29
    assert band.gate == pytest.approx(1.45)
    assert ("chrome", 1) in band.losing


def test_distinctiveness_margin__a_token_one_document_outside_the_gate__is_reported_as_gaining(wide_kb):
    # df 2 against a gate of 1.45: not distinctive today, and one retirement of a benchmark
    # holding it would make it so. 'windows' is held by win2022 and chrome_current.
    conn = open_db_for_test(wide_kb)
    band = distinctiveness_margin(conn)
    assert ("windows", 2) in band.gaining
    assert ("windows", 2) not in band.losing


def test_distinctiveness_margin__a_token_far_outside_the_gate__is_in_neither_list(wide_kb):
    # The band must be bounded on BOTH sides. The 19 fillers all carry 'padding', which is
    # 13 documents outside a gate of 1.45, so a band that only tested `df > gate` would
    # wrongly report it. This is the assertion that fails when the upper bound is dropped.
    conn = open_db_for_test(wide_kb)
    band = distinctiveness_margin(conn)
    reported = {token for token, _ in band.losing + band.gaining}
    assert "padding" not in reported


def test_distinctiveness_margin__a_token_two_documents_inside_the_gate__is_not_reported(tmp_path):
    # The LOWER bound of the losing side, and wide_kb cannot express it: its gate is 1.45, so
    # `gate - 1` is 0.45 and no token can ever fall below it, because df only holds tokens
    # that appear at least once, so no wide_kb test can see the lower bound. This corpus is
    # built large enough that the bound bites: 40 fillers put n at 41 and the gate at 2.05, so
    # the losing side is `1.05 < df <= 2.05`, and a df-1 token sits further than one document
    # below the gate, so it must not be reported at all. Band membership is not the same thing
    # as being one benchmark from crossing: crossing on an added holder needs
    # `df > gate - 0.95`, so the band's outer 0.05 sliver holds tokens that do not cross. See
    # distinctiveness_margin's docstring for the four exact conditions, and for the re-release
    # case they do not cover.
    #
    # Built as a raw stigs-only KB, not through build_kb with 40 filler XCCDF files: the
    # shared _filler_benchmarks helper suffixes each file with a single lowercase letter, so
    # it caps at 26 and raises IndexError past that. _corpus reads title and
    # product_keywords straight from the stigs table, so a direct INSERT reaches the same
    # df/n without that ceiling.
    kb = tmp_path / "big.sqlite"
    conn = create_db(kb)
    _insert_stig(conn, "RHEL_9_STIG", "Red Hat Enterprise Linux 9 Guide", "rhel enterprise linux 9")
    for i in range(40):
        _insert_stig(conn, f"BIG_FILLER_{i}_STIG", "Boundary Filler Padding Guide", "boundary filler padding")
    conn.commit()
    conn.close()
    conn = open_db_for_test(kb)
    band = distinctiveness_margin(conn)
    assert band.n == 41
    assert band.gate == pytest.approx(2.05)
    assert ("rhel", 1) not in band.losing
    assert not [entry for entry in band.losing if entry[1] == 1]


def test_distinctiveness_margin__a_token_exactly_on_the_gate__is_reported_as_losing(tmp_path):
    # `losing` is `gate - width < count <= gate`, and the `<=` only has a distinguishable
    # effect from `<` when count can equal the gate exactly, which needs an integer gate:
    # n=20 makes it 1.0. wide_kb's gate of 1.45 can never equal an integer df, so nothing in
    # this module already pins that boundary.
    kb = tmp_path / "boundary.sqlite"
    conn = create_db(kb)
    _insert_stig(conn, "QUIBBLE_APPLIANCE_STIG", "Quibbleware Appliance Guide", "quibbleware appliance")
    for i in range(19):
        _insert_stig(conn, f"ON_GATE_FILLER_{i}_STIG", "Ledger Sundry Padding Guide", "ledger sundry padding")
    conn.commit()
    conn.close()
    conn = open_db_for_test(kb)
    band = distinctiveness_margin(conn)
    assert band.n == 20
    assert band.gate == pytest.approx(1.0)
    assert ("quibbleware", 1) in band.losing
    # `gaining` is `gate < count`, and at an integer gate loosening that to `<=` would put
    # every on-gate token in BOTH lists, so the summary counter would double-count it and the
    # same token would be warned and informed about at once. Integer gates arrive at every n
    # divisible by 20, so this is a real corpus size, not a contrived one.
    assert ("quibbleware", 1) not in band.gaining


def test_distinctiveness_margin__a_corpus_holding_no_benchmarks__reports_an_empty_band(tmp_path):
    # n=0 is reachable, but not through build_kb: _validate_sources refuses an empty
    # sources.benchmarks list with a FileNotFoundError before _populate ever runs, so the KB
    # itself must be built with no stigs table rows at all rather than via the ingest
    # pipeline. The gate is then 0.0 and both comparisons are against an empty df, so the
    # band is empty rather than a band naming every token.
    out = tmp_path / "empty.sqlite"
    conn = create_db(out)
    conn.commit()
    conn.close()
    conn = open_db_for_test(out)
    band = distinctiveness_margin(conn)
    assert band.n == 0
    assert band.losing == []
    assert band.gaining == []
