from stig_mcp.resolver.normalize import Tokens
from stig_mcp.resolver.resolver import (
    _coverage,
    _matched_tokens,
    build_idf,
    is_high_confidence,
    score,
)

# Synthetic corpus: 'server' common (in many), 'sql'/'exchange'/'windows' rare.
_DOCS = [
    {"sql", "server", "2022"},
    {"exchange", "server", "2019"},
    {"windows", "server", "2022"},
    {"windows", "11"},
    {"apache", "server"},
    {"tomcat", "server"},
]
IDF, DF, N = build_idf(_DOCS)


# NOT tested here, because it is deliberately NOT fixed: a doc that merely MENTIONS the query's
# product still ties one that IS it. `EDB Postgres Advanced Server v11 on Windows` (a real DISA
# benchmark, in the conformance corpus rather than the shipped knowledge base) and
# `Microsoft Windows 11` both cover the one-token query 'windows' completely, so recall cannot
# separate them. An IDF specificity term in `score` would separate them, but it also separates
# legitimate SIBLINGS, dropping `VMW_vSphere_8-0_VCSA_VAMI_STIG` below `VMW_vSphere_7-0_VAMI_STIG`
# for 'VMware vSphere VAMI' and out of the top tier, silently costing the caller a benchmark that
# genuinely applies.


def test_score__query_product_absent_from_the_doc__scores_zero_despite_the_version():
    # A query that names a product means it. Otherwise a version match alone would score
    # 0.8*0 + 0.2*1 = 20.0 and clear _SCORE_FLOOR of 10.0, so 'Netscape 10' would return every
    # benchmark holding a 10.
    assert score({"keycloak"}, {"19"}, {"oracle", "database"}, {"19"}, IDF) == 0.0


def test_score__shared_product_token_beats_shared_year_only():
    # query "sql server 2019": SQL-2022 shares product 'sql'; Exchange-2019 shares only year.
    qp, qv = {"sql", "server"}, {"2019"}
    sql = score(qp, qv, {"sql", "server", "2022"}, {"2022"}, IDF)
    exch = score(qp, qv, {"exchange", "server", "2019"}, {"2019"}, IDF)
    assert sql > exch


def test_high_confidence__missing_distinctive_version__is_false():
    # "sql 2022" in a larger corpus (n=20, cutoff=1.0) where 'sql' is distinctive
    # (df=1): a doc missing the version token '2022' must not be high-confidence
    # even though it has the distinctive product token.
    simple_df, simple_n = {"sql": 1}, 20
    qp, qv = {"sql"}, {"2022"}
    assert is_high_confidence(qp, qv, {"sql", "2022"}, {"2022"}, simple_df, simple_n) is True
    assert is_high_confidence(qp, qv, {"sql"}, set(), simple_df, simple_n) is False


def test_high_confidence__generic_only_query__is_false():
    # "server" alone is not distinctive, so it never auto-scopes.
    assert is_high_confidence({"server"}, set(), {"server"}, set(), DF, N) is False


def test_high_confidence__version_only_query__is_false():
    # A product-less query (e.g. bare "2022") has no distinctive product token,
    # so it must never auto-scope even if the version matches exactly.
    assert is_high_confidence(set(), {"2022"}, {"windows", "server"}, {"2022"}, DF, N) is False


def test_build_idf__returns_three_values():
    idf, df, n = build_idf([{"a", "b"}, {"b", "c"}])
    assert isinstance(idf, dict)
    assert isinstance(df, dict)
    assert isinstance(n, int)
    assert n == 2


def test_build_idf__computes_document_frequency():
    _, df, _ = build_idf([{"a"}, {"a", "b"}, {"b", "c"}])
    assert df["a"] == 2
    assert df["b"] == 2
    assert df["c"] == 1


def test_matched_tokens__returns_intersection():
    result = _matched_tokens({"a", "b", "c"}, {"b", "c", "d"})
    assert result == {"b", "c"}


def test_matched_tokens__empty_on_no_overlap():
    result = _matched_tokens({"a", "b"}, {"c", "d"})
    assert result == set()


def test_coverage__empty_query_returns_zero():
    assert _coverage(set(), {"a", "b"}, IDF) == 0.0


def test_coverage__partial_match_returns_fraction():
    result = _coverage({"sql", "server"}, {"sql"}, IDF)
    assert 0 < result < 1


def test_coverage__full_match_returns_one():
    result = _coverage({"a", "b"}, {"a", "b", "c"}, IDF)
    assert result == 1.0


def test_score__no_product_query_uses_combined_tokens():
    score_val = score(set(), {"2019"}, {"server", "2019"}, {"2019"}, IDF)
    assert score_val == 100.0


def test_score__product_and_version_weighted():
    """Score weights product 0.8 and version 0.2."""
    result = score({"sql"}, {"2019"}, {"sql"}, {"2019"}, IDF)
    # Full product match (1.0) and full version match (1.0) -> 0.8*1.0 + 0.2*1.0 = 1.0
    assert result == 100.0


def test_score__partial_version_match():
    qp, qv = {"sql"}, {"2019", "2020"}
    dp, dv = {"sql"}, {"2019"}
    result = score(qp, qv, dp, dv, IDF)
    # version = 1/2 = 0.5, product = 1.0 -> 0.8*1.0 + 0.2*0.5 = 0.9
    assert round(result, 9) == 90.0


def test_score__no_version_query_assumes_full_match():
    qp = {"sql"}
    qv = set()
    dp, dv = {"sql"}, {"2019"}
    result = score(qp, qv, dp, dv, IDF)
    assert result == 100.0


def test_is_high_confidence__needs_all_distinctive():
    qp, qv = {"a", "b"}, {"2019"}
    dp, dv = {"a", "2019"}, set()
    # Assuming 'a' and 'b' both rare enough to be distinctive
    simple_df = {"a": 1, "b": 1}
    simple_n = 20
    result = is_high_confidence(qp, qv, dp, dv, simple_df, simple_n)
    assert result is False


def test_is_high_confidence__generic_tokens_not_required():
    qp, qv = {"server", "sql"}, {"2019"}  # 'server' is generic, 'sql' is rare
    dp, dv = {"sql"}, {"2019"}
    simple_df = {"server": 5, "sql": 1}
    simple_n = 20
    result = is_high_confidence(qp, qv, dp, dv, simple_df, simple_n)
    assert result is True


def test_is_high_confidence__empty_query_returns_false():
    result = is_high_confidence(set(), set(), {"server"}, {"2019"}, DF, N)
    assert result is False


def test_matched_tokens__a_literal_acronym__is_satisfied_by_its_spelled_out_expansion():
    # The MDB shape: query says `mdb`, the document spells MongoDB out. Dies if the
    # satisfaction relation is dropped back to a bare intersection.
    assert _matched_tokens({"mdb", "8"}, {"mongodb", "enterprise", "advanced"}) == {"mdb"}


def test_matched_tokens__an_acronym_with_a_partial_expansion_present__is_not_satisfied():
    # `sel` expands to three words; a document holding only one of them did not name SEL.
    assert _matched_tokens({"sel"}, {"engineering", "gateway"}) == set()


def test_is_high_confidence__a_distinctive_literal_acronym__is_held_via_its_expansion():
    # Hand-built: n=20, `mdb` absent from every doc (df 0, distinctive), doc spells it out.
    q = Tokens(frozenset({"mdb"}), frozenset(), frozenset())
    assert is_high_confidence(q.product, q.version, frozenset({"mongodb"}), frozenset(), {"mongodb": 3}, 20)
