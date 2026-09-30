"""The resolver derives its corpus once per connection. These pin that it cannot go stale.

A cache bug here does not nudge a score, it answers with another knowledge base's benchmarks, so
every test is about the cache belonging to the right data rather than about the speed-up.
"""

import shutil
import sqlite3

import pytest

from stig_mcp.ingest.orchestrator import IngestSources, build_kb
from stig_mcp.kb.db import create_db
from stig_mcp.resolver import normalize as normalize_module
from stig_mcp.resolver import resolver as resolver_module
from stig_mcp.resolver.normalize import Tokens
from stig_mcp.resolver.resolver import resolve
from tests.conftest import FIX, discovered, open_db_for_test


def test_resolve__two_knowledge_bases_used_alternately__each_keeps_its_own_answers(kb_path, wide_kb):
    # A→B→A. A single-slot cache passes the first two calls and fails the third.
    small, wide = open_db_for_test(kb_path), open_db_for_test(wide_kb)
    first = [hit["stig_id"] for hit in resolve(small, "RHEL 9")]
    other = [hit["stig_id"] for hit in resolve(wide, "Novaflow Database 19c")]
    again = [hit["stig_id"] for hit in resolve(small, "RHEL 9")]
    assert first == again
    assert "NOVAFLOW_DATABASE_19C_STIG" in other
    assert "NOVAFLOW_DATABASE_19C_STIG" not in first, "the fixture must distinguish the two corpora"


def test_resolve__the_same_connection_twice__reads_the_stigs_table_once(kb_path):
    # The cache has to actually be a cache: without this it can be removed entirely and every
    # staleness test below still passes. No cache-clearing needed, because a fresh connection
    # carries no corpus, which is the property the whole design rests on.
    conn = open_db_for_test(kb_path)
    calls = []
    real = resolver_module.stigs_for_resolver

    def counted(connection):
        calls.append(connection)
        return real(connection)

    resolver_module.stigs_for_resolver = counted
    try:
        resolve(conn, "RHEL 9")
        resolve(conn, "RHEL 9")
    finally:
        resolver_module.stigs_for_resolver = real
    assert len(calls) == 1


def test_resolve__the_knowledge_base_rebuilt_in_place__is_not_answered_from_the_old_corpus(tmp_path, kb_path, wide_kb):
    # The hazard this design exists for. `build_kb` writes a temporary file and replaces it into
    # position, so a read-only connection keeps reading the inode it opened while the PATH takes
    # on a new identity. A cache keyed on that file would store the old corpus under the new
    # file's key and serve it to the next connection opened there.
    live = tmp_path / "kb.sqlite"
    shutil.copy(kb_path, live)
    before = open_db_for_test(live)
    assert "RHEL_9_STIG" in {hit["stig_id"] for hit in resolve(before, "RHEL 9")}

    shutil.copy(wide_kb, live)  # same path, different database, exactly as an ingest rebuild leaves it
    after = open_db_for_test(live)
    novaflow = {hit["stig_id"] for hit in resolve(after, "Novaflow Database 19c")}
    assert "NOVAFLOW_DATABASE_19C_STIG" in novaflow, "a new connection must read the new database"
    assert "RHEL_9_STIG" not in {hit["stig_id"] for hit in resolve(after, "Novaflow Database 19c")}


def test_resolve__aliases_file_swapped_under_it__stops_matching_by_alias(kb_path, tmp_path, monkeypatch):
    # Aliases are cached on the file as it is at call time, not as it was at import. Tests
    # monkeypatch _ALIASES_PATH to disable alias matching, and one exists precisely because an alias
    # hit scores 100.0 unconditionally and would otherwise make its assertions vacuous. A cache that
    # missed the swap would hand it the real aliases and it would pass for the wrong reason.
    conn = open_db_for_test(kb_path)
    assert resolve(conn, "RHEL 9")[0]["matched_on"].startswith("alias:")
    empty = tmp_path / "aliases.yaml"
    empty.write_text("{}\n")
    monkeypatch.setattr(resolver_module, "_ALIASES_PATH", empty)
    assert resolve(conn, "RHEL 9")[0]["matched_on"] == "keyword"


def test_resolve__a_connection_that_cannot_hold_the_cache__is_still_answered(kb_path):
    # A bare sqlite3.Connection has no __dict__, so the corpus cannot be attached to it. Such a
    # caller must be answered rather than refused, and must not be served another database's corpus.
    bare = sqlite3.connect(f"file:{kb_path}?mode=ro", uri=True)
    bare.row_factory = sqlite3.Row
    try:
        assert not hasattr(bare, "__dict__"), "the fixture must use a connection that cannot cache"
        assert "RHEL_9_STIG" in {hit["stig_id"] for hit in resolve(bare, "RHEL 9")}
        assert "RHEL_9_STIG" in {hit["stig_id"] for hit in resolve(bare, "RHEL 9")}
    finally:
        bare.close()


def test_open_db__the_returned_connection__can_carry_the_corpus(kb_path):
    # The one line in db.py this depends on. Dropping the factory leaves a connection that silently
    # cannot cache, so every resolve rebuilds and the feature is gone with no test failing.
    conn = open_db_for_test(kb_path)
    resolve(conn, "RHEL 9")
    assert getattr(conn, resolver_module._CORPUS_ATTR, None) is not None


def test_resolve__a_freshly_built_knowledge_base__is_read_rather_than_a_neighbors_corpus(tmp_path):
    # Two knowledge bases built in one process, second at a different path, first still open.
    # Neither may see the other's benchmarks.
    def build(out, benchmark):
        build_kb(
            IngestSources(
                benchmarks=[discovered(FIX / benchmark)],
                cci_path=FIX / "cci_list.xml",
                attack_path=FIX / "attack_bundle.json",
                ctid_path=FIX / "ctid_mappings.csv",
                overrides_path=FIX / "overrides.yaml",
                catalog_path=FIX / "oscal_catalog.json",
            ),
            out,
        )
        return open_db_for_test(out)

    first = build(tmp_path / "one.sqlite", "rhel9_xccdf.xml")
    second = build(tmp_path / "two.sqlite", "win2022_xccdf.xml")
    assert {hit["stig_id"] for hit in resolve(first, "RHEL 9")} == {"RHEL_9_STIG"}
    assert "RHEL_9_STIG" not in {hit["stig_id"] for hit in resolve(second, "Windows Server 2022")}


def _cached_corpus(conn):
    resolve(conn, "RHEL 9")
    return getattr(conn, resolver_module._CORPUS_ATTR)


def test_resolve__the_cached_benchmark_rows__cannot_be_mutated(kb_path):
    # The rows live for the life of the connection and every later resolve reads them, so one
    # in-place write would change every subsequent answer on that connection. Frozen rather than
    # copied per call: copying 387 rows is most of the work the cache exists to avoid.
    stigs = _cached_corpus(open_db_for_test(kb_path))[0]
    with pytest.raises(AttributeError):
        stigs.append({"stig_id": "INJECTED"})
    with pytest.raises(TypeError):
        stigs[0]["title"] = "not the title this benchmark has"


def test_resolve__the_cached_token_sets__cannot_be_mutated(kb_path):
    # product and version decide every score. A token added here is a token the benchmark does
    # not have, applied to every query for the rest of the process.
    toks = _cached_corpus(open_db_for_test(kb_path))[1][0][1]
    with pytest.raises(AttributeError):
        toks.product.add("injected")
    with pytest.raises(AttributeError):
        toks.version.add("99")


def test_resolve__the_cached_document_list__cannot_be_appended_to(kb_path):
    # Separate from the token sets above, which is the point: asserting only on toks.product and
    # toks.version leaves the CONTAINER free. Appending a row whose stig_id already exists slips
    # past resolve's deliberate KeyError guard on the coverage index, so `RHEL 9` would answer with
    # a fabricated version 99 beside the real row, and a multi-fragment query would take an
    # invented benchmark at 100.0.
    docs = _cached_corpus(open_db_for_test(kb_path))[1]
    with pytest.raises(AttributeError):
        docs.append(
            ({"stig_id": "INJECTED", "version": "99"}, Tokens(frozenset({"injected"}), frozenset(), frozenset()))
        )


def test_resolve__the_cached_idf_and_df__cannot_be_mutated(kb_path):
    # idf weights every match and df decides which tokens are distinctive, so writing here moves
    # both scoring and the confidence gate at once.
    _, _, idf, df, _, _, _ = _cached_corpus(open_db_for_test(kb_path))
    with pytest.raises(TypeError):
        idf["injected"] = 99.0
    with pytest.raises(TypeError):
        df["injected"] = 1


def test_resolve__the_cached_coverage_index__cannot_be_mutated(kb_path):
    # This is what the version-coverage classifier reads to decide whether to tell a caller their
    # version is not held, so a mutated entry produces a false denial rather than a wrong rank.
    index = _cached_corpus(open_db_for_test(kb_path))[5]
    with pytest.raises(TypeError):
        index["INJECTED_STIG"] = {}
    entry = index["RHEL_9_STIG"]
    with pytest.raises(TypeError):
        entry["versions"] = frozenset({"99"})
    for view in ("tokens", "versions", "written", "expanded"):
        with pytest.raises(AttributeError):
            entry[view].add("injected")


def test_corpus__the_index_expanded_view__holds_only_expansion_introduced_tokens(tmp_path):
    # `expanded` is retention's addition to the coverage index, and the mutation test above only
    # asserts it refuses .add(). This pins what it CONTAINS: for a doc naming a product by acronym
    # alone, the expansion tokens are marked expanded and the acronym itself, which the title
    # really writes, is not.
    kb = tmp_path / "expanded_view.sqlite"
    conn = create_db(kb)
    conn.execute(
        "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("HPE_ARRAY_STIG", "1", "HPE Storage Array", "hpe storage array", "loose", "test fixture"),
    )
    conn.commit()
    conn.close()
    entry = resolver_module._corpus(open_db_for_test(kb))[5]["HPE_ARRAY_STIG"]
    assert entry["expanded"] == frozenset({"hewlett", "packard", "enterprise"})
    assert "hpe" in entry["tokens"] and "hpe" not in entry["expanded"]


def test_load_aliases__the_cached_table__cannot_be_mutated(kb_path):
    # An alias hit is scored 100.0 and high confidence outright, bypassing is_high_confidence
    # entirely, so a fabricated pattern here does not degrade an answer, it invents a scoped one.
    resolve(open_db_for_test(kb_path), "RHEL 9")
    aliases = resolver_module._load_aliases()
    with pytest.raises(TypeError):
        aliases["MS_Windows_Server_2022_STIG"] = ["rhel 9"]
    with pytest.raises(AttributeError):
        aliases["RHEL_9_STIG"].append("windows server 2022")


def test_resolve__the_synonym_and_glued_version_tables__cannot_be_mutated():
    # A longer reach than the corpus: these live for the PROCESS across every connection, and they
    # sit on the QUERY side, which is re-normalized on every call. Setting _SYNONYMS['rhel'] to
    # 'microsoft windows' would make `RHEL 9` answer with a Windows benchmark even on a connection
    # whose own corpus is frozen and cached.
    with pytest.raises(TypeError):
        normalize_module._SYNONYMS["rhel"] = "microsoft windows"
    with pytest.raises(TypeError):
        normalize_module._GLUED_VERSIONS["19c"] = "99"


def test_load_aliases__an_entry_that_is_not_a_list__names_the_file_and_the_key(tmp_path, monkeypatch):
    # A scalar alias would iterate as one-letter patterns, so 'r', 'h' and 'e' would each become a
    # pattern matching whatever query contains them. Both bad shapes are refused naming what to fix.
    path = tmp_path / "aliases.yaml"
    path.write_text('RHEL_9_STIG: "rhel 9"\n')
    monkeypatch.setattr(resolver_module, "_ALIASES_PATH", path)
    with pytest.raises(ValueError, match="alias entry 'RHEL_9_STIG'.*not a list of phrases"):
        resolver_module._load_aliases()
    path.write_text("RHEL_9_STIG:\n")
    with pytest.raises(ValueError, match="is None, not a list of phrases"):
        resolver_module._load_aliases()
