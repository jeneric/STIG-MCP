import json
import string
from pathlib import Path

import pytest

from stig_mcp.ingest.inventory import DiscoveredBenchmark
from stig_mcp.ingest.orchestrator import IngestSources, _keywords, build_kb
from stig_mcp.kb.db import create_db, open_db
from tests.fixtures.attack_defenses import EXTRA_OBJECTS

FIX = Path(__file__).parent / "fixtures"


def defense_edges_to_an_intrusion_set():
    """A strategy with one analytic, plus a mitigates edge, both aimed at the APT29 intrusion set
    rather than a technique. ATT&CK 19.1 and 19.2 have none; the parser must not mistake a G-id for a T-id."""
    return [
        {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--an0098",
            "name": "Analytic 0098",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [{"name": "WinEventLog:System", "channel": "EventCode=7045"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "AN0098"}],
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--det0098",
            "name": "Strategy aimed at a group",
            "x_mitre_analytic_refs": ["x-mitre-analytic--an0098"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "DET0098"}],
        },
        {
            "type": "relationship",
            "relationship_type": "detects",
            "source_ref": "x-mitre-detection-strategy--det0098",
            "target_ref": "intrusion-set--g0016",
        },
        {
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--m1026",
            "target_ref": "intrusion-set--g0016",
            "description": "aimed at a group",
        },
    ]


def minimal_defenses(technique_stix_id):
    """The smallest set of defensive objects that satisfies require_defenses: one mitigation,
    one strategy with one analytic, and the two edges that attach them to one technique."""
    return [
        {
            "type": "course-of-action",
            "id": "course-of-action--m0000",
            "name": "Minimal Mitigation",
            "description": "fixture",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M0000"}],
        },
        {
            "type": "relationship",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--m0000",
            "target_ref": technique_stix_id,
            "description": "fixture",
        },
        {
            "type": "x-mitre-analytic",
            "id": "x-mitre-analytic--an0000",
            "name": "Analytic 0000",
            "description": "fixture",
            "x_mitre_platforms": ["Windows"],
            "x_mitre_log_source_references": [{"name": "WinEventLog:Security", "channel": "EventCode=4624"}],
            "x_mitre_mutable_elements": [],
            "external_references": [{"source_name": "mitre-attack", "external_id": "AN0000"}],
        },
        {
            "type": "x-mitre-detection-strategy",
            "id": "x-mitre-detection-strategy--det0000",
            "name": "Minimal Strategy",
            "x_mitre_analytic_refs": ["x-mitre-analytic--an0000"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "DET0000"}],
        },
        {
            "type": "relationship",
            "relationship_type": "detects",
            "source_ref": "x-mitre-detection-strategy--det0000",
            "target_ref": technique_stix_id,
        },
    ]


# Connections a test opened through open_db_for_test, drained by the autouse fixture below. A module
# global rather than fixture state so open_db_for_test can stay a plain function: making it a fixture
# would put it in the signature of every test that opens a database, which is most of them.
_OPENED_BY_TESTS = []


def open_db_for_test(path):
    """open_db, with the connection closed when the test that opened it ends.

    Nothing about the connection differs: this registers it for teardown and returns it
    unchanged, so a test reads exactly as it would with open_db and `with closing(...)` still
    works on top (sqlite3's close is idempotent).

    It closes only what a TEST opened through this function. A connection some production
    path opens and drops still raises its ResourceWarning, which is the point: with the suite's
    own connections closed, a real leak stands out.
    """
    conn = open_db(path)
    _OPENED_BY_TESTS.append(conn)
    return conn


@pytest.fixture(autouse=True)
def _close_connections_opened_by_tests():
    yield
    while _OPENED_BY_TESTS:
        _OPENED_BY_TESTS.pop().close()


def kb_holder(conn):
    """A real KnowledgeBase over the file `conn` is already open on.

    The seven connection fixtures in this suite yield a connection and not the path they
    built it at. Rather than change all seven, ask sqlite where the file is: the holder that
    comes back runs the real readiness check and opens its own connection, so a test using it
    exercises the same path a tool call does in production.

    The import is local rather than module-level. This conftest is collected for every test
    session in the repo, and stig_mcp.server.app imports mcp.server.mcpserver; a module-level
    import would pull MCPServer into ingest, resolver and kb test sessions that never call
    kb_holder at all.
    """
    from stig_mcp.server import app as app_module  # noqa: PLC0415 (local: keeps MCPServer out of the whole suite)

    row = conn.execute("PRAGMA database_list").fetchone()
    # open_db and create_db both set row_factory = sqlite3.Row, so every fixture connection
    # in this suite supports name-based access; indexing row[2] would be the fallback if that
    # ever stopped being true.
    return app_module.KnowledgeBase(Path(row["file"]))


def discovered(
    path,
    origin="library",
    source_artifact="U_SRG-STIG_Library_July_2026.zip",
    source_member=None,
    source_document=None,
):
    """A DiscoveredBenchmark for tests that only care about the file, not its provenance."""
    return DiscoveredBenchmark(
        path=path,
        origin=origin,
        source_artifact=source_artifact,
        source_member=source_member,
        source_document=source_document,
    )


# The two inner-zip paths id_corrections.yaml keys the MS SQL 2012 split on. Shared rather
# than duplicated per test module: they are the map's own match fragments, so a copy that
# drifts would silently stop exercising the correction it names.
MSSQL_DATABASE_DOCUMENT = (
    "U_MS_SQL_Server_2012_Database_V1R18_Manual_STIG/U_SQL_Server_2012_Database_STIG_V1R18_Manual-xccdf.xml"
)
MSSQL_INSTANCE_DOCUMENT = (
    "U_MS_SQL_Server_2012_Instance_V1R18_Manual_STIG/U_MS_SQL_Server_2012_STIG_V1R18_Manual-xccdf.xml"
)


def mssql_pair(artifact="U_SRG-STIG_Library_2020_01.zip"):
    """The two documents of the MS SQL 2012 split, as one artifact ships them."""
    return [
        discovered(
            FIX / "mssql2012_database_xccdf.xml",
            origin="library",
            source_artifact=artifact,
            source_member="U_MS_SQL_Server_2012_V1R18_STIG.zip",
            source_document=MSSQL_DATABASE_DOCUMENT,
        ),
        discovered(
            FIX / "mssql2012_instance_xccdf.xml",
            origin="library",
            source_artifact=artifact,
            source_member="U_MS_SQL_Server_2012_V1R18_STIG.zip",
            source_document=MSSQL_INSTANCE_DOCUMENT,
        ),
    ]


def _sources(**overrides):
    """The smallest IngestSources that builds a KB: one benchmark plus the required
    supporting sources, with any field replaced by an override. Shared by the
    minimal_sources fixture below and by tests/ingest/test_orchestrator.py, which imports
    this function rather than keeping its own copy of the recipe."""
    base = dict(
        benchmarks=[discovered(FIX / "rhel9_xccdf.xml")],
        cci_path=FIX / "cci_list.xml",
        attack_path=FIX / "attack_bundle.json",
        ctid_path=FIX / "ctid_mappings.csv",
        overrides_path=FIX / "overrides.yaml",
    )
    base.update(overrides)
    return IngestSources(**base)


@pytest.fixture
def minimal_sources():
    """The smallest IngestSources that builds a KB: one benchmark plus the required
    supporting sources. Function-scoped, and a fresh IngestSources each call, so a test
    that mutates sources.benchmarks never leaks state into another test."""
    return _sources()


@pytest.fixture(scope="session")
def kb_path(tmp_path_factory):
    out = tmp_path_factory.mktemp("kb") / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "win2022_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return out


@pytest.fixture(scope="session")
def defenses_kb(tmp_path_factory):
    """kb_path's sources with APT29 using eight techniques of distinct defensive shape; see
    tests/fixtures/attack_defenses.py for the table of expected counts."""
    out_dir = tmp_path_factory.mktemp("defenses")
    bundle = json.loads((FIX / "attack_bundle.json").read_text())
    bundle["objects"] += EXTRA_OBJECTS
    (out_dir / "bundle.json").write_text(json.dumps(bundle))
    out = out_dir / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "rhel9_xccdf.xml"), discovered(FIX / "win2022_xccdf.xml")],
            cci_path=FIX / "cci_list.xml",
            attack_path=out_dir / "bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return out


_FILLER_XCCDF = """<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="{stig_id}">
  <title>Fillerware Padding Appliance {suffix} Security Technical Implementation Guide</title>
  <version>1</version>
  <plain-text id="release-info">Release: 1 Benchmark Date: 24 Jul 2024</plain-text>
  <Group id="V-{serial}">
    <Rule id="SV-{serial}r1_rule" severity="low">
      <title>Fillerware {suffix} must be configured.</title>
      <description>&lt;VulnDiscussion&gt;Padding only.&lt;/VulnDiscussion&gt;</description>
      <fixtext>Configure Fillerware.</fixtext>
      <check><check-content>Verify Fillerware is configured.</check-content></check>
      <ident system="http://iase.disa.mil/cci">CCI-000015</ident>
    </Rule>
  </Group>
</Benchmark>
"""
_FILLER_COUNT = 19


def _filler_benchmarks(directory, count=_FILLER_COUNT):
    """`count` throwaway benchmarks that exist only to enlarge the corpus.

    The resolver's distinctive-token gate is `df <= _DISTINCTIVE_DF_RATIO * n` with the
    ratio at 0.05, so a token appearing in a single benchmark is distinctive only once the
    corpus holds 20. Nothing below that can produce a confidence verdict or a version
    coverage verdict at all.

    Every title token here is junk on purpose. Any token shared with a real fixture would
    silently push that token's document frequency past the gate, so the tokens must stay
    disjoint, which `test_wide_kb__filler_benchmarks__share_no_token_with_the_real_ones`
    asserts, rather than a word list here. The suffix carries no bare digit because a digit
    token normalizes to a *version*, which would let a filler answer a version query.
    """
    for index in range(count):
        # Multi-letter, because a single letter is a distinctive token in its own right:
        # `FILLER_A_STIG` puts 'a' in the corpus at a document frequency of 1, and any later
        # query containing the word "a" would then silently lose its verdict.
        suffix = f"Zz{string.ascii_lowercase[index]}"
        stig_id = f"FILLER_{suffix.upper()}_STIG"
        path = directory / f"filler_{suffix.lower()}_xccdf.xml"
        path.write_text(_FILLER_XCCDF.format(stig_id=stig_id, suffix=suffix, serial=900001 + index))
        yield discovered(path)


@pytest.fixture(scope="session")
def wide_kb(tmp_path_factory):
    """`kb_path`'s two benchmarks plus a version-less one and enough filler to make a
    document frequency of 1 distinctive. Separate from `kb_path` because enlarging that
    fixture would change every count asserted against it.

    Holds every version shape the notes have to tell apart: `RHEL_9_STIG` alone, which makes
    'RHEL 8' an uncovered version; `Google_Chrome_Current_Windows`, whose title carries no
    digits at all, which makes 'Google Chrome 120' version-agnostic;
    `ZEPHYR_GATEWAY_10-0_STIG`, whose one version is written with a dot and must never render
    as two; `NOVAFLOW_DATABASE_19C_STIG`, whose version is glued to a letter and is the one shape
    `glued_versions` can only read from a curated entry, because `2740s` and `3par` share it and are
    model names; and `ORBITAL_DATASTORE_V10-5_STIG`, the `IBM DB2 V10.5 LUW` shape, where `_WORD_RE`
    splits the version into `v10` and `5` so only the title's written run knows the two belong to
    one version; and `NIMBUS7_RELAY_STIG`, the
    `F5 BIG-IP` shape, whose digit belongs to the product's NAME and so must not stop the
    version-agnostic note; and `QUASAR_FABRIC_L2S_STIG`, whose title's only digit is the 2 of
    "Layer 2", a role phrase rather than a version, which a caller reaches by the acronym L2S; and
    `CAN_UBUNTU_22-04_LTS_STIG`, whose version DISA itself writes zero-padded, so its token `04`
    meets a caller who types `4`; and `SENTINEL_4180X_RELAY_STIG`, the `SEL-2740S` and `HPE 3PAR`
    shape, whose title writes a run the strict pattern accepts (`4180`) while no version token and no
    curated entry confirms it, so the two readings DISAGREE and the classifier must stay silent
    rather than call it version-agnostic."""
    directory = tmp_path_factory.mktemp("wide_kb")
    benchmarks = [
        discovered(FIX / "rhel9_xccdf.xml"),
        discovered(FIX / "win2022_xccdf.xml"),
        discovered(FIX / "chrome_current_xccdf.xml"),
        discovered(FIX / "zephyr_10_0_xccdf.xml"),
        discovered(FIX / "novaflow_19c_xccdf.xml"),
        discovered(FIX / "orbital_v10_5_xccdf.xml"),
        discovered(FIX / "nimbus7_xccdf.xml"),
        discovered(FIX / "sentinel_4180x_xccdf.xml"),
        discovered(FIX / "quasar_l2s_xccdf.xml"),
        discovered(FIX / "ubuntu_22_04_xccdf.xml"),
        *_filler_benchmarks(directory),
    ]
    out = directory / "wide.sqlite"
    build_kb(
        IngestSources(
            benchmarks=benchmarks,
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return out


@pytest.fixture(scope="session")
def component_family_kb(tmp_path_factory):
    """A parent benchmark whose title tokens are a strict subset of its three children's.

    The shape DISA ships as vSphere: a query naming the parent matches every child's title
    just as completely, so all four tie at exactly 100.0 and only the tiebreak separates
    them. The parent's stig_id sorts AFTER all three children, so a test asserting the
    parent ranks first cannot pass on an alphabetical tiebreak.
    """
    out = tmp_path_factory.mktemp("component_family") / "family.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[
                discovered(FIX / "vectrix_orchestrator_xccdf.xml"),
                discovered(FIX / "vectrix_cluster_ingest_xccdf.xml"),
                discovered(FIX / "vectrix_cluster_ledger_xccdf.xml"),
                discovered(FIX / "vectrix_cluster_portal_xccdf.xml"),
            ],
            cci_path=FIX / "cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            catalog_path=FIX / "oscal_catalog.json",
        ),
        out,
    )
    return out


@pytest.fixture
def kb_conn(tmp_path):
    """A minimal KB: one library-origin benchmark, TEST_STIG V1R1, with a single rule
    mapped to control AC-2. Built with build_kb (rather than hand-inserted rows) so
    source_versions has real cci/attack/ctid ingest_meta rows to report.

    ctid_path names the JSON fixture, not the CSV one used elsewhere: the CSV loader
    always returns an empty version (a plain technique_id,control_id CSV carries no
    version metadata to extract), while production always ingests ctid_mappings.json
    (see config.py) and gets a real one. The JSON fixture is what source_versions and
    the sources block should see something real to report.

    Lives here because tests/kb/test_queries.py and tests/server/test_tools.py both need
    it, and a fixture defined in one test module is invisible to another."""
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=[discovered(FIX / "test_stig_xccdf.xml")],
            cci_path=FIX / "test_stig_cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.json",
            overrides_path=FIX / "overrides.yaml",
        ),
        out,
    )
    conn = open_db(out)
    yield conn
    conn.close()


def _single_stig_kb(tmp_path, benchmarks, library_artifact=None):
    """Shared builder for the five provenance-note fixtures below: same supporting
    sources as kb_conn, varying only the benchmark list (and, for broken_library_kb,
    the classified library artifact) each carries."""
    out = tmp_path / "kb.sqlite"
    build_kb(
        IngestSources(
            benchmarks=benchmarks,
            cci_path=FIX / "test_stig_cci_list.xml",
            attack_path=FIX / "attack_bundle.json",
            ctid_path=FIX / "ctid_mappings.csv",
            overrides_path=FIX / "overrides.yaml",
            library_artifact=library_artifact,
        ),
        out,
    )
    return open_db(out)


@pytest.fixture
def deprecated_kb(tmp_path):
    """DEPRECATED_STIG, library-origin, marked deprecated by DISA's own <status>
    element: the one signal inside an XCCDF that reliably proves retirement."""
    conn = _single_stig_kb(tmp_path, [discovered(FIX / "deprecated_stig_xccdf.xml")])
    yield conn
    conn.close()


@pytest.fixture
def sunset_kb(tmp_path):
    """TEST_STIG (library-origin, so a compilation exists to cite) alongside
    SUNSET_STIG, pulled from the sunset archive rather than the current library."""
    conn = _single_stig_kb(
        tmp_path,
        [discovered(FIX / "test_stig_xccdf.xml"), discovered(FIX / "sunset_stig_xccdf.xml", origin="sunset")],
    )
    yield conn
    conn.close()


@pytest.fixture
def local_kb(tmp_path):
    """TEST_STIG (library-origin, so a compilation exists to cite) alongside
    LOCAL_STIG, hand-placed as a product zip and absent from that compilation."""
    conn = _single_stig_kb(
        tmp_path,
        [discovered(FIX / "test_stig_xccdf.xml"), discovered(FIX / "local_stig_xccdf.xml", origin="product_zip")],
    )
    yield conn
    conn.close()


@pytest.fixture
def no_library_kb(tmp_path):
    """LOOSE_STIG only, with no library-origin benchmark anywhere in the KB, so no
    stig_library ingest_meta row exists and absence from it cannot be asserted."""
    conn = _single_stig_kb(tmp_path, [discovered(FIX / "loose_stig_xccdf.xml", origin="product_zip")])
    yield conn
    conn.close()


@pytest.fixture
def broken_library_kb(tmp_path):
    """LOOSE_STIG only, same as no_library_kb, but with library_artifact set to simulate
    a truncated or empty library compilation: classify() found the zip, so the
    stig_library ingest_meta row exists, but it contributed zero library-origin
    benchmarks. Absence from it is not a fact this KB can assert either, but for a
    different reason than no_library_kb, and the note must say so."""
    conn = _single_stig_kb(
        tmp_path,
        [discovered(FIX / "loose_stig_xccdf.xml", origin="product_zip")],
        library_artifact="U_SRG-STIG_Library_July_2026.zip",
    )
    yield conn
    conn.close()


@pytest.fixture
def tie_kb(tmp_path):
    """Two benchmarks sharing a title and product_keywords, differing only in stig_id
    and origin, so a resolver query against either ties on score. Hand-inserted rather
    than built through build_kb: the origin tiebreak in _limit_by_benchmark needs an
    exact tie to prove itself against, and the only way to guarantee that is to give
    both rows the same doc tokens rather than deriving product_keywords per stig_id.

    The library benchmark's id is deliberately made to sort AFTER the non-library one
    alphabetically (ZZZ vs AAA). Both benchmarks share a title, so they also tie on the
    specificity key that follows _origin_rank in _limit_by_benchmark's sort; stig_id is the
    key after that. If the ids agreed with origin order a test asserting library-first could
    pass even with _origin_rank silently dropped from that sort key."""
    db = tmp_path / "tie_kb.sqlite"
    conn = create_db(db)
    title = "Example Product Security Technical Implementation Guide"
    keywords = "example product security technical implementation guide"
    for stig_id, origin in (("EXAMPLE_PRODUCT_AAA_STIG", "sunset"), ("EXAMPLE_PRODUCT_ZZZ_STIG", "library")):
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, "1", title, keywords, origin, "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def origin_over_specificity_kb(tmp_path):
    """Two benchmarks tied on score for one query, differing in origin, where the LIBRARY
    row carries MORE unnamed keywords than the non-library row. Proves _origin_rank is read
    before the specificity key: a sort that read specificity first would put the non-library
    row on top, since it names strictly fewer keywords the query did not ask for.

    Hand-inserted for the same reason tie_kb is: product_keywords needs to differ between the
    two rows in a controlled way, which build_kb's own derivation from stig_id does not give.
    """
    db = tmp_path / "origin_over_specificity.sqlite"
    conn = create_db(db)
    title = "Gadget Widget"
    rows = (
        ("GADGET_WIDGET_LEAN_STIG", "sunset", "gadget widget"),
        ("GADGET_WIDGET_FULL_STIG", "library", "gadget widget aux extra bonus"),
    )
    for stig_id, origin, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, "1", title, keywords, origin, "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def multi_major_specificity_kb(tmp_path):
    """One benchmark with two majors of differing specificity (MULTI_MAJOR_STIG: 1 unnamed
    keyword on major 1, 5 on major 2) and a single-major rival sitting strictly between the
    two (RIVAL_STIG: 3). Proves the per-benchmark specificity used to rank MULTI_MAJOR_STIG
    is the MIN across its majors: only the lean major's count (1) beats RIVAL's 3, so a
    reduction that instead took the max, or just whichever major resolve() processed last,
    would rank RIVAL first.

    Hand-inserted so each major's product_keywords can be set independently; build_kb derives
    keywords from title and stig_id alone, which cannot vary the two majors this way.
    """
    db = tmp_path / "multi_major_specificity.sqlite"
    conn = create_db(db)
    title = "Multi Major"
    rows = (
        ("MULTI_MAJOR_STIG", "1", "multi major zzalpha"),
        ("MULTI_MAJOR_STIG", "2", "multi major zzalpha zzbeta zzgamma zzdelta zzepsilon"),
        ("RIVAL_STIG", "1", "multi major zzfoo zzbar zzbaz"),
    )
    for stig_id, version, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def fragment_win_specificity_kb(tmp_path):
    """A benchmark whose FIRST fragment wins it a low score with a low unnamed count, and
    whose SECOND fragment then wins it a higher score with a higher unnamed count.
    TARGET_STIG's true specificity is the winning (Beta) fragment's 5 unnamed document
    tokens, not the losing (Alpha) fragment's 2; RIVAL_STIG's fixed 3 sits strictly between
    the two (2 < 3 < 5), so this pins the accumulator's per-fragment reduction, not just the
    per-major one multi_major_specificity_kb pins.

    The document is title plus product_keywords (resolver.py:415). Unlike the other
    tiebreak fixtures, this one's product_keywords name only the vocabulary each fragment
    below is written to test and do not repeat the title: TARGET's title adds "target" and
    "product", RIVAL's adds "rival" and "product", and neither fragment names any of them,
    so all four land in the respective document's unnamed count on top of the keyword
    tokens. Recompute by hand against resolver.py's `_corpus`/`_split`/`normalize` if the
    title, keywords, or fragments below ever change; do not carry these numbers forward
    unverified.

    Both benchmarks are library origin so the tiebreak reaches specificity at all. Hand-
    inserted for the same reason the other tiebreak fixtures are: this needs product_keywords
    that name a fragment's OWN extra vocabulary, which build_kb's stig_id-derived keywords
    cannot control.
    """
    db = tmp_path / "fragment_win_specificity.sqlite"
    conn = create_db(db)
    rows = (
        ("TARGET_STIG", "1", "Target Product", "alpha beta junk1 junk2", "library"),
        ("RIVAL_STIG", "1", "Rival Product", "beta extra1", "library"),
    )
    for stig_id, version, title, keywords, origin in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, origin, "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def losing_fragment_specificity_kb(tmp_path):
    """A benchmark whose WINNING fragment names MORE of its document than its losing one.

    Both other fragment fixtures give the surviving fragment the higher unnamed count, which
    a running max across every fragment reproduces by accident. This reverses that: against
    the query in the test below, ZZZ_TARGET_STIG scores 53.3 on 'zzalpha zzbeta' with 5
    unnamed document tokens and 100.0 on 'zzq zzbeta zzgamma zzdelta zzeps' with 1, so the
    winner's count is the SMALLER one. AAA_RIVAL_STIG covers the first fragment exactly (100.0,
    3 unnamed) and only partly covers the second (32.1, 4), so it keeps 3.

    That places 3 between the winner's 1 and the loser's 5: recording the winner puts TARGET
    first, taking the max across fragments puts RIVAL first (4 against 5). Both benchmarks
    reach exactly 100.0, which is what makes the specificity key decide the order at all, and
    TARGET sorts LAST on stig_id so dropping that key changes the answer too.

    Recompute against resolver.py's `_corpus`/`_split`/`normalize`/`score` if the titles,
    keywords or fragments change: the correct order wins by two tokens (1 against 3) and the
    max-across-fragments order loses by one (5 against 4), so that one-token margin is what a
    careless edit erases.
    """
    db = tmp_path / "losing_fragment_specificity.sqlite"
    conn = create_db(db)
    rows = (
        ("ZZZ_TARGET_STIG", "1", "Zzt Zzq", "zzbeta zzgamma zzdelta zzeps"),
        ("AAA_RIVAL_STIG", "1", "Zzr Zzs", "zzalpha zzbeta zzomega"),
    )
    for stig_id, version, title, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def fragment_tie_specificity_kb(tmp_path):
    """A benchmark two query fragments score IDENTICALLY, with different unnamed counts.

    The companion to fragment_win_specificity_kb, which covers a later fragment scoring
    strictly HIGHER. resolve() replaces a hit only on a strict `>`, so a later fragment that
    ties never gets to record its own count, and no other fixture reaches that path.

    Against the query in the test below, AAA_TARGET_STIG scores 100.0 on the first fragment
    with 5 unnamed document tokens and 100.0 again on the second with 2; the first is what
    survives. ZZZ_RIVAL_STIG's 3 sits strictly between them, so it outranks TARGET only while
    TARGET's count is the earlier fragment's 5. The ids are deliberately ordered against the
    expected result (AAA sorts first, ZZZ is what must come back first) so the assertion
    cannot also pass with the specificity key dropped from the sort.

    Whether the earlier fragment SHOULD own a tied key is an open question, not a settled
    rule: measured on the real knowledge base, 'zOS IBM System Display and Search Facility
    for RACF' splits on its own title's "and" and records 11 unnamed for the RACF answer
    against its ACF2 sibling's 8, both measured against a fragment naming neither. This
    fixture pins today's answer so that a future change to it is visible rather than silent.

    Hand-inserted for the same reason the other tiebreak fixtures are: it needs
    product_keywords the fragments below name in controlled proportions, which build_kb's
    stig_id-derived keywords cannot produce.
    """
    db = tmp_path / "fragment_tie_specificity.sqlite"
    conn = create_db(db)
    rows = (
        ("AAA_TARGET_STIG", "1", "Zzt Target", "zzalpha zzbeta zzgamma zzdelta"),
        ("ZZZ_RIVAL_STIG", "1", "Zzr Rival", "zzalpha zzomega"),
    )
    for stig_id, version, title, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def cci_batch_kb(tmp_path):
    """Findings under one control whose CCI sets DIFFER, across two benchmarks.

    The shared fixtures cannot express a mis-batched CCI fetch: `kb_path` yields one finding,
    and `mixed_severity_xccdf.xml`'s three rules all carry the same CCI-000015, so handing
    every finding the union of all CCIs would pass either of them. Here A_RULE_1 carries two
    CCIs, A_RULE_2 carries one, and A_RULE_3 shares one of A_RULE_1's, so a union, an
    order-based pairing, or a grouping keyed on the CCI instead of the rule all produce a
    visibly wrong answer.

    Two benchmarks because the query-count test needs the number of findings to VARY while
    the control stays fixed: scoping to A_STIG alone yields three findings and scoping to
    both yields five, and a fetch that is not batched costs one statement per finding.

    All three CCIs map to AC-3, so `findings_for_control`'s DISTINCT is exercised too: a
    two-CCI rule produces two pre-DISTINCT rows for the same rule.

    Hand-inserted rather than built from XCCDF, like the other query-shape fixtures: the
    ingest derives rule_cci from each rule's own ident elements, and expressing "two rules
    sharing one of two CCIs" through fixture XML would put the arithmetic this test depends
    on in a file the test does not name.
    """
    db = tmp_path / "cci_batch.sqlite"
    conn = create_db(db)
    conn.execute("INSERT INTO controls (control_id, name, family) VALUES ('AC-3', 'Access Enforcement', 'AC')")
    for cci_id in ("CCI-000100", "CCI-000200", "CCI-000300"):
        conn.execute("INSERT INTO ccis (cci_id, definition) VALUES (?, ?)", (cci_id, f"definition of {cci_id}"))
        conn.execute("INSERT INTO cci_control (cci_id, control_id) VALUES (?, 'AC-3')", (cci_id,))
    for stig_id in ("A_STIG", "B_STIG"):
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact, release_label) "
            "VALUES (?, '1', ?, ?, 'library', 'test fixture', 'V1R1')",
            (stig_id, f"{stig_id} Guide", stig_id.lower()),
        )
    rules = (
        ("A_RULE_1", "A_STIG", ("CCI-000100", "CCI-000300")),
        ("A_RULE_2", "A_STIG", ("CCI-000200",)),
        ("A_RULE_3", "A_STIG", ("CCI-000100",)),
        ("B_RULE_1", "B_STIG", ("CCI-000200", "CCI-000300")),
        ("B_RULE_2", "B_STIG", ("CCI-000300",)),
    )
    for rule_id, stig_id, ccis in rules:
        conn.execute(
            "INSERT INTO stig_rules (rule_id, group_id, stig_id, stig_version, severity_cat, severity_level, "
            "title, fix_text, check_text) VALUES (?, ?, ?, '1', 'I', 'high', ?, 'fix', 'check')",
            (rule_id, f"V-{rule_id}", stig_id, f"title of {rule_id}"),
        )
        for cci_id in ccis:
            conn.execute("INSERT INTO rule_cci (rule_id, cci_id) VALUES (?, ?)", (rule_id, cci_id))
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def version_specificity_kb(tmp_path):
    """Two benchmarks whose unnamed-token counts differ ONLY in their VERSION tokens.

    Every other specificity fixture is version-token-free, so `dv` and `qv` never contribute
    to `len((dp | dv) - (qp | qv))` and reducing it to `len(dp - qp)` passes all of them. Here
    both rows carry the identical product token (`gizmo` from title and keywords alike), so the
    product half is 0 for both and the reduced form ties them; the full form separates them,
    because GIZMO_ZEBRA_STIG's document holds only the version the query names and
    GIZMO_ALPHA_STIG's dotted 7.8.9 holds two more.

    Both reach exactly 100.0, which is what lets the sort reach the specificity key at all:
    product coverage is 1.0 for both, and `_version_matched` finds the query's 7 in each, so
    the version half is 1.0 for both as well. Both are library origin and neither is
    high-confidence (one product token at df 2 against a gate of 0.1 clears nothing), so score,
    confidence and origin all tie ahead of specificity. ZEBRA sorts LAST on stig_id, the key
    below specificity, so the reduced form does not merely tie the two: it reverses them.

    Hand-inserted for the same reason the other specificity fixtures are: build_kb derives
    product_keywords from title and stig_id, which would put ALPHA and ZEBRA into the documents
    and leave the two rows differing in product tokens as well as version ones.
    """
    db = tmp_path / "version_specificity.sqlite"
    conn = create_db(db)
    rows = (
        ("GIZMO_ALPHA_STIG", "1", "Gizmo 7.8.9", "gizmo"),
        ("GIZMO_ZEBRA_STIG", "1", "Gizmo 7", "gizmo"),
    )
    for stig_id, version, title, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def vsphere_appliance_kb(tmp_path):
    """The vCenter parent plus three VCSA component benchmarks, under their REAL stig_ids.

    Real ids, not invented ones, because the thing under test is a production aliases.yaml
    entry naming `VMW_vSphere_8-0_vCenter_STIG`: a fixture with invented ids would exercise
    the alias machinery while proving nothing about the shipped table.

    Titles are DISA's own. The components carry `vcsa` in their ids and so reach the parent's
    tier on the keyword path alone, which is why the alias names only the parent: it adds the
    one benchmark a caller naming the appliance was never shown.

    Pins RANKING only, never auto-scoping. `is_high_confidence` gates on `df <= 0.05 * n`, and
    with four rows that ceiling is 0.2 against a minimum df of 1, so no keyword hit in this
    fixture can ever be confident however the resolver behaves. The scoping half of the defect
    is a property of the real knowledge base and is measured there, not asserted here.
    """
    db = tmp_path / "vsphere_appliance.sqlite"
    conn = create_db(db)
    rows = (
        ("VMW_vSphere_8-0_vCenter_STIG", "VMware vSphere 8.0 vCenter Security Technical Implementation Guide"),
        (
            "VMW_vSphere_8-0_VCSA_Envoy_STIG",
            "VMware vSphere 8.0 vCenter Appliance Envoy Security Technical Implementation Guide",
        ),
        (
            "VMW_vSphere_8-0_VCSA_PostgreSQL_STIG",
            "VMware vSphere 8.0 vCenter Appliance PostgreSQL Security Technical Implementation Guide",
        ),
        (
            "VMW_vSphere_8-0_VCSA_Photon_OS_4-0_STIG",
            "VMware vSphere 8.0 vCenter Appliance Photon OS 4.0 Security Technical Implementation Guide",
        ),
    )
    for stig_id, title in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, "1", title, _keywords(title, stig_id), "library", "U_SRG-STIG_Library_July_2026.zip"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def confident_tie_kb(tmp_path):
    """Five unconfident benchmarks and one confident one, all tied on score to the digit.

    Reproduces the real `tier 4` shape against the NSX family, minimally. `score` measures
    product coverage against `dp` ALONE while `is_high_confidence` satisfies against
    `dp | dv`, so a query whose digit lands in `qp` can tie a benchmark that holds the digit
    only as a VERSION against benchmarks that do not hold it at all. All six cover `zzalpha`
    and `tier` and nothing covers the `4`, so all six score identically; only ZZZ_TARGET
    holds a `4` anywhere, so only it is confident.

    `tier` is one of normalize._PHRASE_HEADS, which is what keeps the query's `4` a PRODUCT
    token instead of a version one. The target writes its own version `4.x`, as DISA writes
    NSX's, so the digit lands in `dv` rather than `dp`. Both details are load bearing: change
    either and the six stop tying.

    Twenty filler rows because `is_high_confidence` gates on `df <= 0.05 * n`, so a document
    frequency of 1 is distinctive only once the corpus holds 20. The six named rows plus
    fourteen fillers would reach 20 exactly; the margin over that protects against fillers
    being dropped, not added, because a new row raises both sides of the gate. A row holding a
    `4` of its own would put `df` at 2 and need a corpus of 40. The rivals sort before the
    target on `stig_id`, the last key, and carry the same `unnamed` count, so without the
    confidence term the default cap of five keeps all five rivals and drops the one row
    anything would be scoped to.
    """
    db = tmp_path / "confident_tie.sqlite"
    conn = create_db(db)
    rows = [
        (f"AAA_RIVAL_{word}_STIG", f"Zzalpha Tier Zz{word.lower()} Security Technical Implementation Guide")
        for word in ("ONE", "TWO", "THREE", "FOUR", "FIVE")
    ]
    rows.append(("ZZZ_TARGET_STIG", "Zzalpha 4.x Tier Zzgamma Security Technical Implementation Guide"))
    rows += [
        (f"FILLER_ZZ{letter.upper()}_STIG", f"Fillerware Zz{letter} Security Technical Implementation Guide")
        for letter in string.ascii_lowercase[:20]
    ]
    for stig_id, title in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, "1", title, _keywords(title, stig_id), "library", "U_SRG-STIG_Library_July_2026.zip"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def splittable_name_kb(tmp_path):
    """Three siblings whose shared product name contains a separator.

    The z/OS SDSF shape at fixture scale. Split, the fragment holding 'Zzsystem Display' names
    none of the three discriminators, ties all three, and every one comes back confident.
    Unsplit, only the sibling the caller named holds its own distinctive token.

    **The row count is forced by arithmetic, not chosen.** The defect needs `display` to be
    DISTINCTIVE so that fragment one can make all three siblings confident, and the gate is
    `df <= 0.05 * n`. Three siblings hold it, so n must be at least 60. Recompute against
    resolver.py's `build_idf` and `is_high_confidence` if the row counts below change; a
    smaller fixture cannot reproduce the defect and every assertion built on it reads as
    though it had.
    """
    db = tmp_path / "splittable_name.sqlite"
    conn = create_db(db)
    rows = [
        (f"SIB_{name.upper()}_STIG", "1", f"Zzsystem Display and Search Zzfacility for {name}", "")
        for name in ("Zzalpha", "Zzbeta", "Zzgamma")
    ]
    rows += [(f"FILLER{i}_STIG", "1", f"Zzfill{i} Zzpad{i}", "") for i in range(57)]
    for stig_id, version, title, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()


@pytest.fixture
def unrelated_straddling_kb(tmp_path):
    """A product benchmark plus an unrelated benchmark whose own title straddles a separator,
    for pinning the ACCEPTED COST that protection carries.

    `_straddling_pairs` protects a separator by the words bracketing it, not by which product
    a caller is describing, so a description that writes ordinary English matching a protected
    pair after an unrelated product name is left undivided too. On this fixture,
    `resolve(conn, "Zzapache Server 2.4")` alone returns ZZAPACHE_STIG at score 100.0,
    high_confidence=True; `resolve(conn, "Zzapache Server 2.4 security and development
    environment")` returns ZZAPACHE_STIG and ZZAPPSECDEV_STIG both under the confidence gate,
    high_confidence=False on both, an EMPTY high-confidence scope where the bare description
    was confident.

    The mechanism: the merged query carries FIVE distinctive product tokens at this fixture's
    scale (n=60, gate 3.0), 'and', 'development', 'environment', 'server' and 'zzapache', and
    `is_high_confidence` requires EVERY one of them to be satisfied by a candidate's own
    tokens. Neither candidate manages it, and they fail on DIFFERENT tokens, which is the
    point: ZZAPACHE_STIG is missing 'and', 'development' and 'environment', while
    ZZAPPSECDEV_STIG holds those first two and is missing 'environment', 'server' and
    'zzapache'. So no single word is doing this alone, and dropping 'environment' would not
    rescue either one. Row count otherwise follows splittable_name_kb's scale (n=60, gate
    0.05*60=3.0, comfortably above every named benchmark's own df=1 tokens); the shape does not
    depend on this exact n.
    """
    db = tmp_path / "unrelated_straddling.sqlite"
    conn = create_db(db)
    rows = [
        ("ZZAPACHE_STIG", "2.4", "Zzapache Server 2.4 Security Technical Implementation Guide", ""),
        (
            "ZZAPPSECDEV_STIG",
            "1",
            "Zzapplication Security and Development Security Technical Implementation Guide",
            "",
        ),
    ]
    rows += [(f"FILLER{i}_STIG", "1", f"Zzfill{i} Zzpad{i}", "") for i in range(58)]
    for stig_id, version, title, keywords in rows:
        conn.execute(
            "INSERT INTO stigs (stig_id, version, title, product_keywords, origin, source_artifact) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stig_id, version, title, keywords, "library", "test fixture"),
        )
    conn.commit()
    conn.close()
    conn = open_db(db)
    yield conn
    conn.close()
