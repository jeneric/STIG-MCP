"""Checks on the test suite itself, not on the package."""

import ast
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).parent

# test_db.py tests open_db's own guards, so it has to call the real function; it wraps each
# call in contextlib.closing instead. conftest.py is where open_db_for_test is defined.
# Relative paths, not bare names, so a future tests/<anything>/test_db.py is not exempt too.
ALLOWED_TO_IMPORT_OPEN_DB = {"conftest.py", "kb/test_db.py"}


def _imports_open_db(source):
    """True if the module imports the name open_db from anywhere, however it spells it.

    An ast walk rather than a scan of line prefixes, which would miss the three spellings a real
    regression is most likely to use: an import indented inside a function or fixture body, a
    parenthesized multi-line import, and a backslash continuation.

    Any module, not just stig_mcp.kb.db, because `stig_mcp.server.app` imports open_db at
    module level and so re-exports the real function; tests/server/test_app.py already imports
    from that module, which makes it a reachable mistake rather than a hypothetical one.
    """
    return any(
        isinstance(node, ast.ImportFrom) and any(alias.name == "open_db" for alias in node.names)
        for node in ast.walk(ast.parse(source))
    )


def test_test_modules__none_import_open_db_directly__so_every_connection_gets_closed():
    """A test that opens a connection through open_db has nothing to close it.

    open_db_for_test hands each connection to a teardown, and this keeps the next test module
    from quietly going back to open_db, whose unclosed connections would bury a real leak's
    ResourceWarning among the suite's own.

    What it does NOT catch: a connection from create_db or from a bare sqlite3.connect, and a
    call written as `db.open_db(...)` against a module import. The first two are closed by hand
    and guarded by the create_db check below; nothing guards the third. (A star import would
    also escape, but ruff's F403 blocks it at the mandatory `uv run ruff check .` gate.)

    Not enforced by pytest configuration: an `error` filter on the ResourceWarning or on
    PytestUnraisableExceptionWarning lets a reintroduced leak pass. sqlite3 raises the warning
    while finalizing the connection, where an exception cannot propagate, so no warning filter
    can turn it into a failure.
    """
    offenders = sorted(
        str(path.relative_to(TESTS))
        for path in TESTS.rglob("*.py")
        if str(path.relative_to(TESTS)) not in ALLOWED_TO_IMPORT_OPEN_DB and _imports_open_db(path.read_text())
    )
    assert offenders == [], (
        f"{offenders} import open_db directly. Import open_db_for_test from tests.conftest instead, "
        f"or wrap the call in contextlib.closing and add the module to ALLOWED_TO_IMPORT_OPEN_DB here."
    )


# The two spellings that reach sqlite3 without going through open_db. Attribute and bare name
# both, so `sqlite3.connect(...)` and a `from sqlite3 import connect` are one rule.
_OPENING_CALLS = {"create_db", "connect"}


def _closed_or_handed_back(fn):
    """Names the function either closes itself or gives to someone else to close.

    Any ATTRIBUTE named close, not only a call to one, so that `request.addfinalizer(conn.close)`
    and `stack.callback(conn.close)` count. Those pass the method itself, which parses as an
    ast.Attribute with no ast.Call around it, so matching calls alone would report the standard
    pytest cleanup idiom as a leak.

    Except an attribute standing alone as its own statement. `conn.close` on a line consumed by
    nothing does exactly as much at runtime as a bare `conn` does, which is nothing, and ruff's
    rules here do not flag either. Widening to the attribute is what makes the finalizer work
    and would otherwise reopen the same hole one line further along.
    """
    discarded = {id(node.value) for node in ast.walk(fn) if isinstance(node, ast.Expr)}
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and node.attr == "close" and isinstance(node.value, ast.Name):
            if id(node) not in discarded:
                names.add(node.value.id)
        elif isinstance(node, (ast.Return, ast.Yield)) and isinstance(node.value, ast.Name):
            names.add(node.value.id)
    return names


def _unclosed_connections(source):
    """Every `x = create_db(...)` or `x = sqlite3.connect(...)` whose x is then dropped on the floor.

    Returns line numbers. A connection RETURNED or YIELDED is not an offender: that is the
    fixture and helper shape, where the caller or the teardown owns the close.
    """
    offenders = []
    for fn in ast.walk(ast.parse(source)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kept = _closed_or_handed_back(fn)
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            func = node.value.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if called not in _OPENING_CALLS:
                continue
            offenders += [node.lineno for t in node.targets if isinstance(t, ast.Name) and t.id not in kept]
    return offenders


def test_test_modules__every_create_db_connection__is_closed_or_handed_back():
    """The import check above cannot see a connection that never went through open_db.

    Its own docstring names create_db and sqlite3.connect as the escapes; this closes them.

    An AST walk rather than a warning filter, for the reason the import check gives: sqlite3
    raises `ResourceWarning: unclosed database` while FINALIZING the connection, so no filter
    can fail the suite on it. A finalizer warning also prints straight to stderr and never
    enters pytest's warnings summary, so that summary reads clean over a real leak. This check
    depends on no garbage-collection timing at all.

    What it does NOT catch: a connection opened by a HELPER and assigned from its return
    value, since the assignment names the helper and not a spelling in _OPENING_CALLS.
    `_permissive_kb` in tests/tools/test_corpus_conformance.py is the one such helper, and every
    one of its call sites closes what it hands back, but the guard would not see it if one
    stopped. Catching that needs the return value taint-followed into every caller.

    Nor does it model control flow or scope. A close reached only on one branch, a name
    reassigned from a second connection, a walrus binding, a connection stored on `self` or in
    a container, and a `.close()` inside a nested function on a same-named other object all
    escape it. None of those shapes appears anywhere in tests/ today.
    """
    offenders = sorted(
        f"{path.relative_to(TESTS)}:{lineno}"
        for path in TESTS.rglob("*.py")
        for lineno in _unclosed_connections(path.read_text())
    )
    assert offenders == [], (
        f"{offenders} open a database connection and neither close nor return it. Call "
        f"conn.close() before the test ends, or wrap the call in contextlib.closing as "
        f"tests/kb/test_db.py does."
    )


def test_unclosed_connections__a_connection_handed_to_a_finalizer__is_not_an_offender():
    # request.addfinalizer(conn.close) and ExitStack.callback(conn.close) pass the method
    # itself, which parses as an ast.Attribute and not an ast.Call, so a scan for close()
    # CALLS alone sees no close at all and reports the standard idiom as a leak.
    source = "def test_x(tmp_path, request):\n    conn = create_db(tmp_path)\n    request.addfinalizer(conn.close)\n"
    assert _unclosed_connections(source) == []


def test_unclosed_connections__a_bare_name_statement__is_still_an_offender():
    # `conn` alone on a line does nothing at runtime, so counting it as a hand-off would let
    # any leak evade this guard with one line. Ruff's enabled rules here (E, W, F, I, S, PL,
    # no bugbear) do not flag a bare-name statement either, so nothing downstream would catch it.
    source = "def test_x(tmp_path):\n    conn = create_db(tmp_path)\n    conn\n"
    assert _unclosed_connections(source) == [2]


def test_unclosed_connections__a_bare_close_attribute__is_still_an_offender():
    # `conn.close` without the parentheses is the same no-op the bare name above is, and
    # counting the ATTRIBUTE is exactly what lets the finalizer idiom through, so the two
    # shapes have to be told apart by whether anything consumes the attribute.
    source = "def test_x(tmp_path):\n    conn = create_db(tmp_path)\n    conn.close\n"
    assert _unclosed_connections(source) == [2]


# Printed by the child rather than asserted there, so a failure NAMES the module that leaked
# instead of only reporting a non-zero exit.
_OFFLINE_PROBE = (
    "import sys, stig_mcp.ingest.orchestrator; "
    "print(sorted(m for m in ('stig_mcp.ingest.fetch', 'stig_mcp.ingest.catalog') if m in sys.modules))"
)


def test_orchestrator__imported_in_a_fresh_interpreter__pulls_in_neither_fetch_nor_catalog():
    """build_kb must not import the download half, and only a fresh interpreter can see that.

    This is what keeps the manual placement path first-class: the ingest reads a directory and
    consults nothing that fetches, so an operator on a host that cannot reach dl.dod.cyber.mil
    runs exactly the same pipeline. catalog states the guarantee in prose and imports fetch at
    module level, so the two halves are one import away from each other at all times.

    A subprocess because pytest has already imported both by the time any test runs: an
    in-process `assert "stig_mcp.ingest.fetch" not in sys.modules` passes or fails on what the
    rest of the suite imported, never on what the ingest imports.
    """
    # S603: argv is sys.executable plus a literal probe defined above, not external input.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _OFFLINE_PROBE], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]", (
        f"importing stig_mcp.ingest.orchestrator pulled in {result.stdout.strip()}. The ingest "
        f"must not import the fetch half: move whatever needs it into a function-local import, "
        f"as fetch.selection and fetch.prune already do for catalog."
    )


def test_corpus_manifest__tier_of__is_imported_not_redefined():
    # One rule in one place: two copies of one rule (as with inventory.LOOSE_GLOB against
    # _kind_of) can silently disagree about exactly the population at risk.
    source = (Path(__file__).parent.parent / "tools" / "corpus_manifest.py").read_text()
    tree = ast.parse(source)
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "tier_of" not in defined
    assert "fetch_listing" not in defined
    assert "from stig_mcp.ingest.catalog import" in source


# The fixtures built specifically to collide, for the rule_id attribution ordering. Every other
# fixture must be collision-free, or a test combining two of them silently exercises the
# attribution path instead of what it claims to test.
DELIBERATELY_COLLIDING = {
    "shared_rules_2024_xccdf.xml",
    "shared_rules_2026_xccdf.xml",
    "shared_rules_same_date_xccdf.xml",
    "shared_rules_same_date_twin_xccdf.xml",
    "shared_rules_no_date_xccdf.xml",
    "shared_rules_major1_xccdf.xml",
    "shared_rules_major2_xccdf.xml",
    "shared_rules_two_holders_xccdf.xml",
    "mixed_holders_xccdf.xml",
}


def test_benchmark_fixtures__two_with_different_stig_ids__share_no_rule_id():
    """A shared rule_id makes the winner depend on insertion order, inside a test that is not about that.

    `_insertion_order` makes the winner a stated rule, so two unrelated fixtures sharing an id
    can make a test about something else, such as resolve()'s limit, fail for a reason that has
    nothing to do with it.

    A listed fixture is still PARSED and still owns its ids; only a collision where BOTH sides
    are listed is excused. Skipping the listed files outright would leave their ids unowned, so
    a new fixture reusing one would be invisible to this check.
    """
    from stig_mcp.ingest.stig_parser import parse_stig  # noqa: PLC0415

    owners = {}
    collisions = []
    for path in sorted((TESTS / "fixtures").glob("*_xccdf.xml")):
        parsed = parse_stig(path)
        for rule in parsed.rules:
            other = owners.setdefault(rule.rule_id, (parsed.stig_id, path.name))
            if other[0] == parsed.stig_id or {other[1], path.name} <= DELIBERATELY_COLLIDING:
                continue
            collisions.append(f"{rule.rule_id}: {other[1]} ({other[0]}) and {path.name} ({parsed.stig_id})")
    assert collisions == [], (
        f"fixtures share a rule_id across different benchmarks: {collisions}. Renumber one of "
        f"them, or add it to DELIBERATELY_COLLIDING here if the collision is the point."
    )
