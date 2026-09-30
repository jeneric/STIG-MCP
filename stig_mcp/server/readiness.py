"""Whether the knowledge base can be answered from, and what to run when it cannot.

Returns a state rather than raising. A server that refuses to start is invisible in VS Code:
the user gets an error indicator and has to open an output pane to learn why. A state lets
the tools say it in band, where an agent can read it and act.

The server never answers from a knowledge base it cannot trust; it declines per call rather
than at startup, which also catches a knowledge base that appears or is rebuilt while the
server runs.
"""

import os
import sqlite3
import sys

from stig_mcp.ingest import config, inventory
from stig_mcp.kb.db import SCHEMA_VERSION, open_db

READY = "ready"

_MODULES = {
    "install": "stig_mcp.kb.install",
    "fetch": "stig_mcp.ingest.fetch",
    "ingest": "stig_mcp.ingest.orchestrator",
}
_SCRIPTS = {"install": "stig-mcp-install-kb", "fetch": "stig-mcp-fetch", "ingest": "stig-mcp-ingest"}


def identity(kb_path):
    """What makes one build of the knowledge base different from another, cheaply.

    Same shape as applicability._file_identity. Checked on every tool call so a rebuild is noticed
    without a restart; see CorpusCachingConnection for why a held connection would otherwise
    keep serving the old file.
    """
    try:
        stat = os.stat(kb_path)
    except OSError:
        return None
    return (str(kb_path), stat.st_mtime_ns, stat.st_size)


def check(kb_path):
    """One of READY, "no_knowledge_base", "schema_outdated", "unreadable"."""
    if identity(kb_path) is None:
        return "no_knowledge_base"
    try:
        conn = open_db(kb_path)
    except (RuntimeError, FileNotFoundError):
        return "unreadable"
    try:
        row = conn.execute("SELECT schema_version FROM ingest_meta LIMIT 1").fetchone()
    except sqlite3.DatabaseError:
        return "unreadable"
    finally:
        conn.close()
    found = row["schema_version"] if row else None
    return READY if found == SCHEMA_VERSION else "schema_outdated"


def _step(key, why):
    # Both forms, deliberately. `run` is what an agent should execute and works from an
    # isolated install because sys.executable provably has the package; `as_installed` is
    # what a human reads and what the documentation uses.
    return {"why": why, "run": f"{sys.executable} -m {_MODULES[key]}", "as_installed": _SCRIPTS[key]}


def _install_step():
    # The tool is what an agent should call; run and as_installed are the same download from a
    # terminal, so they need GitHub as much as the tool does. A host that cannot reach GitHub
    # installs with stig-mcp-install-kb --file PATH --sha256 HEX, which neither command here runs.
    return {"tool": "install_knowledge_base", **_step("install", "install the prebuilt knowledge base")}


# Every reason `check` can return that is not READY. payload renders a body whose status is
# always "not_ready", so READY is not merely unhandled here, it is a contradiction.
_NOT_READY_REASONS = ("no_knowledge_base", "schema_outdated", "unreadable")


def payload(kb_path, reason):
    """The not_ready body a tool returns.

    Refuses READY, and anything `check` cannot return, rather than rendering it. The body's
    status is hardcoded "not_ready", so `payload(kb, READY)` would render
    `{"status": "not_ready", "reason": "ready"}`, which reads as an answer and is not one.
    """
    if reason not in _NOT_READY_REASONS:
        raise ValueError(
            f"readiness.payload cannot render the reason {reason!r}. It builds a not_ready body, so "
            f"it takes one of {', '.join(_NOT_READY_REASONS)}. If this came from readiness.check, the "
            f"caller must branch on check() == readiness.READY and answer from the knowledge base "
            f"instead of calling payload at all."
        )
    status = inventory.source_status(config.SOURCES_DIR)
    steps = [_install_step(), _step("ingest", "or rebuild the knowledge base from the sources")]
    if reason == "no_knowledge_base":
        steps = [
            _install_step(),
            _step("fetch", "or download the sources"),
            _step("ingest", "then build the knowledge base"),
        ]
    elif reason == "unreadable":
        steps = [_install_step(), _step("ingest", f"or delete {kb_path} first, then rebuild the knowledge base")]
    return {
        "status": "not_ready",
        "reason": reason,
        "have": sorted(name for name, present in status.items() if present),
        "missing": sorted(name for name, present in status.items() if not present),
        "sources_dir": str(config.SOURCES_DIR),
        "next": steps,
        "manual": (
            f"Or place the artifacts in {config.SOURCES_DIR} by hand and run the ingest. "
            f"Nothing in the ingest requires the fetch to have run."
        ),
    }
