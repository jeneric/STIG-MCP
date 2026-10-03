import sqlite3
from pathlib import Path

SCHEMA_VERSION = "7"
_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def create_db(path):
    path = Path(path)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA_PATH.read_text())
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class CorpusCachingConnection(sqlite3.Connection):
    """A connection the resolver can hang its derived corpus on.

    `resolve` derives most of its work from the corpus rather than the query, and that work must be
    cached against the DATA THE CONNECTION READS. Neither obvious mechanism allows it: a bare
    `sqlite3.Connection` has no `__dict__`, so the cache cannot be an attribute, and it is not
    weak-referenceable, so it cannot key a `WeakKeyDictionary` either.

    Keying an external dict on the KB FILE would be wrong. `build_kb` and the installer write a
    temporary file and `replace()` it into position, so a read-only connection goes on reading the
    inode it opened while the path acquires a new identity. The old corpus would then be stored under
    the NEW file's key and handed to the next connection opened on it, which would report a benchmark
    its database does not contain and hide one it does.

    Subclassing binds the cache to the connection, so it lives exactly as long as the view it
    describes and can never reach a connection reading a different database.
    """


def open_db(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"Knowledge base not found at {path}. Run the ingest pipeline "
            f"(stig-mcp-ingest) to build it before starting the server."
        )
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, factory=CorpusCachingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        # connect() is lazy and PRAGMA does not read the file header, so this catalog
        # read is the first thing that touches it. Without it a corrupt KB opens fine
        # and fails much later, inside a tool call, as a raw sqlite3 error.
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise RuntimeError(
            f"Knowledge base at {path} cannot be read as a SQLite database ({exc}). "
            f"Delete the file and re-run the ingest pipeline (stig-mcp-ingest) to rebuild it."
        ) from exc
    return conn


def table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r["name"] for r in rows}
