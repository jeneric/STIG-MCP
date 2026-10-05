from stig_mcp.kb import actor_match

_CAT_ORDER = "CASE severity_cat WHEN 'I' THEN 1 WHEN 'II' THEN 2 ELSE 3 END"


def _tactics(row_value):
    return row_value.split(",") if row_value else []


def technique_row(conn, technique_id):
    row = conn.execute(
        "SELECT technique_id, name, tactics FROM techniques WHERE technique_id = ?",
        (technique_id,),
    ).fetchone()
    if row is None:
        return None
    return {"id": row["technique_id"], "name": row["name"], "tactics": _tactics(row["tactics"])}


def effective_controls(conn, technique_id):
    """Controls mapped to a technique, with an override outranking the CTID default.

    Suppression is NOT re-resolved here. `_effective_pairs` drops a tombstoned pair at ingest
    and the only INSERT into technique_control hardcodes `suppressed = 0`, so a correlated
    NOT EXISTS over `source='override' AND suppressed = 1` would match nothing. The
    `suppressed = 0` filter below is the cheap schema-level guard, since the column admits a 1
    and this query would otherwise serve one silently.

    Do not write `suppressed = 1` rows to handle tombstones here: that would apply tombstones to
    overrides.yaml's own `add:` entries, contradicting the documented rule that an operator's
    suppress entry never kills their own add entry.
    """
    rows = conn.execute(
        """
        SELECT c.control_id, c.name, c.family,
               MAX(CASE WHEN tc.source='override' THEN 'override' ELSE 'ctid' END) AS source
        FROM technique_control tc
        JOIN controls c ON c.control_id = tc.control_id
        WHERE tc.technique_id = ? AND tc.suppressed = 0
        GROUP BY c.control_id, c.name, c.family
        ORDER BY c.control_id
        """,
        (technique_id,),
    ).fetchall()
    return [
        {"control_id": r["control_id"], "name": r["name"], "family": r["family"], "source": r["source"]} for r in rows
    ]


# One bound parameter per rule, so the batch below has to respect SQLITE_LIMIT_VARIABLE_NUMBER.
# SQLite below 3.32 defaults it to 999 (32766 from 3.32). The published package accepts any
# Python from 3.11 up, linked against whatever SQLite that interpreter carries, so the older
# ceiling is the one to design against: CM-6 returns 3721 rules at full scope.
_RULE_CHUNK = 900


def _ccis_by_rule(conn, rule_ids):
    """Every rule's CCIs, keyed by rule_id, in one query per _RULE_CHUNK rules.

    Chunked rather than one `IN` list to stay under SQLite's pre-3.32 parameter ceiling (see
    _RULE_CHUNK). Keys therefore come out sorted within each chunk and in caller order across
    chunks, not globally; callers read by `.get`, so nothing depends on the order.

    The batch's own `ORDER BY` is kept for intent and cannot be pinned by deleting it:
    `rule_cci`'s primary key is `(rule_id, cci_id)`, so the covering index already returns each
    rule's CCIs sorted and removing the clause changes no fixture. A test pins the ascending
    order, so reversing it to DESC fails.

    Deduplicated first so a rule appearing twice cannot land in two chunks and have its CCIs
    appended twice.

    Every rule the caller passes gets a key, because its outer query reaches a rule only by
    joining THROUGH rule_cci. The caller's `.get(..., [])` covers a future caller that does not
    share that join.

    `placeholders` is bound `?` markers only, one per rule_id, and every value is passed as a
    parameter, so no caller input reaches the SQL text. Same reasoning as the query below.
    """
    unique = list(dict.fromkeys(rule_ids))
    by_rule = {}
    for start in range(0, len(unique), _RULE_CHUNK):
        chunk = unique[start : start + _RULE_CHUNK]
        placeholders = ",".join("?" for _ in chunk)
        rows = conn.execute(
            f"SELECT rule_id, cci_id FROM rule_cci WHERE rule_id IN ({placeholders}) ORDER BY rule_id, cci_id",  # noqa: S608
            chunk,
        )
        for row in rows:
            by_rule.setdefault(row["rule_id"], []).append(row["cci_id"])
    return by_rule


def findings_for_control(conn, control_id, scope, severities=None):
    """STIG findings for a control within explicit (stig_id, version) pairs, without check or
    fix text (see finding_details).

    The version is part of the key because one benchmark can exist at two majors with
    different remediations, for example vSphere 8.0 V1 and V2, and returning both hands
    the caller two contradictory fixes for the same requirement."""
    if not scope:
        return []
    # Only bound "?" markers are interpolated; the stig_id, version and CAT values are
    # parameters, and _CAT_ORDER is a trusted module constant, so this is not injectable.
    placeholders = ",".join("(?,?)" for _ in scope)
    # CTID maps base controls and DISA often tags an enhancement, so a control's rules include
    # those under `<control>(`. The id prefix, not parent_control_id, because a KB built
    # without the NIST catalog has no parent links.
    prefix = f"{control_id}("
    params = [control_id, control_id, control_id, len(prefix), prefix]
    for stig_id, version in scope:
        params += [stig_id, version]
    severity_clause = ""
    if severities:
        severity_clause = f"AND r.severity_cat IN ({','.join('?' for _ in severities)})"
        params += list(severities)
    # GROUP BY rather than DISTINCT: one rule reached through several CCIs or enhancements is
    # one row, and the matched enhancement ids aggregate into it.
    rows = conn.execute(
        f"""
        SELECT r.rule_id, r.group_id, r.stig_id, r.stig_version,
               r.severity_cat, r.severity_level, r.title,
               MAX(cc.control_id = ?) AS cites_control,
               GROUP_CONCAT(DISTINCT CASE WHEN cc.control_id <> ? THEN cc.control_id END) AS enhancements
        FROM cci_control cc
        JOIN rule_cci rc ON rc.cci_id = cc.cci_id
        JOIN stig_rules r ON r.rule_id = rc.rule_id
        WHERE (cc.control_id = ? OR substr(cc.control_id, 1, ?) = ?)
          AND (r.stig_id, r.stig_version) IN (VALUES {placeholders}) {severity_clause}
        GROUP BY r.rule_id, r.group_id, r.stig_id, r.stig_version, r.severity_cat, r.severity_level, r.title
        ORDER BY {_CAT_ORDER}, r.stig_id, r.stig_version, r.rule_id
        """,  # noqa: S608
        params,
    ).fetchall()
    ccis_by_rule = _ccis_by_rule(conn, [r["rule_id"] for r in rows])
    return [
        {
            "stig_id": r["stig_id"],
            "stig_version": r["stig_version"],
            "rule_id": r["rule_id"],
            "group_id": r["group_id"],
            "severity": {"cat": r["severity_cat"], "level": r["severity_level"]},
            "title": r["title"],
            "ccis": ccis_by_rule.get(r["rule_id"], []),
            "via": [] if r["cites_control"] else sorted(r["enhancements"].split(",")),
        }
        for r in rows
    ]


def finding_details(conn, ids):
    """Rules matching `ids` by rule id or V- id, ignoring case, with check and fix text."""
    wanted = sorted({finding_id.strip().upper() for finding_id in ids})
    placeholders = ",".join("?" for _ in wanted)
    rows = conn.execute(
        f"""
        SELECT r.rule_id, r.group_id, r.stig_id, r.stig_version, s.title AS stig_title,
               s.release_label, s.origin, r.severity_cat, r.severity_level, r.title,
               r.check_text, r.fix_text
        FROM stig_rules r
        JOIN stigs s ON s.stig_id = r.stig_id AND s.version = r.stig_version
        WHERE upper(r.rule_id) IN ({placeholders}) OR upper(r.group_id) IN ({placeholders})
        ORDER BY {_CAT_ORDER}, r.stig_id, r.stig_version, r.rule_id
        """,  # noqa: S608
        wanted + wanted,
    ).fetchall()
    ccis_by_rule = _ccis_by_rule(conn, [r["rule_id"] for r in rows])
    return [
        {
            "stig_id": r["stig_id"],
            "stig_version": r["stig_version"],
            "stig_title": r["stig_title"],
            "stig_release": r["release_label"],
            "origin": r["origin"],
            "rule_id": r["rule_id"],
            "group_id": r["group_id"],
            "severity": {"cat": r["severity_cat"], "level": r["severity_level"]},
            "title": r["title"],
            "check_text": r["check_text"],
            "fix_text": r["fix_text"],
            "ccis": ccis_by_rule.get(r["rule_id"], []),
        }
        for r in rows
    ]


def search_techniques(conn, query, limit=10):
    """Live techniques matching the query, plus replacements for any revoked id or old
    name it matches. A redirected hit scores below both live tiers, because a technique
    whose current text matches is likelier to be what the caller wants than a renumbered
    one. Dedup keeps the direct hit, so a replacement never appears twice; when two retired
    ids redirect to the same technique, the lowest retired id is the one reported."""
    like = f"%{query.lower()}%"
    rows = conn.execute(
        """
        SELECT t.technique_id, t.name, t.tactics, NULL AS redirected_from,
               CASE WHEN lower(t.technique_id)=lower(:q) OR lower(t.name)=lower(:q) THEN 100 ELSE 60 END AS score
        FROM techniques t
        WHERE lower(t.name) LIKE :like OR lower(t.technique_id)=lower(:q)
        UNION ALL
        SELECT t.technique_id, t.name, t.tactics, r.revoked_id AS redirected_from, 50 AS score
        FROM revoked_technique r
        JOIN techniques t ON t.technique_id = r.replacement_id
        WHERE lower(r.revoked_id)=lower(:q) OR lower(r.revoked_name) LIKE :like
        ORDER BY score DESC, technique_id, redirected_from
        """,
        {"q": query, "like": like},
    ).fetchall()
    hits = {}
    for r in rows:
        # Ordered score-first, so the first row for a technique is its best hit; a direct
        # match therefore always beats the same technique arriving through a redirect.
        hits.setdefault(
            r["technique_id"],
            {
                "technique_id": r["technique_id"],
                "name": r["name"],
                "tactics": _tactics(r["tactics"]),
                "score": r["score"],
                "redirected_from": r["redirected_from"],
            },
        )
    return list(hits.values())[:limit]


def resolve_actor(conn, actor):
    """The ATT&CK groups `actor` names, as an actor_match.ActorMatch."""
    actors = [
        actor_match.Actor(
            row["actor_id"], row["name"], [a.strip() for a in (row["aliases"] or "").split(",") if a.strip()]
        )
        for row in conn.execute("SELECT actor_id, name, aliases FROM actors")
    ]
    return actor_match.match(actors, actor)


def techniques_for_actor(conn, actor_id):
    rows = conn.execute(
        """
        SELECT t.technique_id, t.name, t.tactics
        FROM actor_technique at
        JOIN techniques t ON t.technique_id = at.technique_id
        WHERE at.actor_id = ?
        ORDER BY t.technique_id
        """,
        (actor_id,),
    ).fetchall()
    return [{"technique_id": r["technique_id"], "name": r["name"], "tactics": _tactics(r["tactics"])} for r in rows]


_STIG_COLUMNS = (
    "stig_id, title, version, release_label, release_info, origin, "
    "source_artifact, source_member, xccdf_status, xccdf_status_date"
)


def _stig_row(r):
    return {
        "stig_id": r["stig_id"],
        "title": r["title"],
        "version": r["version"],
        "release_label": r["release_label"],
        "release_info": r["release_info"],
        "origin": r["origin"],
        "source_artifact": r["source_artifact"],
        "source_member": r["source_member"],
        "xccdf_status": r["xccdf_status"],
        "xccdf_status_date": r["xccdf_status_date"],
    }


def stigs_for_resolver(conn):
    """Like list_stigs but returns product_keywords, for the fuzzy resolver.
    Kept separate so list_stigs keeps its MCP contract shape: list_stigs matches
    against keywords but never returns them."""
    rows = conn.execute(
        f"SELECT {_STIG_COLUMNS}, product_keywords FROM stigs ORDER BY stig_id, version"  # noqa: S608
    ).fetchall()
    return [{**_stig_row(r), "product_keywords": r["product_keywords"] or ""} for r in rows]


def list_stigs(conn, filter=None):
    if filter:
        # stig_id: callers get one from resolve_system, and ids like RHEL_9_STIG share no
        # substring with titles like "Red Hat Enterprise Linux 9". Only this clause matches a
        # hyphenated id literally.
        # product_keywords: folds the id's separators to spaces, so it is the only clause
        # matching a space-separated "RHEL 9" or "MS SQL".
        # title: subsumed by product_keywords, which _keywords() builds as title + folded id.
        # Kept so this query states its own contract rather than depending on that
        # concatenation, or on product_keywords never being NULL.
        rows = conn.execute(
            f"SELECT {_STIG_COLUMNS} FROM stigs "  # noqa: S608
            "WHERE lower(title) LIKE :term "
            "OR lower(stig_id) LIKE :term "
            "OR lower(product_keywords) LIKE :term "
            "ORDER BY stig_id, version",
            {"term": f"%{filter.lower()}%"},
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {_STIG_COLUMNS} FROM stigs ORDER BY stig_id, version"  # noqa: S608
        ).fetchall()
    return [_stig_row(r) for r in rows]


def stigs_by_ids(conn, stig_ids):
    """Full rows for explicitly named benchmark ids, one per version the KB holds.
    A single IN query rather than one per id, because techniques_for_actor expands
    mitigations per technique and would otherwise re-query for every one of them."""
    if not stig_ids:
        return []
    # placeholders is only bound "?" markers (one per stig_id); the stig_id VALUES are
    # passed as parameters below, never interpolated. No caller input reaches the SQL
    # text, so this is not injectable.
    placeholders = ",".join("?" for _ in stig_ids)
    rows = conn.execute(
        f"""
        SELECT {_STIG_COLUMNS} FROM stigs
        WHERE stig_id IN ({placeholders})
        ORDER BY stig_id, version
        """,  # noqa: S608
        tuple(stig_ids),
    ).fetchall()
    return [_stig_row(r) for r in rows]


def source_versions(conn):
    """The corpus-wide input sources this knowledge base was built from, for citation in a
    response: cci, attack, ctid, and, when present, catalog and stig_library. Keyed by
    source_name, each value holds the recorded version, the bare artifact filename (never
    a full path), and the ingested_at timestamp. Excludes the per-benchmark rows
    ingest_meta also carries under a `stig:<stig_id>:<version>` source_name, which record
    one STIG's own provenance rather than a corpus-wide input."""
    rows = conn.execute(
        "SELECT source_name, source_version, artifact_url_or_file, ingested_at FROM ingest_meta "
        "WHERE source_name NOT LIKE 'stig:%'"
    ).fetchall()
    return {
        r["source_name"]: {
            "version": r["source_version"],
            "artifact": r["artifact_url_or_file"],
            "ingested_at": r["ingested_at"],
        }
        for r in rows
    }


def technique_coverage(conn, technique_id):
    """A technique's ATT&CK creation date and CTID mapping status, for explaining why it has
    no controls."""
    row = conn.execute("SELECT created, ctid_status FROM techniques WHERE technique_id = ?", (technique_id,)).fetchone()
    return {"created": row["created"], "ctid_status": row["ctid_status"]}


def library_populated(conn):
    """True when at least one stigs row actually came from the library compilation.

    A stig_library row in ingest_meta only proves classify() found a compilation in
    sources/ by name; it says nothing about whether that zip was readable or held any
    STIG benchmarks. This is the fact _currency_note needs to tell a truncated or
    empty compilation apart from a healthy one that simply doesn't ship a given
    benchmark, both of which leave the meta row in place."""
    return conn.execute("SELECT 1 FROM stigs WHERE origin = 'library' LIMIT 1").fetchone() is not None


def revocation(conn, technique_id):
    """The live technique that replaced a revoked id, or None if the id was not revoked.
    Callers use this only after technique_row misses, so it never shadows a live id."""
    row = conn.execute(
        "SELECT revoked_id, replacement_id, revoked_name FROM revoked_technique WHERE revoked_id = ?",
        (technique_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "revoked_id": row["revoked_id"],
        "replacement_id": row["replacement_id"],
        "revoked_name": row["revoked_name"],
    }
