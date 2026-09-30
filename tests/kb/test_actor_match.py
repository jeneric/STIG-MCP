from contextlib import closing

import pytest

from stig_mcp.kb import actor_match, queries
from stig_mcp.kb.db import create_db

# Real ATT&CK rows chosen to trap a loose matcher: names one character apart, a name that is
# another group's alias, and an alias two groups share.
_ACTORS = [
    ("G0007", "APT28", "APT28,Fancy Bear"),
    ("G0016", "APT29", "APT29,Cozy Bear"),
    ("G0022", "APT3", "APT3,Gothic Panda"),
    ("G0013", "APT30", "APT30"),
    ("G0032", "Lazarus Group", "Lazarus Group,HIDDEN COBRA"),
    ("G0034", "Sandworm Team", "Sandworm Team,Voodoo Bear"),
    ("G0010", "Turla", "Turla,Venomous Bear"),
    ("G1017", "Volt Typhoon", "Volt Typhoon"),
    ("G0076", "Thrip", "Thrip"),
    ("G0030", "Lotus Blossom", "Lotus Blossom,Thrip"),
    ("G1003", "Ember Bear", "Ember Bear,UAC-0056"),
    ("G1031", "Saint Bear", "Saint Bear,UAC-0056"),
    ("G1014", "LuminousMoth", "LuminousMoth"),
    ("G0129", "Mustang Panda", "Mustang Panda,LUMINOUS MOTH"),
]


@pytest.fixture
def actors_conn(tmp_path):
    with closing(create_db(tmp_path / "actors.sqlite")) as conn:
        conn.executemany("INSERT INTO actors (actor_id, name, aliases) VALUES (?, ?, ?)", _ACTORS)
        conn.commit()
        yield conn


def _ids(groups):
    return [group["id"] for group in groups]


@pytest.mark.parametrize(
    ("typed", "expected_id"),
    [("G0016", "G0016"), ("g0016", "G0016"), ("apt29", "G0016"), ("Cozy Bear", "G0016"), ("  Cozy Bear ", "G0016")],
)
def test_resolve_actor__exact_id_name_or_alias__resolves_without_matched_as(actors_conn, typed, expected_id):
    match = queries.resolve_actor(actors_conn, typed)
    assert _ids(match.groups) == [expected_id]
    assert match.matched_as is None


def test_resolve_actor__name_of_one_group_and_alias_of_another__resolves_to_the_named_group(tmp_path):
    # Lotus Blossom comes first, as in the real table, so a first-row lookup picks it.
    with closing(create_db(tmp_path / "reversed.sqlite")) as conn:
        conn.executemany(
            "INSERT INTO actors (actor_id, name, aliases) VALUES (?, ?, ?)",
            [("G0030", "Lotus Blossom", "Lotus Blossom,Thrip"), ("G0076", "Thrip", "Thrip")],
        )
        match = queries.resolve_actor(conn, "Thrip")
    assert _ids(match.groups) == ["G0076"]


def test_resolve_actor__alias_shared_by_two_groups__returns_both(actors_conn):
    match = queries.resolve_actor(actors_conn, "UAC-0056")
    assert sorted(_ids(match.groups)) == ["G1003", "G1031"]


@pytest.mark.parametrize(
    ("typed", "expected_id", "matched_as"),
    [
        ("APT 28", "G0007", "APT28"),
        ("APT-29", "G0016", "APT29"),
        ("apt_3", "G0022", "APT3"),
        ("APT 30", "G0013", "APT30"),
        ("Cozybear", "G0016", "Cozy Bear"),
        ("Lazarus", "G0032", "Lazarus Group"),
        ("Sandworm", "G0034", "Sandworm Team"),
        ("Turla Group", "G0010", "Turla"),
        ("G-0016", "G0016", "G0016"),
        ("g 0016", "G0016", "G0016"),
    ],
)
def test_resolve_actor__spacing_punctuation_or_group_suffix__resolves_and_reports_what_matched(
    actors_conn, typed, expected_id, matched_as
):
    match = queries.resolve_actor(actors_conn, typed)
    assert _ids(match.groups) == [expected_id]
    assert match.matched_as == matched_as


def test_resolve_actor__loose_form_shared_by_two_groups__returns_both(actors_conn):
    match = queries.resolve_actor(actors_conn, "Luminous-Moth")
    assert sorted(_ids(match.groups)) == ["G0129", "G1014"]


def test_resolve_actor__exact_alias_beats_a_loose_name__and_names_the_other_group(actors_conn):
    match = queries.resolve_actor(actors_conn, "luminous moth")
    assert _ids(match.groups) == ["G0129"]
    assert match.also_matches == [{"id": "G1014", "name": "LuminousMoth", "via": None}]


def test_resolve_actor__exact_name_shared_as_another_groups_alias__names_that_group(actors_conn):
    match = queries.resolve_actor(actors_conn, "Thrip")
    assert _ids(match.groups) == ["G0076"]
    assert match.also_matches == [{"id": "G0030", "name": "Lotus Blossom", "via": "Thrip"}]


@pytest.mark.parametrize("typed", ["APT29", "UAC-0056", "Luminous-Moth", "APT 29", "Cosy Bear"])
def test_resolve_actor__no_other_group_shares_the_label_or_no_single_resolution__has_no_also_matches(
    actors_conn, typed
):
    assert queries.resolve_actor(actors_conn, typed).also_matches == []


@pytest.mark.parametrize(
    ("typed", "key"), [("Turla Group", "turla"), ("Sandworm-Team", "sandworm"), ("Group", "group")]
)
def test_loose_key__trailing_group_or_team_word__is_dropped_but_never_the_whole_input(typed, key):
    assert actor_match._loose_key(typed) == key


@pytest.mark.parametrize(
    ("typed", "expected_first"),
    [
        ("Cosy Bear", "G0016"),
        ("Fancy Bears", "G0007"),
        ("Volt Typhon", "G1017"),
        ("Lazarus Grp", "G0032"),
        ("Lazarus Groop", "G0032"),
        ("Lazurus", "G0032"),
        ("Sandwrm", "G0034"),
    ],
)
def test_resolve_actor__misspelling__resolves_nothing_and_suggests_the_intended_group_first(
    actors_conn, typed, expected_first
):
    match = queries.resolve_actor(actors_conn, typed)
    assert match.groups == []
    assert match.suggestions[0]["id"] == expected_first


def test_resolve_actor__one_character_from_two_groups__never_picks_either(actors_conn):
    # Real ATT&CK lists APT2 as Putter Panda's alias; this table omits it to reach the typo path.
    match = queries.resolve_actor(actors_conn, "APT2")
    assert match.groups == []
    assert {"G0007", "G0016"} <= set(_ids(match.suggestions))


def test_resolve_actor__suggestion_through_an_alias__names_the_alias(actors_conn):
    match = queries.resolve_actor(actors_conn, "Cosy Bear")
    assert match.suggestions[0] == {"id": "G0016", "name": "APT29", "via": "Cozy Bear"}


def test_resolve_actor__suggestion_through_the_name__carries_no_via(actors_conn):
    match = queries.resolve_actor(actors_conn, "Volt Typhon")
    assert match.suggestions[0] == {"id": "G1017", "name": "Volt Typhoon", "via": None}


def test_resolve_actor__whole_word_of_many_names__suggests_at_most_five_distinct_groups(actors_conn):
    match = queries.resolve_actor(actors_conn, "Bear")
    assert match.groups == []
    ids = _ids(match.suggestions)
    assert len(ids) == len(set(ids)) == 5


def test_resolve_actor__unrelated_text__suggests_nothing(actors_conn):
    match = queries.resolve_actor(actors_conn, "Microsoft Windows")
    assert match.groups == [] and match.suggestions == []


def test_resolve_actor__resolved_group__carries_its_aliases(actors_conn):
    match = queries.resolve_actor(actors_conn, "Fancy Bear")
    assert match.groups == [{"id": "G0007", "name": "APT28", "aliases": ["APT28", "Fancy Bear"]}]


def _refuse_scoring(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("similarity scoring ran")

    monkeypatch.setattr(actor_match.difflib, "SequenceMatcher", refuse)


def test_resolve_actor__input_over_the_length_limit__skips_similarity_scoring(actors_conn, monkeypatch):
    # No input this long can score close to a real name, so the limit shows only as skipped work.
    _refuse_scoring(monkeypatch)
    match = queries.resolve_actor(actors_conn, "x" * (actor_match._SUGGESTION_INPUT_LIMIT + 1))
    assert match.suggestions == []


def test_resolve_actor__input_at_the_length_limit__is_scored(actors_conn, monkeypatch):
    _refuse_scoring(monkeypatch)
    with pytest.raises(AssertionError, match="similarity scoring ran"):
        queries.resolve_actor(actors_conn, "x" * actor_match._SUGGESTION_INPUT_LIMIT)


def test_resolve_actor__ambiguous_groups__come_back_in_group_id_order(actors_conn):
    # Name order and table order both disagree with id order here.
    match = queries.resolve_actor(actors_conn, "Luminous-Moth")
    assert _ids(match.groups) == ["G0129", "G1014"]


def test_resolve_actor__suggestions__rank_by_closeness_then_group_id(actors_conn):
    # APT28 and APT29 tie at 0.89, APT3 trails at 0.75.
    match = queries.resolve_actor(actors_conn, "APT2")
    assert _ids(match.suggestions) == ["G0007", "G0016", "G0022"]


@pytest.fixture
def one_group_db(tmp_path):
    with closing(create_db(tmp_path / "one_group.sqlite")) as conn:
        yield conn


def _insert_actor(conn, row):
    conn.execute("INSERT INTO actors (actor_id, name, aliases) VALUES (?, ?, ?)", row)
    conn.commit()
    return conn


def test_resolve_actor__loose_match_through_name_and_alias__reports_the_name(one_group_db):
    conn = _insert_actor(one_group_db, ("G9001", "APT-C-23", "APT C23,Desert Falcons"))
    match = queries.resolve_actor(conn, "aptc23")
    assert match.matched_as == "APT-C-23"


def test_resolve_actor__two_labels_of_one_group_qualify__suggests_through_the_closer(one_group_db):
    conn = _insert_actor(one_group_db, ("G9002", "Example Spider", "Example Spyder Team"))
    match = queries.resolve_actor(conn, "Example Spidr")
    assert match.suggestions == [{"id": "G9002", "name": "Example Spider", "via": None}]


def test_resolve_actor__misspelling_without_an_aliases_team_suffix__names_the_alias_as_written(one_group_db):
    conn = _insert_actor(one_group_db, ("G9002", "Example Spider", "Example Spyder Team"))
    match = queries.resolve_actor(conn, "Example Spydr")
    assert match.suggestions == [{"id": "G9002", "name": "Example Spider", "via": "Example Spyder Team"}]


def test_resolve_actor__fullwidth_digit__reads_as_the_ascii_digit(actors_conn):
    match = queries.resolve_actor(actors_conn, "APT3\uff10")
    assert _ids(match.groups) == ["G0013"]


def test_resolve_actor__non_ascii_letter__is_not_dropped_as_punctuation(actors_conn):
    match = queries.resolve_actor(actors_conn, "APT29\u00e9")
    assert match.groups == []


def test_resolve_actor__sharp_s__casefolds_to_ss(one_group_db):
    conn = _insert_actor(one_group_db, ("G0045", "menuPass", "menuPass,APT10"))
    match = queries.resolve_actor(conn, "MENUPAß")
    assert _ids(match.groups) == ["G0045"]


def test_resolve_actor__other_group_matching_through_name_and_alias__is_named_through_its_name(one_group_db):
    _insert_actor(one_group_db, ("G0129", "Mustang Panda", "Mustang Panda,LUMINOUS MOTH"))
    conn = _insert_actor(one_group_db, ("G1014", "LuminousMoth", "LuminousMoth,Luminous-Moth"))
    match = queries.resolve_actor(conn, "LUMINOUS MOTH")
    assert match.also_matches == [{"id": "G1014", "name": "LuminousMoth", "via": None}]


def test_resolve_actor__several_other_groups_share_the_label__lists_them_in_group_id_order(one_group_db):
    _insert_actor(one_group_db, ("G9003", "Shared", "Shared"))
    _insert_actor(one_group_db, ("G9002", "Other Two", "Other Two,Sha-red"))
    conn = _insert_actor(one_group_db, ("G9001", "Other One", "Other One,SHARED!"))
    match = queries.resolve_actor(conn, "Shared")
    assert _ids(match.groups) == ["G9003"]
    assert _ids(match.also_matches) == ["G9001", "G9002"]
