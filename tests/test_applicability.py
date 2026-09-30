import os
import re

import pytest
import yaml

from stig_mcp import applicability
from stig_mcp.applicability import NOT_GOVERNED, Entry


@pytest.fixture
def entries():
    return applicability.load_entries()


def _entry(**overrides):
    base = {
        "name": "test",
        "id_pattern": re.compile(r"^TEST_"),
        "build_pattern": re.compile(r"\bu(?P<n>\d+)\b", re.IGNORECASE),
        "thresholds": ((3, "2"), (2, "1"), (0, None)),
        "source": "src",
        "verified_against": "lib",
    }
    base.update(overrides)
    return Entry(**base)


def test_load_entries__shipped_file__parses_the_vsphere_rule(entries):
    entry = next(e for e in entries if e.name == "VMW_vSphere_8_0")
    assert entry.thresholds == ((3, "2"), (2, "1"), (0, None))
    assert entry.id_pattern.search("VMW_vSphere_8-0_ESXi_STIG")
    assert entry.verified_against == "SRG-STIG Library July 2026"


def test_load_entries__shipped_id_pattern__matches_the_dot_spelled_benchmark(entries):
    # DISA spells one of the twelve with a dot. A plain prefix would miss it, and every
    # drift check except the governed count would still pass.
    entry = next(e for e in entries if e.name == "VMW_vSphere_8_0")
    assert entry.id_pattern.search("VMW_vSphere_8.0_Virtual_Machine_STIG")


def test_load_entries__missing_required_key__raises_naming_the_entry_and_key(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"BROKEN": {"build_pattern": r"\bu(?P<n>\d+)\b"}}))
    with pytest.raises(ValueError, match="'BROKEN' is missing required key 'id_pattern'"):
        applicability.load_entries(path)


def test_load_entries__build_pattern_without_group_n__raises(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {"BROKEN": {"id_pattern": "^X_", "build_pattern": r"\bu\d+\b", "thresholds": [{"min": 0, "version": None}]}}
        )
    )
    with pytest.raises(ValueError, match="named group 'n'"):
        applicability.load_entries(path)


def test_load_entries__no_zero_threshold__raises_because_a_build_could_fall_through(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": [{"min": 2, "version": "1"}],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="no threshold with min: 0"):
        applicability.load_entries(path)


def test_load_entries__threshold_missing_min__raises_naming_the_entry_and_the_file(tmp_path):
    # A missing 'min' must name the entry ('BROKEN') and the file, so an operator who
    # fat-fingers a quarterly refresh gets an actionable error rather than a bare KeyError.
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": [{"version": "2"}, {"min": 0, "version": None}],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="'BROKEN' has a threshold missing required key 'min'") as excinfo:
        applicability.load_entries(path)
    # Names the file actually loaded, not the shipped default: a fixed path here would
    # pass whichever file failed, making the assertion vacuous.
    assert str(path) in str(excinfo.value)


def test_load_entries__threshold_non_numeric_min__raises_naming_entry_value_and_file(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": [{"min": "three", "version": "2"}, {"min": 0, "version": None}],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="'BROKEN' has a threshold whose 'min' is not numeric") as excinfo:
        applicability.load_entries(path)
    assert "three" in str(excinfo.value)  # the bad value is still visible, in the row repr
    assert str(path) in str(excinfo.value)


def test_load_entries__threshold_row_is_not_a_mapping__raises_cleanly_not_a_chained_typeerror(tmp_path):
    # A threshold row that parses as a plain string (a quoting mistake) must raise the intended
    # ValueError naming the entry and the file, not a second TypeError from an exception
    # handler that re-subscripts threshold['min'], the very expression that just raised.
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": ["min: 3, version: 2"],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="'BROKEN' has a threshold whose 'min' is not numeric") as excinfo:
        applicability.load_entries(path)
    assert str(path) in str(excinfo.value)


def test_load_entries__threshold_missing_version_key__raises_naming_the_entry_key_and_file(tmp_path):
    # A typo'd key ("versoin") must be refused, not loaded as a (min, None) pair
    # indistinguishable from a deliberate `version: null`. applicable_version() would return
    # None for that build, meaning "governed, no STIG applies" for a build a real threshold
    # does cover: a vSphere 8.0 U3 host would get zero findings and a false "predates the
    # first official STIG" note while the V2 STIG sits right there in the knowledge base.
    path = tmp_path / "rules.yaml"
    path.write_text(
        "BROKEN:\n"
        "  id_pattern: '^X_'\n"
        "  build_pattern: '\\bu(?P<n>\\d+)\\b'\n"
        "  thresholds:\n"
        "    - min: 3\n"
        '      versoin: "2"\n'
        "    - min: 0\n"
        "      version: null\n"
    )
    with pytest.raises(ValueError, match="'BROKEN' has a threshold missing required key 'version'") as excinfo:
        applicability.load_entries(path)
    assert str(path) in str(excinfo.value)


def test_load_entries__threshold_version_is_an_unquoted_integer__raises_telling_the_operator_to_quote_it(tmp_path):
    # An unquoted YAML integer version would compare unequal to every STIG version this KB
    # stores as text, so every governed row would read as superseded-major, and the renderer
    # would then assert a knowledge-base fact ("does not hold V2") it never queried and that
    # is false. Reject it at load time instead.
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": [{"min": 3, "version": 2}, {"min": 0, "version": None}],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="Quote it") as excinfo:
        applicability.load_entries(path)
    assert str(path) in str(excinfo.value)


def test_load_entries__thresholds_present_but_empty__raises_distinct_from_missing(tmp_path):
    # An operator who comments out every threshold row leaves
    # "thresholds: []" present, not absent. The message must say so, not "missing".
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump({"BROKEN": {"id_pattern": "^X_", "build_pattern": r"\bu(?P<n>\d+)\b", "thresholds": []}})
    )
    with pytest.raises(ValueError, match="'BROKEN' has key 'thresholds' but it is empty") as excinfo:
        applicability.load_entries(path)
    assert "missing required key" not in str(excinfo.value)


def test_load_entries__invalid_regex__raises_naming_the_pattern(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "BROKEN": {
                    "id_pattern": "^X_[",
                    "build_pattern": r"\bu(?P<n>\d+)\b",
                    "thresholds": [{"min": 0, "version": None}],
                }
            }
        )
    )
    with pytest.raises(ValueError, match="invalid id_pattern"):
        applicability.load_entries(path)


def _rules_yaml(name, version):
    return yaml.safe_dump(
        {
            name: {
                "id_pattern": f"^{name}_",
                "build_pattern": r"\bu(?P<n>\d+)\b",
                "thresholds": [{"min": 0, "version": version}],
            }
        }
    )


def _versions(entries):
    return [version for entry in entries for _, version in entry.thresholds]


def test_load_entries__the_same_file_twice__parses_it_once(tmp_path, monkeypatch):
    # The cache has to actually be a cache: without this every invalidation test below still
    # passes with the caching removed entirely. A fresh tmp file guarantees the first call misses,
    # so the count is 1 rather than 0 whatever earlier tests left behind.
    path = tmp_path / "rules.yaml"
    path.write_text(_rules_yaml("AAA", "1"))
    calls = []
    real = applicability._parse_entries
    monkeypatch.setattr(applicability, "_parse_entries", lambda p: calls.append(p) or real(p))
    applicability.load_entries(path)
    applicability.load_entries(path)
    assert len(calls) == 1


def test_load_entries__two_rule_files_used_alternately__each_keeps_its_own_entries(tmp_path):
    # A to B to A, against a cache that reads a slot without checking whose it is. A cache BOUNDED
    # to one slot passes this: it evicts and re-parses, so the answer stays right and only the
    # speed-up is lost, which is why the third call is here rather than only the second.
    first, second = tmp_path / "one.yaml", tmp_path / "two.yaml"
    first.write_text(_rules_yaml("AAA", "1"))
    second.write_text(_rules_yaml("BBB", "2"))
    assert _versions(applicability.load_entries(first)) == ["1"]
    assert _versions(applicability.load_entries(second)) == ["2"]
    assert _versions(applicability.load_entries(first)) == ["1"]


def test_load_entries__the_file_edited_to_the_same_size__is_reparsed(tmp_path):
    # Pins st_mtime_ns in the key. Both spellings are the same length, so size cannot tell them
    # apart, and the mtime is bumped explicitly rather than trusting the filesystem to give two
    # writes in one test distinguishable timestamps.
    path = tmp_path / "rules.yaml"
    path.write_text(_rules_yaml("AAA", "1"))
    assert _versions(applicability.load_entries(path)) == ["1"]
    before = path.stat()
    path.write_text(_rules_yaml("AAA", "2"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
    assert path.stat().st_size == before.st_size, "the two spellings must be the same length"
    assert _versions(applicability.load_entries(path)) == ["2"]


def test_load_entries__a_file_restored_with_its_old_mtime__is_reparsed(tmp_path):
    # Pins st_size in the key. `cp -p` and `tar -x` both write content while restoring the old
    # mtime, so mtime alone is not enough to notice the change.
    path = tmp_path / "rules.yaml"
    path.write_text(_rules_yaml("AAA", "1"))
    assert _versions(applicability.load_entries(path)) == ["1"]
    before = path.stat()
    path.write_text(_rules_yaml("LONGER_NAME", "2"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size != before.st_size
    assert _versions(applicability.load_entries(path)) == ["2"]


def test_load_entries__RULES_PATH_monkeypatched__reads_the_new_path(tmp_path, monkeypatch):
    # The default path is resolved at call time, not captured at import. Five tests across three
    # other modules disable applicability this way, and a cache keyed on an import-time snapshot
    # would hand them the shipped vSphere rule instead and pass for the wrong reason.
    path = tmp_path / "rules.yaml"
    path.write_text(_rules_yaml("AAA", "1"))
    monkeypatch.setattr(applicability, "RULES_PATH", path)
    assert [entry.name for entry in applicability.load_entries()] == ["AAA"]


def test_load_entries__the_returned_list_mutated__does_not_change_the_next_call(tmp_path):
    # Entry is frozen, but the list holding them is not, and it is now shared for the life of the
    # process. Handing out the cached list itself lets any caller rewrite every later answer.
    path = tmp_path / "rules.yaml"
    path.write_text(_rules_yaml("AAA", "1"))
    applicability.load_entries(path).clear()
    assert [entry.name for entry in applicability.load_entries(path)] == ["AAA"]


def test_load_entries__a_malformed_file__raises_on_every_call_not_only_the_first(tmp_path):
    # A cached failure would let a second caller proceed with no rules at all, which is the
    # unfiltered behavior this module raises specifically to prevent.
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"BROKEN": {"build_pattern": r"\bu(?P<n>\d+)\b"}}))
    for _ in range(2):
        with pytest.raises(ValueError, match="'BROKEN' is missing required key 'id_pattern'"):
            applicability.load_entries(path)


def test_load_entries__two_files_sharing_a_size_and_an_mtime__do_not_answer_for_each_other(tmp_path):
    # Pins str(path) in the key, which nothing else does: without it the whole suite stays green.
    # `cp -p`, `tar -x` and `rsync --times` all produce two files with one mtime, so a same-size
    # pair is reachable, and the collision returns another file's rules rather than re-parsing.
    first, second = tmp_path / "one.yaml", tmp_path / "two.yaml"
    first.write_text(_rules_yaml("AAA", "1"))
    second.write_text(_rules_yaml("BBB", "2"))
    assert first.stat().st_size == second.stat().st_size, "the two files must be indistinguishable by size"
    stamp = first.stat().st_mtime_ns
    os.utime(second, ns=(stamp, stamp))
    assert [entry.name for entry in applicability.load_entries(first)] == ["AAA"]
    assert [entry.name for entry in applicability.load_entries(second)] == ["BBB"]


def test_load_entries__an_empty_rule_file__is_parsed_once(tmp_path, monkeypatch):
    # An empty file caches as an empty tuple, which is falsy, so the cache is read with `is None`.
    # A truthiness test would re-parse it on every call, silently and only for this one input.
    path = tmp_path / "rules.yaml"
    path.write_text("")
    calls = []
    real = applicability._parse_entries
    monkeypatch.setattr(applicability, "_parse_entries", lambda p: calls.append(p) or real(p))
    assert applicability.load_entries(path) == []
    assert applicability.load_entries(path) == []
    assert len(calls) == 1


def test_extract_build__update_token__returns_the_number_and_strips_it(entries):
    build, rest = applicability.extract_build("vSphere 8.0 U3 ESXi", entries)
    assert build == 3
    assert "u3" not in rest.lower()
    assert "esxi" in rest.lower()


def test_extract_build__letter_suffix__yields_the_same_number_as_the_bare_update(entries):
    assert applicability.extract_build("ESXi 8.0 U3f", entries)[0] == 3
    assert applicability.extract_build("ESXi 8.0 U3", entries)[0] == 3


def test_extract_build__ga_token__means_update_zero(entries):
    # "ga" matches the pattern without the "n" group participating.
    assert applicability.extract_build("vSphere 8.0 GA ESXi", entries)[0] == 0


def test_extract_build__no_build_token__returns_none_and_the_text_unchanged(entries):
    assert applicability.extract_build("ESXi 8.0", entries) == (None, "ESXi 8.0")


def test_extract_build__update_word_with_a_space__returns_the_number_and_strips_it(entries):
    # "Update 3" is the exact phrasing DISA's Overview PDF uses, quoted verbatim in
    # applicability.yaml's header.
    build, rest = applicability.extract_build("ESXi 8.0 Update 3", entries)
    assert build == 3
    assert "update" not in rest.lower()


def test_extract_build__update_word_with_no_space__returns_the_number_and_strips_it(entries):
    assert applicability.extract_build("ESXi 8.0 update3", entries)[0] == 3


def test_extract_build__token_inside_a_word__does_not_match(entries):
    # The word boundary matters: "ubuntu" must not read as update 0, and "menu2" must
    # not read as update 2.
    assert applicability.extract_build("ubuntu 22.04", entries)[0] is None
    assert applicability.extract_build("menu2 appliance", entries)[0] is None


def test_governing_entry__benchmark_outside_every_pattern__returns_none(entries):
    assert applicability.governing_entry("RHEL_9_STIG", entries) is None


def test_applicable_version__update_three_or_later__selects_major_two(entries):
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", 3, entries) == "2"
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", 9, entries) == "2"


def test_applicable_version__update_two__selects_major_one(entries):
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", 2, entries) == "1"


def test_applicable_version__before_update_two__returns_none_meaning_no_official_stig(entries):
    # None and NOT_GOVERNED must not be conflated: None yields zero findings with an
    # explanation, NOT_GOVERNED yields everything unfiltered.
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", 1, entries) is None
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", 0, entries) is None


def test_applicable_version__ungoverned_benchmark__returns_not_governed(entries):
    assert applicability.applicable_version("RHEL_9_STIG", 3, entries) is NOT_GOVERNED


def test_applicable_version__no_build_supplied__returns_not_governed(entries):
    assert applicability.applicable_version("VMW_vSphere_8-0_ESXi_STIG", None, entries) is NOT_GOVERNED


def test_applicable_version__entry_with_no_zero_threshold__raises_rather_than_returning_none():
    # Unreachable through load_entries, which rejects such an entry. Constructed directly
    # so a future loader change fails loudly instead of silently meaning "no STIG".
    entry = _entry(thresholds=((5, "2"),))
    with pytest.raises(ValueError, match="matched no threshold for build 1"):
        applicability.applicable_version("TEST_A", 1, [entry])


def test_check_against_kb__every_major_mapped__reports_counts_and_no_warnings(entries):
    rows = [("VMW_vSphere_8-0_ESXi_STIG", "1"), ("VMW_vSphere_8-0_ESXi_STIG", "2")]
    info, warnings, unmapped = applicability.check_against_kb(rows, entries)
    assert warnings == []
    assert unmapped == 0
    assert any("governs 1 benchmark(s), 2 row(s)" in line for line in info)


def test_check_against_kb__major_no_threshold_maps__warns_and_counts_the_rows(entries):
    rows = [("VMW_vSphere_8-0_ESXi_STIG", "2"), ("VMW_vSphere_8-0_ESXi_STIG", "3")]
    _, warnings, unmapped = applicability.check_against_kb(rows, entries)
    assert unmapped == 1
    assert any("major '3'" in w and "no threshold maps" in w for w in warnings)


def test_check_against_kb__mapped_major_absent_from_the_kb__warns(entries):
    rows = [("VMW_vSphere_8-0_ESXi_STIG", "2")]
    _, warnings, _ = applicability.check_against_kb(rows, entries)
    assert any("major '1'" in w and "does not hold" in w for w in warnings)


def test_check_against_kb__two_benchmarks_at_the_same_unmapped_major__counts_rows_not_majors(entries):
    # The counter is row-granular, not major-granular. Two different benchmarks both at the
    # unmapped major '3' must report unmapped == 2; one benchmark alone cannot tell a row
    # count from a per-major count.
    rows = [
        ("VMW_vSphere_8-0_ESXi_STIG", "3"),
        ("VMW_vSphere_8-0_VCSA_STIG", "3"),
    ]
    _, warnings, unmapped = applicability.check_against_kb(rows, entries)
    assert unmapped == 2
    major_3_warnings = [w for w in warnings if "major '3'" in w]
    assert len(major_3_warnings) == 1  # one warning naming major '3', not one per row


def test_check_against_kb__entry_governs_nothing__warns_that_the_pattern_matches_nothing(entries):
    _, warnings, _ = applicability.check_against_kb([("RHEL_9_STIG", "2")], entries)
    assert any("governs no benchmark" in w for w in warnings)
