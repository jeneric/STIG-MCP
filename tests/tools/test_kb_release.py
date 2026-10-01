import json
import shutil

import pytest

from stig_mcp.ingest import catalog, fetch
from stig_mcp.kb import releases
from stig_mcp.kb.db import SCHEMA_VERSION
from tests.kb.fake_github import FakeGitHub
from tools import kb_release

TODAY = "2026-10-05"


def _listing(*entries):
    """The listing GitHub's API returns, published in argument order so the last is newest."""
    github = FakeGitHub()
    for tag, draft in entries:
        github.publish(tag, b"kb", schema=SCHEMA_VERSION, draft=draft)
    listing = json.loads(github.bodies[releases.LISTING_URL])
    for number, entry in enumerate(listing, start=1):
        entry["id"] = number
    return listing


def test_decide__nothing_changed_and_current__does_not_build(tmp_path):
    listing = _listing(("kb-2026-09-28", False))
    decision = kb_release.decide(listing, 0, "schedule", {"built_with": "0.1.0"}, TODAY, "0.1.0")
    assert decision == {"build": False, "reasons": [], "tag": f"kb-{TODAY}", "delete_drafts": []}


def test_decide__nothing_changed_but_a_draft_waits__does_not_schedule_it_for_deletion():
    listing = _listing(("kb-2026-09-28", False), ("kb-2026-09-27", True))
    decision = kb_release.decide(listing, 0, "schedule", {"built_with": "0.1.0"}, TODAY, "0.1.0")
    assert decision["build"] is False
    assert decision["delete_drafts"] == []


def test_decide__upstream_changed__builds_and_replaces_only_kb_drafts():
    listing = _listing(("kb-2026-09-28", False), ("kb-2026-09-29", True))
    listing.append({"id": 99, "tag_name": "v0.2.0", "draft": True, "prerelease": False, "assets": []})
    decision = kb_release.decide(listing, 10, "schedule", {"built_with": "0.1.0"}, TODAY, "0.1.0")
    assert decision["build"] is True
    assert decision["reasons"] == ["upstream sources changed since the cached fetch"]
    draft_id = next(e["id"] for e in listing if e["tag_name"] == "kb-2026-09-29")
    assert decision["delete_drafts"] == [draft_id]


def test_decide__no_published_release_for_this_schema__builds_even_with_a_draft_waiting():
    listing = _listing(("kb-2026-09-29", True))
    decision = kb_release.decide(listing, 0, "schedule", None, TODAY, "0.1.0")
    assert decision["reasons"] == [f"no published release for schema {SCHEMA_VERSION}"]


def test_decide__main_is_a_newer_stig_mcp__builds():
    listing = _listing(("kb-2026-09-28", False))
    decision = kb_release.decide(listing, 0, "schedule", {"built_with": "0.1.0"}, TODAY, "0.2.0")
    assert decision["reasons"] == ["newest release was built with stig-mcp 0.1.0, main is 0.2.0"]


def test_decide__manual_run__builds():
    listing = _listing(("kb-2026-09-28", False))
    assert kb_release.decide(listing, 0, "workflow_dispatch", {"built_with": "0.1.0"}, TODAY, "0.1.0")["build"]


def test_decide__check_could_not_reach_a_source__is_refused():
    with pytest.raises(kb_release.ReleaseToolError, match="exit 3"):
        kb_release.decide([], fetch.EXIT_COULD_NOT_CHECK, "schedule", None, TODAY, "0.1.0")


def test_decide__check_exit_neither_0_3_nor_10__is_refused():
    with pytest.raises(kb_release.ReleaseToolError, match="expected 0, 3 or 10"):
        kb_release.decide([], 5, "schedule", None, TODAY, "0.1.0")


def test_decide__today_already_published__is_refused_when_building():
    listing = _listing((f"kb-{TODAY}", False))
    with pytest.raises(kb_release.ReleaseToolError, match=f"kb-{TODAY} is already published"):
        kb_release.decide(listing, 10, "schedule", {"built_with": "0.1.0"}, TODAY, "0.1.0")


def test_decide__today_already_published_but_nothing_to_build__does_not_raise():
    listing = _listing((f"kb-{TODAY}", False))
    decision = kb_release.decide(listing, 0, "schedule", {"built_with": "0.1.0"}, TODAY, "0.1.0")
    assert decision == {"build": False, "reasons": [], "tag": f"kb-{TODAY}", "delete_drafts": []}


_SOURCES = {"entries": {"U_Foo_V1R1_STIG.zip": "a" * 64}, "public": {"attack": "b" * 64}}


def test_unchanged__same_content_built_with_the_same_version__is_true():
    doc = {
        "built_with": "0.1.0",
        "upstream": {"attack": "19.2"},
        "benchmarks": [{"stig_id": "A"}],
        "sources": _SOURCES,
        "sha256": {},
    }
    assert kb_release.unchanged(doc, {**doc, "sha256": {"xz": "different bytes, same content"}})
    assert not kb_release.unchanged(doc, {**doc, "benchmarks": []})
    assert not kb_release.unchanged(doc, None)


@pytest.mark.parametrize("section", ["entries", "public"])
def test_unchanged__a_source_re_posted_under_the_same_name__is_false(section):
    # DISA replacing a zip's content under the same file name changes neither a benchmark
    # label nor an upstream version: only the recorded digest tells the two builds apart.
    doc = {"built_with": "0.1.0", "upstream": {"attack": "19.2"}, "benchmarks": [{"stig_id": "A"}]}
    reposted = {**_SOURCES, section: {name: "c" * 64 for name in _SOURCES[section]}}
    assert kb_release.unchanged({**doc, "sources": _SOURCES}, {**doc, "sources": _SOURCES})
    assert not kb_release.unchanged({**doc, "sources": reposted}, {**doc, "sources": _SOURCES})


def test_notes__a_previous_release__lists_added_changed_and_dropped_benchmarks():
    previous = {
        "upstream": {},
        "benchmarks": [
            {"stig_id": "Kept", "version": "1", "release": "V1R1", "file": "f"},
            {"stig_id": "Bumped", "version": "2", "release": "V2R8", "file": "f"},
            {"stig_id": "Gone", "version": "1", "release": "V1R4", "file": "f"},
        ],
    }
    doc = {
        "built_with": "0.1.0",
        "upstream": {"attack": "19.2"},
        "sha256": {"xz": "x" * 64, "sqlite": "s" * 64},
        "benchmarks": [
            {"stig_id": "Kept", "version": "1", "release": "V1R1", "file": "f"},
            {"stig_id": "Bumped", "version": "2", "release": "V2R9", "file": "f"},
            {"stig_id": "New", "version": "1", "release": "V1R1", "file": "f"},
        ],
    }
    text = kb_release.notes(doc, previous, "kb-2026-09-28", f"kb-{TODAY}")
    assert "Since kb-2026-09-28:\n\n### Added (1)\n- New V1R1\n\n### Changed" in text
    assert "### Changed (1)\n- Bumped V2R8 -> V2R9\n" in text
    assert "### Dropped (1)\n- Gone V1R4\n" in text
    assert "Kept" not in text


def test_notes__several_changes__puts_each_benchmark_on_its_own_bullet():
    previous = {"upstream": {}, "benchmarks": [{"stig_id": "B", "version": "1", "release": "V1R1", "file": "f"}]}
    doc = {
        "built_with": "0.1.0",
        "upstream": {},
        "sha256": {"xz": "x" * 64, "sqlite": "s" * 64},
        "benchmarks": [
            {"stig_id": "A", "version": "1", "release": "V1R1", "file": "f"},
            {"stig_id": "C", "version": "1", "release": "V1R2", "file": "f"},
        ],
    }
    text = kb_release.notes(doc, previous, "kb-2026-09-28", f"kb-{TODAY}")
    assert "### Added (2)\n- A V1R1\n- C V1R2\n" in text
    assert "### Changed (0)\n- none\n" in text
    assert "### Dropped (1)\n- B V1R1\n" in text


def test_notes__any_release__lists_benchmarks_before_upstream():
    doc = {"built_with": "0.1.0", "upstream": {"attack": "19.2"}, "sha256": {"xz": "x" * 64, "sqlite": "s" * 64}}
    text = kb_release.notes({**doc, "benchmarks": []}, None, None, f"kb-{TODAY}")
    assert text.index("## Benchmarks") < text.index("## Upstream")


def test_notes__no_previous_release__says_so_and_counts_the_benchmarks():
    doc = {
        "built_with": "0.1.0",
        "upstream": {},
        "sha256": {"xz": "x" * 64, "sqlite": "s" * 64},
        "benchmarks": [{"stig_id": "A", "version": "1", "release": "V1R1", "file": "f"}],
    }
    text = kb_release.notes(doc, None, None, f"kb-{TODAY}")
    assert f"First release for schema {SCHEMA_VERSION}: 1 benchmark(s)." in text


def test_tripwireSummary__names_on_the_index__lists_each_under_its_heading():
    wire = {
        "stale": [],
        "other_major": ["U_Foo_V3R1_STIG.zip"],
        "unmatched": ["U_Old_V1R1_STIG.zip", "U_Older_V1R2_STIG.zip"],
    }
    text = kb_release.tripwire_summary(wire)
    assert "### Newer major on the index, library major kept (1)\n- `U_Foo_V3R1_STIG.zip`\n" in text
    assert "came from (usually an older name) (2)\n- `U_Old_V1R1_STIG.zip`\n- `U_Older_V1R2_STIG.zip`\n" in text


def test_tripwireSummary__nothing_unmatched__says_none_under_each_heading():
    text = kb_release.tripwire_summary({"stale": [], "other_major": [], "unmatched": []})
    assert text.count("(0)\n- none\n") == 2


def test_build__an_unmatched_index_name__goes_to_the_step_summary_not_the_notes(kb_path, tmp_path, monkeypatch):
    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    out = tmp_path / "release"
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n")
    kb_release.build(f"kb-{TODAY}", out, kb_path=kb, sources_dir=sources, version="0.1.0", step_summary=summary)
    assert "U_Foo_V1R1_STIG.zip" not in (out / "notes.md").read_text()
    written = summary.read_text()
    assert written.startswith("earlier step\n")
    assert "(1)\n- `U_Foo_V1R1_STIG.zip`\n" in written


def test_build__a_verified_build__writes_assets_notes_and_the_upload_list(kb_path, tmp_path, monkeypatch):
    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    out = tmp_path / "release"
    result = kb_release.build(f"kb-{TODAY}", out, kb_path=kb, sources_dir=sources, version="0.1.0")
    assert result["changed"] is True
    listed = (out / "assets.txt").read_text().splitlines()
    assert listed == [str(path) for path in result["assets"]]
    assert (out / "notes.md").read_text().startswith(f"# Knowledge base kb-{TODAY}")


def _build_inputs(kb_path, tmp_path, monkeypatch):
    from tools import kb_verify  # noqa: PLC0415

    monkeypatch.setattr(kb_verify, "GOLDEN", ())
    kb = tmp_path / "stig_kb.sqlite"
    shutil.copyfile(kb_path, kb)
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "U_Foo_V1R1_STIG.zip").write_bytes(b"z")
    fetch.write_manifest(sources, [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)])
    return kb, sources


def test_build__same_content_as_the_previous_release__is_unchanged_and_lists_nothing(kb_path, tmp_path, monkeypatch):
    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    first = tmp_path / "first"
    kb_release.build("kb-2026-09-28", first, kb_path=kb, sources_dir=sources, version="0.1.0")
    second = tmp_path / "second"
    previous = first / "release.json"
    result = kb_release.build(f"kb-{TODAY}", second, previous, kb_path=kb, sources_dir=sources, version="0.1.0")
    assert result["changed"] is False
    assert (second / "assets.txt").read_text() == ""
    manual = kb_release.build(
        f"kb-{TODAY}",
        tmp_path / "third",
        previous,
        "workflow_dispatch",
        kb_path=kb,
        sources_dir=sources,
        version="0.1.0",
    )
    assert manual["changed"] is True


def test_build__a_source_re_posted_with_new_content__is_changed(kb_path, tmp_path, monkeypatch):
    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    first = tmp_path / "first"
    kb_release.build("kb-2026-09-28", first, kb_path=kb, sources_dir=sources, version="0.1.0")
    (sources / "U_Foo_V1R1_STIG.zip").write_bytes(b"corrected")
    fetch.write_manifest(sources, [catalog.Entry(name="U_Foo_V1R1_STIG.zip", href="x", date="d", size_bytes=1)])
    second = tmp_path / "second"
    result = kb_release.build(
        f"kb-{TODAY}", second, first / "release.json", kb_path=kb, sources_dir=sources, version="0.1.0"
    )
    before, after = (json.loads((d / "release.json").read_text()) for d in (first, second))
    assert after["benchmarks"] == before["benchmarks"] and after["upstream"] == before["upstream"]
    assert result["changed"] is True
    assert (second / "assets.txt").read_text() != ""


def test_build__a_previous_release__passes_the_previous_tag_into_the_notes(kb_path, tmp_path, monkeypatch):
    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    first = tmp_path / "first"
    kb_release.build("kb-2026-09-28", first, kb_path=kb, sources_dir=sources, version="0.1.0")
    second = tmp_path / "second"
    previous = first / "release.json"
    kb_release.build(
        f"kb-{TODAY}", second, previous, previous_tag="kb-2026-09-28", kb_path=kb, sources_dir=sources, version="0.1.0"
    )
    assert "Since kb-2026-09-28:" in (second / "notes.md").read_text()


def test_main__decide_with_github_output__appends_the_outputs(tmp_path, monkeypatch):
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps(_listing(("kb-2026-09-29", True))))
    output = tmp_path / "out.txt"
    monkeypatch.setattr(kb_release, "_today", lambda: TODAY)
    code = kb_release.main(
        [
            "decide",
            "--listing",
            str(listing),
            "--check-exit",
            "10",
            "--event",
            "schedule",
            "--github-output",
            str(output),
        ]
    )
    assert code == 0
    lines = output.read_text().splitlines()
    assert "build=true" in lines
    assert f"tag=kb-{TODAY}" in lines
    assert "delete_drafts=1" in lines


def test_main__decide_refused__exits_1_with_the_reason_on_stderr(tmp_path, capsys):
    listing = tmp_path / "listing.json"
    listing.write_text("[]")
    code = kb_release.main(["decide", "--listing", str(listing), "--check-exit", "3", "--event", "schedule"])
    assert code == 1
    assert "exit 3" in capsys.readouterr().err


def test_main__newest__prints_the_tag_of_the_newest_compatible_published_release(tmp_path, capsys):
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps(_listing(("kb-2026-09-28", False), ("kb-2026-09-29", True))))
    assert kb_release.main(["newest", "--listing", str(listing)]) == 0
    assert capsys.readouterr().out == "kb-2026-09-28\n"


def test_main__build__writes_changed_to_github_output_and_reads_config_paths(kb_path, tmp_path, monkeypatch):
    from stig_mcp.ingest import config  # noqa: PLC0415

    kb, sources = _build_inputs(kb_path, tmp_path, monkeypatch)
    monkeypatch.setattr(config, "KB_PATH", kb)
    monkeypatch.setattr(config, "SOURCES_DIR", sources)
    output = tmp_path / "out.txt"
    first = tmp_path / "first"
    assert kb_release.main(["build", "--tag", "kb-2026-09-28", "--out", str(first)]) == 0
    code = kb_release.main(
        [
            "build",
            "--tag",
            f"kb-{TODAY}",
            "--out",
            str(tmp_path / "second"),
            "--previous",
            str(first / "release.json"),
            "--previous-tag",
            "kb-2026-09-28",
            "--github-output",
            str(output),
            "--step-summary",
            str(tmp_path / "summary.md"),
        ]
    )
    assert code == 0
    assert output.read_text() == "changed=false\n"
    assert "Since kb-2026-09-28:" in (tmp_path / "second" / "notes.md").read_text()
    assert "## Freshness tripwire notes" in (tmp_path / "summary.md").read_text()


def test_main__decide_with_a_malformed_previous_release__exits_1_naming_release_json(tmp_path, capsys):
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps(_listing(("kb-2026-09-28", False))))
    previous = tmp_path / "release.json"
    previous.write_text("{}")
    code = kb_release.main(
        [
            "decide",
            "--listing",
            str(listing),
            "--check-exit",
            "0",
            "--event",
            "schedule",
            "--previous",
            str(previous),
        ]
    )
    assert code == 1
    assert "release.json" in capsys.readouterr().err


def test_main__newest_with_no_compatible_release__prints_nothing(tmp_path, capsys):
    listing = tmp_path / "listing.json"
    listing.write_text("[]")
    assert kb_release.main(["newest", "--listing", str(listing)]) == 0
    assert capsys.readouterr().out == ""
