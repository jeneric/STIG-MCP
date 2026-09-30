import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "kb-release.yml"
_SHA_PIN = re.compile(r"[\w.-]+/[\w.-]+(/[\w.-]+)?@[0-9a-f]{40}")


def _doc():
    return yaml.safe_load(WORKFLOW.read_text())


def _steps():
    return _doc()["jobs"]["release"]["steps"]


def _step(name):
    return next(step for step in _steps() if step.get("name") == name)


def _logical_lines(script):
    # Joins a `run:` block's `\`-continued lines back into one shell command per logical
    # line, so a check that must see the whole command (not just one physical line of it)
    # can look at it as the shell would.
    logical, buffer = [], ""
    for raw_line in script.splitlines():
        piece = raw_line.rstrip()
        continued = piece.endswith("\\")
        piece = piece[:-1].rstrip() if continued else piece
        buffer = f"{buffer} {piece.strip()}".strip() if buffer else piece.strip()
        if not continued:
            logical.append(buffer)
            buffer = ""
    if buffer:
        logical.append(buffer)
    return logical


def _without_trailing_comment(line):
    # A harmless "# why" at the end of a shell line is not part of the command; strip it
    # (and the whitespace before it) so a comment cannot fail or hide a real check.
    match = re.search(r"\s#.*$", line)
    return line[: match.start()].rstrip() if match else line


def test_kb_release_workflow__every_action__is_pinned_by_commit_sha():
    uses = [step["uses"] for step in _steps() if "uses" in step]
    assert uses, "no actions found, so this test would pass on an empty workflow"
    assert [u for u in uses if not _SHA_PIN.fullmatch(u)] == []


def test_kb_release_workflow__permissions__are_exactly_contents_and_issues_write():
    assert _doc()["permissions"] == {"contents": "write", "issues": "write"}


def test_kb_release_workflow__triggers__are_a_weekly_schedule_off_the_hour_and_manual_dispatch():
    triggers = _doc().get("on", _doc().get(True))  # PyYAML reads the bare key on as True
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    minute = triggers["schedule"][0]["cron"].split()[0]
    assert minute not in ("0", "*")


def test_kb_release_workflow__releases__are_only_ever_created_as_drafts():
    runs = "\n".join(step.get("run", "") for step in _steps())
    assert "gh release create" in runs
    for line in runs.splitlines():
        if "gh release create" in line or "gh release edit" in line:
            assert "--draft" in line and "--draft=false" not in line, line
    assert "--prerelease" not in runs


def test_kb_release_workflow__sources_cache__is_saved_only_after_the_draft_exists():
    # A refresh that fails later must leave the cache at the previous fetch, or next week's
    # --check sees nothing new and the failed build is never retried. Order alone is not
    # enough: an "if: always()" on Save sources would run it even when an earlier step in
    # between failed, defeating the ordering this test otherwise pins.
    names = [step.get("name", "") for step in _steps()]
    assert names.index("Save sources") > names.index("Draft release")
    assert names.index("Save sources") > names.index("Record kb/LATEST on kb-latest")
    save_step = next(step for step in _steps() if step.get("name") == "Save sources")
    condition = save_step.get("if", "")
    forbidden = ("always()", "failure()", "cancelled()", "!cancelled()")
    assert not any(term in condition for term in forbidden), condition


def test_kb_release_workflow__dependencies__install_from_the_lockfile():
    assert any(step.get("run", "").strip() == "uv sync --locked" for step in _steps())


def test_kb_release_workflow__keepalive__pushes_to_kb_latest_and_never_to_main():
    # A substring check alone passes a line like "push origin kb-latest:main": the refspec
    # after the colon retargets the push. Every push line must end in exactly this target,
    # once a harmless trailing "# ..." shell comment is stripped away first.
    runs = "\n".join(step.get("run", "") for step in _steps())
    push_lines = [line.strip() for line in runs.splitlines() if re.search(r"(?:^|\s)push\s", line)]
    assert push_lines, "no push lines found, so this test would pass on a workflow with no push at all"
    for line in push_lines:
        assert _without_trailing_comment(line).endswith("push origin kb-latest"), line


def test_kb_release_workflow__decide_step__downloads_the_previous_release_and_never_swallows_a_failure():
    # Two separate facts, both required, neither implying the other: the "previous" array
    # must actually be populated from the download (the assignment line), and that array
    # must actually reach the decide invocation ("${previous[@]}" in its logical line). A
    # whole-script "--previous" substring check catches neither in isolation: it is
    # satisfied by the assignment alone even if the invocation never uses it, and it
    # disappears together with the assignment if that line is deleted, silently leaving
    # `previous=()` and no way to tell decide about the previous release.
    decide = next(step for step in _steps() if step.get("name") == "Decide")
    script = decide.get("run", "")
    assert "gh release download" in script
    assert "set +e" not in script
    for line in script.splitlines():
        stripped = line.strip()
        assert not stripped.endswith("|| true"), line
        assert not stripped.endswith("|| :"), line
    logical = _logical_lines(script)
    assert any(line.startswith("previous=(--previous ") for line in logical), script
    invocation = next(line for line in logical if "tools.kb_release decide" in line)
    assert '"${previous[@]}"' in invocation, invocation


def test_kb_release_workflow__report_failure__also_runs_when_the_job_times_out():
    # A job that hits timeout-minutes ends as cancelled, never as failed, so failure() alone
    # would let the weekly run die silently.
    assert _step("Report failure")["if"].replace(" ", "") == "failure()||cancelled()"


def test_kb_release_workflow__replace_drafts__re_reads_draft_and_refuses_before_any_delete():
    # The ids come from a listing read earlier in the run; a release published since then
    # must not be deleted, so each id is re-read and must still be a draft.
    lines = [line.strip() for line in _step("Replace unpublished drafts")["run"].splitlines()]
    read = next(i for i, line in enumerate(lines) if "--jq .draft" in line and '"repos/$GH_REPO/releases/$id"' in line)
    guard = next(i for i, line in enumerate(lines) if '[ "$draft" = "true" ] ||' in line)
    delete = next(i for i, line in enumerate(lines) if "-X DELETE" in line)
    assert read < guard < delete
    assert re.search(r"\bexit [1-9]\d*\b", lines[guard]), lines[guard]


def test_kb_release_workflow__confirm_sources__runs_between_refresh_and_ingest_under_the_same_condition():
    names = [step.get("name", "") for step in _steps()]
    assert names.index("Refresh sources") < names.index("Confirm sources are current") < names.index("Ingest")
    assert _step("Confirm sources are current")["if"] == _step("Refresh sources")["if"]
    assert "stig-mcp-fetch --check" in _step("Confirm sources are current")["run"]


@pytest.mark.parametrize(("check_exit", "step_fails"), [(0, False), (3, True), (10, True)])
def test_kb_release_workflow__confirm_sources__fails_the_step_unless_check_exits_0(check_exit, step_fails):
    # Runs the step's own script the way GitHub runs a step with no shell: override, with uv
    # stubbed to exit as stig-mcp-fetch --check would. A script that swallows 3 or 10 passes
    # the job on a stale source, so the outcome is measured rather than read off the text.
    step = _step("Confirm sources are current")
    assert "shell" not in step
    bash = shutil.which("bash")
    assert bash, "bash is required to run the workflow step"
    script = f"uv() {{ return {check_exit}; }}\n{step['run']}"
    # S603: argv is bash plus this repository's own workflow text, never external input.
    result = subprocess.run(  # noqa: S603
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", script], capture_output=True, text=True, check=False
    )
    assert (result.returncode != 0) is step_fails, result
    if step_fails:
        assert f"exited {check_exit}" in result.stdout + result.stderr


def test_kb_release_workflow__decide_step__runs_under_the_default_bash_e_shell():
    # The Decide step's no-swallow guarantee is GitHub's default `bash -e`: a shell: override on
    # the step, or a defaults.run.shell on the workflow or the job, would silently remove it.
    doc = _doc()
    assert "shell" not in _step("Decide")
    assert "shell" not in (doc.get("defaults") or {}).get("run", {})
    assert "shell" not in (doc["jobs"]["release"].get("defaults") or {}).get("run", {})
