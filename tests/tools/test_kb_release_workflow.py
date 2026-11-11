import json
import os
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


def _job(name):
    return _doc()["jobs"][name]


def _steps(job="build"):
    return _job(job)["steps"]


def _all_steps():
    for job_name, job in _doc()["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, step


def _step(name, job="build"):
    return next(step for step in _steps(job) if step.get("name") == name)


def _run_bash(script, env=None, cwd=None):
    # GitHub runs a step with no shell: override as `bash -e {0}`, without pipefail.
    bash = shutil.which("bash")
    assert bash, "bash is required to run the workflow step"
    # S603: argv is bash plus this repository's own workflow text, never external input.
    return subprocess.run(  # noqa: S603
        [bash, "--noprofile", "--norc", "-e", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(env or {})},
        cwd=cwd,
    )


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
    uses = [step["uses"] for _, step in _all_steps() if "uses" in step]
    assert uses, "no actions found, so this test would pass on an empty workflow"
    assert [u for u in uses if not _SHA_PIN.fullmatch(u)] == []


def test_kb_release_workflow__permissions__are_empty_at_workflow_level_and_least_per_job():
    # The build job runs upstream data and third-party code, so it never holds a write token.
    assert _doc()["permissions"] == {}
    assert _job("build")["permissions"] == {"contents": "read"}
    assert _job("publish")["permissions"] == {"contents": "write"}
    assert _job("report")["permissions"] == {"issues": "write", "actions": "write"}


def test_kb_release_workflow__jobs__are_exactly_build_publish_and_report():
    # Every job's permissions are pinned above; a fourth job would escape them.
    assert set(_doc()["jobs"]) == {"build", "publish", "report"}


def test_kb_release_workflow__triggers__are_a_weekly_schedule_off_the_hour_and_manual_dispatch():
    triggers = _doc().get("on", _doc().get(True))  # PyYAML reads the bare key on as True
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    minute = triggers["schedule"][0]["cron"].split()[0]
    assert minute not in ("0", "*")


def test_kb_release_workflow__releases__are_only_ever_created_as_drafts():
    runs = "\n".join(step.get("run", "") for _, step in _all_steps())
    assert "gh release create" in runs
    for line in runs.splitlines():
        if "gh release create" in line or "gh release edit" in line:
            assert "--draft" in line and "--draft=false" not in line, line
    assert "--prerelease" not in runs


def test_kb_release_workflow__sources_cache__is_saved_last_in_build_after_the_upload():
    # A build that fails must leave the cache at the previous fetch, or next week's --check
    # sees nothing new and the failed build is never retried. Order alone is not enough: an
    # "if: always()" on Save sources would run it even when an earlier step failed.
    names = [step.get("name", "") for step in _steps()]
    assert names[-1] == "Save sources"
    assert names.index("Save sources") > names.index("Upload the release")
    save_step = _step("Save sources")
    condition = save_step.get("if", "")
    forbidden = ("always()", "failure()", "cancelled()", "!cancelled()")
    assert not any(term in condition for term in forbidden), condition


def test_kb_release_workflow__dependencies__install_from_the_lockfile():
    assert any(step.get("run", "").strip() == "uv sync --locked" for step in _steps())


def test_kb_release_workflow__keepalive__pushes_to_kb_latest_and_never_to_main():
    # A substring check alone passes a line like "push origin kb-latest:main": the refspec
    # after the colon retargets the push. Every push line must end in exactly this target,
    # once a harmless trailing "# ..." shell comment is stripped away first.
    runs = "\n".join(step.get("run", "") for _, step in _all_steps())
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
    decide = _step("Decide")
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
    assert _job("report")["if"].replace(" ", "") == "failure()||cancelled()"
    # A step's failure() reads only its own job's status, so a step condition here never fires.
    assert "if" not in _step("Report failure", "report")
    assert _job("report")["needs"] == ["build", "publish"]
    steps = _steps("report")
    assert {"checkout", "setup-uv"}.isdisjoint(
        {step["uses"].split("@")[0].split("/")[1] for step in steps if "uses" in step}
    )
    assert not any("uv " in step.get("run", "") for step in steps)


def test_kb_release_workflow__cache_retraction__runs_only_when_publish_failed_or_was_cancelled():
    step = _step("Retract the sources cache", "report")
    condition = step["if"]
    assert set(re.findall(r"'([^']*)'", condition)) == {"failure", "cancelled"}
    assert set(re.findall(r"[\w.]+\.result", condition)) == {"needs.publish.result"}
    assert re.sub(r"needs\.publish\.result\s*==\s*'(failure|cancelled)'", "", condition).strip() == "||"
    # The delete names exactly the key the build job saves under, never a wildcard or prefix.
    saved_key = _step("Save sources")["with"]["key"]
    assert saved_key == "kb-sources-${{ github.run_id }}"
    assert step["run"].strip() == f'gh cache delete "{saved_key.replace("${{ github.run_id }}", "$GITHUB_RUN_ID")}"'


def test_kb_release_workflow__cache_retraction__comes_before_the_issue_and_cannot_stop_it():
    names = [step["name"] for step in _steps("report")]
    assert names.index("Retract the sources cache") < names.index("Report failure")
    retract = _step("Retract the sources cache", "report")
    # A failed delete stays visible as a failed step but must not block the issue, so the
    # issue step stays unconditional and the delete is never made to exit 0 by hand.
    assert retract["continue-on-error"] is True
    assert "if" not in _step("Report failure", "report")
    for line in retract["run"].splitlines():
        assert "||" not in line and "set +e" not in line, line


def test_kb_release_workflow__replace_drafts__re_reads_draft_and_refuses_before_any_delete():
    # The ids come from a listing read earlier in the run; a release published since then
    # must not be deleted, so each id is re-read and must still be a draft.
    lines = [line.strip() for line in _step("Replace unpublished drafts", "publish")["run"].splitlines()]
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
    result = _run_bash(f"uv() {{ return {check_exit}; }}\n{step['run']}")
    assert (result.returncode != 0) is step_fails, result
    if step_fails:
        assert f"exited {check_exit}" in result.stdout + result.stderr


def test_kb_release_workflow__decide_step__runs_under_the_default_bash_e_shell():
    # The Decide step's no-swallow guarantee is GitHub's default `bash -e`: a shell: override on
    # the step, or a defaults.run.shell on the workflow or the job, would silently remove it.
    doc = _doc()
    assert "shell" not in _step("Decide")
    assert "shell" not in (doc.get("defaults") or {}).get("run", {})
    for job in doc["jobs"].values():
        assert "shell" not in (job.get("defaults") or {}).get("run", {})


# A gh call may sit at line start, after a shell operator, inside $( ) or backticks, or after !.
_GH_COMMAND = re.compile(r"(?:^|[\s;&|(`!])gh\s")
# The write token reaches a step under either expression, whatever env name carries it.
_TOKEN_EXPRESSIONS = ("github.token", "secrets.GITHUB_TOKEN")


def _runs_gh(step):
    return any(_GH_COMMAND.search(line) for line in _logical_lines(step.get("run", "")))


def _has_token(step):
    return any(expression in str(step) for expression in _TOKEN_EXPRESSIONS)


def _token_steps():
    return {(job, step["name"]) for job, step in _all_steps() if _has_token(step)}


def test_kb_release_workflow__workflow_and_job_env__carry_no_token():
    # A workflow- or job-level token reaches every step, the DISA fetch and the ingest included.
    envs = [_doc().get("env") or {}, *((job.get("env") or {}) for job in _doc()["jobs"].values())]
    for env in envs:
        assert not {"GH_TOKEN", "GITHUB_TOKEN"} & set(env), env
        assert not any(expression in str(env) for expression in _TOKEN_EXPRESSIONS), env


def test_kb_release_workflow__token__is_given_to_exactly_the_steps_that_run_gh():
    gh_steps = {(job, step["name"]) for job, step in _all_steps() if _runs_gh(step)}
    # Report failure runs only when a job breaks, so a green run never shows it lacks a token.
    assert {
        ("build", "Decide"),
        ("publish", "Replace unpublished drafts"),
        ("publish", "Draft release"),
        ("publish", "Record kb/LATEST on kb-latest"),
        ("report", "Retract the sources cache"),
        ("report", "Report failure"),
    } <= gh_steps
    assert _token_steps() == gh_steps
    tokens = {step.get("env", {}).get("GH_TOKEN") for _, step in _all_steps() if _has_token(step)}
    assert tokens == {"${{ github.token }}"}


@pytest.mark.parametrize(
    "command",
    [
        "uv sync",
        "stig-mcp-fetch --refresh",
        "stig-mcp-fetch --check",
        "stig-mcp-ingest",
        "pytest",
        "tools.kb_release build",
    ],
)
def test_kb_release_workflow__steps_that_run_upstream_data_or_dependencies__get_no_token(command):
    steps = [(job, step["name"]) for job, step in _all_steps() if command in step.get("run", "")]
    assert steps, f"no step runs {command}, so this test would pass vacuously"
    assert set(steps) & _token_steps() == set()


def test_kb_release_workflow__checkout__does_not_persist_the_token_in_git_config():
    # A persisted credential sits in .git/config where every later step can read it.
    checkouts = [step for _, step in _all_steps() if step.get("uses", "").startswith("actions/checkout@")]
    assert checkouts
    assert [step for step in checkouts if step.get("with", {}).get("persist-credentials") is not False] == []


def test_kb_release_workflow__every_push__authenticates_through_gh_earlier_in_its_own_step():
    # Without the persisted checkout credential, a push has no other way to authenticate.
    pushing = [
        (job, step)
        for job, step in _all_steps()
        if any(re.search(r"\spush\s", line) for line in _logical_lines(step.get("run", "")))
    ]
    assert pushing, "no push found, so this test would pass vacuously"
    for job, step in pushing:
        lines = _logical_lines(step["run"])
        assert "gh auth setup-git" in lines, step["name"]
        first_push = min(i for i, line in enumerate(lines) if re.search(r"\spush\s", line))
        assert lines.index("gh auth setup-git") < first_push, step["name"]
        assert (job, step["name"]) in _token_steps()


def test_kb_release_workflow__publish__runs_no_repository_code_or_dependencies():
    # publish holds the write token, so it runs only gh, git and jq from the runner image.
    uses = [step.get("uses", "") for step in _steps("publish")]
    assert not [u for u in uses if u.startswith(("actions/checkout@", "astral-sh/setup-uv@"))], uses
    runs = [line for step in _steps("publish") for line in _logical_lines(step.get("run", ""))]
    assert runs, "publish runs nothing, so this test would pass vacuously"
    assert [line for line in runs if re.search(r"\b(uv|python3?|pip)\b", line)] == []


def test_kb_release_workflow__publish__runs_only_when_the_build_changed():
    assert _job("publish")["needs"] == "build"
    assert _job("publish")["if"] == "needs.build.outputs.changed == 'true'"


def test_kb_release_workflow__build_outputs__come_from_the_decide_and_build_steps():
    assert _job("build")["outputs"] == {
        "changed": "${{ steps.build.outputs.changed }}",
        "tag": "${{ steps.decide.outputs.tag }}",
    }
    assert _job("publish")["env"]["TAG"] == "${{ needs.build.outputs.tag }}"


def test_kb_release_workflow__artifact__is_uploaded_and_downloaded_under_one_name():
    upload = _step("Upload the release")
    download = _step("Download the release", "publish")
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert download["uses"].startswith("actions/download-artifact@")
    assert upload["if"] == "steps.build.outputs.changed == 'true'"
    assert upload["with"] == {
        "name": "kb-release",
        "path": "${{ runner.temp }}/release",
        "retention-days": 5,
        "if-no-files-found": "error",
    }
    assert download["with"] == {"name": "kb-release", "path": "${{ runner.temp }}/release"}


def test_kb_release_workflow__publish_checks__run_before_any_step_that_runs_gh():
    # The tag and the asset names are untrusted build output; nothing may use them first.
    names = [step["name"] for step in _steps("publish")]
    assert names[0] == "Check the tag"
    gh_indexes = [i for i, step in enumerate(_steps("publish")) if _runs_gh(step)]
    assert gh_indexes, "publish runs no gh, so this test would pass vacuously"
    assert names.index("Check the assets") < min(gh_indexes)


@pytest.mark.parametrize(
    ("tag", "accepted"),
    [("kb-2026-11-11", True), ("v0.3.0", False), ("kb-2026-11-11; x", False), ("kb-2026-11-11\n", False), ("", False)],
)
def test_kb_release_workflow__check_the_tag__refuses_anything_but_a_kb_date(tag, accepted):
    result = _run_bash(_step("Check the tag", "publish")["run"], env={"TAG": tag})
    assert (result.returncode == 0) is accepted, result
    if not accepted:
        assert "refusing to publish" in result.stdout + result.stderr


_TAG = "kb-2026-11-11"
_LATEST = f"{_TAG}\nschema 7\nsha256 {'a' * 64}\n"


def _release_dir(tmp_path, listed):
    release = tmp_path / "release"
    release.mkdir()
    (release / "release.json").write_text("{}\n")
    (release / "SHA256SUMS").write_text("sums\n")
    (release / "notes.md").write_text("notes\n")
    (release / "LATEST").write_text(_LATEST)
    (release / "assets.txt").write_text("".join(f"{line}\n" for line in listed))
    return release


def _check_assets(tmp_path):
    env = {"RUNNER_TEMP": str(tmp_path), "TAG": _TAG}
    return _run_bash(_step("Check the assets", "publish")["run"], env=env)


def test_kb_release_workflow__check_the_assets__writes_basenames_and_refuses_unsafe_names(tmp_path):
    # assets.txt holds absolute paths on the build runner; publish uploads by basename.
    _release_dir(
        tmp_path, ["/home/runner/work/_temp/release/release.json", "/home/runner/work/_temp/release/SHA256SUMS"]
    )
    result = _check_assets(tmp_path)
    assert result.returncode == 0, result
    assert (tmp_path / "assets.checked").read_text() == "release.json\nSHA256SUMS\n"


@pytest.mark.parametrize("listed", ["-rf", "a/b", "missing.txt", "link.json", None])
def test_kb_release_workflow__check_the_assets__refuses_an_unsafe_or_empty_list(tmp_path, listed):
    # Each case is refused by one guard alone: "-rf" and the symlink name real files, and the
    # symlink points at a regular one. "a/b" reduces to "b", which is refused as missing.
    release = _release_dir(tmp_path, ["release.json"] + ([listed] if listed else []))
    if listed is None:
        (release / "assets.txt").write_text("")
    (release / "-rf").write_text("x\n")
    (release / "link.json").symlink_to(release / "release.json")
    result = _check_assets(tmp_path)
    assert result.returncode != 0, result
    assert "refusing to publish" in result.stdout + result.stderr


def _draft_filter():
    jq = shutil.which("jq")
    assert jq, "jq is required: it ships on GitHub's ubuntu runners and runs the publish job's draft filter"
    return jq, _step("Replace unpublished drafts", "publish")["env"]["DRAFT_FILTER"]


# The hostile first page from the old decide regression, then a second page.
_LISTING_PAGES = [
    [
        {"id": 1, "tag_name": "kb-2026-09-29", "draft": True},
        {"id": 2, "tag_name": "kb-2026-09-29/../v0.1.0", "draft": True},
        {"id": 3, "tag_name": "v0.1.0", "draft": True},
        {"id": 4, "tag_name": "kb-2026-09-28", "draft": False},
        {"id": "5; rm", "tag_name": "kb-2026-09-27", "draft": True},
        {"id": True, "tag_name": "kb-2026-09-26", "draft": True},
        {"id": 0, "tag_name": "kb-2026-09-25", "draft": True},
        {"id": -1, "tag_name": "kb-2026-09-24", "draft": True},
    ],
    [
        {"id": 7, "tag_name": "kb-2026-09-20", "draft": True},
        {"id": 8.5, "tag_name": "kb-2026-09-19", "draft": True},
        {"id": 9, "tag_name": "kb-2026-09-18\n", "draft": True},
        {"id": 10, "tag_name": ["kb-2026-09-17"], "draft": True},
    ],
]


def test_kb_release_workflow__draft_filter__selects_only_positive_int_kb_draft_ids_across_pages():
    # gh api --paginate prints one JSON array per page, back to back.
    jq, program = _draft_filter()
    pages = "".join(json.dumps(page) + "\n" for page in _LISTING_PAGES)
    # S603: argv is jq plus this repository's own workflow text, never external input.
    result = subprocess.run([jq, "-r", program], input=pages, capture_output=True, text=True, check=False)  # noqa: S603
    # jq's exit status reflects only the last page, and an error abandons the rest of its own
    # page, so a filter that errors on one entry silently skips drafts after it.
    assert result.returncode == 0, result
    assert result.stderr == ""
    assert result.stdout == "1\n7\n"


def test_kb_release_workflow__replace_drafts__lists_every_page():
    lines = _logical_lines(_step("Replace unpublished drafts", "publish")["run"])
    listing = [line for line in lines if "gh api" in line and "releases?per_page=" in line]
    assert len(listing) == 1, lines
    assert "--paginate" in listing[0].split()


_GH_STUB = """
gh() {
  case "$*" in
    *--paginate*) [ -n "$LIST_FAILS" ] && return 1; cat "$PAGES" ;;
    *"--jq .draft"*) echo true ;;
    *"-X DELETE"*) echo "$*" >> "$DELETED" ;;
    *) return 1 ;;
  esac
}
"""


@pytest.mark.parametrize("list_fails", [False, True])
def test_kb_release_workflow__replace_drafts__deletes_only_filtered_drafts_and_fails_on_a_failed_listing(
    tmp_path, list_fails
):
    _, program = _draft_filter()
    pages = tmp_path / "pages.json"
    pages.write_text("".join(json.dumps(page) + "\n" for page in _LISTING_PAGES))
    deleted = tmp_path / "deleted"
    env = {
        "RUNNER_TEMP": str(tmp_path),
        "GH_REPO": "owner/repo",
        "DRAFT_FILTER": program,
        "PAGES": str(pages),
        "DELETED": str(deleted),
        "LIST_FAILS": "1" if list_fails else "",
    }
    result = _run_bash(_GH_STUB + _step("Replace unpublished drafts", "publish")["run"], env=env)
    if list_fails:
        assert result.returncode != 0, result
        assert not deleted.exists()
    else:
        assert result.returncode == 0, result
        assert (
            deleted.read_text()
            == "api -X DELETE repos/owner/repo/releases/1\napi -X DELETE repos/owner/repo/releases/7\n"
        )


def test_kb_release_workflow__draft_release__uploads_the_checked_basenames_from_the_download_directory(tmp_path):
    release = _release_dir(tmp_path, [])
    (tmp_path / "assets.checked").write_text("release.json\nSHA256SUMS\n")
    calls = tmp_path / "calls"
    stub = 'gh() { printf "%s|%s\\n" "$PWD" "$*" >> "$CALLS"; }\n'
    env = {"RUNNER_TEMP": str(tmp_path), "TAG": "kb-2026-11-11", "GITHUB_SHA": "abc123", "CALLS": str(calls)}
    result = _run_bash(stub + _step("Draft release", "publish")["run"], env=env)
    assert result.returncode == 0, result
    assert calls.read_text() == (
        f"{release}|release create kb-2026-11-11 --draft --target abc123 --title Knowledge base kb-2026-11-11 "
        "--notes-file notes.md release.json SHA256SUMS\n"
    )


def _replace_with_symlink(release, name):
    # The target is a valid copy, so only the symlink test can refuse it.
    target = release.parent / f"{name}.target"
    target.write_text((release / name).read_text())
    (release / name).unlink()
    (release / name).symlink_to(target)


@pytest.mark.parametrize("name", ["notes.md", "LATEST"])
@pytest.mark.parametrize("change", ["missing", "symlink"])
def test_kb_release_workflow__check_the_assets__refuses_notes_or_latest_that_is_not_a_plain_file(
    tmp_path, name, change
):
    # The token steps read notes.md into the draft and push LATEST to a public branch, so a
    # symlink to /proc/self/environ there would publish the step's GH_TOKEN.
    release = _release_dir(tmp_path, ["release.json"])
    if change == "missing":
        (release / name).unlink()
    else:
        _replace_with_symlink(release, name)
    result = _check_assets(tmp_path)
    assert result.returncode != 0, result
    assert "refusing to publish" in result.stdout + result.stderr


@pytest.mark.parametrize(
    "latest",
    [
        f"kb-2026-11-10\nschema 7\nsha256 {'a' * 64}\n",
        f"{_TAG}\nschema seven\nsha256 {'a' * 64}\n",
        f"{_TAG}\nschema 7 GH_TOKEN=secret\nsha256 {'a' * 64}\n",
        f"{_TAG}\nschema 7\nsha256 {'a' * 63}\n",
        f"{_TAG}\nschema 7\nsha256 {'A' * 64}\n",
        f"{_TAG}\nschema 7\nsha256 {'a' * 64}\nGH_TOKEN=secret\n",
        f"{_TAG}\nschema 7\n",
        f"{_TAG}\nschema 7\nsha256 {'a' * 64} GH_TOKEN=secret\n",
    ],
    ids=[
        "other_tag",
        "schema_not_a_number",
        "schema_trailing_text",
        "short_sha",
        "uppercase_sha",
        "extra_line",
        "two_lines",
        "trailing_text",
    ],
)
def test_kb_release_workflow__check_the_assets__refuses_latest_not_in_the_package_format(tmp_path, latest):
    release = _release_dir(tmp_path, ["release.json"])
    (release / "LATEST").write_text(latest)
    result = _check_assets(tmp_path)
    assert result.returncode != 0, result
    assert "refusing to publish" in result.stdout + result.stderr
