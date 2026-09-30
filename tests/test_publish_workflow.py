import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"
_SHA_PIN = re.compile(r"[\w.-]+/[\w.-]+(/[\w.-]+)?@[0-9a-f]{40}")
TESTPYPI_UPLOAD = "https://test.pypi.org/legacy/"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish@"


def _doc():
    return yaml.safe_load(WORKFLOW.read_text())


def _jobs():
    return _doc()["jobs"]


def _steps(job):
    return _jobs()[job]["steps"]


def _publish_step(job):
    (step,) = [s for s in _steps(job) if s.get("uses", "").startswith(PUBLISH_ACTION)]
    return step


def test_publish_workflow__every_action__is_pinned_by_commit_sha():
    uses = [step["uses"] for job in _jobs() for step in _steps(job) if "uses" in step]
    assert uses, "no actions found, so this test would pass on an empty workflow"
    assert [u for u in uses if not _SHA_PIN.fullmatch(u.split(" ")[0])] == []


def test_publish_workflow__triggers__are_manual_dispatch_and_version_tags_only():
    triggers = _doc().get("on", _doc().get(True))  # PyYAML reads the bare key on as True
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"] == {"tags": ["v*"]}


def test_publish_workflow__id_token__is_granted_only_to_the_three_publishing_jobs():
    assert _doc()["permissions"] == {"contents": "read"}
    granted = {job for job, body in _jobs().items() if body.get("permissions", {}).get("id-token") == "write"}
    assert granted == {"testpypi", "pypi", "registry"}


def test_publish_workflow__testpypi__runs_only_on_dispatch_and_uploads_only_to_testpypi():
    job = _jobs()["testpypi"]
    assert job["if"] == "github.event_name == 'workflow_dispatch'"
    assert job["environment"] == "testpypi"
    assert _publish_step("testpypi")["with"]["repository-url"] == TESTPYPI_UPLOAD
    # A "re-run failed jobs" re-uploads the same artifact; the verify job's digest check
    # is what proves the served files are this build.
    assert _publish_step("testpypi")["with"]["skip-existing"] is True


RELEASE_ONLY = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"


def test_publish_workflow__pypi_and_registry__run_only_on_a_pushed_version_tag():
    # A manual dispatch can be started ON a tag ref, and then github.ref starts with
    # refs/tags/v too; only the event name tells a release from a dry run.
    for job in ("pypi", "registry"):
        assert _jobs()[job]["if"] == RELEASE_ONLY, job
    assert _jobs()["pypi"]["environment"] == "pypi"
    assert "repository-url" not in _publish_step("pypi").get("with", {})
    assert "pypi" in _jobs()["registry"]["needs"]


def test_publish_workflow__pypi__can_finish_a_partial_upload_on_rerun():
    # The registry job's digest check against pypi.org is what proves the files already
    # there are this build, as the verify job does for TestPyPI.
    assert _publish_step("pypi")["with"]["skip-existing"] is True


def test_publish_workflow__dry_run_version__is_unique_per_run_attempt():
    runs = [s.get("run", "") for s in _steps("build") if s.get("if") == "github.event_name == 'workflow_dispatch'"]
    assert len(runs) == 1
    assert "GITHUB_RUN_NUMBER" in runs[0] and "GITHUB_RUN_ATTEMPT" in runs[0]
    assert ".dev" in runs[0]


def test_publish_workflow__tag__must_name_the_project_version():
    (step,) = [s for s in _steps("build") if s.get("if") == RELEASE_ONLY]
    assert "GITHUB_REF_NAME#v" in step["run"] and "uv version --short" in step["run"]


def test_publish_workflow__run_scripts__interpolate_no_expressions():
    # Template injection: an expression inside run: is pasted into the shell before it
    # runs. Values reach scripts through env: instead.
    offenders = [
        f"{job}: {step.get('name')}" for job in _jobs() for step in _steps(job) if "${{" in step.get("run", "")
    ]
    assert offenders == []


def test_publish_workflow__mcp_publisher__is_a_pinned_version_checked_by_sha256():
    env = _doc()["env"]
    assert re.fullmatch(r"v\d+\.\d+\.\d+", env["MCP_PUBLISHER_VERSION"])
    assert re.fullmatch(r"[0-9a-f]{64}", env["MCP_PUBLISHER_SHA256"])
    installs = [s["run"] for job in _jobs() for s in _steps(job) if "mcp-publisher_linux_amd64" in s.get("run", "")]
    assert len(installs) == 2, "server-json and registry each install it"
    for script in installs:
        assert "releases/latest" not in script
        assert "sha256sum -c" in script
        assert script.index("sha256sum -c") < script.index("tar ")


def test_publish_workflow__registry__checks_pypi_serves_the_build_before_publishing():
    runs = [s.get("run", "") for s in _steps("registry")]
    check = next(i for i, r in enumerate(runs) if "tools.publish_check" in r)
    publish = next(i for i, r in enumerate(runs) if "mcp-publisher publish" in r)
    assert "--index-url https://pypi.org" in runs[check]
    assert check < publish
