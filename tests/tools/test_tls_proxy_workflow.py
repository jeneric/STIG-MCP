import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "tls-proxy.yml"
SCRIPT = ROOT / "tools" / "tls_ci.sh"
_SHA_PIN = re.compile(r"[\w.-]+/[\w.-]+(/[\w.-]+)?@[0-9a-f]{40}")


def _doc():
    return yaml.safe_load(WORKFLOW.read_text())


def _triggers():
    # PyYAML reads the bare key `on` as the boolean True.
    return _doc()[True]


def test_tls_proxy_workflow__pull_request_paths__cover_every_module_that_opens_tls():
    users = {
        p.relative_to(ROOT).as_posix() for p in (ROOT / "stig_mcp").rglob("*.py") if "tls.opener(" in p.read_text()
    }
    assert users, "no module calls tls.opener(, so nothing was checked"
    assert users | {"stig_mcp/tls.py", "tools/tls_probe.py", "tools/tls_ci.sh", "uv.lock", "pyproject.toml"} <= set(
        _triggers()["pull_request"]["paths"]
    )


def test_tls_proxy_workflow__triggers__are_pull_requests_a_weekly_schedule_and_dispatch():
    triggers = _triggers()
    assert set(triggers) == {"pull_request", "schedule", "workflow_dispatch"}
    assert len(triggers["schedule"]) == 1


def test_tls_proxy_workflow__every_action__is_pinned_to_a_commit_sha():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW.read_text())
    assert uses, "no `uses:` found, so nothing was checked"
    assert [u for u in uses if not _SHA_PIN.fullmatch(u)] == []


def test_tls_proxy_workflow__permissions__are_read_only():
    assert _doc()["permissions"] == {"contents": "read"}


def test_tls_proxy_workflow__probe_matrix__three_systems_and_every_supported_python():
    matrix = _doc()["jobs"]["probe"]["strategy"]["matrix"]
    assert set(matrix["os"]) == {"ubuntu-latest", "windows-latest", "macos-latest"}
    floor = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["requires-python"]
    assert floor == ">=3.11"
    assert matrix["python"] == ["3.11", "3.12", "3.13", "3.14"]


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("openssl")), reason="needs bash and openssl")
def test_tls_ci__make_cas__only_the_strict_ca_leaves_basic_constraints_non_critical(tmp_path):
    # S603: argv is a resolved bash or openssl, this repository's script and a pytest tmp_path.
    subprocess.run([shutil.which("bash"), str(SCRIPT), "make-cas", str(tmp_path)], check=True)  # noqa: S603
    for name, critical in (("untrusted", True), ("compliant", True), ("strict", False)):
        cert = tmp_path / name / "cert.pem"
        text = subprocess.run(  # noqa: S603
            [shutil.which("openssl"), "x509", "-in", str(cert), "-noout", "-ext", "basicConstraints"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "CA:TRUE" in text
        assert ("critical" in text) is critical, name
        # mitmdump needs the key before the certificate in this file.
        assert "PRIVATE KEY" in (tmp_path / name / "mitmproxy-ca.pem").read_text().splitlines()[0]


def test_tls_proxy_workflow__mitmproxy_install__uses_its_own_interpreter():
    # mitmproxy needs Python 3.12 or newer, and uv tool install honors the job's UV_PYTHON.
    installs = [
        step["run"]
        for job in _doc()["jobs"].values()
        for step in job["steps"]
        if "uv tool install" in step.get("run", "")
    ]
    assert installs, "no `uv tool install` step found, so nothing was checked"
    assert [run for run in installs if "--python 3.14" not in run] == []


def test_tls_proxy_workflow__every_job__has_a_timeout():
    jobs = _doc()["jobs"]
    assert [name for name, job in jobs.items() if "timeout-minutes" not in job] == []


def test_tls_proxy_workflow__uv_leg__runs_the_shipped_env_pair_on_a_normal_network_first():
    steps = _doc()["jobs"]["uv-leg"]["steps"]
    unproxied = [
        i
        for i, step in enumerate(steps)
        if {"UV_SYSTEM_CERTS", "UV_NATIVE_TLS"} <= set(step.get("env", {})) and "with-proxy" not in step.get("run", "")
    ]
    assert len(unproxied) >= 2
    first_proxied = next(i for i, step in enumerate(steps) if "with-proxy" in step.get("run", ""))
    assert max(unproxied) < first_proxied


def test_tls_proxy_workflow__strict_case__requires_the_strict_reason_only_off_macos_on_python_3_13_and_later():
    probe = _doc()["jobs"]["probe"]
    strict = "matrix.os != 'macos-latest' && (matrix.python == '3.13' || matrix.python == '3.14')"
    assert probe["env"]["STRICT_DEFAULT"] == "${{ " + strict + " && 'fail' || 'any' }}"
    assert probe["env"]["STRICT_REASON"] == "${{ " + strict + " && 'not marked critical' || '' }}"
    (case4,) = [step["run"] for step in probe["steps"] if step.get("name", "").startswith("Case 4")]
    assert '--expect-default "$STRICT_DEFAULT" ${STRICT_REASON:+--default-reason "$STRICT_REASON"}' in case4


def test_tls_proxy_workflow__install_kb__first_proves_the_install_goes_through_the_proxy():
    runs = [step.get("run", "") for step in _doc()["jobs"]["install-kb"]["steps"]]
    control = (
        'tools/tls_ci.sh with-proxy "$CAS/untrusted" tools/tls_ci.sh expect-fail uv run --no-sync stig-mcp-install-kb'
    )
    real = 'tools/tls_ci.sh with-proxy "$CAS/strict" uv run --no-sync stig-mcp-install-kb'
    assert runs.index(control) < runs.index(real)
    assert not any('tls_ci.sh trust "$CAS/untrusted' in run for run in runs)


_NOT_MACOS = "runner.os != 'macOS'"


def _steps():
    return [(name, step) for name, job in _doc()["jobs"].items() for step in job["steps"]]


def test_tls_proxy_workflow__os_trust_steps__skip_macos():
    trusting = [step for _, step in _steps() if "tls_ci.sh trust" in step.get("run", "")]
    assert trusting, "no trust step found, so nothing was checked"
    assert [step["name"] for step in trusting if step.get("if") != _NOT_MACOS] == []


def test_tls_proxy_workflow__proxied_cases_needing_os_trust__skip_macos():
    needs_trust = [
        step
        for _, step in _steps()
        if re.search(r'with-proxy "\$CAS/(compliant|strict)"', step.get("run", "")) and "expect-fail" not in step["run"]
    ]
    assert len(needs_trust) >= 5, "expected cases 3 and 4, the proxied install and two uv legs"
    assert [step["name"] for step in needs_trust if step.get("if") != _NOT_MACOS] == []


def test_tls_proxy_workflow__install_kb__installs_with_no_proxy_on_macos_only():
    steps = _doc()["jobs"]["install-kb"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "Install the knowledge base with no proxy"]
    assert step["if"] == "runner.os == 'macOS'"
    assert step["run"].splitlines()[-1] == "uv run --no-sync stig-mcp-install-kb"


_UNPROXIED_INSTALL = "Install the knowledge base with no proxy"


def _unproxied_install_step():
    (step,) = [s for _, s in _steps() if s.get("name") == _UNPROXIED_INSTALL]
    return step


def test_tls_proxy_workflow__github_token__is_given_to_the_unproxied_macos_install_step_only():
    holders = [step for _, step in _steps() if "github.token" in str(step.get("env", {}))]
    assert holders, "no step receives github.token, so nothing was checked"
    assert [step["name"] for step in holders] == [_UNPROXIED_INSTALL]
    assert holders[0]["if"] == "runner.os == 'macOS'"
    assert holders[0]["env"] == {"GITHUB_TOKEN": "${{ github.token }}"}
    assert [name for name, job in _doc()["jobs"].items() if "github.token" in str(job.get("env", {}))] == []
    assert "github.token" not in str({k: v for k, v in _doc().items() if k != "jobs"})


def test_tls_proxy_workflow__github_token_step__masks_the_token_first():
    assert _unproxied_install_step()["run"].startswith('echo "::add-mask::$GITHUB_TOKEN"\n')


def test_tls_proxy_workflow__raw_text__names_github_token_exactly_once():
    assert WORKFLOW.read_text().count("github.token") == 1


def test_tls_proxy_workflow__macos_install_step__runs_only_the_mask_and_the_install():
    assert _unproxied_install_step()["run"].splitlines() == [
        'echo "::add-mask::$GITHUB_TOKEN"',
        "uv run --no-sync stig-mcp-install-kb",
    ]


def test_tls_proxy_workflow__no_step__writes_github_token_to_github_env():
    runs = [step.get("run", "") for _, step in _steps()]
    assert any("GITHUB_ENV" in run for run in runs), "no step writes GITHUB_ENV, so nothing was checked"
    assert [run for run in runs if "GITHUB_TOKEN" in run and "GITHUB_ENV" in run] == []


def test_tls_proxy_workflow__every_checkout__sets_persist_credentials_false():
    checkouts = [step for _, step in _steps() if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 4, "the workflow has four checkouts"
    assert [step for step in checkouts if step.get("with", {}).get("persist-credentials") is not False] == []


def test_tls_proxy_workflow__pull_request_paths__include_github_auth():
    assert "stig_mcp/github_auth.py" in _triggers()["pull_request"]["paths"]


def test_tls_proxy_workflow__make_cas_steps__run_on_every_os():
    making = [step for _, step in _steps() if "tls_ci.sh make-cas" in step.get("run", "")]
    assert len(making) == 3, "probe, install-kb and uv-leg each make the CAs"
    assert [step["name"] for step in making if "if" in step] == []


def _expect_fail(output, exit_code):
    # S603: argv is a resolved bash, this repository's script and literal test text.
    return subprocess.run(  # noqa: S603
        [shutil.which("bash"), str(SCRIPT), "expect-fail", "bash", "-c", f'echo "{output}"; exit {exit_code}'],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
@pytest.mark.parametrize(
    "output",
    [
        "stig-mcp-install-kb: The TLS connection to api.github.com failed (A certificate chain processed ...)",
        "error: invalid peer certificate: UnknownIssuer",
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
    ],
    ids=["stig_mcp_explain", "rustls", "openssl"],
)
def test_tls_ci__expect_fail_on_a_certificate_failure__succeeds(output):
    assert _expect_fail(output, 1).returncode == 0


@pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")
def test_tls_ci__expect_fail_on_another_failure__fails():
    result = _expect_fail("Could not reach api.github.com: connection refused", 1)
    assert result.returncode == 1
    assert "not on a certificate error" in result.stderr
