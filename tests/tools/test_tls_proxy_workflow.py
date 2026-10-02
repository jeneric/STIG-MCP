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
