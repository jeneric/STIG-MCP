import io
import ssl
import urllib.error

import pytest

from tools import tls_probe

URL = "https://pypi.org/pypi/stig-mcp/json"


def _passing(request, timeout=None):
    return io.BytesIO(b"{}")


def _certificate_failure(request, timeout=None):
    raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed"))


def _run(capsys, *expect, default=_passing, tls=_passing):
    code = tls_probe.main(["--url", URL, *expect], default_opener=default, tls_opener=tls)
    return code, capsys.readouterr().out


def test_main__both_pass_as_expected__exits_zero(capsys):
    code, out = _run(capsys, "--expect-default", "pass", "--expect-tls", "pass")
    assert code == 0
    assert "default: pass" in out and "tls: pass" in out


def test_main__tls_fails_where_pass_was_expected__exits_one_and_prints_the_reason(capsys):
    code, out = _run(capsys, "--expect-default", "pass", "--expect-tls", "pass", tls=_certificate_failure)
    assert code == 1
    assert "tls: fail" in out and "certificate verify failed" in out


def test_main__any__accepts_either_outcome(capsys):
    code, _ = _run(capsys, "--expect-default", "any", "--expect-tls", "any", default=_certificate_failure)
    assert code == 0


def test_main__no_worse_and_tls_fails_where_default_passes__exits_one(capsys):
    code, out = _run(capsys, "--expect-default", "any", "--expect-tls", "any", "--no-worse", tls=_certificate_failure)
    assert code == 1
    assert "worse" in out


def test_main__no_worse_and_both_fail__exits_zero(capsys):
    code, _ = _run(
        capsys,
        "--expect-default",
        "any",
        "--expect-tls",
        "any",
        "--no-worse",
        default=_certificate_failure,
        tls=_certificate_failure,
    )
    assert code == 0


def test_main__url_not_https__refuses_before_opening_anything():
    with pytest.raises(SystemExit, match="https://"):
        tls_probe.main(
            ["--url", "http://pypi.org/", "--expect-default", "any", "--expect-tls", "any"],
            default_opener=_passing,
            tls_opener=_passing,
        )


def test_main__expected_fail_but_not_a_certificate_error__exits_one(capsys):
    def refused(request, timeout=None):
        raise urllib.error.URLError(ConnectionRefusedError("connection refused"))

    code, out = _run(capsys, "--expect-default", "fail", "--expect-tls", "fail", default=refused, tls=refused)
    assert code == 1
    assert "not a certificate error" in out
