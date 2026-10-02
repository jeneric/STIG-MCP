"""Open one URL through Python's default urllib and through stig_mcp.tls, and check each outcome
against what the caller expects. Run by .github/workflows/tls-proxy.yml.

A "fail" counts only when the failure is a certificate error, so a control behind a proxy that
never started cannot pass by accident."""

import argparse
import ssl
import sys
import urllib.error
import urllib.request

from stig_mcp import tls

TIMEOUT = 30
OUTCOMES = ("pass", "fail", "any")


def attempt(open_url, url):
    """("pass", "") or ("fail", reason), where reason names whether it was a certificate error."""
    if not url.startswith("https://"):
        raise SystemExit(f"tls_probe needs an https:// URL, got {url!r}")
    # S310: the URL is the workflow's own constant, and the scheme is checked above.
    request = urllib.request.Request(url, headers={"User-Agent": "stig-mcp tls probe"})  # noqa: S310
    try:
        with open_url(request, timeout=TIMEOUT) as response:
            response.read(1)
    except (OSError, urllib.error.URLError) as exc:
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        kind = "certificate error" if isinstance(reason, ssl.SSLError) else "not a certificate error"
        return "fail", f"{kind}: {reason!r}"
    return "pass", ""


def _problems(name, outcome, reason, expected):
    if expected == "any" or outcome == expected == "pass":
        return []
    if outcome == expected == "fail":
        return [] if reason.startswith("certificate error") else [f"{name} failed, but {reason}"]
    return [f"{name} was expected to {expected} and did {outcome}"]


def main(argv=None, default_opener=None, tls_opener=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True)
    parser.add_argument("--expect-default", choices=OUTCOMES, required=True)
    parser.add_argument("--expect-tls", choices=OUTCOMES, required=True)
    parser.add_argument("--no-worse", action="store_true", help="fail if tls fails where default passes")
    args = parser.parse_args(argv)
    results = {
        "default": attempt(default_opener or urllib.request.urlopen, args.url),
        "tls": attempt(tls_opener or tls.opener(), args.url),
    }
    problems = []
    for name, expected in (("default", args.expect_default), ("tls", args.expect_tls)):
        outcome, reason = results[name]
        print(f"{name}: {outcome}" + (f" ({reason})" if reason else ""))
        problems += _problems(name, outcome, reason, expected)
    if args.no_worse and results["default"][0] == "pass" and results["tls"][0] == "fail":
        problems.append("tls is worse than Python's default here: default passed and tls failed")
    for problem in problems:
        print(f"PROBLEM: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
