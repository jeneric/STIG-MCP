"""Prove a package index serves this build, carrying the MCP Registry's ownership line.

The registry proves PyPI ownership by finding `mcp-name: <server name>` in the long
description PyPI's JSON API returns, but only against pypi.org and only while publishing.
A TestPyPI dry run therefore cannot ask the registry; this runs the same check against
what the index actually stored, and compares the served files with the local build.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from stig_mcp.kb.releases import USER_AGENT

SERVER_JSON = Path(__file__).resolve().parents[1] / "server.json"
POLL_ATTEMPTS = 20
POLL_DELAY = 15  # seconds: the JSON API trails an upload by up to a few minutes
_DISTRIBUTIONS = (".whl", ".tar.gz")
# The characters a server name may contain, per the schema's name pattern.
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-")


def contains_mcp_name_token(content, server_name):
    """Port of the registry's containsMCPNameToken (internal/validators/registries/mcpname.go).

    The name must end at a boundary, so `.../stig-mcp-pro` never proves `.../stig-mcp`.
    A comment close counts even though `-` is a name character.
    """
    token = f"mcp-name: {server_name}"
    start = content.find(token)
    while start >= 0:
        rest = content[start + len(token) :]
        if not rest or rest[0] not in _NAME_CHARS or rest.startswith(("-->", "--!>")):
            return True
        start = content.find(token, start + 1)
    return False


def digest_mismatches(release_files, dist_dir):
    """How the index's files for one version differ from the distributions in `dist_dir`."""
    built = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path(dist_dir).iterdir()
        if path.name.endswith(_DISTRIBUTIONS)
    }
    served = {entry["filename"]: entry["digests"]["sha256"] for entry in release_files}
    problems = [f"{name}: built but not served" for name in sorted(built.keys() - served.keys())]
    problems += [f"{name}: served but not built here" for name in sorted(served.keys() - built.keys())]
    problems += [
        f"{name}: served sha256 {served[name]} but built {built[name]}"
        for name in sorted(built.keys() & served.keys())
        if built[name] != served[name]
    ]
    return problems


def fetch_release(index_url, project, version, opener=urllib.request.urlopen, sleep=time.sleep):
    """The index's JSON for one version, polling while it answers 404; None if it never appears.

    Tries POLL_ATTEMPTS times, POLL_DELAY seconds apart, both read at call time.
    """
    if not index_url.startswith("https://"):
        raise ValueError(f"index URL {index_url!r} must be https, since its answer decides what is trusted")
    url = f"{index_url.rstrip('/')}/pypi/{project}/{version}/json"
    for attempt in range(POLL_ATTEMPTS):
        if attempt:
            sleep(POLL_DELAY)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 (https checked above)
        try:
            with opener(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 404:  # noqa: PLR2004
                raise
    return None


def _server():
    return json.loads(SERVER_JSON.read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--index-url", default="https://test.pypi.org")
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    server = _server()
    name, project = server["name"], server["packages"][0]["identifier"]
    release = fetch_release(args.index_url, project, args.version)
    if release is None:
        print(f"{args.index_url} never listed {project} {args.version}; check the upload step's log.", file=sys.stderr)
        return 1
    problems = digest_mismatches(release["urls"], args.dist)
    if not contains_mcp_name_token(release["info"]["description"] or "", name):
        problems.append(
            f"the served description has no `mcp-name: {name}` ending at a boundary, so the registry "
            "will refuse to publish; check README.md and pyproject.toml's readme key"
        )
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
