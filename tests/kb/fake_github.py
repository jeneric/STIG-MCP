"""A stand-in for GitHub's releases API and asset downloads, serving real bytes by URL.

Used as the `opener` every stig_mcp.kb network function accepts, the same seam
stig_mcp.ingest.upstream uses, so no test patches urllib."""

import email.message
import hashlib
import io
import json
import lzma
import urllib.error

from stig_mcp.kb import releases


class Response(io.BytesIO):
    def __init__(self, body, url):
        super().__init__(body)
        self._url = url

    def geturl(self):
        return self._url


def http_error(url, code, headers=None):
    message = email.message.Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return urllib.error.HTTPError(url, code, "error", message, None)


def refuse_network(request, timeout=None):
    raise AssertionError(f"this path must not touch the network, but it requested {request.full_url}")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class FakeGitHub:
    def __init__(self):
        self.bodies = {}
        self.requested = []
        self.releases = []
        self.redirects = {}
        self.refresh()

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.requested.append(url)
        body = self.bodies.get(url)
        if body is None:
            raise http_error(url, 404)
        if isinstance(body, BaseException):
            raise body
        return Response(body, self.redirects.get(url, url))

    def refresh(self):
        self.bodies[releases.LISTING_URL] = json.dumps(self.releases).encode()
        for entry in self.releases:
            self.bodies[releases.TAG_URL.format(tag=entry["tag_name"])] = json.dumps(entry).encode()

    # Six params, one per varying release field, so a test names only the ones it changes.
    def publish(self, tag, kb_bytes, schema="6", built_with="0.1.0", upstream=None, draft=False):  # noqa: PLR0913
        """A release as the CI workflow will publish it, newest first like GitHub's listing."""
        date = tag.removeprefix("kb-")
        xz_name = f"stig_kb-schema{schema}-{date}.sqlite.xz"
        xz = lzma.compress(kb_bytes)
        sums = f"{_sha(xz)}  {xz_name}\n{_sha(kb_bytes)}  {xz_name.removesuffix('.xz')}\n".encode()
        meta = {
            "schema": schema,
            "built_with": built_with,
            "sha256": {"xz": _sha(xz), "sqlite": _sha(kb_bytes)},
            "upstream": upstream or {},
        }
        assets = {xz_name: xz, releases.SUMS_NAME: sums, releases.RELEASE_JSON_NAME: json.dumps(meta).encode()}
        entry = {"tag_name": tag, "draft": draft, "prerelease": False, "assets": []}
        for name, body in assets.items():
            url = f"{releases.DOWNLOAD_PREFIX}{tag}/{name}"
            self.bodies[url] = body
            entry["assets"].append({"name": name, "size": len(body), "browser_download_url": url})
        self.releases.insert(0, entry)
        self.refresh()
        return entry

    def publish_directory(self, tag, directory, names):
        """A release whose assets are exactly these files, as the workflow uploads them."""
        entry = {"tag_name": tag, "draft": False, "prerelease": False, "assets": []}
        for name in names:
            url = f"{releases.DOWNLOAD_PREFIX}{tag}/{name}"
            body = (directory / name).read_bytes()
            self.bodies[url] = body
            entry["assets"].append({"name": name, "size": len(body), "browser_download_url": url})
        self.releases.insert(0, entry)
        self.refresh()
        return entry
