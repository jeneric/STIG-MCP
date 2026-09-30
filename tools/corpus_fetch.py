"""Stage manifest entries onto disk.

Politeness is deliberate rather than incidental. The published directory carries no
Crawl-delay, so this tool chooses a conservative one itself and identifies itself in a
User-Agent, because a developer harness has no business issuing back-to-back requests at a
DoD host."""

import argparse
import hashlib
import json
import signal
import time
import urllib.request
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from stig_mcp.ingest.fetch import require_web_url
from tools.corpus_manifest import ADVERSARIAL, BENCHMARK, COMPILATION, JUNK, USER_AGENT, entry_url, write_manifest

_CHUNK = 1 << 16

# Socket-level, so it bounds the connect and every individual read rather than the transfer
# as a whole: a slow but progressing 145 MB download is not interrupted, a silent one is.
_TIMEOUT = 60
_ATTEMPTS = 3


def _digest_of(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _target_for(dest_dir, name):
    """The staging path for an entry name, refusing anything that escapes dest_dir.

    A manifest is a file on disk that a human can edit, so a name like ../escape.zip has to
    be rejected here rather than trusted."""
    if name.lower().startswith("cui_"):
        raise ValueError(
            f"Refusing to stage {name!r}: CUI content requires a DOD PKI certificate (CAC) and is "
            f"permanently out of scope. Remove the entry from the manifest."
        )
    target = (dest_dir / name).resolve()
    if dest_dir.resolve() not in target.parents:
        raise ValueError(
            f"Refusing to stage {name!r}: it resolves outside the destination directory {dest_dir}. "
            f"Regenerate the manifest with tools.corpus_manifest instead of editing it by hand."
        )
    return target


def _refuse_cui_url(url):
    """Refuse a resolved download URL carrying CUI content, independent of the entry's name.

    _target_for only inspects entry["name"]; the URL actually downloaded is built from
    entry["href"], so a hand-edited manifest can diverge the two and slip a CUI resource
    past the name check under an innocuous name. This closes that gap."""
    if "cui_" in url.lower():
        raise ValueError(
            f"Refusing to stage {url!r}: it resolves to CUI content, which requires a DOD PKI "
            f"certificate (CAC) and is permanently out of scope. Remove the entry from the manifest."
        )


def _download(url, target, opener, sleep=time.sleep, delay=1.0):  # noqa: PLR0913
    """Fetch one archive, giving up on a stalled connection rather than waiting forever.

    urlopen without a timeout inherits socket.getdefaulttimeout(), which is None, so a
    connection that goes quiet mid-transfer blocks the whole run indefinitely.

    Retries are bounded at _ATTEMPTS and pay the politeness delay between tries, so a
    transient stall costs one file's worth of time instead of the run."""
    require_web_url(url)
    request = Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310  scheme confined by require_web_url above
    open_url = opener or urllib.request.urlopen
    target.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            with open_url(request, timeout=_TIMEOUT) as response, target.open("wb") as handle:
                while True:
                    chunk = response.read(_CHUNK)
                    if not chunk:
                        break
                    handle.write(chunk)
        except (TimeoutError, URLError, OSError):
            # A partial file may be on disk. stage() records a checksum only after a clean
            # return, so the entry keeps its old (or absent) checksum and the next run
            # re-downloads it rather than trusting the truncated bytes.
            if attempt == _ATTEMPTS:
                raise
            sleep(delay)
        else:
            return


def stage(manifest, dest_dir, tiers, opener=None, sleep=time.sleep, delay=1.0):  # noqa: PLR0913
    """Download every manifest entry in the requested tiers into dest_dir.

    Records each entry's real size and sha256 in the manifest as it goes, and skips a file
    whose recorded checksum still matches what is on disk, which is what makes an
    interrupted multi-gigabyte run resumable."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    result = {"downloaded": 0, "skipped": 0, "bytes": 0}
    for entry in manifest["entries"]:
        if entry["tier"] not in tiers:
            continue
        target = _target_for(dest_dir, entry["name"])
        url = entry_url(manifest, entry)
        _refuse_cui_url(url)
        if entry["sha256"] and target.exists() and _digest_of(target) == entry["sha256"]:
            result["skipped"] += 1
            continue
        sleep(delay)
        _download(url, target, opener, sleep=sleep, delay=delay)
        entry["sha256"] = _digest_of(target)
        entry["size"] = target.stat().st_size
        result["downloaded"] += 1
        result["bytes"] += entry["size"]
    return result


def _raise_keyboard_interrupt(signum, frame):
    """Turn SIGTERM into the same KeyboardInterrupt a Ctrl-C already sends.

    main()'s try/finally persists the manifest on KeyboardInterrupt; routing SIGTERM (the
    default `kill`) through the same exception makes that finally fire on a hard kill too,
    so the checksums recorded that session survive it."""
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    parser = argparse.ArgumentParser(description="Stage a STIG corpus from a manifest.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--dest", required=True)
    # Compilations are staged to their own --dest, never alongside product zips: the
    # published directory carries nine library compilations and inventory.classify refuses
    # more than one at a time. The harness pairs them up one at a time instead.
    parser.add_argument("--tier", action="append", choices=[BENCHMARK, ADVERSARIAL, COMPILATION, JUNK], default=None)
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    tiers = tuple(args.tier or (BENCHMARK,))
    # stage() records each entry's checksum in the manifest dict as it downloads, before
    # moving to the next one, so whatever it has mutated so far is worth keeping even if it
    # raises or is interrupted partway through. Persisting in a finally, rather than only
    # after a clean return, is what makes the next run resume instead of re-downloading
    # everything: the exception still propagates after the write.
    try:
        result = stage(manifest, args.dest, tiers=tiers, delay=args.delay)
    finally:
        write_manifest(manifest, args.manifest)
    print(f"Staged {result['downloaded']} file(s), skipped {result['skipped']}, {result['bytes']} bytes")


if __name__ == "__main__":
    main()
