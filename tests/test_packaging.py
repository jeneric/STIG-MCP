"""The wheel must carry the data files the package opens at runtime.

Every one of them is read through `Path(__file__).parent`, so a missing entry in
[tool.setuptools.package-data] is invisible from a source checkout and fatal from an
installed wheel: `schema.sql` is what creates the database. These tests build a real
wheel rather than matching the declared globs themselves, because a glob matcher that
agrees with pyproject can still agree about an empty wheel.

The build goes through the setuptools API rather than a `uv build` subprocess because it
is two orders of magnitude faster and depends on nothing outside this interpreter: no
`uv` on PATH, no network, no build isolation to provision.
"""

import email
import json
import logging
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from setuptools import build_meta
from setuptools._distutils import dir_util

REPO_ROOT = Path(__file__).parent.parent
PACKAGE_ROOT = REPO_ROOT / "stig_mcp"

# The operator's downloads and built knowledge base live here. It is a working directory
# the package writes to, not content the package ships.
OPERATOR_DATA_DIR = PACKAGE_ROOT / "data"


def _runtime_data_files():
    """Package files that are not Python source, as paths relative to the repository root.

    Excludes `__pycache__` and everything under `stig_mcp/data`, so the operator's archives
    are not mistaken for content the package owes its installer.
    """
    return {
        path.relative_to(REPO_ROOT)
        for path in PACKAGE_ROOT.rglob("*")
        if path.is_file()
        and path.suffix != ".py"
        and "__pycache__" not in path.parts
        and OPERATOR_DATA_DIR not in path.parents
    }


def _clear_stale_build_state():
    """Remove what a previous build left in the repository root, and prove it is gone.

    Both of these carry a previous build forward: build/lib stages the package and never
    drops a file that has stopped being selected, and egg-info/SOURCES.txt is a cached
    manifest that include-package-data (on by default under pyproject) ships from. Either
    one hands these tests the files they are supposed to be checking for, which is why the
    removal is asserted rather than attempted: a swallowed failure here would not fail the
    build, it would pass it for the wrong reason.

    Both paths are shared by every process building this checkout, so this module is not
    safe to run under `pytest -n` or alongside a second pytest in the same tree.
    """
    assert (REPO_ROOT / "pyproject.toml").is_file(), (
        f"{REPO_ROOT} does not look like the repository root, and this function is about to "
        "delete directories inside it. REPO_ROOT is derived from this file's location, so a "
        "moved test file is the likely cause."
    )
    stale = [REPO_ROOT / "build", *REPO_ROOT.glob("*.egg-info")]
    for path in stale:
        shutil.rmtree(path, ignore_errors=True)
    # distutils' mkpath caches every directory it has created, per process, and only its own
    # remove_tree forgets them. Without this a second build in the same process skips
    # re-creating the egg-info deleted above, then fails to update its time stamp.
    dir_util.SkipRepeatAbsolutePaths.clear()
    survived = sorted(str(path) for path in stale if path.exists())
    assert not survived, (
        f"{survived} could not be removed, so the wheel built next would inherit an earlier "
        "build's file selection and these tests would pass without proving anything. Remove "
        "them by hand (`make clean`) and re-run."
    )


def _build(out_dir, build):
    """Run one setuptools build hook against the repository, isolated from the test process.

    `build` is `build_meta.build_wheel` or `build_meta.build_sdist`; returns the artifact's path.
    """
    _clear_stale_build_state()
    root_logger_level = logging.getLogger().level
    with pytest.MonkeyPatch.context() as patch:
        # build_meta rebinds sys.argv to the bdist_wheel command line, appends setuptools'
        # vendored directory to sys.path, and raises the root logger to INFO. It restores
        # none of it, and this fixture runs mid-suite, so whatever pytest collects next
        # would inherit all three.
        patch.setattr(sys, "argv", list(sys.argv))
        patch.setattr(sys, "path", list(sys.path))
        patch.chdir(REPO_ROOT)
        try:
            return out_dir / build(str(out_dir))
        finally:
            # setLevel rather than restoring the attribute, because the level is cached per
            # logger and only setLevel invalidates the cache.
            logging.getLogger().setLevel(root_logger_level)


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    yield _build(tmp_path_factory.mktemp("wheel"), build_meta.build_wheel)
    _clear_stale_build_state()


@pytest.fixture(scope="module")
def wheel_members(built_wheel):
    """Every path inside a freshly built wheel, excluding the .dist-info metadata."""
    with zipfile.ZipFile(built_wheel) as archive:
        return {Path(name) for name in archive.namelist() if not Path(name).parts[0].endswith(".dist-info")}


@pytest.fixture(scope="module")
def sdist_members(tmp_path_factory):
    """Every file inside a freshly built sdist, relative to its top-level directory."""
    sdist = _build(tmp_path_factory.mktemp("sdist"), build_meta.build_sdist)
    with tarfile.open(sdist) as archive:
        members = {Path(*Path(member.name).parts[1:]) for member in archive.getmembers() if member.isfile()}
    _clear_stale_build_state()
    return members


def test_built_wheel__runtime_data_files__ships_all_of_them(wheel_members):
    missing = _runtime_data_files() - wheel_members
    assert not missing, (
        f"{sorted(str(path) for path in missing)} are opened relative to the installed package but "
        "are absent from the wheel. Add each one to [tool.setuptools.package-data] in pyproject.toml, "
        "under the key naming its package."
    )


def test_built_wheel__operator_data_directory__ships_nothing_from_it(wheel_members):
    shipped = {member for member in wheel_members if member.parts[:2] == ("stig_mcp", "data")}
    assert not shipped, (
        f"{sorted(str(member) for member in shipped)} come from stig_mcp/data, which holds the "
        "operator's DISA archives and knowledge base. Narrow the [tool.setuptools.package-data] "
        "patterns so they cannot reach it."
    )


def test_built_sdist__tests_directory__ships_nothing_from_it(sdist_members):
    shipped = sorted(str(member) for member in sdist_members if member.parts[0] == "tests")
    assert not shipped, (
        f"{shipped} are in the sdist. setuptools adds tests/test*.py implicitly; MANIFEST.in's "
        "`prune tests` is what keeps them out, so check it is still there."
    )


def test_built_sdist__tools_and_operator_data__ship_nothing(sdist_members):
    shipped = sorted(
        str(member)
        for member in sdist_members
        if member.parts[0] == "tools" or member.parts[:2] == ("stig_mcp", "data")
    )
    assert not shipped


def test_built_sdist__notices_and_readme__are_all_present(sdist_members):
    required = {
        Path("README.md"),
        Path("LICENSE"),
        Path("NOTICE"),
        Path("licenses/apache-2.0.txt"),
        Path("pyproject.toml"),
    }
    assert required - sdist_members == set()


def test_built_sdist__runtime_data_files__ship_all_of_them(sdist_members):
    # An sdist missing a data file builds a wheel missing it, on every machine that installs
    # from source.
    assert _runtime_data_files() - sdist_members == set()


def _metadata(built_wheel):
    with zipfile.ZipFile(built_wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        return email.message_from_string(archive.read(name).decode("utf-8"))


def test_built_wheel__long_description__is_the_readme_as_markdown(built_wheel):
    metadata = _metadata(built_wheel)
    assert metadata["Description-Content-Type"] == "text/markdown"
    assert metadata.get_payload().strip() == (REPO_ROOT / "README.md").read_text().strip()


def test_built_wheel__long_description__carries_the_registry_ownership_token(built_wheel):
    from tools.publish_check import SERVER_JSON, contains_mcp_name_token  # noqa: PLC0415

    name = json.loads(SERVER_JSON.read_text())["name"]
    assert contains_mcp_name_token(_metadata(built_wheel).get_payload(), name)


@pytest.mark.parametrize(
    "module",
    ["stig_mcp.ingest.orchestrator", "stig_mcp.ingest.fetch", "stig_mcp.ingest.library", "stig_mcp.kb.install"],
)
def test_cli_modules__run_with_dash_m__expose_their_entry_point(module):
    # Console scripts land on PATH only if the install method exposes them. A uvx or
    # ephemeral-environment install does not, and the readiness payload has to name a
    # command that actually runs. `-m` is reachable from any interpreter that has the
    # package, which sys.executable provably is.
    # S603: argv is sys.executable plus a module name from this test's own parametrize list,
    # never external input.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", module, "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{module}: {result.stderr}"
    # A module reachable with `-m` but missing the `if __name__ == "__main__": main()`
    # guard also exits 0 here: nothing runs, so nothing fails. The returncode check alone
    # cannot tell that apart from main() actually running and handling --help, so pin the
    # one thing only a real argparse --help run produces.
    assert "usage" in result.stdout.lower(), f"{module} produced no help output: {result.stdout!r}"


def test_readme__tool_count__matches_the_registered_tools(tmp_path):
    import asyncio  # noqa: PLC0415
    import re  # noqa: PLC0415

    from stig_mcp.server.app import build_server  # noqa: PLC0415

    registered = len(asyncio.run(build_server(tmp_path / "absent.sqlite").list_tools()))
    words = {"five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}
    match = re.search(r"confirm the (\w+) tools", (Path(__file__).parent.parent / "README.md").read_text())
    assert match and words[match.group(1)] == registered


def test_docs__could_not_check_exit_code__matches_the_constant():
    import re  # noqa: PLC0415

    from stig_mcp.ingest import fetch  # noqa: PLC0415

    root = Path(__file__).parent.parent
    readme = re.search(r"and (\d+) when a source could not\s+be reached", (root / "README.md").read_text())
    table = re.search(
        r"^\| (\d+) \| nothing is to download from the sources", (root / "docs/operations.md").read_text(), re.M
    )
    guide = re.search(r"exits (\d+) when nothing else is to take", (root / "docs/user-guide.md").read_text())
    assert [int(m.group(1)) for m in (readme, table, guide) if m] == [fetch.EXIT_COULD_NOT_CHECK] * 3
