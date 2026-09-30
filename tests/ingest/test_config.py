import importlib
import os
from pathlib import Path

import pytest

from stig_mcp.ingest import config
from stig_mcp.ingest.config import checkout_root, resolve_paths


def _checkout(tmp_path, name="stig-mcp"):
    """A package directory inside a source checkout: a pyproject.toml sits beside it."""
    package_dir = tmp_path / "stig_mcp"
    package_dir.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "{name}"\n')
    return package_dir


def _constants():
    """The five module constants, in resolve_paths field order."""
    return (config.DATA_DIR, config.SOURCES_DIR, config.KB_PATH, config.OVERRIDES_PATH, config.OVERRIDES_FROM_ENV)


def _installed(tmp_path):
    """A package directory with no pyproject.toml above it, which is what site-packages is."""
    package_dir = tmp_path / "site-packages" / "stig_mcp"
    package_dir.mkdir(parents=True)
    return package_dir


def test_checkout_root__a_pyproject_beside_the_package__is_the_checkout(tmp_path):
    assert checkout_root(_checkout(tmp_path)) == tmp_path


def test_checkout_root__no_pyproject_above_the_package__is_none(tmp_path):
    assert checkout_root(_installed(tmp_path)) is None


def test_checkout_root__a_pyproject_directory_rather_than_a_file__is_none(tmp_path):
    # Rejected twice over: is_file() turns it away, and if that precondition were dropped the
    # read would raise IsADirectoryError, which _declared_name catches as an OSError. The
    # behavior is what this pins; neither half of the mechanism is load bearing alone.
    package_dir = _installed(tmp_path)
    (package_dir.parent / "pyproject.toml").mkdir()
    assert checkout_root(package_dir) is None


def test_checkout_root__a_pyproject_whose_project_key_is_not_a_table__is_none(tmp_path):
    # Valid TOML, and `.get("project", {})` returns the default only when the key is ABSENT,
    # so a scalar there would reach `.get("name")` and raise AttributeError. checkout_root
    # runs at import, so that would kill every entry point outright.
    package_dir = _checkout(tmp_path)
    (tmp_path / "pyproject.toml").write_text('project = "not a table"\n')
    assert checkout_root(package_dir) is None


def test_checkout_root__a_pyproject_whose_name_is_not_a_string__is_none(tmp_path):
    # The other half of the same shape: TOML permits any value here, and normalizing a
    # non-string raises TypeError, which _declared_name's except clause does not name either.
    package_dir = _checkout(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 42\n")
    assert checkout_root(package_dir) is None


def test_checkout_root__a_pyproject_with_no_project_table__is_none(tmp_path):
    package_dir = _checkout(tmp_path)
    (tmp_path / "pyproject.toml").write_text('[build-system]\nrequires = ["setuptools"]\n')
    assert checkout_root(package_dir) is None


def test_checkout_root__a_pyproject_that_is_not_utf8__is_none_rather_than_raising(tmp_path):
    # Pins the UnicodeDecodeError arm of _declared_name's except clause.
    package_dir = _checkout(tmp_path)
    (tmp_path / "pyproject.toml").write_bytes(b'[project]\nname = "\xff\xfe not utf-8"\n')
    assert checkout_root(package_dir) is None


def test_checkout_root__a_pyproject_that_cannot_be_read__is_none_rather_than_raising(tmp_path):
    # Pins the OSError arm. Dropping OSError propagates PermissionError out of an import that
    # every entry point performs.
    package_dir = _checkout(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.chmod(0o000)
    try:
        assert checkout_root(package_dir) is None
    finally:
        pyproject.chmod(0o644)


def test_checkout_root__the_name_spelled_with_an_underscore__is_still_this_distribution(tmp_path):
    # PEP 503 makes stig_mcp, STIG-MCP and stig.mcp one name, and the docstring claims the
    # pyproject "declares THIS distribution" rather than "spells it our way".
    for spelling in ("stig_mcp", "STIG-MCP", "Stig.Mcp"):
        assert checkout_root(_checkout(tmp_path / spelling, name=spelling)) == tmp_path / spelling


def test_resolve_paths__a_checkout__keeps_the_data_beside_the_code(tmp_path):
    # A checkout keeps the knowledge base beside the code, at <repo>/stig_mcp/data/stig_kb.sqlite,
    # so an operator running from a checkout is unaffected by installed-path resolution.
    package_dir = _checkout(tmp_path)
    paths = resolve_paths({}, package_dir)
    assert paths.data_dir == package_dir / "data"
    assert paths.sources_dir == package_dir / "data" / "sources"
    assert paths.kb_path == package_dir / "data" / "stig_kb.sqlite"
    assert paths.overrides_path == tmp_path / "overrides.yaml"
    assert paths.overrides_from_env is False


def test_resolve_paths__an_install__puts_the_data_under_xdg_not_site_packages(tmp_path):
    package_dir = _installed(tmp_path)
    env = {"XDG_DATA_HOME": "/xdg/data", "XDG_CONFIG_HOME": "/xdg/config"}
    paths = resolve_paths(env, package_dir)
    assert paths.data_dir == Path("/xdg/data/stig-mcp")
    assert paths.kb_path == Path("/xdg/data/stig-mcp/stig_kb.sqlite")
    assert paths.overrides_path == Path("/xdg/config/stig-mcp/overrides.yaml")
    # The whole point: nothing lands inside the installed package.
    assert package_dir not in paths.data_dir.parents


def test_checkout_root__a_pyproject_declaring_another_project__is_none(tmp_path):
    # A vendored copy of this package dropped into somebody else's repository. Without the name
    # check that repository looks like this project's checkout, and an operator's knowledge base
    # and overrides.yaml are created inside it.
    assert checkout_root(_checkout(tmp_path, name="some-unrelated-monorepo")) is None


def test_checkout_root__an_unparseable_pyproject__is_none_rather_than_raising(tmp_path):
    # Every entry point imports this module, so somebody else's malformed file must not be
    # able to stop the server starting.
    package_dir = _checkout(tmp_path)
    (tmp_path / "pyproject.toml").write_text("this is not toml = = =\n")
    assert checkout_root(package_dir) is None


def test_resolve_paths__an_install_without_xdg_set__falls_back_under_the_home_directory(tmp_path):
    paths = resolve_paths({}, _installed(tmp_path))
    assert paths.data_dir == Path.home() / ".local/share/stig-mcp"
    assert paths.overrides_path == Path.home() / ".config/stig-mcp/overrides.yaml"


def test_resolve_paths__an_empty_xdg_variable__falls_back_like_an_unset_one(tmp_path):
    # The XDG base directory spec says an empty value means "use the default", and this is
    # the same empty-string class the STIG_MCP_DATA test below pins.
    env = {"XDG_DATA_HOME": "", "XDG_CONFIG_HOME": ""}
    paths = resolve_paths(env, _installed(tmp_path))
    assert paths.data_dir == Path.home() / ".local/share/stig-mcp"
    assert paths.overrides_path == Path.home() / ".config/stig-mcp/overrides.yaml"


def test_resolve_paths__stig_mcp_data_set__wins_over_both_defaults(tmp_path):
    for package_dir in (_checkout(tmp_path / "a"), _installed(tmp_path / "b")):
        paths = resolve_paths({"STIG_MCP_DATA": "/named/data"}, package_dir)
        assert paths.data_dir == Path("/named/data")
        assert paths.sources_dir == Path("/named/data/sources")


def test_resolve_paths__stig_mcp_overrides_set__wins_and_is_marked_as_named(tmp_path):
    paths = resolve_paths({"STIG_MCP_OVERRIDES": "/named/overrides.yaml"}, _checkout(tmp_path))
    assert paths.overrides_path == Path("/named/overrides.yaml")
    # The flag, not the path, is what makes a missing file an error rather than a silence.
    assert paths.overrides_from_env is True


def test_resolve_paths__an_empty_environment_variable__is_treated_as_unset(tmp_path):
    # An empty value counts as unset: Path("") is the CURRENT DIRECTORY, so an exported-but-empty
    # STIG_MCP_DATA would otherwise put the knowledge base wherever the shell was.
    package_dir = _checkout(tmp_path)
    paths = resolve_paths({"STIG_MCP_DATA": "", "STIG_MCP_OVERRIDES": ""}, package_dir)
    assert paths.data_dir == package_dir / "data"
    assert paths.overrides_path == tmp_path / "overrides.yaml"
    assert paths.overrides_from_env is False


def test_resolve_paths__this_very_package__resolves_as_a_checkout():
    repository_root = Path(__file__).resolve().parent.parent.parent
    paths = resolve_paths({}, config._PACKAGE_DIR)
    assert config.checkout_root(config._PACKAGE_DIR) == repository_root
    assert paths.data_dir == config._PACKAGE_DIR / "data"
    assert paths.overrides_path == repository_root / "overrides.yaml"


@pytest.fixture
def config_reloaded_with(monkeypatch):
    """Re-execute config with environment variables set, then put it back.

    The module constants are computed once at import, so this is the only way to observe that
    they are computed from the environment AT ALL. Everything that uses them holds the module
    object rather than a copy of its attributes, so reload updates every holder, and the
    teardown reload restores them for the rest of the suite.
    """
    before = _constants()

    def _reload(**environment):
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        return importlib.reload(config)

    yield _reload
    monkeypatch.undo()
    importlib.reload(config)
    # Against the snapshot taken at SETUP, not against a fresh resolve_paths(os.environ, ...):
    # a teardown that reloaded without undoing the environment first would compute both sides
    # from the same polluted environment and they would agree, which is the vacuity this whole
    # fixture exists to close one level up.
    assert _constants() == before


def test_module_constants__the_environment_names_an_overrides_file__are_computed_from_it(
    config_reloaded_with, tmp_path
):
    # The one thing the comparison below cannot show. It holds trivially when the variable is
    # unset, because both sides are then False, so hardcoding OVERRIDES_FROM_ENV to False
    # passes it while turning the named-overrides refusal off in production: every test of
    # that refusal monkeypatches the constant and so cannot see it either.
    named = tmp_path / "named.yaml"
    reloaded = config_reloaded_with(STIG_MCP_OVERRIDES=str(named), STIG_MCP_DATA=str(tmp_path / "d"))
    assert reloaded.OVERRIDES_FROM_ENV is True
    assert reloaded.OVERRIDES_PATH == named
    assert reloaded.DATA_DIR == tmp_path / "d"


def test_module_constants__each_one__is_assigned_from_its_own_field_of_resolve_paths():
    # Every constant compared in one tuple, because they are the same five values in the same
    # order and a mismatched pair is the whole failure mode. Both sides read the ambient
    # os.environ, so this holds for an operator who has exported STIG_MCP_DATA; asserting the
    # constants against literal paths does not, which is why the test above computes instead.
    assert _constants() == tuple(resolve_paths(os.environ, config._PACKAGE_DIR))


# The four tests below patch config._on_windows rather than config.os.name. A faked os.name
# makes pathlib build WindowsPaths, which CPython 3.14 refuses to join with `/` on POSIX
# (the guard reads the real os.name at import), so every join in resolve_paths would raise.
# These tests pin only which branch resolve_paths takes, not real Windows path handling. The
# two _on_windows tests further below pin that the predicate itself reads os.name.


def test_resolve_paths__on_windows_outside_a_checkout__uses_localappdata(tmp_path, monkeypatch):
    # ~/.local/share sits in the profile root, which a roaming profile copies at every
    # logon and logoff. About a gigabyte of DISA content would roam with it. Windows
    # excludes AppData\Local from roaming precisely for bulk machine-local data.
    monkeypatch.setattr(config, "_on_windows", lambda: True)
    env = {"LOCALAPPDATA": str(tmp_path / "AppData" / "Local")}
    paths = config.resolve_paths(env, tmp_path / "not-a-checkout" / "stig_mcp")
    assert paths.data_dir == tmp_path / "AppData" / "Local" / "stig-mcp"


def test_resolve_paths__on_windows_with_localappdata_unset__falls_back_to_the_xdg_default(tmp_path, monkeypatch):
    # With LOCALAPPDATA unset the code falls all the way through to the POSIX fallback, since
    # _user_dir's last resort does not itself branch on the predicate. Asserting the whole path
    # rather than just paths.data_dir.name pins that fallback chain: .name alone would pass for
    # any path ending in "stig-mcp", correct or not.
    monkeypatch.setattr(config, "_on_windows", lambda: True)
    paths = config.resolve_paths({}, tmp_path / "not-a-checkout" / "stig_mcp")
    assert paths.data_dir == Path.home() / ".local/share/stig-mcp"


def test_resolve_paths__on_posix_without_xdg_set__ignores_localappdata(tmp_path, monkeypatch):
    # LOCALAPPDATA is present, as it might be by coincidence or leftover state, but _on_windows
    # says this is not Windows, so it must be ignored in favor of the POSIX fallback. Setting
    # XDG_DATA_HOME here instead would short-circuit before the _on_windows gate is reached at
    # all, and would keep passing if that gate were deleted and the Windows branch taken
    # unconditionally.
    monkeypatch.setattr(config, "_on_windows", lambda: False)
    env = {"LOCALAPPDATA": str(tmp_path / "AppData" / "Local")}
    paths = config.resolve_paths(env, tmp_path / "not-a-checkout" / "stig_mcp")
    assert paths.data_dir == Path.home() / ".local/share/stig-mcp"


def test_resolve_paths__on_windows_outside_a_checkout__nests_overrides_inside_the_data_dir(tmp_path, monkeypatch):
    # Intentional, not a coincidence: on POSIX, XDG splits data (~/.local/share) from config
    # (~/.config), so overrides.yaml sits in a different directory than the knowledge base.
    # Windows has one call-site variable, LOCALAPPDATA, for both defaults, so overrides.yaml
    # lands inside the data directory instead. STIG_MCP_DATA and STIG_MCP_OVERRIDES still split
    # them for anyone who wants that.
    monkeypatch.setattr(config, "_on_windows", lambda: True)
    env = {"LOCALAPPDATA": str(tmp_path / "AppData" / "Local")}
    paths = config.resolve_paths(env, tmp_path / "not-a-checkout" / "stig_mcp")
    assert paths.overrides_path == tmp_path / "AppData" / "Local" / "stig-mcp" / "overrides.yaml"
    assert paths.overrides_path.parent == paths.data_dir


def test_on_windows__os_name_is_nt__is_true(monkeypatch):
    # Builds no Path, so patching the real os.name here is safe: nothing in this call path
    # divides a Path, which is the operation that breaks under a faked os.name on this
    # interpreter (see the block comment above). This is what pins that _on_windows actually
    # reads os.name, which the tests above, patching _on_windows itself, cannot show.
    monkeypatch.setattr(config.os, "name", "nt")
    assert config._on_windows() is True


def test_on_windows__os_name_is_posix__is_false(monkeypatch):
    monkeypatch.setattr(config.os, "name", "posix")
    assert config._on_windows() is False
