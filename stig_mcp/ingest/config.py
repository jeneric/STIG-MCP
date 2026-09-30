import os
import re
import tomllib
from collections import namedtuple
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent.parent
_DISTRIBUTION_NAME = "stig-mcp"

Paths = namedtuple("Paths", "data_dir sources_dir kb_path overrides_path overrides_from_env")


def _normalized(name):
    """A distribution name in PEP 503 form, so stig_mcp and STIG-MCP are one name."""
    return re.sub(r"[-_.]+", "-", name).lower() if isinstance(name, str) else None


def _declared_name(pyproject):
    """The distribution `pyproject` declares, or None if it declares none that can be read.

    Every failure is a None rather than an exception, because checkout_root runs at import
    and every entry point imports this module: somebody else's unreadable, undecodable,
    unparseable or merely strange file must not become a failure to start. `project` is bound
    and type-checked rather than defaulted, because a file whose top-level `project` key is
    not a table is valid TOML, and `.get("project", {}).get("name")` raises AttributeError on
    it, which is not an error this can catch by name.
    """
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    project = document.get("project")
    return _normalized(project.get("name")) if isinstance(project, dict) else None


def checkout_root(package_dir):
    """The source checkout this package lives in, or None when it is installed.

    A checkout is the directory holding both the package and the pyproject.toml that declares
    THIS distribution. The name is checked rather than assumed: a vendored copy of the package
    dropped into somebody else's repository would otherwise read that repository's pyproject
    as its own and put an operator's knowledge base and overrides inside it.

    An editable install resolves `__file__` into the checkout and so reads as one, which is
    what an editable install is for.
    """
    root = package_dir.parent
    # A cheap precondition, not the guard: a directory named pyproject.toml is also rejected
    # by _declared_name, whose read raises IsADirectoryError. This keeps the ordinary
    # installed case, where no such file exists at all, off the exception path.
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return None
    return root if _declared_name(pyproject) == _normalized(_DISTRIBUTION_NAME) else None


def _on_windows():
    """Whether this is running on Windows, extracted so the branch below can be tested off
    Windows.

    Faking `os.name` in a test would make `pathlib.Path` hand back a `WindowsPath`, and a
    `WindowsPath` cannot be joined with `/` on a POSIX system: CPython 3.14's pathlib compiles
    `WindowsPath.__new__`'s guard from the real `os.name` at import time, not the current
    value, so every later `/` on that object raises `UnsupportedOperation` regardless of what
    a test patches afterward. Patching this predicate instead keeps every `Path` a real,
    joinable `PosixPath` while still exercising the selection logic.
    """
    return os.name == "nt"


def _user_dir(env, variable, fallback, windows_variable):
    """Where per-user data lives outside a checkout. Reached only when this is NOT a checkout:
    resolve_paths returns the in-checkout defaults before calling this at all.

    The precedence, in the order the code below reads it and on every platform alike, is the
    XDG variable, then the Windows one, then the home-relative fallback. STIG_MCP_DATA and
    STIG_MCP_OVERRIDES outrank all three, and resolve_paths applies STIG_MCP_DATA after this
    returns.

    So XDG_DATA_HOME wins on Windows too when it is set, which is NOT what the roaming
    argument below wants, and is known rather than fixed here: reordering it is a behavior
    change, and a Windows user who set the variable deliberately would find their data move
    without warning. The order is documented as it is, not as it ought to be.

    macOS uses the POSIX layout. The Windows branch is not cosmetic: ~/.local/share sits in
    the profile root, which a roaming profile copies at every logon and logoff, so roughly a
    gigabyte of DISA content would roam with it. AppData\\Local is excluded from roaming
    precisely for machine-local bulk data. platformdirs stays unnecessary, which keeps this
    project at three dependencies.
    """
    named = env.get(variable)
    if named:
        return Path(named)
    if _on_windows():
        windows = env.get(windows_variable)
        if windows:
            return Path(windows)
    return Path.home() / fallback


def resolve_paths(env, package_dir):
    """Where the operator's knowledge base, sources and mapping overrides live.

    Both defaults turn on whether this is a checkout, because the two cases want opposite
    things. In a checkout the data belongs beside the code, which is where every existing
    knowledge base already is and where it must stay. Under an install the package directory
    is inside site-packages: usually not writable, and the wrong home for multi-gigabyte DISA
    downloads even when it is.

    An environment variable set to the empty string is treated as unset, not as the current
    directory that `os.environ.get(name, default)` would make of it.
    """
    checkout = checkout_root(package_dir)
    if checkout is not None:
        data_default = package_dir / "data"
        overrides_default = checkout / "overrides.yaml"
    else:
        data_default = _user_dir(env, "XDG_DATA_HOME", ".local/share", "LOCALAPPDATA") / "stig-mcp"
        overrides_default = _user_dir(env, "XDG_CONFIG_HOME", ".config", "LOCALAPPDATA") / "stig-mcp" / "overrides.yaml"

    named_data = env.get("STIG_MCP_DATA")
    data_dir = Path(named_data) if named_data else data_default
    named_overrides = env.get("STIG_MCP_OVERRIDES")
    return Paths(
        data_dir=data_dir,
        sources_dir=data_dir / "sources",
        kb_path=data_dir / "stig_kb.sqlite",
        overrides_path=Path(named_overrides) if named_overrides else overrides_default,
        # Whether the operator NAMED the file, which is what decides between refusing and
        # staying quiet when it is absent. See orchestrator.main.
        overrides_from_env=bool(named_overrides),
    )


_PATHS = resolve_paths(os.environ, _PACKAGE_DIR)
DATA_DIR = _PATHS.data_dir
SOURCES_DIR = _PATHS.sources_dir
KB_PATH = _PATHS.kb_path
OVERRIDES_PATH = _PATHS.overrides_path
OVERRIDES_FROM_ENV = _PATHS.overrides_from_env
