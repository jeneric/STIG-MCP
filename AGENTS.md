# STIG-MCP

Local MCP server mapping MITRE ATT&CK techniques → NIST 800-53r5 controls →
DISA STIG fix/check steps, severity-ordered. See docs/operations.md for the full
knowledge-base build walkthrough.

# Python Project Development Rules

## System & Tooling (Astral Integration)
- This project strictly uses `uv` for python execution and package management.
- Do not run vanilla `pip`, `python`, or global commands. Always use `uv run <command>`.

## Code Quality & Security Compliance
- Before completing any task or marking it finished, you MUST run:
  `uv run ruff check .`
- Fix any formatting or structural style issues instantly with `uv run ruff check --fix .` or `uv run ruff format .`.
- Under no circumstances should security vulnerabilities (flake8-bandit / Rules prefixed with 'S') be ignored.

## Automated Testing & Coverage Tracking
- Whenever a code defect, logical bug, or Ruff security warning is fixed, you are REQUIRED to author a corresponding security regression test.
- Place regression tests in the `tests/` directory (e.g., `tests/test_security_regressions.py`).
- The test must explicitly mock or feed the previously failing malicious/insecure input and assert that the application securely handles or rejects it.
- You MUST review the terminal coverage output block. If your changes cause total code coverage to drop below the project threshold (configured in pyproject.toml), you must write additional tests targeting the untested lines before completing the task.
- Never commit test artifact databases or coverage directories (`.coverage`, `htmlcov/`, `coverage.xml`) to the git history. Verify they are caught by `.gitignore`.

## Production Builds & Maintenance
- Before compiling, packaging, or preparing the project for production distribution, you MUST purge local development metadata, testing artifacts, and caches.
- Execute the global workspace cleanup command by running:
  `make clean`
- Ensure the repository tree is completely pristine and that no untracked `.coverage` or cache data files leak into production distribution packages.

## Conventions
- **Comments** explain only what the code cannot show, such as the reason behind a non-obvious decision, in the present tense. They never recount how the code got that way.
- **Error messages** say what the caller must change, and come from the call that must change.

## Style Guide
- **Commit Messages:** Write concise, single-line messages using the imperative mood (e.g., "fix bug"). Do not include body text, explanations, or markdown formatting.
