# Development maintenance tasks.
# `clean` purges test/build artifacts and caches. It uses shell `rm` rather than a
# Python entry point so it needs no project import and triggers no uv settings
# discovery.
.PHONY: clean

clean:
	rm -rf .coverage .coverage.* htmlcov coverage.xml *.lcov \
	       .pytest_cache .ruff_cache build dist *.egg-info
