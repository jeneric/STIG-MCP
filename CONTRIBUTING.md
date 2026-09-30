# Contributing

For working on stig-mcp from a source checkout. Report a suspected vulnerability privately,
as [SECURITY.md](SECURITY.md) describes, never in a public issue or pull request.

## Set up

    git clone https://github.com/jeneric/STIG-MCP.git
    cd STIG-MCP
    uv sync
    uv run pre-commit install

## Before a change is done

    uv run pytest
    uv run pre-commit run --all-files

These are the checks CI runs. [AGENTS.md](AGENTS.md) lists the rules and conventions every
change follows, whoever makes it.

`tests/test_docs.py` checks the documentation against the code: links, the tool list, exit
codes and other figures the prose states. When one fails after a code change, update the
document rather than the test.

Publishing a release is maintainer-only; see [RELEASING.md](RELEASING.md).

## Corpus conformance harness

`tools/corpus_conformance.py` runs the shipped ingest pipeline over DISA's full public
archive, rather than the small fixture set the test suite uses. It exists to catch a defect
that only a corpus of that size can surface; it is **not** part of any
supported workflow, is not run in CI, and is not wired to `stig-mcp-fetch`. Running it is a
deliberate, occasional check, not something day-to-day development depends on.

The published directory holds 1,032 file rows, measured on 2026-08-14 against
`tests/fixtures/disa_index.html`, the saved copy of it this repository tests against: 613
benchmark-tier product zips, 10 compilations, 323 adversarial, 70 junk, and 16 rows that are
not zips at all and are tiered out. Junk is the largest tier by volume at 5.78 GiB, and the
nine STIG Viewer desktop application archives that land there are only 1.31 GiB of it: the
SCC scanner bundles are the bulk, so junk would still be the largest tier without them. The
documented command below therefore runs several builds, not one: the default `benchmark` tier
stages those 613 product zips, about 1.1 GiB by the index's advertised sizes and confirmed
against 612 of them staged on disk, and every one of them is reused across every build;
`--tier compilation` separately stages all ten compilations, about 2.8 GiB, being nine
historical SRG-STIG Library releases plus the Rev 4 sunset archive. The harness runs one
build per library, nine builds today, each paired with the sunset archive (see below), so a
full run means nine complete passes of the ingest pipeline over the product corpus.

Four commands, run in order. The manifest step comes first because it downloads nothing;
it only tiers the published listing:

    uv run python -m tools.corpus_manifest --out /tmp/corpus/manifest.json
    uv run python -m tools.corpus_fetch --manifest /tmp/corpus/manifest.json --dest /tmp/corpus/files
    uv run python -m tools.corpus_fetch --manifest /tmp/corpus/manifest.json \
        --dest /tmp/corpus/compilations --tier compilation
    uv run python -m tools.corpus_conformance --corpus /tmp/corpus/files \
        --compilations /tmp/corpus/compilations \
        --inputs stig_mcp/data/sources --report /tmp/corpus/report.md

`corpus_fetch --tier` defaults to `benchmark`; the compilation, adversarial, and junk tiers
are opt-in, staged with a separate invocation as shown in the second `corpus_fetch` call
above.

Add `--skip-determinism` to the last command to skip the second, order-reversed build each
compilation runs to check that composition does not depend on artifact order. It halves the
run time; use it for a quick pass and drop it before trusting a result that matters.

**Why compilations are staged to their own directory, and paired one at a time.** The
published archive carries nine historical SRG-STIG Library compilations, and
`inventory.classify` refuses more than one library at a time on purpose, because month names
do not sort chronologically. The harness therefore runs one build per library. The sunset
archive is not itself a library, so `classify` accepts it alongside one, and the harness
pairs it into every library's build rather than giving it a build of its own: a library plus
the sunset archive is exactly the shape a real knowledge base is built from, and it is the
only way the library-vs-sunset arbitration `_select` exists for gets exercised at corpus
scale. `--compilations` points at a directory staged separately from `--corpus` for the same
reason: staging a compilation into the same directory as the product zips makes the run fail
immediately, since `classify` would then see two libraries in one build; that is correct
behavior, not a bug to work around.

`--compilations` is optional. Omit it and the harness runs a single build over the product
zips alone.

The tool never writes to `stig_mcp/data/`. `--inputs` is read only for `U_CCI_List.xml` and
the three JSON sources the ingest needs; `stig_mcp/data/sources` is a convenient place to
point it at, but nothing under it is ever modified.

`CUI_` content is not publicly available and is refused by the tool at two separate
points: `corpus_manifest` tiers it out with the credential reason before anything is
fetched, and `corpus_fetch` refuses it again if a manifest entry is smuggled in
regardless. `stig-mcp-ingest` and `stig-mcp-extract` refuse it too, by name: any source file
or archive member with a path component starting `CUI_` stops the run and is named in the
message. Only names in an archive the run actually opens are checked. The members of a zip
nested inside a product zip, or nested inside one of a compilation's inner zips, and the
members of a product zip or inner zip that cannot be read, are never opened, so they are never
checked, and nothing from them is ingested either.

The public `U_` content this harness stages may be used and distributed in the same manner as
individually downloaded documents, per the Library Compilation readme, so the manual staging
above is a choice about scale and stability rather than a restriction: verifying against over a
thousand archives, several gigabytes and nine full builds, is expensive enough in time and disk
that it should stay a deliberate, occasional check rather than something that runs on every
change.
