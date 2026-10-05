# Knowledge base operations

For whoever installs, builds and maintains the STIG-MCP knowledge base.

This document is written for a source checkout: it spells paths as a checkout has them and
prefixes every command with `uv run`. An installed copy keeps its data elsewhere, because
`site-packages` is the wrong home for gigabyte-scale downloads. It runs the entry points
without the `uv run` prefix, or, when run through `uvx`, as `uvx --from stig-mcp <command>`.
See [Where the data lives](install.md#where-the-data-lives) in install.md for the locations
and the two environment variables that override them.

Three sections below are checkout-only and say so again where they appear: building a
release by hand, which runs the `tools/` package that is deliberately not shipped in the
wheel, and editing `applicability.yaml` or `id_corrections.yaml`, both of which an installed
copy keeps inside `site-packages`. The corpus conformance harness, a developer tool, is in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Contents

- [Install a prebuilt knowledge base](#install-a-prebuilt-knowledge-base)
  - [Installing on a host that cannot reach GitHub](#installing-on-a-host-that-cannot-reach-github)
- [Build the knowledge base](#build-the-knowledge-base)
  - [1. Fetch the sources](#1-fetch-the-sources)
  - [2. Ingest](#2-ingest)
- [ATT&CK mitigations and detections](#attck-mitigations-and-detections)
- [Placing the sources by hand](#placing-the-sources-by-hand)
  - [The SRG-STIG Library Compilation](#the-srg-stig-library-compilation)
- [Keeping current](#keeping-current)
  - [`--check`: what has moved, downloading nothing](#--check-what-has-moved-downloading-nothing)
  - [`--refresh`: take what changed, prune what it supersedes](#--refresh-take-what-changed-prune-what-it-supersedes)
- [How knowledge-base releases are built](#how-knowledge-base-releases-are-built)
  - [Building a release by hand (checkout only)](#building-a-release-by-hand-checkout-only)
- [The lifecycle of sources/](#the-lifecycle-of-sources)
- [Quarterly refresh](#quarterly-refresh)
- [Why a benchmark disappeared](#why-a-benchmark-disappeared)
- [Mapping overrides](#mapping-overrides)
- [Product build applicability](#product-build-applicability)
  - [What the ingest reports](#what-the-ingest-reports)
  - [Warnings and what to do about them](#warnings-and-what-to-do-about-them)
- [Resolver distinctiveness margin](#resolver-distinctiveness-margin)
  - [What the ingest reports](#what-the-ingest-reports-1)
  - [The warning and what to do about it](#the-warning-and-what-to-do-about-it)
- [Same-key benchmark corrections](#same-key-benchmark-corrections)
- [Why a rule id can be held by another benchmark](#why-a-rule-id-can-be-held-by-another-benchmark)
  - [What a current library actually produces](#what-a-current-library-actually-produces)
  - [Building from an archival library](#building-from-an-archival-library)
  - [What a scoped query returns, and how to find the holder](#what-a-scoped-query-returns-and-how-to-find-the-holder)
- [Where the server's log is](#where-the-servers-log-is)

## Install a prebuilt knowledge base

Building the knowledge base yourself costs about a gigabyte of downloads and an ingest;
installing a published one costs neither. Each `kb-YYYY-MM-DD` release on this project's
GitHub releases carries the knowledge base as one xz-compressed file, a `SHA256SUMS` file and
a `release.json` describing what it was built from, and is made the way "How knowledge-base
releases are built" below describes.

    uv run stig-mcp-install-kb

installs the newest published release for the schema this stig-mcp reads. To install one
exact release instead, to pin a version or to roll back to an earlier one, name its tag
(this one is an example; the releases page and `check_sources` name the real ones):

    uv run stig-mcp-install-kb --release kb-2026-10-05

The install verifies the download against the release's `SHA256SUMS`, decompresses it,
checks that the result is an intact knowledge base for this stig-mcp's schema, and only then
replaces the installed file. It exits 0 and prints what it installed and what it replaced. A
refusal at any step exits 1 with the reason on stderr, and nothing is replaced. The one exit
1 after a replacement says so: "The knowledge base was installed, but its release record ...
could not be written". The new knowledge base is then in place, and `check_sources` treats
it as a local build until the record exists. A usage error exits 2. The knowledge base lands
where [Where the data lives](install.md#where-the-data-lives) says, as
`stig_kb.sqlite` in the data directory, with `stig_kb.release.json` beside it recording
which release it is. That record is trusted only while the SHA-256 it holds still matches
the installed file, so a knowledge base rebuilt or replaced afterwards reads as a local
build rather than as the release. On Windows a running server holds the file open: install
through that server's `install_knowledge_base` tool, or stop the server first.

Until the project publishes its first knowledge-base release, the install says that no
release is published for this schema yet and names `stig-mcp-fetch` and `stig-mcp-ingest`,
the build described under "Build the knowledge base" below. When a published release needs
a newer schema than this stig-mcp reads, the install names the stig-mcp to upgrade to: as its
refusal when nothing is published for this schema, and beside its result when something is.

### Installing on a host that cannot reach GitHub

The same install takes a file you carry across. Neither the command nor the agent's tool
touches the network on this path. The file names below are an example; use the ones from the
release you download.

1. On a connected host, open the release on <https://github.com/jeneric/STIG-MCP/releases>
   and download two of its assets: the knowledge base, named like
   `stig_kb-schema7-2026-10-05.sqlite.xz`, and `SHA256SUMS`.
2. In the directory holding both, verify the download. On Linux:

       sha256sum -c SHA256SUMS --ignore-missing

   On macOS:

       shasum -a 256 -c SHA256SUMS --ignore-missing

   Either prints `OK` beside the file name. `--ignore-missing` is needed because
   `SHA256SUMS` also lists the decompressed `.sqlite`, which is not a release asset. Windows
   PowerShell has no checker; print the value and compare it by eye with the `.xz` line of
   `SHA256SUMS`:

       (Get-FileHash .\stig_kb-schema7-2026-10-05.sqlite.xz -Algorithm SHA256).Hash.ToLower()

3. Carry both files to the host that cannot reach GitHub.
4. Install, passing as `--sha256` the 64-character value at the start of the `SHA256SUMS`
   line for the exact file you pass, the value alone rather than the whole line:

       uv run stig-mcp-install-kb --file stig_kb-schema7-2026-10-05.sqlite.xz --sha256 HEX

The install checks the SHA-256 itself, so step 2 catches a bad download before you carry it
across rather than being a check the install depends on. The decompressed `.sqlite` is
accepted too, for example after `xz -dk stig_kb-schema7-2026-10-05.sqlite.xz`; pass it with
its own line's value, since `SHA256SUMS` lists both files and the value for one refuses the
other. The agent can do the same through `install_knowledge_base(path=..., sha256=...)`, with
a path on the machine the server runs on. A file install records the file name rather than a
release, so `check_sources` recognizes it as the newest release only by its SHA-256, and
otherwise compares it by its source versions, as it does a local build.

## Build the knowledge base

All source artifacts go in `stig_mcp/data/sources/` (git-ignored). Four are needed:
MITRE ATT&CK® STIX, the CTID ATT&CK→800-53 mapping, the DISA CCI list, and one or more
DISA STIG XCCDF benchmarks.

### 1. Fetch the sources

    uv run stig-mcp-fetch

**This transfers roughly a gigabyte.**

It takes two groups. The first is three public JSON sources: `enterprise-attack.json`,
`ctid_mappings.json`, and the NIST SP 800-53r5 OSCAL control catalog
(`nist_800_53_rev5_catalog.json`). ATT&CK is taken at its newest release listed in MITRE's
`index.json`, and CTID at its highest `attack-X.Y` mapping folder. `attack_index.json`, the
downloaded index itself, is saved beside the sources too. The CTID mapping file names its
own ATT&CK version either way. `attack_index.json` supplies only the release *date* of that
version: when the file is present the ingest records the date as `ctid_attack_release`, and
when it is absent the ingest records no date. The catalog supplies control names, families, and the
links between a base control and its enhancements; without it, control rows are id-only.

The second comes from one read of DISA's published index at
<https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/>, from which it selects the current
SRG-STIG Library Compilation, the Rev 4 sunset compilation, the CCI list, and the newest
loose STIG zip of each product. Measured against the live index on 2026-08-14, that is 272
files and about 0.95 GiB; both figures drift as DISA publishes, so treat them as a scale
rather than a number to check against.
Requests are spaced by `--delay` seconds, 0.25 by default, because every one of them goes to
a single government host.

Before the first byte it checks free space, and refuses if there is less than 2 GiB or less
than twice what this run would transfer, whichever is larger. The floor covers the ingest's
temporary extraction and the knowledge base as well as the downloads themselves. Point
`STIG_MCP_DATA` at a larger volume if the sources directory sits on a small one.

Each run records what it took in `.stig-mcp-manifest.json` beside the files, and a later run
skips anything already on disk at its recorded length. An interrupted fetch therefore
resumes rather than starting over: run the same command again. The manifest is written even
when a download fails, which is what makes that work.

A single dropped connection need not end the run at all. The DISA half of the fetch
tries each download and the index read up to 4 times, waiting 5, 15 and 45 seconds between
tries, when the failure is one a retry can heal: a reset, refused or dropped connection,
a timeout, a DNS or other network error, or HTTP 429, 500, 502, 503 or 504. A certificate
error, any other HTTP error and the refusal of a `CUI_` URL fail at once. Each retry prints
one line to stderr naming the file, or the index, and the attempt it is about to make. This
holds for a plain fetch and for `--refresh` alike. The three public sources are not retried,
and neither is `--check`, which reports a source it cannot reach instead.

DISA publishes the CCI list only as `U_CCI_List.zip` and the ingest reads `U_CCI_List.xml`,
so the fetch extracts that one member into the sources directory and prints its path with
the rest. It extracts from whatever archive is on disk rather than only from one it has just
downloaded, so a run that skips the download because the manifest still matches restores a
deleted XML too. Leave the zip where it is: the ingest opens it, finds no XCCDF benchmark,
and logs one line about it. That costs about 0.04 seconds: the ingest decompresses and parses
the 3.2 MB list to find nothing. Deleting the zip costs the whole download again on the next
fetch, because the manifest would no longer describe what is on disk.

When the DISA half fails, the command prints the artifacts to fetch by hand and then
re-raises, so a half-finished fetch is never mistaken for a finished one. **Ctrl-C is the
exception.** An interrupt is not one of the errors that reminder is attached to, so
canceling a fetch prints no guidance at all. What it prints is the DISA half alone: the
library compilation, the CCI list, and loose product zips. "Placing the sources by hand"
below is a longer list, because it also covers the three JSON sources this command takes
from GitHub before it ever reaches DISA.

### 2. Ingest

    uv run stig-mcp-ingest

Builds `stig_mcp/data/stig_kb.sqlite` atomically. XCCDF discovery is
case-insensitive; a malformed benchmark is logged and skipped rather than aborting
the build. When a benchmark ships in multiple versions, only the newest is kept.
The summary reports both `stig_files` (documents that classified as a STIG and parsed) and
`stigs` (unique benchmarks that survived selection).

The summary also counts `mitigations`, `detection_strategies`, `analytics` and
`analytic_log_sources` from the ATT&CK bundle (44, 697, 1,745 and 4,130 for ATT&CK 19.2).
The ingest refuses a bundle that yields zero live mitigations, or zero detection strategies
joined to a technique by a `detects` relationship, and names the count: that is what a
change to ATT&CK's data model looks like, and an unattended build must stop rather than
publish empty tables. A spec version whose major is not 3 only warns.

The ingest stores two log source names corrected: ATT&CK 19.2 spells `linux:syslog` as
`linus:syslog` on AN0272 and as `linuxsyslog` on AN0364, so a caller collecting syslog would
otherwise see those analytics as undetectable. Each correction names its analytic and the exact
misspelling, so once ATT&CK fixes a name the correction no longer matches and does nothing.
`defense_details` shows the corrected name for those two analytics.

The knowledge base carries a schema version. The server starts against a knowledge base
built by an older release, but never answers from it: it reports the outdated schema and
tells you to re-run the ingest. Rebuilding is always the recovery: the knowledge base is
derived entirely from the sources above. The current schema is `7`. Schema 7 adds ATT&CK's mitigations and detection strategies
(see "ATT&CK mitigations and detections" below); schema 6 began recording every
input file with its SHA-256 in `source_files`, and carries this project's license files in
`notices`, so the notices travel with any copy of the knowledge base.

## ATT&CK mitigations and detections

Schema 7 holds ATT&CK's defensive objects in six tables, all read from the same
`enterprise-attack.json` as the techniques:

- **`mitigations`**: course-of-action objects by M-id, with name and description.
- **`technique_mitigation`**: which mitigation applies to which technique, with MITRE's text
  about that pairing.
- **`detection_strategies`**: one row per DET-id, joined to its technique by a `detects`
  relationship.
- **`analytics`**: each AN-id with its strategy, platforms and mutable elements.
- **`analytic_log_sources`**: each log source an analytic names, with its channel and data
  component. Names and channels are stored with surrounding whitespace stripped, because
  callers' `log_sources` are stripped before matching; ATT&CK 19.2 ships
  `firmware:integrity ` and `networkconfig ` with a trailing space.
- **`data_components`**: DC-ids with name and description.

`ingest_meta` carries a row named `attack_spec_version` recording the bundle's
`x_mitre_attack_spec_version`, which is what to read first when a new ATT&CK release
changes the shape of these objects. How the server answers from these tables is in the
user guide's "Protect and Detect" section ([docs/user-guide.md](user-guide.md)).

## Placing the sources by hand

This is the mechanism, not a degraded fallback. The ingest reads a directory of files and
has no idea how they got there; `stig-mcp-fetch` is a convenience layered on top of it and
is never consulted by `stig-mcp-ingest`. Use this path on an air-gapped host, on a host
whose egress to `dl.dod.cyber.mil` is blocked, or any time you would rather choose the
artifacts yourself. The "Ingest" step above then applies unchanged, because it is the same
step either way.

Put these in `stig_mcp/data/sources/`, then run `uv run stig-mcp-ingest`:

- The three JSON sources, if the host can reach GitHub at all: `enterprise-attack.json`,
  `ctid_mappings.json`, and `nist_800_53_rev5_catalog.json`. Only the catalog has a fixed
  URL, in `SOURCE_URLS` in `stig_mcp/ingest/fetch.py`; ATT&CK and CTID are each taken at
  their newest release instead, from MITRE's `index.json` and CTID's highest `attack-X.Y`
  mapping folder (`stig_mcp/ingest/upstream.py`). `attack_index.json` is optional here: a
  hand-placed source needs none, and the ingest never requires it. Without it,
  `ctid_attack_release` goes unrecorded, so a technique the CTID mapping simply does not
  cover gets the generic explanation ("_technique_id_ is not in the CTID mapping file
  (ATT&CK _version_); provide attack_index.json to tell a newer technique from an
  uncovered one.") instead of the more specific one naming whether it is newer than the
  mapping or an actual gap. A technique whose mapped controls `overrides.yaml` suppresses,
  or that CTID reviewed as non-mappable, still gets its own message either way. When that
  message reads "ATT&CK unknown", the mapping file itself names no ATT&CK version, so no
  `attack_index.json` can help: there is no version to look a release date up for. A CTID
  JSON file without `metadata.attack_version` does this, and so does a CSV mapping, which
  carries no version at all (`stig-mcp-ingest` reads `ctid_mappings.json` as JSON; the CSV
  form is read only when the ingest is driven from Python with a `.csv` path).
- **DISA CCI list.** Download `U_CCI_List.zip` and extract `U_CCI_List.xml` from it. The XML
  is what the ingest reads, and the zip is what DISA publishes, so on this path you unpack it
  yourself:

      cd stig_mcp/data/sources
      unzip -o U_CCI_List.zip U_CCI_List.xml

  Placing the XML alone is enough on this path. If you keep the zip beside it, the ingest
  opens it, finds no XCCDF benchmark, and logs one line about it.
- **DISA STIG benchmarks.** Either the quarterly SRG-STIG Library Compilation, or
  individual product zips, or loose `*xccdf.xml` benchmark files, or any mixture. The
  section below explains how each is recognized.

When its DISA download fails, `stig-mcp-fetch` prints the last two of those three itself,
the ones it would have fetched from DISA. The server says the same thing from the other
end: call a tool before the knowledge base exists and the reply names the source classes it
cannot see, the directory it looked in, and the line "Nothing in the ingest requires the
fetch to have run."

### The SRG-STIG Library Compilation

Find the current compilation link on the DoD Cyber Exchange STIGs Document Library
(<https://www.cyber.mil/stigs/downloads>), listed as **"Compilation - SRG-STIG
Library"**. The filename embeds the release month, e.g.
`U_SRG-STIG_Library_July_2026.zip` at
`https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/<that-filename>`.

Download it into `sources/`. From there you have two options:

- **Just ingest it**: leave the zip in `sources/` and run `stig-mcp-ingest`. It
  auto-detects the compilation, extracts the STIG XCCDFs, and ingests them
  (SRGs, drafts, and checklists are skipped). This is the supported path; prefer it unless you
  have a specific reason to extract first.
- **Extract explicitly**: run the helper to unpack the STIG XCCDFs into `sources/`
  first, useful only to inspect what will be ingested before you actually ingest:

      uv run stig-mcp-extract stig_mcp/data/sources/U_SRG-STIG_Library_July_2026.zip

  Files keep DISA's own names. Where two inner zips ship one basename, an identical
  repeat is written once and counted as a duplicate, and only a repeat whose bytes
  differ is renamed, taking a `2_` prefix (then `3_`, and so on) so it still ends in
  `xccdf.xml` and is recognized on the filename rule rather than having to be opened.
  Measured over ten staged compilations, three collide and all four
  collisions are identical repeats: 2020_01 twice, 2020_01v3 and 2020_01v4 once each,
  DISA having bundled one benchmark under two inner zip names. A prefixed file therefore
  means something new, and is worth looking at.

  Extracted files are recorded as `loose`, not `library`: ingest can no longer tell
  they came from the compilation. Leave both the zip and the extracted copies in
  `sources/` and every benchmark is parsed twice, with the extracted copy losing to
  the zip's copy every time (see `superseded_by_library` below). Delete the zip
  instead of the extracted copies and every benchmark loses its library provenance
  outright. Inspect, then delete the extracted files and ingest the zip directly.

## Keeping current

`stig-mcp-fetch` carries two mutually exclusive flags for maintaining a sources directory
it has already populated; neither builds a knowledge base. `--check` reads all four
sources, ATT&CK, the CTID mapping, the NIST 800-53 catalog and DISA's index. `--refresh`
reads the same three public sources before it ever reaches DISA; unlike `--check`, its own
read of the DISA index is not isolated the same way, so a failure there raises instead of
printing `unknown`.

### `--check`: what has moved, downloading nothing

    uv run stig-mcp-fetch --check

Prints one line per difference between the index and the manifest the last fetch wrote,
labeled `new`, `resized` or `withdrawn`, then a closing line. **The exit code is the part
worth scripting against**, which is why it is here and not only in `--help`:

| exit | meaning |
|---|---|
| 0 | every source was checked and nothing is to download. Either all are current, or DISA has only withdrawn names, which changes nothing a fetch would transfer. |
| 3 | nothing is to download from the sources it could check, but at least one printed `unknown` with the reason it could not be reached. The closing line carries "Could not check:" followed by each such source. Re-run once the network or upstream recovers. |
| 10 | something new or resized is available, on DISA's index or on ATT&CK, the CTID mapping or the catalog. The closing line names the next command, and any source it could not check: a source it could not reach never masks a 10, so a script still refreshes what is available. |

A usage error exits 2, as for any command-line tool; 3 is kept distinct from it.

A withdrawal on its own exits 0 deliberately: nothing came in for a fetch to take. The
output still lists the withdrawn names, and qualifies one with "(superseded by ...)" when
the withdrawal is an ordinary version bump rather than DISA dropping a product.

After the DISA lines, `--check` prints one more line each for ATT&CK, the CTID mapping and
the catalog: current, or, for ATT&CK and CTID, the newer release available upstream (the
catalog has no release number of its own to show, so it prints `changed upstream` instead).
A catalog on disk whose version no fetch has recorded, as after upgrading from a release
that kept no such record or after placing the file by hand, prints `matches upstream, but no
version is recorded` and counts as something to take. The bytes already match, so one
`--refresh` downloads the file again only to record its version; that second download is
the known cost. (The `check_sources` tool answers a different question,
whether a newer knowledge-base release is published; see the [user guide](user-guide.md),
"Checking for a newer knowledge base".) A source it cannot reach, DISA's index included,
prints `unknown` with the whole reason instead, however long, since the remedy is often at
its end. That source sets the exit code to 3 unless something else is to take; only a `new`
or `resized` DISA entry, or a public source reporting a change, gives 10. The closing line
never calls such a source current: it names every one it could not check.

Run before there has ever been a fetch, `--check` finds no manifest, reports every selected
artifact as `new`, and exits 10.

### `--refresh`: take what changed, prune what it supersedes

    uv run stig-mcp-fetch --refresh

Takes each public source `--check` reports as available, ATT&CK, the CTID mapping or the
catalog, then downloads what changed on the DISA index and deletes the local files those
arrivals supersede, printing how many it fetched, deleted and retained, and with
`--drop-withdrawn` how many it dropped.

Properties worth knowing before you schedule it:

- **A refresh does not ingest.** It leaves the sources directory correct and the knowledge
  base untouched. When anything changed it says so and names `stig-mcp-ingest`; when
  nothing did it says "Sources were already current; nothing to rebuild.", so an unchanged
  quarter costs you no rebuild.
- **The public sources are taken first, DISA second.** A source whose `--check` failed
  (reported `unknown`) is named and left as it was, not retried. A source that starts
  downloading and fails stops the whole refresh before DISA is fetched or anything is
  pruned, so a broken connection to GitHub costs you nothing already on disk, DISA's files
  included. It prints one line naming the source that failed before the error itself, for
  example "ATT&CK download failed: any previous enterprise-attack.json was kept and nothing
  was pruned." Fix whatever blocked it and run `--refresh` again.
- **The plain, flagless `uv run stig-mcp-fetch` never prunes.** If you run it directly,
  rather than `--refresh`, after DISA has published something new, it downloads the newer
  files (skipping whatever is already on disk at its recorded length) but leaves the old
  ones in place; a new library compilation then lands beside the old one, and the next
  `stig-mcp-ingest` refuses to build, naming both files and telling you to delete the one
  you are not building from. Nothing is lost, but the fix is manual. Prefer `--refresh` for
  a sources directory that already has a fetch in it; the plain command is for populating
  one for the first time.

What it deletes is deliberately narrow. Without `--drop-withdrawn`, a file is removed only
when a replacement for it actually arrived and is verified on disk, never merely because the
index stopped carrying its name. **A product DISA has withdrawn keeps its local copy**,
because that copy is coverage that cannot be fetched again, and the server already labels an
answer that came from an artifact the current library no longer ships. Those retentions are
counted in the closing summary.

`--drop-withdrawn` changes exactly that, and applies only with `--refresh`: given alone it is
a usage error and exits 2. It also deletes every DISA file the manifest recorded that the
index no longer carries and no arrival superseded, and names each one it dropped. The CCI list
is the one exception, kept because the ingest cannot run without it, and a file the manifest
never recorded, such as a zip you placed by hand, is never touched. The flag exists for
building a release only from what DISA publishes now, which is how the release pipeline below
uses it. For an operator the default is the right one: keep withdrawn products.

A suggested cadence is `--check` quarterly, since that is how often the library
compilation moves, and `--refresh` followed by `stig-mcp-ingest` when it exits 10.

## How knowledge-base releases are built

`.github/workflows/kb-release.yml` makes the releases "Install a prebuilt knowledge base"
installs. It runs every Monday at 06:17 UTC and whenever it is started by hand, and it
never publishes anything: what it makes is a draft. GitHub disables a public repository's
scheduled workflows after 60 days with no repository activity; re-enable it from the Actions
tab if that happens.

It restores the sources directory an earlier run cached and runs `stig-mcp-fetch --check`
against it. `tools/kb_release.py` then decides from that exit code and the repository's
release listing. It builds when the check reported something new (exit 10), when no release
is published for the current schema, when the newest published release was built with a
different stig-mcp version than the code the run checked out, or when the run was started by
hand. A check that exits 3, a source it could not reach, fails the run instead, because the
run cannot then tell whether upstream changed; so does any exit other than 0, 3 and 10. With
none of those reasons the run stops there, having built nothing.

A build then does, in order:

1. `stig-mcp-fetch --refresh --drop-withdrawn`, so the sources hold only what is published
   now.
2. `stig-mcp-fetch --check` again, which must exit 0. The refresh reports a public source it
   could not reach as not refreshed and carries on, so without this step a release could
   ship an old file beside current DISA ones; an exit of 10 or 3 here fails the run rather
   than building from those sources.
3. `stig-mcp-ingest`.
4. The test suite, run as CI runs it rather than against the knowledge base just built.
5. Verification, in `tools/kb_verify.py`. The knowledge base must pass the server's readiness
   check. Three checks, driving four server tools, must each get a real answer: T1078 on
   Windows 11 resolves to `Microsoft_Windows_11_STIG` with STIG findings, the first of which
   `finding_details` returns fix text for; APT29 has techniques; and "RHEL 9" resolves with
   `RHEL_9_STIG` as its top candidate. The sources
   must hold a fetch manifest and no file the fetch did not record. And the freshness
   tripwire must pass: no benchmark on DISA's index may be at a newer release than the
   knowledge base holds for the same product and major. A benchmark on the index under
   another major, or under a name no stored benchmark came from (usually the old name of a
   renamed product), is listed in the run's Actions job summary and does not fail the build.
6. Packaging, in `tools/kb_package.py`: the knowledge base compressed as
   `stig_kb-schema<N>-<date>.sqlite.xz`, a `SHA256SUMS` listing it and the decompressed
   `.sqlite`, a `release.json` (schema, `built_with`, both SHA-256 values, the upstream source
   versions, every benchmark held, and the SHA-256 of every source file the fetch recorded),
   and the project's license files from the knowledge base's `notices` table.

When that `release.json` matches the newest published release's in `built_with`, upstream
versions, benchmarks and source digests, the build is unchanged and the run drafts nothing,
unless it was started by hand from the Actions tab (`workflow_dispatch`), which always
drafts. Otherwise it deletes every `kb-*` draft still waiting, refusing if one has been
published meanwhile, then drafts a release tagged `kb-` and the UTC date, with those assets
and notes listing the benchmarks added, changed and dropped since the newest published
release, one per line, then the upstream versions and both SHA-256 values. It records the
draft on the `kb-latest` branch in `kb/LATEST`: the tag, the schema and the decompressed
knowledge base's SHA-256.

**Approving a release is publishing its draft** on the repository's releases page. Until
then no install and no `check_sources` sees it: a draft is absent from the listing an
unauthenticated request receives, and the installer skips drafts in any case. Published
releases are never deleted or replaced. A newer build replaces a draft still waiting, and a
run that would build on a day whose release is already published fails and names the tag,
since the tag is the date; run it again after 00:00 UTC.

A run that fails, or is canceled, which is how a timeout ends, opens an issue labeled
`kb-release` linking to the run, or comments on the one already open.

### Building a release by hand (checkout only)

This is for a host that can reach DISA when GitHub's runners cannot. It needs a source
checkout: `tools/` is excluded from the wheel on purpose, so an installed copy has no such
module to run. The build verifies the knowledge
base in the data directory against its sources, so refresh and ingest there first. Point
`STIG_MCP_DATA` at a directory kept for releases, as the workflow points it at scratch:
`--drop-withdrawn` would otherwise thin your own sources, and verification refuses any file
the fetch did not record, which includes every zip you placed by hand. Then fetch the release
listing with an authenticated `gh`, so that waiting drafts appear in it, and the newest
published release's `release.json`, which `decide` and the build compare against. The
commands are bash, run from the checkout; the listing and the release directory go under
`$WORK`, outside the checkout, because neither is git-ignored:

```bash
export STIG_MCP_DATA="$HOME/stig-mcp-release"
WORK="$HOME/stig-mcp-release-work"
mkdir -p "$WORK"
uv run stig-mcp-fetch --refresh --drop-withdrawn
uv run stig-mcp-fetch --check
uv run stig-mcp-ingest
gh api "repos/jeneric/STIG-MCP/releases?per_page=100" > "$WORK/releases.json"
PREVIOUS=$(uv run python -m tools.kb_release newest --listing "$WORK/releases.json")
previous=()
if [ -n "$PREVIOUS" ]; then
    gh release download "$PREVIOUS" --repo jeneric/STIG-MCP --pattern release.json --dir "$WORK/previous"
    previous=(--previous "$WORK/previous/release.json")
fi
uv run python -m tools.kb_release decide --listing "$WORK/releases.json" --check-exit 0 \
    --event workflow_dispatch "${previous[@]}"
if [ -n "$PREVIOUS" ]; then
    previous+=(--previous-tag "$PREVIOUS")
fi
uv run python -m tools.kb_release build --tag TAG --out "$WORK/release" "${previous[@]}"
```

Go on only if the `--check` exits 0, which is why `decide` is passed 0. `decide` prints the
`tag` to pass as `TAG` and the `delete_drafts` to remove, or refuses and says why. `newest`
prints the newest published release for this schema, and nothing when there is none: then
the block skips the download and runs `decide` and `build` without `--previous` and
`--previous-tag`, and the notes say "First release for schema N". The release directory
then holds the assets, `notes.md`, `assets.txt` (the assets to upload) and `LATEST`; draft
the release from them as the workflow's "Draft release" step does. Without `--previous` the
build always counts as changed; with it, a build matching that release writes an empty
`assets.txt`, and there is nothing to draft.

## The lifecycle of sources/

Everything ingest reads comes from `stig_mcp/data/sources/`. Archives are classified by
filename alone; a loose `.xml` may be opened to see what it is:

| artifact | recognized by | what ingest does | what you must do |
|---|---|---|---|
| SRG-STIG Library Compilation | `*stig_library*.zip`, matched against the lowercased filename | builds from it | delete the previous one before adding a new one, or the build refuses to run |
| sunset compilation | `*sunset_compilation*.zip`, matched against the lowercased filename | walks it the same way as the library and extracts what it holds, marked `sunset` | nothing; several may coexist |
| product zip | any other file ending `.zip` | opens it one level, never recursing into a nested zip, and extracts every XCCDF benchmark member it finds inside | nothing; remove it to drop the benchmark |
| loose XCCDF | any file ending `xccdf.xml`, matched against the lowercased filename, plus any other `.xml` whose root element is a `Benchmark` | takes it as-is, recorded as `loose` | nothing |

The matching is case-insensitive in effect: ingest lowercases the filename before
comparing it to these patterns, so `U_SRG-STIG_Library_July_2026.zip` and a
hypothetical `..._Stig_Library_....zip` classify identically. The glob patterns
themselves are written lowercase because that is what they are compared against, not
because case matters to you.

A file that is neither a `.zip`, nor a name ending `xccdf.xml`, nor an `.xml` holding a
`Benchmark` root element is not classified at all. A PDF or a README is never opened and
produces no log line; ingest never sees it. An `.xml` is opened, so one that fails to parse
leaves a debug line naming it, and one that cannot be read at all leaves a warning.

There are two loose rules, and keeping both is what makes this safe. A file DISA named
`..._Manual-xccdf.xml` is taken on its name alone, so a corrupt one still reaches the parser
and its failure is reported against it rather than being skipped here. A name the glob cannot
reach is opened and judged by its root element instead, which is how a benchmark named like
`EDB_Postgres_Advanced_Server_STIG.xml` is ingested. The name rule is tried first
only to avoid opening a file needlessly; either order classifies the same files the same way.
Inside a product zip or a compilation, every archive is opened. A filename cannot answer what a
document is: `U_zOS_RACF_Y26M07_Products.zip` in the current library holds 31 real STIG
benchmarks and says nothing about it in its name. What each document is gets decided after it is
parsed, from its own benchmark id, title and status. A zip that holds no XCCDF benchmark at all
is logged with a count of what it held instead, one line, grouped by file extension.

Two library compilations in `sources/` is a hard failure rather than a guess: month names do
not sort chronologically, so a silent choice would serve stale guidance for a quarter.
Delete the one you are not building from and re-run `stig-mcp-ingest`; the error names every
compilation it found. A benchmark the current library ships wins over any copy from a sunset
archive or a hand-placed product zip, unless that copy carries a strictly newer major
version of the same benchmark id. Then the newer major is kept and the library's older major
stays as well, so answers about that product come from both; the user guide's
[Why am I seeing steps from two versions of the same STIG?](user-guide.md#why-am-i-seeing-steps-from-two-versions-of-the-same-stig)
describes what that looks like. A newer release within the same major, under the same spelling
of the id, also beats the library's copy of that major, and this holds where the library ships
a newer major of the id as well: yours replaces the library's copy of the older major and both
majors stay. Two ids differing only in case count as the same id here, because DISA has spelled
one product's id both ways across artifacts; the drop message names the benchmark that won,
which is worth reading when the two spellings differ. Sunset content is opt-in by presence:
drop the archive in and it is used, move it out and it is not.

## Quarterly refresh

Steps 1 and 2 are what `stig-mcp-fetch --refresh` does for you; do them by hand on a host
that cannot reach DISA, or when you want to choose the compilation yourself.

1. Download the new SRG-STIG Library Compilation into `sources/`.
2. Delete the old compilation zip. Leaving both in place aborts the build (see the table
   above).
3. Re-run `uv run stig-mcp-ingest`.
4. Read the summary line it prints and check `superseded_by_library`, `superseded_same_key` and
   `superseded_by_newer_major`. The first counts benchmarks from a sunset archive, a product zip or
   a loose file that the current library beat. Within one major the contest goes by release first,
   so the library wins there only at the same release or a newer one, while a copy at a major the
   library does not ship, below the highest one it does, loses whatever its release; so does a copy
   at the same major whose id differs from the library's only in case, since those are compared by
   major alone. A newer release that you supplied of a major the library ships beats the library's
   copy of that major, even where the library also ships a newer major, and that library copy is
   then counted by the second counter while yours is kept.
   The second counts every other same-key loss: a library copy beaten by a newer release you
   supplied, two archives supplying one benchmark where the later document wins, or a document
   self-reporting an id this build already split into two (see "Same-key benchmark corrections"
   below), which the map cannot name and so is discarded with no winning document at all. The third
   counts benchmarks from a sunset archive, a product zip or a loose file dropped because another
   of those artifacts carries a newer major of an id the current library does not ship; a loss to
   a major the library ships is counted by the first. Any of the three can legitimately be
   zero, depending on what else is in `sources/`; what is worth a second look is a count that
   changed unexpectedly from the last refresh, not its absolute value.

   The summary also prints `same_key_departures`, which is not a fourth kind of drop and needs no
   separate reading: it re-counts the same-key losses already split across the first two, so the
   corpus conformance harness can check that total against its own replay. The first counter
   cannot serve for that, because the major-level contest behind the third one writes it as well.
5. Check `skipped_srg`, `skipped_draft` and `skipped_unclassified`. The first two are routine.
   The third is the one to read: it counts documents that identify as neither a STIG nor an SRG,
   each named individually in the log. One is the expected value for any library from April 2025
   onward: the Traditional Security Checklist, which identifies as neither and is not meant to be
   ingested. A count above one means DISA has changed how they title benchmarks, and the classifier
   in `stig_mcp/ingest/stig_parser.py` needs a new rule before those benchmarks are lost.
6. Check `rule_id_collisions`. It counts rules dropped because something already claimed the same
   `rule_id`, and like the counters above it depends entirely on what else is in `sources/`. A
   `sources/` holding only the library and the sunset archive produces none of them, because every
   collision a current library yields needs a loose product zip on one side. Where loose zips are
   staged, three losers are constant and a fourth varies with the library. The useful check is
   whether your build matches that list rather than what the number is. "Why a rule id can be
   held by another benchmark" below names them and shows the arithmetic. The WARNING names the
   holding benchmarks itself, and the SQL below covers the case where there are more of them than
   one line should carry. **None of them is anything an operator can fix during a refresh**, so
   this step is for explaining a short answer to a scoped query; the one that is a real data loss,
   a duplicate id inside one document, needs a schema change and is described below.
   A loser you do not recognize from that list
   usually means DISA has published something new, and is worth reading the WARNING for; a zip you
   placed in `sources/` by hand is the other cause.
7. Check `distinctiveness_margin_tokens`, which counts the tokens sitting closest to the resolver's
   distinctiveness gate, on both sides of it. It depends entirely on the corpus you built: 5 on a
   knowledge base of 386 benchmark rows, 1 on the 522 rows a full `stig-mcp-fetch` produced on
   2026-08-14. The number is a pointer rather than the thing to read: what matters is which tokens
   the log lines name and what their `df` values are, so read those lines and compare them against
   the last refresh. See "Resolver distinctiveness margin" below.

## Why a benchmark disappeared

The compilation root holds `_SRG-STIG_Library_Revision_History.pdf`, which lists every
sunset zip filename by quarter under "Deleted content that has been sunset". A
benchmark's `source_member` value, recorded in the knowledge base, is the exact string to
look up there. The server does not parse this PDF and makes no claim about why a
benchmark is absent, only that it is; the revision history is the only place that
explains the reason.

## Mapping overrides

In a source checkout `overrides.yaml` lives at the repository root, next to
`pyproject.toml`; [Where the data lives](install.md#where-the-data-lives) gives the installed
location and the `STIG_MCP_OVERRIDES` variable that names the file directly.

It is optional: if it is missing, the ingest applies no overrides at all, the same as an
empty file. The one exception is a file you named yourself. When `STIG_MCP_OVERRIDES` is
set and points at nothing, `stig-mcp-ingest` refuses to run instead of building a knowledge
base with none of your overrides in it, because that failure is otherwise invisible: the
knowledge base builds, and the pairs you added are simply absent.

It holds two lists of `{technique, control}` pairs:

    add:
      - technique: T1078
        control: AC-9
    suppress:
      - technique: T1078
        control: AC-9

- `add:` entries are pairs included on top of the CTID mapping set, recorded in the
  knowledge base with `source: override`.
- `suppress:` entries are pairs tombstoned out of the mapping set: a pair the CTID data
  carries is dropped if it also appears under `suppress:`.

The rule that surprises people: a `suppress:` tombstone only ever removes a pair that
came from the upstream CTID mapping set. It cannot remove your own `add:` entry, even
one naming the exact same technique and control, as in the example above, where the
`add:` entry survives its own `suppress:` entry untouched. That is deliberate: `suppress:`
exists to correct the mapping set you did not author, not to let one part of your file
cancel another.

A change to `overrides.yaml` only takes effect after the next `uv run stig-mcp-ingest`;
the knowledge base is built offline from the sources on disk, so nothing short of
re-running the ingest picks it up.

An optional top-level `version:` key records the provenance of your local additions, the
same way the CTID mapping set's own version is recorded against each pair it contributes.
Leave it out and the knowledge base stamps `local` for every override-sourced row instead.

## Product build applicability

`stig_mcp/applicability.yaml` records which STIG major applies to which product build.
Editing it is a checkout activity: an installed copy keeps the file inside `site-packages`,
where a change is lost at the next upgrade.
Today it holds one rule, for vSphere 8.0, taken from
`U_VMW_vSphere_8-0_Overview.pdf` section 1.2 "Support and Compatibility" inside
the vSphere zip:

> "The VMware vSphere 8.0 V2 STIGs are intended for vSphere 8 Update 3 builds only, and
> application of this guidance prior to Update 3 is not supported. If guidance is needed
> for Update 2 builds, reference the VMware vSphere 8.0 V1R1 STIGs included as
> supplemental documentation."

The file records the library release it was verified against. **Re-read that PDF section
whenever you refresh the library**, and update the file if DISA's wording has changed.
Nothing detects a change in the prose; the checks below only detect a change in the
shipped benchmarks.

### What the ingest reports

Every run, one line per rule:

    INFO Applicability: 'VMW_vSphere_8_0' governs 12 benchmark(s), 24 row(s), majors ['1', '2'].

The counts are printed unconditionally because they are the only thing that makes a
*partial* match visible. Eleven governed benchmarks is a perfectly plausible number with
nothing to compare it against, and DISA spells one of the twelve vSphere 8.0 benchmarks
with a dot rather than a hyphen. If that count drops, the pattern has stopped matching
something.

### Warnings and what to do about them

- **"governs benchmarks at major 'N', which no threshold maps"**: the library now ships a
  STIG major the rule does not know about. Those rows are never scoped by build. Re-read
  the source PDF and add a threshold. This is the strongest signal that the rule is stale.
  It also fires if a draft or Readiness Guide XCCDF introduced an unexpected major, which
  is worth checking before you edit the rule.
- **"maps builds to major 'N', which this knowledge base does not hold"**: the rule
  references a major the current library no longer ships. Check whether it was withdrawn.
- **"governs no benchmark in this knowledge base"**: the benchmark ids were renamed
  upstream, or you are building a knowledge base that does not include that product. The
  rule is inert until it matches again.

None of these stops a build. A stale rule degrades to unfiltered behavior, which returns
more than necessary rather than less, so it is safe to ship while you investigate.

## Resolver distinctiveness margin

The resolver treats a query token as identity-bearing only while it appears in no more than 5%
of the rows the knowledge base holds, so the threshold moves as DISA publishes. A token crossing
it changes what a query naming that token will confidently scope, and it does so with no code
change and no test failure, because the suite runs on fixtures while this is a property of your
corpus. The ingest therefore reports the tokens sitting one document either side of the gate,
which makes a crossing visible in the build log.

### What the ingest reports

Every build, one line for the tokens inside the gate and one for those outside it. Either line is
suppressed when it has nothing to name, so a corpus with a clear margin says nothing. On a corpus
of 386 rows, both lines appear:

    WARNING distinctiveness margin: 3 token(s) sit inside the distinctiveness gate by one
            document or less (gate df <= 19.30 at n=386): '4' df 19, 'ms' df 19, 'switch' df 19.
    INFO    distinctiveness margin: 2 token(s) sit outside the distinctiveness gate by one
            document or less: 'android' df 20, 'ca' df 20.

On the 522 rows a full `stig-mcp-fetch` produced on 2026-08-14, only the first appears, naming one
token, and the INFO line is suppressed because nothing sits within one document outside the gate:

    WARNING distinctiveness margin: 1 token(s) sit inside the distinctiveness gate by one
            document or less (gate df <= 26.10 at n=522): 'ibm' df 26.

`n` is the number of rows the knowledge base holds, one per benchmark version, and `df` is the
number of those rows whose title or product keywords carry the token. The summary counter
`distinctiveness_margin_tokens` is the two lines' token counts added together: 5 in the first
build above, 1 in the second.

### The warning and what to do about it

- **"token(s) sit inside the distinctiveness gate by one document or less"**: this fired on both
  corpora above, naming three tokens at 386 rows and one at 522, so its presence tells you little
  on its own. Neither does a change in the count between two different corpora, which is what you
  are reading if you compare your first build against the figures here rather than against your
  own last one. The value is in the token names and their `df`, which is why both are
  printed: read them against the last refresh. What is worth acting on is a token you
  recognize leaving the list or a new one entering it. A token entering has moved to the gate's
  edge. A token leaving has always moved at least one document away from the gate, and the
  question is whether it crossed on the way: a token whose `df` holds still while the corpus
  grows ends up further inside the gate without anything changing about how it scopes, while one
  whose `df` grew faster than the gate did has crossed and now scopes differently. **The `df`
  printed here cannot tell those two apart**, because a departed token prints no line in the new
  build and its old line reads the same either way. Read the token's current `df` out of the
  rebuilt knowledge base to settle it. Acting means deciding whether queries
  naming that token should still scope confidently, which may mean an alias entry or a resolver
  change. A crossing is not a defect and nothing in the pipeline acts on it: the gate is a ratio
  precisely so that what counts as distinctive tracks corpus growth. The INFO line beside it
  reports movement in the other direction, where a token becomes distinctive and more queries
  start scoping confidently. Read it as the mirror of this line and no further: the two sides
  are not symmetric, and the paragraph above does not transfer, since a gaining token whose `df`
  holds still while the corpus grows moves toward the gate rather than away from it.

## Same-key benchmark corrections

`stig_mcp/ingest/id_corrections.yaml` records the STIG ids where a DISA artifact ships two
genuinely different benchmarks stamped with one `Benchmark/@id`. The ingest keys on
`(stig_id, version)`, so without a correction the second document is discarded as an ordinary
duplicate; this file names the two documents' corrected `stig_id` and title so both are kept.
Editing it is a checkout activity, for the same reason as `applicability.yaml`: it ships
inside the wheel, so an installed copy keeps it in `site-packages` and a change there is lost
at the next upgrade.
Each entry cites the Overview PDF section that states the split, the same relationship
`applicability.yaml` has with `U_VMW_vSphere_8-0_Overview.pdf`.

When the ingest meets a same-artifact, same-release collision with disjoint rule sets that this
file does not cover, it falls back to the ordinary contest, discarding one document by walk order,
and logs a WARNING naming both `id_corrections.yaml` and the two document paths involved. The fix
is to read that product's Overview PDF and add an entry naming both documents' corrected identity;
see the shipped `MS_SQL_Server_2012_Database_Instance_STIG` entry for the shape. Re-check this
file at each library refresh the same way you re-check `applicability.yaml`: DISA can retitle or
re-split a benchmark, and nothing here detects a change in the underlying PDF prose.

The same summary line covered in "Quarterly refresh" also prints `same_key_content_collision`
(a collision was found, whether or not it could be corrected) and `id_corrections_applied` (how
many documents this run actually renamed). Neither needs a routine check. The one to act on is
`same_key_collision_unmapped`, printed alongside them: each increment means a benchmark was
discarded with no other trace in the composition, and the WARNING logged alongside it names the
documents and says what to change, whether that is adding an entry, widening an existing entry's
match fragment to cover a document it currently misses, or resolving an id one entry's correction
already collides with.

## Why a rule id can be held by another benchmark

This is a different mechanism from "Same-key benchmark corrections" above, and the two are easy to
confuse. That section is about one artifact shipping two documents under a single
`Benchmark/@id`. This one is about one `rule_id` being claimed more than once, usually by two
different benchmarks and sometimes twice within one document.

`stig_rules.rule_id` is a global `PRIMARY KEY` and the ingest keeps the first occurrence, so the
benchmark inserted first answers for a shared id and the other stores one rule fewer.
`rule_id_collisions` counts those drops. **Insertion order decides who is first**: newest
`xccdf_status_date`, then library origin, then `stig_id` ascending, then the newer major. A
benchmark stating no status date sorts last, because preferring one that states its currency is
the point. What the order buys is reproducibility: the winner does not depend on the order of the
directory walk.

### What a current library actually produces

Measured by the [corpus conformance harness](../CONTRIBUTING.md#corpus-conformance-harness), over each of the nine published libraries
paired with the sunset archive and the full loose corpus. **A build from any 2025 or 2026 library
loses rules from three or four benchmarks. The first three rows below appear on every one of
them; the last two are conditional on the library, as their `why` column says.**

| loser | loses | to | why |
|---|---|---|---|
| `RH_OpenShift_Container_Platform_4-12_STIG` V2R2 | 66 of 83 | `RH_OpenShift_Container_Platform_4-x_STIG` V2R6 | DISA renamed the product and carried the rules across. All 66 are byte-identical in title, fix text, check text and severity. |
| `SAN` | 1 of 28 | nothing at all | `SV-6802r1_rule` appears twice in one document, on two different requirements: V-6656 on SNMP access and V-6662 on vendor support, with different titles, fix text and check text. The second is stored under no benchmark, and the WARNING names its `group_id`. **The only shape here where a requirement is lost from the store.** Separating them needs `group_id` in the key; a `(stig_id, stig_version, rule_id)` key would not separate them either, since both occurrences share all three. |
| `MULTI-FUNCTION_DEVICE` | 1 of 22 | nothing at all | `SV-7031r1_rule`, the same shape: V-6806 on administrator restriction and V-6807 on vendor support. |
| `MongoDB_Enterpise_Advanced_8-x_STIG` V1 | 54 of 55 | `MongoDB_Enterprise_Advanced_8-x_STIG` V1 | A typo in a published `Benchmark/@id`. See below. Present on the April 2026 and July 2026 libraries. |
| `Apple_iOS-iPadOS_18_STIG` major 1 | 77 of 92 | its own major 2 | A genuinely superseded release. Present on the July 2025 library. |

Those add up exactly to the counter, which is the cheapest way to confirm your own build matches:
66 + 1 + 1 is the 68 reported on the April 2025, October 2025 and January 2026 libraries; adding
MongoDB's 54 gives the 122 on April 2026 and July 2026; adding Apple's 77 instead gives the 145 on
July 2025.

**Those figures are for the harness composition**, which stages every loose zip DISA publishes. A
`stig-mcp-fetch` corpus holds only the newest release per product and can differ: a fetch-shaped
build from the April 2025 library reports 125 rather than 68, because the
loose release that would otherwise have displaced `Apple_iOS-iPadOS_18_STIG` major 1 is not staged.

**None of the five is actionable by an operator**, which is not the same as none of them
mattering. Two are DISA's own publishing decisions and one is a superseded major behaving as
intended; nothing is missing from the knowledge base in those three. The two within-document
duplicates are different: a requirement really is lost from the store, and the fix is a schema
change in this project rather than anything to do during a refresh. **It would not change any
answer today**, because neither benchmark's rules carry the CCI idents a control query joins
through: `SAN` has 0 of 28 and `MULTI-FUNCTION_DEVICE` 1 of 22, so neither the
surviving occurrence nor the dropped one is reachable by `defenses_for_technique`. Separating
them is also not just a wider key: `rule_cci.rule_id` is a foreign key onto `stig_rules(rule_id)`
and would have to move with it. The step in "Quarterly refresh" exists so that a
short answer to a scoped query is explicable.

**The MongoDB case is the one worth understanding**, because it is the only case between two
benchmarks where the loser is not an older or renamed edition of the winner. DISA published the
same V1R1 document twice, once inside the library as `MongoDB_Enterpise_Advanced_8-x_STIG` (note
the missing `r`) and once as a loose zip with the correct spelling. Both carry Benchmark Date 26
Jan 2026; their `xccdf_status_date` values differ by six days, 2026-02-20 against 2026-02-26. The
newer date means the correctly spelled copy wins, so the outcome is the right way round. What
remains is a near-empty `stigs` row under the misspelled id, holding the single rule the two do
not share: one `SV-279386` rule carries a different revision suffix in each copy, which is why 54
of 55 collide and not all 55. **`id_corrections.yaml` cannot address it**: both of its entry
points key on two documents sharing one published id, and these publish different ids.

### Building from an archival library

The conformance harness also builds from the 2020_01 library family, and those builds look nothing
like the above: 64 or 65 losing benchmarks and 2885 or 3556 collisions. The
extra losses are whole families of sibling benchmarks that DISA shipped as one requirement set
across several roles, architectures or security products. `Windows_2012_MS_STIG` loses 323 of its
335 rules to `Windows_2012_DC_STIG`; 22 `zOS_*_for_RACF` and `_for_TSS` documents each lose to
their `_for_ACF2` counterpart, and `zOS_RACF_STIG` loses 121 to `zOS_ACF2_STIG`, the largest of
that family; the Solaris x86 and SPARC editions collide, as do the `Network_-_*` and `WLAN_*`
device families, three of the four `Enclave_-_Zone_*` documents and three of the four Exchange 2010
server roles. Of the 3556 ids dropped on that build, 1660 tie with their holder on status date and
are separated only by `stig_id` ascending, which is alphabetical and carries no meaning of its own.

**These families have not simply been retired, and that is the more useful fact.** 34 of the 65
losers on the 2020_01 build are still shipping in a July 2026 one, the zOS security-product triples
and Solaris 11 among them, and they produce no collisions there at all. What changed is that DISA
renumbered the rules, so siblings no longer share ids. Some of the families above really are gone
from a current library, including Windows 2012, the Enclave zones, Exchange 2010 and the older
`Network_-_*` and `WLAN_*` documents; do not read the whole list as retired.

**This is not a build an operator makes**, and the sibling shape is described only so that nobody
recognizes it from a conformance report and goes looking for it in a current knowledge base. If you
do build from an old library, note that a loser's ids are not necessarily all held by one
benchmark: `Network_-_Infrastructure_Router_-_Cisco` loses its 88 ids to four different holders.

### What a scoped query returns, and how to find the holder

The WARNING names the benchmarks that ended up with the dropped ids, largest share first, with
how many each took: `... are already held by RH_OpenShift_Container_Platform_4-x_STIG 2 (66).` A
duplicate inside one document says so instead of naming the document as its own holder, and is
listed first so the cap cannot truncate it. It names at most three other holders and then counts
the rest, because a loser's ids are not necessarily held by one benchmark. For a duplicate inside
one document, the WARNING also names the dropped group id(s), the only thing identifying which
requirement was lost; ids held by another benchmark are counted per holder, not listed. Where the
WARNING summarizes, ask the knowledge base:

    SELECT stig_id, stig_version FROM stig_rules WHERE rule_id = ?

A benchmark can lose every rule it parsed. On the 2020_01-family builds five did, including
`WLAN_Bridge` (0 of 34) and `Network_-_Infrastructure_Router` (0 of 78); no build from a 2025 or
2026 library produced one. The `stigs` row is written before any rule, so such a benchmark still
exists and a query scoped to it returns that row and no rules: `_explicit_scope` hydrates it, the
join through `rule_cci` and `stig_rules` matches nothing, and the tool layer reports "Control X has
no rules, at the control or any of its enhancements, in the resolved STIG(s)". The guidance is
retrievable, but only through the benchmark that holds the ids.

One caveat on "the guidance is retrievable": of the 3556 drops on the 2020_01 build, nine involve a
rule whose text differs from the one the holder stored, in title, fix text or check text and
several in more than one of the three. Those nine cover four distinct rule ids, one of which
accounts for six of them. Say that the id is present under another benchmark rather than that
nothing is lost.

The ingest also logs one DEBUG line per dropped rule, naming the id, the group it came from and
the benchmark that stored it. `stig-mcp-ingest` logs at INFO and has no option to lower that, so
those lines appear only when the ingest is driven from Python with DEBUG logging configured; from
the command line, the WARNING and the query above are the record. The WARNING is per benchmark
because the per-rule form runs to 122 lines on a harness build from the July 2026 library.

## Where the server's log is

The server logs to stderr, at INFO and above, since stdout carries the MCP protocol itself.
Its first lines name the knowledge base it serves from and, when that knowledge base is not
usable yet, say why. Where stderr ends up is the client's decision:

- **VS Code**: run **MCP: List Servers**, select the server, and choose **Show Output**, as
  [install.md](install.md#starting-the-server-and-checking-the-tools) also says.
- **Claude Code**: `/mcp` shows each server's status, and a server that fails to start shows
  as failed there. The server's stderr is written to Claude Code's debug log,
  `~/.claude/debug/<session-id>.txt`, when Claude Code is started with `claude --debug=mcp`,
  as documented on 2026-09-28 at <https://code.claude.com/docs/en/debug-your-config>.
