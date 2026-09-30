# STIG-MCP user guide

For a person talking to an LLM that has this server wired in as an MCP tool.

## Tools

- `mitigations_for_technique(technique_id, system_description?, stig_ids?, severity?)`
- `techniques_for_actor(actor, system_description?, stig_ids?, include_mitigations?, severity?)`
- `finding_details(ids)` returns DISA's check and fix text for findings named by rule id or V- id
- `resolve_system(system_description, limit?)` returns `{candidates, notes}`
- `search_techniques(query, limit?)`
- `list_stigs(filter?)`
- `install_knowledge_base(release?, path?, sha256?)`
- `check_sources()` returns `{kb_ready, not_ready, installed, newest, action, reason}`, plus `newer_schema_available` when a release needs a newer stig-mcp

### Revoked MITRE ATT&CK® ids

ATT&CK retires and renumbers techniques between releases, and published mapping sets lag
behind. The knowledge base records the `revoked-by` relationships it can resolve to a
technique the bundle still defines, so a mapping written against a retired id is applied
to its replacement instead of being dropped, and both `mitigations_for_technique` and
`search_techniques` accept a retired id. Each answers for the replacement and reports the
old id in `redirected_from`. A maintainer-side tombstone still removes a pair, and its
technique id is remapped the same way, so a tombstone written against a retired id also
removes the pair the mapping set already carried on the replacement. If a mapping here
looks wrong or missing, that is fixable, just not from this side: see "Mapping overrides"
in [docs/operations.md](operations.md), written for whoever builds and maintains this
knowledge base.

## Getting the LLM to use the server

Wiring the server in is necessary but not sufficient. The failure mode to watch for is
not a wrong answer: it is the model answering from its training data and never calling a
tool at all. A general question like "What does STIG guidance say about SSH?" can get
answered fluently and incorrectly, with nothing in the reply to show a tool ran.

Prompt shapes that reliably trigger tool use ask for something the model cannot already
know: a specific ATT&CK technique id, a named actor, a STIG benchmark id, or a system
description with a product and version. When you want certainty rather than a best
guess, name the tool directly:

    Using #list_stigs, which RHEL benchmarks are in the knowledge base?

GitHub Copilot needs one more thing before any of this works: see the Agent-mode
requirement in the GitHub Copilot section of [../README.md](../README.md).

To tell whether a tool actually ran, look for the tool's output shape in the answer:
benchmark ids, rule ids (`SV-...r..._rule`), CCI numbers, or CAT severities the model has
no other way to produce verbatim. A fluent paragraph with no ids, rule numbers, or a
`notes` explanation in it is a sign the model answered from memory, not from a result.

## Scoping the prompt for a well-matched answer

Two things narrow an answer well: an ATT&CK technique id or actor, and a system
description carrying both a product and a version, for example "RHEL 9" or "Windows 11"
rather than "Linux" or "our servers."

Vague input does not fail loudly. Matching against product and version is how the
knowledge base decides it is confident enough to commit to a benchmark; a vague
description just does not clear that bar. The result is a list of candidate systems
instead of a resolved one, and the answer comes back with controls but no STIG steps
until you narrow it.

If you already know which STIG benchmark applies, for example because your organization
mandates a specific one, name its id directly rather than describing the system and
letting resolution guess. `list_stigs` returns the ids the knowledge base actually holds;
passing one of them in `stig_ids` skips resolution entirely.

## Reading the answer

### Why did it answer about a different technique than I named?

You named a retired ATT&CK id. See "Revoked MITRE ATT&CK® ids" above: the knowledge base
answers for the replacement technique and sets `redirected_from` to the id you gave it,
with a note naming both ids. Cite the replacement id going forward.

### How does it match the actor I named?

`techniques_for_actor` accepts an ATT&CK group id (`G0016`), the group's name (`APT29`),
or any alias ATT&CK lists for it (`Cozy Bear`). Case, spacing, punctuation and a
trailing "Group" or "Team" do not matter, so `apt 29`, `Cozybear`, `Lazarus` and
`G-0016` all resolve. When the name you gave only matched in that looser way,
`actor.matched_as` shows the id, name or alias it was read as. Check it: the answer is for
that group.

A misspelling is not corrected. Real group names differ by a single character (APT28
and APT29 are different adversaries), so the tool refuses rather than guesses, and its
error names the closest groups:

    Unknown actor 'Cosy Bear'. Closest ATT&CK groups: APT29 (G0016, as 'Cozy Bear'). Call again with the group id of the one you mean.

The model can retry with one of those ids on its own; if it does, confirm it chose the
group you meant. A name that ATT&CK lists for more than one group, such as `UAC-0056`,
is refused the same way and names each group.

A few labels belong to one group and loosely match another. `Thrip` is one group's name
and another's alias, and `LUMINOUS MOTH` is an alias of Mustang Panda while a separate
group is named LuminousMoth. The answer is for the exact match, and
`actor.also_matches` lists the other groups. If you meant one of those, ask again with
its id.

### When a technique has no controls

`mitigations_for_technique` can come back with an empty `controls` list: the CTID mapping
(and any local override) simply named none for this technique. When that happens, `notes`
carries one of five messages explaining why, drawn from the technique's own ATT&CK
metadata and the CTID mapping's. Each is shown below as you would actually see it, with the
value it fills in written as _technique_id_, _created_, _version_ or _released_ so the
placeholder names stay readable:

- **Suppressed by your own overrides.** "All CTID-mapped controls for _technique_id_ are
  suppressed in overrides.yaml." Remove the `suppress:` entry for this technique if that
  was not intended.
- **CTID reviewed it and found nothing.** "CTID reviewed _technique_id_ and found no
  800-53r5 control that mitigates it." Nothing to do; this is CTID's own considered
  verdict, not missing data.
- **The technique is newer than the mapping.** "_technique_id_ was added to ATT&CK on
  _created_, after ATT&CK _version_ (_released_), which the CTID mapping covers." Nothing
  to fix here: a later CTID mapping may cover it. `check_sources` reports a newer knowledge
  base once one built from that mapping is published, and `stig-mcp-fetch --check` reports
  the mapping itself as soon as CTID publishes it.
- **A mapping gap.** "The CTID mapping does not cover _technique_id_. Add a mapping in
  overrides.yaml if this is a gap." This is the one cause naming an actual gap; add the
  control there if you believe one applies.
- **Not enough data to tell which of the above it is.** "_technique_id_ is not in the CTID
  mapping file (ATT&CK _version_); provide attack_index.json to tell a newer technique from
  an uncovered one." If this is because the release date of the CTID mapping's own ATT&CK
  version was never recorded, fetch or hand-place `attack_index.json` and rebuild so a
  rebuild can tell the two causes above apart. If instead the technique's own ATT&CK data
  carries no `created` date at all, no `attack_index.json` can supply what is missing, and
  this message is what you get regardless. The same holds when the message reads "ATT&CK
  unknown": the mapping file names no ATT&CK version (a CSV mapping never does), so there is
  no release date to look up, and the newer-technique and mapping-gap causes above cannot
  be told apart from that file.

Separately, whenever the technique data and the CTID mapping were built from different
ATT&CK releases, a note says so regardless of whether any controls were found: "Controls
come from the CTID mapping for ATT&CK _ctid_version_; technique data is ATT&CK
_attack_version_." The `sources` block's `ctid_attack_version` key names the release the
mapping covers, next to `attack` for the technique data's own release, so the same gap is
visible there without waiting for a technique that triggers the note.

### Why did I get controls but no STIG steps?

The `notes` field distinguishes these causes:

- **No system given.** You called without `system_description` or `stig_ids`, so there is
  nothing to scope STIG findings to. The note says as much and names both parameters.
- **Nothing matched confidently.** Usually your `system_description` did not name a
  distinctive product and version, so nothing cleared the confidence bar. It can also
  happen after you named one correctly: see "Why did naming one product return three
  STIGs?" below for a wording that empties the scope even though the product was named
  plainly. Either way, the note suggests calling `resolve_system` or `list_stigs` to see
  candidates, or passing `stig_ids` explicitly.
- **The version you named is not held.** Your description named a product this knowledge
  base does cover, at a version it does not. The note replaces the one above, names the
  benchmarks that are held and the versions they cover, and tells you to pass `stig_ids`
  if you mean to use one anyway. It never claims DISA published no such STIG, only that
  this knowledge base does not hold one. Coverage is judged on the major version, so
  naming a patch level of a major that is held (`11.4` against a Solaris 11 benchmark)
  is not treated as naming a version that is missing. A version a benchmark's own title
  writes glued to a letter is read as the major it names, so `Oracle Database 12` is told
  the knowledge base holds `Oracle_Database_19c_STIG` rather than getting the generic
  no-match note. Two limits: only the `v9`/`v10.x` spelling and a short curated list are
  read this way, and only from what DISA published, never from what you type. So
  `Oracle Database 12c` still gets the generic note where `Oracle Database 12` gets the
  specific one, because no rule can tell Oracle's `19c` from a model number like `SEL-2740S`
  or `HPE 3PAR`.
- **Naming two systems gets you a note per system.** A description that names more than
  one product is split on `and` and commas, and each piece is judged on its own, so
  `RHEL 7 and Windows Server 2025` gets the same sentence about RHEL 7 that `RHEL 7`
  alone gets while saying nothing about the Windows half, which is held. Not every `and`
  or comma splits, though: see "Why did naming one product return three STIGs?" below for
  the wording that does not. Each note quotes
  the piece it is about, not your whole description, and a piece repeated character for
  character is reported once (`RHEL 7 and RHEL 7`). A repeat that differs in case or spacing
  is not collapsed, so `RHEL 7 and rhel 7` still gets two near-identical notes. A piece that matched its own product confidently stays silent, on the same
  reasoning as everywhere else here: the two statements would contradict each other.
  Two things to know before reading these:
  - **A piece that is a modifier rather than a product can still produce one.**
    `Red Hat Enterprise Linux 9, x86_64` is told nothing is held for `x86_64` and pointed
    at a Solaris benchmark; `Red Hat Enterprise Linux 9, site 1` is pointed at the Apache
    and IIS site benchmarks. Both are noise. The sentence is scoped to the words it quotes,
    so it is not a claim about your RHEL, but the "closest benchmark" clause is unhelpful.
    Telling these apart from a real product needs judgment this knowledge base does not
    have, so they are left in rather than guessed at.
  - **Two pieces naming related products can recommend overlapping `stig_ids`.**
    `Cisco IOS XE 17, Cisco IOS 15` returns two lists, the second a superset of the first.
    Both are true; neither is the union.
- **The benchmark is not version-specific.** Some products get one STIG rather than one
  per release, so naming your build costs you the auto-scope. The note says which
  benchmark this is and that the mismatch is not evidence it does not apply.
- **Your build predates any official STIG.** vSphere 8.0 GA through U1e is the example:
  DISA published only a STIG Readiness Guide for those builds, which is not an official
  STIG and is not in this knowledge base. The V1 STIG applies from 8.0 U2 onward. The
  800-53 controls still apply and are still returned; a top-level note names the build and
  says why there are no steps.
- **No applicable benchmark.** A benchmark did resolve, but it does not enforce most or
  any of the controls mapped to this technique. You will see this as a `notes` entry per
  control rather than one overall failure; see the next question.

### Why does a control say it has no rules in the resolved STIG?

The 800-53r5 mapping and the STIG benchmark are independent sources. A control can be
mapped to the technique (from CTID's ATT&CK-to-800-53 mapping or a local override) while
the specific benchmark you resolved to has no rule tagged to a CCI under that control.
That is not an error: different products enforce different slices of 800-53, and DISA
writes STIG rules per product, not per control. The control is still relevant; this
benchmark just does not have a checkable rule for it.

### Why does the answer say benchmarks were omitted?

When more benchmarks tie with the last benchmark shown than the limit allows, the response
says so: "N further benchmarks scored exactly as well as the last one shown ... and were
omitted." Those N were cut by the cap rather than by score, which is what raising `limit`
recovers for a `resolve_system` caller. A `mitigations_for_technique` caller has no `limit`
parameter to raise; call `resolve_system` with a higher limit instead, or pass `stig_ids` to
name the benchmark directly. Benchmarks dropped for scoring lower are not counted, because
they were not dropped arbitrarily.

### Why did naming one product return three STIGs?

For these products it does not. A description naming several products is divided at "and"
and commas so each is scored on its own, but a handful of DISA titles use one of those
words inside the product name itself, such as "Application Security and Development" and
the z/OS "System Display and Search Facility" family. Those word pairs are not split, so
naming one of those products returns only the one you named rather than every sibling in
the family.

The words are what decide whether a separator splits, not which product you meant, so a
description that places ordinary English matching one of these word pairs after a product name
is also left undivided. "Apache Server 2.4 security and development environment" and "our
Windows Server security and development team" are both read as one piece rather than two, even
though neither is about the "Application Security and Development" benchmark at all, and the
merged piece can come back with nothing confident where naming the product alone would have.

### Why is a benchmark id I named reported as not in the knowledge base?

`stig_ids` is matched literally against the ids `list_stigs` returns, case-sensitively.
This fires for a typo, the wrong case, or a benchmark that genuinely was never fetched
into this build. Call `list_stigs` (optionally with a `filter` substring) to see the
exact ids on hand before naming one.

The list also accepts at most 200 ids, and a longer one is refused rather than answered.
That is well past any real system: the widest grouping `list_stigs` can return for one
filter substring is 94 (`zOS`), and the widest single product family is 24 (`vSphere`).
If you genuinely need more, split the ids across calls of at most 200 and merge the
results, which returns the same findings as one call would.

Note that the cap bounds the id list, not the size of the answer. A call at the cap can
return a very large answer, especially from `techniques_for_actor` with
`include_mitigations`. Ask for the benchmarks you need rather than the most you are allowed.

### Why am I seeing steps from two versions of the same STIG?

A few products ship two STIG versions at once, and their remediations differ. vSphere 8.0
is the only one in the current library: DISA publishes V2 as current guidance and bundles
V1R1 as supplemental guidance for older builds. Ask about ESXi 8.0 without saying which
build you run and you get both, labeled by `stig_version`, because neither can be ruled
out.

Name the build and you get one:

> What DISA STIG steps mitigate T1078 on ESXi 8.0 U3?

The answer then covers V2 only, and a note says so. For a build on Update 2, it covers
V1R1 only.

The letter suffix does not change the answer. `8.0 U3` and `8.0 U3f` both select V2,
because this knowledge base holds one release per major and cannot distinguish V2R1 from
V2R4. A note says this whenever a build is used, so you know to check the release actually
deployed at your site.

### Why does a rule say it is Not Applicable in its own text?

Some STIGs express applicability inside individual requirements rather than by shipping
separate versions. Windows 11 is the example: one STIG covers every feature release, and
a handful of rules carry conditions like "For Windows 11 version 24H2 and newer, this
requirement is Not Applicable" or "This is NA for Windows 11 LTSC" inside their check
text. Those rules are returned verbatim with their conditions intact, and you have to
apply the condition yourself. Naming a Windows feature release in your prompt will not
filter them, because there is only one STIG to select.

### Why doesn't the answer include the check and fix steps?

Because the answers would be too big to read. DISA's check and fix text is most of every
finding, and an actor's techniques share most of their findings, so an answer carrying
all of it would run to megabytes. VS Code's Copilot agent currently saves any tool result
over 8 KB to a temporary file and shows the model only its first 500 characters; Claude
Code does the same above 25,000 tokens. A model then reads the file in pieces and tends
to summarize, which is how a list of CAT I findings comes back incomplete.

So `mitigations_for_technique` and `techniques_for_actor` send one line of compact JSON
that lists each finding once, by id, severity and title, and opens with `summary`: the
number of rules found, the number at each CAT, `control_counts` (how many controls map
and how many have rules in the resolved STIGs), `cat_i` (the CAT I V- ids with their
count) and, last, the ids of the controls that have rules. `techniques_for_actor` also
counts the techniques.
The counts come first so they fall inside that preview, and they spare the model counting
long lists itself, which it gets wrong. How many CAT I ids also fit depends on the client:
Copilot may reformat the answer before saving it, so rely on `cat_i.count` to tell whether
the ids in view are all of them. That count is of V- ids, not rules: a requirement held at
two majors, as vSphere 8.0's are, is one V- id and two rules.

Ask for the steps of the findings you care about and the model calls `finding_details`,
which returns DISA's exact check and fix text for up to 50 rule ids or V- ids at a time.
A V- id that two benchmarks or two majors share returns every match, each labeled with its
benchmark.

In `techniques_for_actor` with `include_mitigations`, each technique names its controls
grouped by where the mapping came from (`ctid` or `override`), `controls` lists each
control once with its rules, and a control with no rules in scope is named in one note
rather than under every technique that maps to it.

If Copilot asks permission to read a file named like `…copilot-tool-output-….txt`, that
is it reading this server's answer back from where it saved it. It is safe to allow.

### What do CAT I, II, and III mean, and why is the answer ordered that way?

CAT is DISA's severity ranking: CAT I is the highest-risk finding (mapped from XCCDF
`severity="high"`), CAT II is medium, and CAT III is low, or unknown severity treated as
the safe default. `findings` are always listed CAT I first, then II, then III, and a
control's `rules` follow the same order, so the findings that matter most for risk are the
ones you see first without having to sort them yourself. Pass `severity` (for example
`["I"]`) to leave the lower levels out of the answer altogether.

## Where an answer's facts came from

### Which artifacts did this answer come from, and can I check it myself?

`mitigations_for_technique`, `techniques_for_actor` and `finding_details` responses carry
a `sources` block naming what the answer was built from: which DISA STIG library
compilation, which ATT&CK release, which CTID mapping-set version, which CCI list, and
when the knowledge base was built (`ingested_at`). Keys appear only when that source was
actually used and its version could be recorded, so the block's key set can differ between
builds. A source that contributed nothing is left out rather than cited blank.
`resolve_system`, `search_techniques`, and `list_stigs` do not carry a `sources` block.

Two fields on individual results, not the `sources` block, let you check a specific
benchmark: a `finding_details` entry's `stig_release` field is DISA's own release token
(for example `V3R9`). This server composes that token itself, from two fields inside the
STIG document: its `<version>` element and a `Release: N` line. Neither the document nor
a filename carries it as a single string. DISA's own zip names, revision history, and
cyber.mil pages use the identical composed token, though, which is why it is still the
right string to search for there. `origin`, present on a `finding_details` entry and on most
`resolved_systems` entries (the placeholder row synthesized for a `stig_ids` value the
knowledge base does not hold carries no `origin` key), says which kind of artifact
supplied that benchmark: `library` (the current DISA STIG Library Compilation),
`product_zip` (a hand-placed zip file), `sunset` (a superseded compilation kept only
because the library no longer ships that benchmark), or `loose` (a hand-placed bare
XCCDF file).

### Checking for a newer knowledge base

`check_sources()` asks this project's GitHub releases whether a newer knowledge base is
published than the one installed. It contacts only GitHub (the release listing and the
`release.json` of the release it reports on, plus that of a newer-schema release when one exists), never MITRE, CTID, NIST or DISA, and it answers even before a knowledge
base is installed. Then `kb_ready` is false and `not_ready` holds the same payload every
other tool returns in that state; on a ready knowledge base `not_ready` is null.

`installed` holds `sha256`, the SHA-256 of the installed file (null when there is none or
the file cannot be used), and `release`, the tag it was installed from (null for a local
build, for a file installed with `path`, or for a file whose install record no longer
matches it). `newest` describes the newest release for this server's schema: its `release`,
`schema`, `built_with`, `sha256` (a pair, `xz` and `sqlite`) and `upstream` source versions,
or null when none is published. `newer_schema_available` (`schema`, `release` and
`upgrade_to`) appears only when a published release needs a newer stig-mcp than this one.
`action` says what to do about it and `reason` says why, in a sentence. The actions are:

- `"none"`: the installed knowledge base is the newest release, or a local build at least as
  current as it. It is also what a ready knowledge base gets while no release is published.
- `"install"`: a newer release for this schema is published, or nothing usable is installed;
  call `install_knowledge_base`.
- `"upgrade_package"`: a release for a newer schema is published and nothing installable at
  this schema is newer than what is installed; `newer_schema_available.upgrade_to` names the
  stig-mcp to move to (see "Upgrading stig-mcp").
- `"build_locally"`: nothing usable is installed and no release is published yet; build with
  `stig-mcp-fetch` and `stig-mcp-ingest` as [docs/operations.md](operations.md) describes.

A locally built knowledge base matches no release's hash, so it is compared by the source
versions it recorded (ATT&CK, the ATT&CK version the CTID mapping covers, the catalog, and
the DISA library) against the release's. The action is `"install"` only when the release was
built from newer ones, and then the reason also names any source where the local build is
the newer.

A failure to reach GitHub (a rate limit, no network, or a proxy that inspects TLS, for
example) reaches the agent as an error that names the offline alternative.
Text quoted from GitHub in a message is cut to 120 characters; the guidance around it never is.

For whoever builds locally, `stig-mcp-fetch --check` still compares the sources directly
against MITRE, CTID, NIST and DISA. It prints the whole reason for any source it could not reach, and
exits 3 when nothing else is to take.

### Installing or updating the knowledge base

`install_knowledge_base()` with no arguments downloads the newest published release for this
server's schema, verifies the download against the release's `SHA256SUMS`, checks that it is
an intact knowledge base for this schema, and replaces the installed one. The running server
answers from the new file on its next call, and nothing is replaced if any check fails.

`release="kb-YYYY-MM-DD"` installs that exact release, to pin a version or roll back. `path`
and `sha256` install a file already on this machine, either the `.sqlite.xz` asset or the
decompressed `.sqlite`, and never touch the network; `sha256` is the value `SHA256SUMS` lists
for the file passed. `release` and `path` cannot be combined. A release install's result names
the release, both SHA-256 values (of the compressed and the decompressed file), the schema,
`built_with`, the source versions, and `replaced`, which holds the SHA-256 and release of the
knowledge base that was there before. A file install's result names the file instead of a
release (its release is null), and holds the SHA-256 values, the schema and `replaced`; the
compressed value is null for a `.sqlite` file, and there is no `built_with` or source versions.

Answers from `mitigations_for_technique`, `techniques_for_actor` and `finding_details`
carry `kb_sha256` in their `sources` block. It is the installed file's SHA-256, which is
what two people compare to know they queried the same knowledge base.

Before any knowledge base exists, every tool's `not_ready` lists `install_knowledge_base`
first. While no release is published, the install refuses and names `stig-mcp-fetch` and
`stig-mcp-ingest`; that is the path to take, and `check_sources` reports it as
`"build_locally"`.

#### Upgrading stig-mcp

`uvx` keeps running the version it has cached. To move to the newest release, run
`uvx --from stig-mcp@latest stig-mcp-install-kb --help`, which refreshes uv's copy. From a
source checkout, run `git pull` and `uv sync`. Either way, restart the server from the client,
then call `install_knowledge_base`. A newer stig-mcp may read a newer schema, and until a matching
knowledge base is installed every tool reports `schema_outdated` and names the install tool.

## When a STIG is no longer current

A resolved benchmark that is not confirmed-current library guidance gets a note in
`notes` explaining why, in one of four forms (`label` below is the benchmark id followed
by its release label, the same token `finding_details` exposes as `stig_release`):

- **DISA retired it.** `DISA marked label deprecated on <date>.` DISA sets this status
  itself, inside the XCCDF; it can appear even on a benchmark the current library still
  ships.
- **It came from a sunset archive.** `label came from a sunset compilation and is not in
  <library artifact>.`
- **It was supplied locally.** `label (<release info>) was supplied as a local artifact
  and is not in <library artifact>. It may be newer than that compilation or retained
  from an earlier one.`
- **There is no library to compare against.** `This knowledge base was built without a
  library compilation, so whether label is current guidance cannot be determined.`

A benchmark absent from the library is not necessarily retired. Nothing inside a STIG's
own XCCDF distinguishes "DISA stopped shipping this" from any other reason it might be
missing, so these notes state a verifiable fact about where the benchmark came from, not
a claim about why. A current library benchmark that is not deprecated gets no currency
note at all, since nothing about it needs qualifying. To find out the actual reason a
specific benchmark is absent from the library, see "Why a benchmark disappeared" in
[docs/operations.md](operations.md).

## Getting more out of it

- **Narrow to specific benchmark ids.** Pass `stig_ids` once you know which benchmarks
  apply, instead of re-describing the system every time.
- **Ask for CAT I only.** `severity` narrows an answer to the CAT levels you name, so
  "only CAT I findings" becomes a smaller answer rather than a filter the model applies to
  a large one.
- **Ask which benchmarks exist for a product before asking for steps.** `list_stigs` with
  a `filter` substring (a product name, or a benchmark id fragment) shows what is on hand
  before you commit to a `system_description` or `stig_ids`.
- **Ask for the exact steps, word for word.** Every finding carries a `rule_id` and
  `group_id`; asking the model to fetch them with `finding_details` gets DISA's own
  `check_text` and `fix_text`, and lets you check the source STIG XCCDF yourself. The tool
  asks the model to quote that text and label anything it adds, but a model may still
  paraphrase it, or cite a third-party website as DISA's. Say so in the prompt, for example
  `Quote DISA's check and fix text for V-253284 word for word, then explain it`. The
  `stig_title` and `stig_release` in that answer name the benchmark release the text came
  from.
- **Ask how current the knowledge base is.** `list_stigs` returns each benchmark's own DISA
  revision number as `version`, not a build date. `mitigations_for_technique` and
  `techniques_for_actor` carry that in their `sources` block instead: which DISA STIG
  library compilation, and `ingested_at` for when this knowledge base was built. Call
  `check_sources` to learn whether a newer knowledge base is published.

## Limits

This server maps ATT&CK techniques to 800-53r5 controls to DISA STIG guidance text. It
does not scan anything, does not connect to the system you are asking about, and does not
know your actual configuration. It can tell you what the guidance says to check and fix;
it cannot tell you whether you are compliant. Reading a `check_text` back to you is not
the same as having run the check.

## Two worked examples

### A live technique: T1078 on RHEL 9

Prompt: `What DISA STIG steps mitigate T1078 on RHEL 9?`

The model calls `mitigations_for_technique("T1078", system_description="RHEL 9")`.
"RHEL 9" names both a product and a version, so it resolves the RHEL 9 STIG benchmark
with high confidence rather than returning candidates.

The response's `technique` block is T1078 (Valid Accounts) with `redirected_from: null`,
since T1078 is a live id. `resolved_systems` names the RHEL 9 benchmark. `controls` lists
the 800-53r5 controls mapped to T1078 (AC-2, AC-3, AC-6, and others), each naming the
`rules` for that benchmark, and `findings` lists each of those rules once, CAT-ordered.
Some controls come back with rules; others come back empty with a `notes` entry reading
"Control AC-2 has no rules in the resolved STIG(s)." That means the RHEL 9 STIG, as DISA
wrote it, has no rule tagged to a CCI under AC-2, not that AC-2 is irrelevant. To quote
the steps themselves, the model then calls `finding_details` with the V- ids of the
findings it is answering about, and reads DISA's check and fix text from that.

### A revoked id: T1086 on Windows 11

Prompt: `What DISA STIG steps mitigate T1086 on Windows 11?`

T1086 was ATT&CK's id for PowerShell before it was retired and folded into T1059.001, the
"PowerShell" sub-technique of Command and Scripting Interpreter. The model calls
`mitigations_for_technique("T1086", system_description="Windows 11")`. T1086 is not a
live id, so the knowledge base looks up its `revoked-by` replacement instead of failing.

The response's `technique` block is T1059.001, with `redirected_from: "T1086"`, and
`notes` opens with "ATT&CK revoked T1086 (PowerShell) in favor of T1059.001. Answering
for T1059.001; cite that id instead." Everything after that, `resolved_systems`,
`controls`, `findings`, follows exactly as in the first example, scoped to Windows
11. The surprising part is not an error: it is the intended behavior for a retired id,
and the fix is to use T1059.001 in future calls.
