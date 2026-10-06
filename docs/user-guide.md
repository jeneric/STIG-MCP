# STIG-MCP user guide

## Summary

STIG-MCP gives an AI assistant a local, searchable copy of public security guidance. You ask
in plain language, in GitHub Copilot, Claude Code or another assistant that supports the
Model Context Protocol (MCP). The assistant calls this server's tools and answers from what
they return, rather than from what the model remembers.

The server connects four public sources:

- **MITRE ATT&CK®**: the catalog of how attackers operate. It lists techniques (such as
  T1078, Valid Accounts) and the threat actor groups known to use them (such as APT29). It
  also gives ATT&CK's own mitigations and the analytics that detect each technique.
- **The Center for Threat-Informed Defense (CTID) mapping**: which security controls from
  NIST Special Publication 800-53, Revision 5, mitigate each ATT&CK technique.
- **DISA's Security Technical Implementation Guides (STIGs)**: the Defense Information
  Systems Agency's configuration rules for specific products, such as RHEL 9 or Windows
  Server 2022. Each rule is tied to the 800-53 controls it implements, and ranked by
  severity from CAT I (high) to CAT III (low).
- **The NIST 800-53 catalog**: the names and families of the controls.

Name a technique or an actor, and the system you care about, and the answer gives you:

- the 800-53 controls that mitigate it;
- the STIG rules that implement those controls on your system, most severe first, with
  DISA's exact check and fix text on request;
- ATT&CK's own mitigations, useful where the STIG has no rule for a control;
- ATT&CK's detection analytics, and which of them work with the logs you collect.

Two words carry a narrower meaning here than in an assessment:

- **Finding**: a STIG rule that applies to your system, a requirement to check. It is not a
  failure the server detected.
- **Mitigation**: a safeguard ATT&CK lists for a technique. "Mitigated" means ATT&CK lists
  one, not that you have deployed it.

The server does not scan anything, connect to your systems or know their configuration. It
can tell you what the guidance says to check and fix, but not whether you are compliant.

The answers come from a knowledge base: a local database of about 6 MB, built from those
public sources and installed once. The server runs on your machine, and contacts GitHub only
when asked to install a knowledge base or check for a newer one.

The terms are explained again in the [Glossary](#glossary), near the end.

## Contents

- [Summary](#summary)
- [Three ways to use it](#three-ways-to-use-it)
  - [Security controls assessor](#security-controls-assessor)
  - [System owner](#system-owner)
  - [SOC analyst, detection engineer or threat hunter](#soc-analyst-detection-engineer-or-threat-hunter)
- [Getting the model to use the server](#getting-the-model-to-use-the-server)
- [Scoping the prompt for a well-matched answer](#scoping-the-prompt-for-a-well-matched-answer)
- [More example prompts](#more-example-prompts)
  - [Starting from a technique](#starting-from-a-technique)
  - [Starting from an actor](#starting-from-an-actor)
  - [Finding the right benchmark](#finding-the-right-benchmark)
  - [Finding a technique](#finding-a-technique)
  - [Getting DISA's or MITRE's exact text](#getting-disas-or-mitres-exact-text)
  - [Keeping current](#keeping-current)
- [Two worked examples](#two-worked-examples)
  - [A live technique: T1078 on RHEL 9](#a-live-technique-t1078-on-rhel-9)
  - [A revoked id: T1086 on Windows 11](#a-revoked-id-t1086-on-windows-11)
- [Reading the answer](#reading-the-answer)
  - [Why did it answer about a different technique than I named?](#why-did-it-answer-about-a-different-technique-than-i-named)
  - [How does it match the actor I named?](#how-does-it-match-the-actor-i-named)
  - [When a technique has no controls](#when-a-technique-has-no-controls)
  - [Why did I get controls but no STIG steps?](#why-did-i-get-controls-but-no-stig-steps)
  - [Why does a control say it has no rules in the resolved STIG?](#why-does-a-control-say-it-has-no-rules-in-the-resolved-stig)
  - [Why does the answer say benchmarks were omitted?](#why-does-the-answer-say-benchmarks-were-omitted)
  - [Why did naming one product return three STIGs?](#why-did-naming-one-product-return-three-stigs)
  - [Why is a benchmark id I named reported as not in the knowledge base?](#why-is-a-benchmark-id-i-named-reported-as-not-in-the-knowledge-base)
  - [Why am I seeing steps from two versions of the same STIG?](#why-am-i-seeing-steps-from-two-versions-of-the-same-stig)
  - [Why does a rule say it is Not Applicable in its own text?](#why-does-a-rule-say-it-is-not-applicable-in-its-own-text)
  - [Why doesn't the answer include the check and fix steps?](#why-doesnt-the-answer-include-the-check-and-fix-steps)
  - [What do CAT I, II, and III mean, and why is the answer ordered that way?](#what-do-cat-i-ii-and-iii-mean-and-why-is-the-answer-ordered-that-way)
  - [How do I get more out of it?](#how-do-i-get-more-out-of-it)
- [Protect and Detect: ATT&CK mitigations and detections](#protect-and-detect-attck-mitigations-and-detections)
  - [What is in the protect and detect parts of an answer?](#what-is-in-the-protect-and-detect-parts-of-an-answer)
  - [How do I narrow detections to my platforms and logs?](#how-do-i-narrow-detections-to-my-platforms-and-logs)
  - [What do an actor's coverage counts mean?](#what-do-an-actors-coverage-counts-mean)
  - [Which tools does each conversation use?](#which-tools-does-each-conversation-use)
  - [Why is an analytic not detectable when I collect its log?](#why-is-an-analytic-not-detectable-when-i-collect-its-log)
- [Where an answer's facts came from](#where-an-answers-facts-came-from)
  - [Which artifacts did this answer come from, and can I check it myself?](#which-artifacts-did-this-answer-come-from-and-can-i-check-it-myself)
  - [Checking for a newer knowledge base](#checking-for-a-newer-knowledge-base)
  - [Installing or updating the knowledge base](#installing-or-updating-the-knowledge-base)
  - [What does it mean when a STIG is no longer current?](#what-does-it-mean-when-a-stig-is-no-longer-current)
- [Glossary](#glossary)
- [Reference](#reference)
  - [Tools](#tools)
  - [Revoked MITRE ATT&CK® ids](#revoked-mitre-attck-ids)
  - [Limits](#limits)

## Three ways to use it

Different people bring different questions:

- **Security controls assessor**: "How well are we covered against this actor?" They produce
  a coverage report.
- **System owner**: "What do I fix first on this system?" They work through the STIG
  findings in severity order.
- **SOC analyst, detection engineer or threat hunter**: "What can we see, and what should we
  collect or tune?" They produce log-source and analytic decisions.

Each section below gives a conversation tested against the server, prompt by prompt, and
what a good answer to each prompt contains. Ask in your own words. The prompts show the
detail that gets a precise answer: a technique or actor, a product with its version, and,
for detection, the logs you collect.

A good answer is "fetched from the server": it quotes what the server returned rather than
what the model remembers. If you cannot tell which it is, ask the model where a statement
came from.

The figures in an answer change as new ATT&CK and STIG releases arrive, so this guide
describes what to look for rather than quoting them.

### Security controls assessor

You evaluate how well a system's defenses hold up against a threat, and write up the gaps.
The result might support an authorization decision under the DoD Risk Management Framework
(RMF), or a report to leadership. Here the threat is APT29, a group ATT&CK tracks, and the
system is a Windows Server 2022 estate that collects Windows Security event logs and Sysmon.

1. > I'm assessing our Windows Server 2022 estate against APT29. We collect Windows
   > Security event logs and Sysmon. Give me a coverage picture: which of APT29's
   > techniques have no mitigation, which are mitigated but have no STIG rule on this
   > system, and which we can and cannot detect with the logs we have.

   A good answer sorts APT29's techniques into those groups and names the techniques in
   each by ATT&CK id. "No mitigation" means ATT&CK lists none for the technique. "Mitigated
   but no STIG rule" means ATT&CK lists one, but no rule in this system's STIG enforces a
   matching control. Neither says what you have deployed. Check that the counts in later
   answers match this one.

2. > For the techniques that are mitigated but have no STIG rule, what does MITRE say
   > each mitigation actually involves?

   A good answer gives MITRE's own description of each mitigation, which the model fetches
   from the server for this question. It should not describe a mitigation from memory.

3. > For the undetectable ones, what log sources would we need to add to detect them?

   A good answer names the log sources that ATT&CK's analytics for those techniques need,
   again fetched from the server. Some techniques have no analytic for Windows at all. A
   good answer says so, rather than suggesting a log that would not help.

4. > Summarize this per technique as a table I can put in an assessment report.

   A good answer is a table whose counts match the first answer. If they differ, ask the
   model which answer it took them from.

5. > List the CAT II STIG findings in this assessment that relate to account management,
   > with their titles.

   Expect a second lookup here: answers carry titles for CAT I findings only, and titles
   for lower severities are fetched on request. A good answer quotes DISA's titles with
   each finding's V- id, DISA's number for a requirement, such as `V-257777`. If a title
   reads like a paraphrase, ask the model where it came from.

### System owner

You are responsible for a system, as its administrator, its owner or its Information
System Security Officer (ISSO). You need to know which STIG rules matter most against a
threat, and exactly how to check and fix them. Here the system is a RHEL 9 server, and the
concern is ATT&CK technique T1078, Valid Accounts: an attacker signing in with real
credentials.

1. > I own a RHEL 9 server. Valid Accounts (T1078) is a concern. Which STIG findings
   > should I fix first?

   A good answer names the RHEL 9 STIG it used and says how many findings there are at
   each severity. It starts with the CAT I findings, the most severe, by V- id and title.
   If it reports controls but no STIG findings, it did not identify your system: see
   [Why did I get controls but no STIG steps?](#why-did-i-get-controls-but-no-stig-steps)

2. > Give me DISA's exact check and fix text for the CAT I findings.

   A good answer quotes DISA's check and fix text word for word, fetched from the server.
   Anything the model adds is labeled as its own explanation.

3. > For the controls that have no STIG rule on RHEL 9, what does MITRE recommend
   > instead, and why?

   A good answer names the controls the RHEL 9 STIG has no rule for, and gives ATT&CK's
   mitigations for T1078 with MITRE's reasoning. It presents them as MITRE's
   recommendations, to implement by other means, not as STIG requirements. That
   vendor-neutral reasoning is what a Plan of Action and Milestones (POA&M) entry needs
   beside DISA's rule.

4. > Which CAT II findings concern account lockout or password policy? Give their V- ids
   > and titles.

   As in the assessor's last prompt, expect a second lookup for the CAT II titles. A good answer quotes DISA's titles rather than describing the findings in its
   own words.

### SOC analyst, detection engineer or threat hunter

You decide which telemetry to collect, and what to alert on or hunt for. The server never
touches your logs. It tells you which ATT&CK analytics the logs you collect can support,
what each analytic looks for, and what to tune. The search itself happens in your security
information and event management system (SIEM). Here the actor is APT29 again, and the
telemetry is Windows Security event logs and Sysmon.

1. > I run detection for a Windows shop. Our telemetry is Windows Security event logs
   > and Sysmon. For APT29, which techniques can we already detect, and what exactly
   > should we be alerting on?

   A good answer says which of APT29's techniques those two logs can detect. For each, it
   names the ATT&CK analytics and the events they look for, fetched from the server.

2. > For the techniques we can't detect, which log sources and event channels would we
   > need to turn on?

   A good answer lists, for each undetectable technique, the log sources and channels its
   analytics need. It calls out the techniques that have no analytic for Windows at all.

3. > Pick one detectable technique and draft a detection from MITRE's analytic,
   > including what we should tune for our environment.

   A good answer builds the detection from one analytic's own description, log sources
   and channels. It lists the settings ATT&CK says to tune, which it calls mutable
   elements, rather than inventing fields.

4. > Are there STIG rules that would enable the audit logging these detections need?

   A good answer says plainly that the server does not link STIG rules to detections,
   because the published data does not. It may still point to STIG rules that turn on
   audit logging, but as its own suggestion, backed by DISA's text fetched from the
   server.

5. > List the CAT II STIG findings about audit logging that would support these
   > detections, with their titles.

   As in the other conversations, expect a second lookup for the CAT II titles, and a good
   answer quotes them.

The tools behind each of these conversations are listed under
[Which tools does each conversation use?](#which-tools-does-each-conversation-use)

## Getting the model to use the server

Wiring the server in is necessary but not sufficient. The failure mode to watch for is
not a wrong answer: it is the model answering from its training data and never calling a
tool at all. A general question like "What does STIG guidance say about SSH?" can get
answered fluently and incorrectly, with nothing in the reply to show a tool ran.

Prompts that reliably trigger tool use ask for something the model cannot already know:

- a specific ATT&CK technique id;
- a named actor;
- a STIG benchmark id;
- a system description with a product and version.

When you want certainty rather than a best guess, name the tool directly:

    Using #list_stigs, which RHEL benchmarks are in the knowledge base?

GitHub Copilot needs one more thing before any of this works: see the Agent-mode
requirement in the README's [quick start](../README.md#vs-code-github-copilot).

To tell whether a tool actually ran, look for the tool's output shape in the answer. Look
for benchmark ids, rule ids (`SV-...r..._rule`), or CAT severities the model has no other
way to produce verbatim. A fluent paragraph is a warning sign if it has no ids, no rule
numbers, and no `notes` explanation (the server's own caveats about the answer). It means
the model answered from memory, not from a result.

## Scoping the prompt for a well-matched answer

Two things narrow an answer well: an ATT&CK technique id or actor, and a system
description carrying both a product and a version, for example "RHEL 9" or "Windows 11"
rather than "Linux" or "our servers."

Vague input does not fail loudly. The server picks a STIG only when it recognizes both a
product and a version, and a vague description does not clear that bar. The result is a list of candidate systems
instead of a resolved one, and the answer comes back with controls but no STIG steps
until you narrow it.

If you already know which STIG benchmark applies, for example because your organization
mandates a specific one, name its id directly rather than describing the system and
letting resolution guess. `list_stigs` returns the ids the knowledge base actually holds;
passing one of them in `benchmark_ids` skips resolution entirely.

## More example prompts

The model picks which of the server's tools to call. Each prompt below is followed by the
tool it should call, so you can check which one ran; [Tools](#tools), under
Reference, lists them all.

Each prompt asks for something only a tool result supplies: benchmark ids, rule ids or
DISA's text. If the answer has none of those, name the tool in the prompt, as the
`#list_stigs` example above does. In GitHub Copilot, write `#` and the tool's name. In
Claude Code, say "using the list_stigs tool".

### Starting from a technique

- `What DISA STIG steps mitigate T1078 on Windows 11?` (`defenses_for_technique`)
- `Show only CAT I findings for T1059.001 on RHEL 9.` (`defenses_for_technique` with
  `severity`)

### Starting from an actor

- `Which ATT&CK techniques does APT29 use?` (`techniques_for_actor`)
- `Which STIG steps mitigate the techniques Lazarus Group uses on Windows 11?`
  (`techniques_for_actor` with `include_defenses`)
- `What can I detect of APT29 on Windows Server 2022 with Security and Sysmon logs?`
  (`techniques_for_actor` with `include_defenses`, `platforms` and `log_sources`)

### Finding the right benchmark

- `Which STIG benchmarks apply to RHEL 9?` (`resolve_system`)
- `Using #list_stigs, which Cisco benchmarks are in the knowledge base?` (`list_stigs`)

### Finding a technique

- `Which ATT&CK techniques cover credential dumping?` (`search_techniques`)

### Getting DISA's or MITRE's exact text

- `Quote DISA's check and fix text for V-253284 word for word, then explain it.`
  (`finding_details`)
- `Quote MITRE's text for M1032 on T1078.` (`defense_details` with `technique_id`)

### Keeping current

- `Is a newer stig-mcp knowledge base published?` (`check_sources`)

[Two worked examples](#two-worked-examples), next, walk through what a technique
answer contains.

## Two worked examples

### A live technique: T1078 on RHEL 9

Prompt: `What DISA STIG steps mitigate T1078 on RHEL 9?`

The model calls `defenses_for_technique("T1078", system_description="RHEL 9")`.
"RHEL 9" names both a product and a version, so it resolves the RHEL 9 STIG benchmark
with high confidence rather than returning candidates.

The response's `technique` block is T1078 (Valid Accounts) with `redirected_from: null`,
since T1078 is a live id. `resolved_systems` names the RHEL 9 benchmark. `protect.controls`
maps each 800-53r5 control id mapped to T1078 (AC-2, AC-3, AC-6, and others) to its
`rules` for that benchmark, and `protect.findings` lists each of those rules once,
CAT-ordered. `protect.mitigations` lists ATT&CK's mitigations for T1078, among them M1026
and M1032, and `detect` names DET0560 with its analytics; neither carries text until
`defense_details` is called.
Some controls come back with rules. AC-2 is one, though DISA tags none of its RHEL 9 rules
to AC-2 itself: they sit under its enhancements, and AC-2's `via` names which. Others come
back empty with a `notes` entry reading "Control AC-5 has no rules, at the control or any of
its enhancements, in the resolved STIG(s)." That means the RHEL 9 STIG, as DISA wrote it,
has no rule tagged to a CCI under AC-5 or its enhancements, not that AC-5 is irrelevant.
To quote the steps themselves, the model then calls `finding_details` with the V- ids of the
findings it is answering about, and reads DISA's check and fix text from that.

### A revoked id: T1086 on Windows 11

Prompt: `What DISA STIG steps mitigate T1086 on Windows 11?`

T1086 was ATT&CK's id for PowerShell before it was retired and folded into T1059.001, the
"PowerShell" sub-technique of Command and Scripting Interpreter. The model calls
`defenses_for_technique("T1086", system_description="Windows 11")`. T1086 is not a
live id, so the knowledge base looks up its `revoked-by` replacement instead of failing.

The response's `technique` block is T1059.001, with `redirected_from: "T1086"`, and
`notes` opens with "ATT&CK revoked T1086 (PowerShell) in favor of T1059.001. Answering
for T1059.001; cite that id instead." Everything after that, `resolved_systems`,
`protect.controls`, `protect.findings`, follows exactly as in the first example, scoped to
Windows 11. The surprising part is not an error: it is the intended behavior for a retired id,
and the fix is to use T1059.001 in future calls.

## Reading the answer

### Why did it answer about a different technique than I named?

You named a retired ATT&CK id. The knowledge base answers for the replacement technique
and sets `redirected_from` to the id you gave it, with a note naming both ids. Cite the
replacement id going forward. [Revoked MITRE ATT&CK® ids](#revoked-mitre-attck-ids), under
Reference, explains why.

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

`defenses_for_technique` can come back with an empty `protect.controls`: the CTID mapping
(and any local override) simply named none for this technique. When that happens, `notes`
carries one of five messages explaining why, drawn from the technique's own ATT&CK
metadata and the CTID mapping's. Each is shown below as you would actually see it, with the
value it fills in written as _technique_id_, _created_, _version_ or _released_ so the
placeholder names stay readable:

- **Suppressed by your own overrides**: "All CTID-mapped controls for _technique_id_ are
  suppressed in overrides.yaml." Remove the `suppress:` entry for this technique if that
  was not intended.
- **CTID reviewed it and found nothing**: "CTID reviewed _technique_id_ and found no
  800-53r5 control that mitigates it." Nothing to do; this is CTID's own considered
  verdict, not missing data.
- **The technique is newer than the mapping**: "_technique_id_ was added to ATT&CK on
  _created_, after ATT&CK _version_ (_released_), which the CTID mapping covers." Nothing
  to fix here: a later CTID mapping may cover it. `check_sources` reports a newer knowledge
  base once one built from that mapping is published, and `stig-mcp-fetch --check` reports
  the mapping itself as soon as CTID publishes it.
- **A mapping gap**: "The CTID mapping does not cover _technique_id_. Add a mapping in
  overrides.yaml if this is a gap." This is the one cause naming an actual gap; add the
  control there if you believe one applies.
- **Not enough data to tell which of the above it is**: "_technique_id_ is not in the CTID
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

- **No system given**: You called without `system_description` or `benchmark_ids`, so there is
  nothing to scope STIG findings to. The note says as much and names both parameters.
- **Nothing matched confidently**: Usually your `system_description` did not name a
  distinctive product and version, so nothing cleared the confidence bar. It can also
  happen after you named one correctly: see "Why did naming one product return three
  STIGs?" below for a wording that empties the scope even though the product was named
  plainly. Either way, the note suggests calling `resolve_system` or `list_stigs` to see
  candidates, or passing `benchmark_ids` explicitly.
- **The version you named is not held**: Your description named a product this knowledge
  base does cover, at a version it does not. The note replaces the one above, names the
  benchmarks that are held and the versions they cover, and tells you to pass `benchmark_ids`
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
- **Naming two systems gets you a note per system**: A description that names more than
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
  - **A piece that is a modifier rather than a product can still produce one**:
    `Red Hat Enterprise Linux 9, x86_64` is told nothing is held for `x86_64` and pointed
    at a Solaris benchmark; `Red Hat Enterprise Linux 9, site 1` is pointed at the Apache
    and IIS site benchmarks. Both are noise. The sentence is scoped to the words it quotes,
    so it is not a claim about your RHEL, but the "closest benchmark" clause is unhelpful.
    Telling these apart from a real product needs judgment this knowledge base does not
    have, so they are left in rather than guessed at.
  - **Two pieces naming related products can recommend overlapping `benchmark_ids`**:
    `Cisco IOS XE 17, Cisco IOS 15` returns two lists, the second a superset of the first.
    Both are true; neither is the union.
- **The benchmark is not version-specific**: Some products get one STIG rather than one
  per release, so naming your build costs you the auto-scope. The note says which
  benchmark this is and that the mismatch is not evidence it does not apply.
- **Your build predates any official STIG**: vSphere 8.0 GA through U1e is the example:
  DISA published only a STIG Readiness Guide for those builds, which is not an official
  STIG and is not in this knowledge base. The V1 STIG applies from 8.0 U2 onward. The
  800-53 controls still apply and are still returned; a top-level note names the build and
  says why there are no steps.
- **No applicable benchmark**: A benchmark did resolve, but it does not enforce most or
  any of the controls mapped to this technique. You will see this as a `notes` entry per
  control rather than one overall failure; see the next question.

### Why does a control say it has no rules in the resolved STIG?

The 800-53r5 mapping and the STIG benchmark are independent sources. A control can be
mapped to the technique (from CTID's ATT&CK-to-800-53 mapping or a local override) while
the specific benchmark you resolved to has no rule tagged to a CCI under that control.
That is not an error: different products enforce different slices of 800-53, and DISA
writes STIG rules per product, not per control. The control is still relevant; this
benchmark just does not have a checkable rule for it.

CTID maps techniques to base controls such as AC-6, while DISA often tags a rule to one of
the control's enhancements, such as AC-6(9). The server counts a rule tagged to an
enhancement toward its base control, so a control reported with no rules has none at the
control or any of its enhancements. A control whose rules come only through enhancements
says so in `via`, which maps each enhancement to those rules.

### Why does the answer say benchmarks were omitted?

When more benchmarks tie with the last benchmark shown than the limit allows, the response
says so: "N further benchmarks scored exactly as well as the last one shown ... and were
omitted." Those N were cut by the cap rather than by score, which is what raising `limit`
recovers for a `resolve_system` caller. A `defenses_for_technique` caller has no `limit`
parameter to raise; call `resolve_system` with a higher limit instead, or pass `benchmark_ids` to
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

`benchmark_ids` is matched literally against the ids `list_stigs` returns, case-sensitively.
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
`include_defenses`. Ask for the benchmarks you need rather than the most you are allowed.

### Why am I seeing steps from two versions of the same STIG?

A few products ship two STIG versions at once, and their remediations differ. vSphere 8.0
is the only one in the current library: DISA publishes V2 as current guidance and bundles
V1R1 as supplemental guidance for older builds. Ask about ESXi 8.0 without saying which
build you run and you get both, labeled by `benchmark` (`…/1` and `…/2`), because neither
can be ruled out.

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
finding, and an actor's techniques share most of their findings, so an answer carrying all
of it would run to megabytes. VS Code's Copilot agent currently saves any tool result over
8 KB to a temporary file and shows the model only its first 500 characters; Claude Code
saves any text result over 50,000 characters to a file. A model then reads the file in
pieces and tends to summarize, which is how a list of CAT I findings comes back
incomplete.

So `defenses_for_technique` and `techniques_for_actor` send one line of compact JSON that
lists each finding once, by benchmark, V- id and CAT, with titles for CAT I only unless
`severity` names other CATs (`summary.titles` then reads "CAT I only" and a note names the
call that brings the others' titles), and
opens with `summary`: the number of rules found, the number at each CAT, `control_counts`
(how many controls map and how many have rules in the resolved STIGs, counting rules
tagged to a control's enhancements), the mitigation and detection counts, `cat_i` (the CAT
I V- ids with their count) and, last, the ids of the controls that have rules.
`techniques_for_actor` also counts the techniques, and with `include_defenses` puts
`coverage` ahead of the mitigation and detection counts, so the gap counts sit inside the
preview too. The counts come first so they fall inside that preview, and they spare the
model counting long lists itself, which it gets wrong. How many CAT I ids also fit depends
on the client: Copilot may reformat the answer before saving it, so rely on `cat_i.count`
to tell whether the ids in view are all of them. That count is of V- ids, not rules: a
requirement held at two majors, as vSphere 8.0's are, is one V- id and two rules.

Ask for the steps of the findings you care about and the model calls `finding_details`,
which returns DISA's exact check and fix text, and the CCIs, for up to 50 rule ids or V-
ids at a time. A V- id that two benchmarks or two majors share returns every match, each
labeled with its benchmark.

In `techniques_for_actor` with `include_defenses`, each technique names its controls
grouped by where the mapping came from (`ctid` or `override`), `controls` lists each
control once with its rules, and a control with no rules in scope is named in one note
rather than under every technique that maps to it.

If Copilot asks permission to read a file named like `…copilot-tool-output-….txt`, that
is it reading this server's answer back from where it saved it. It is safe to allow.

### What do CAT I, II, and III mean, and why is the answer ordered that way?

CAT is DISA's severity ranking: CAT I is the highest-risk finding (mapped from XCCDF
`severity="high"`), CAT II is medium, and CAT III is low, or unknown severity treated as
the safe default. `findings` (`protect.findings` in a technique answer) are always listed
CAT I first, then II, then III, and a control's `rules` follow the same order, so the
findings that matter most for risk are the ones you see first without having to sort them
yourself. Pass `severity` (for example
`["I"]`) to leave the lower levels out of the answer altogether. Naming a CAT in `severity`
also brings its findings' titles: `["II"]` lists the CAT II findings with their titles.

### How do I get more out of it?

- **Narrow to specific benchmark ids**: Pass `benchmark_ids` once you know which benchmarks
  apply, instead of re-describing the system every time.
- **Ask for CAT I only**: `severity` narrows an answer to the CAT levels you name, so
  "only CAT I findings" becomes a smaller answer rather than a filter the model applies to
  a large one.
- **Ask which benchmarks exist for a product before asking for steps**: `list_stigs` with
  a `filter` substring (a product name, or a benchmark id fragment) shows what is on hand
  before you commit to a `system_description` or `benchmark_ids`.
- **Ask for the exact steps, word for word**: Every finding carries a `rule_id` and
  `group_id`; asking the model to fetch them with `finding_details` gets DISA's own
  `check_text` and `fix_text`, and lets you check the source STIG XCCDF yourself. The tool
  asks the model to quote that text and label anything it adds, but a model may still
  paraphrase it, or cite a third-party website as DISA's. Say so in the prompt, for example
  `Quote DISA's check and fix text for V-253284 word for word, then explain it`. The
  `stig_title` and `stig_release` in that answer name the benchmark release the text came
  from.
- **Ask how current the knowledge base is**: `list_stigs` returns each benchmark's own DISA
  revision number as `version`, not a build date. `defenses_for_technique` and
  `techniques_for_actor` carry that in their `sources` block instead: which DISA STIG
  library compilation, and `ingested_at` for when this knowledge base was built. Call
  `check_sources` to learn whether a newer knowledge base is published.

## Protect and Detect: ATT&CK mitigations and detections

Every `defenses_for_technique` answer has two parts, named for two functions of the NIST
Cybersecurity Framework (CSF) 2.0. `protect` says what prevents or limits the technique, and
`detect` says how to spot it. The questions below explain each part, the options that narrow
it, and the tools each role's conversation relies on.

### What is in the protect and detect parts of an answer?

`protect` holds three things:

- `controls` are the 800-53r5 controls CTID maps to the technique.
- `findings` are the STIG rules that implement them on the system you named.
- `mitigations` are ATT&CK's own safeguards, such as `M1026 Privileged Account Management`.

`detect` holds two:

- `detection_strategy` names the technique's ATT&CK detection strategy, such as `DET0560`
  for T1078.
- `analytics` maps each of its analytics (`AN1543` to `AN1547` for T1078) to its name and
  platforms.

`detect` is null for a technique ATT&CK gives no detection strategy.

The answer carries ids, names and platforms, not MITRE's text.
`defense_details` takes up to 10 ids of any of those three kinds and returns MITRE's text:

- a mitigation's description, and how many techniques it covers;
- each analytic's description, platforms, `log_sources` and `mutable_elements`, the
  settings a detection engineer tunes.

Each log source gives the log name (such as `WinEventLog:Security`), its channel (such as
`EventCode=4624`) and the `data_component` it records, by id and name, or null when ATT&CK
names no component the bundle defines. Pass `technique_id` to `defense_details` to get
MITRE's text about a mitigation on that particular technique, as `technique_description`.

### How do I narrow detections to my platforms and logs?

Two optional filters judge the Detect side. Neither removes an analytic from the answer;
each adds a list of the analytics that pass.

- `platforms` lists ATT&CK platform names in any case (`["Windows"]`). `detect.applicable`
  then lists the ids of the analytics that apply. An unknown name is refused with the full
  list.
- `log_sources` lists the telemetry you collect, using ATT&CK's log source names as
  `defense_details` prints them. `detect.detectable` then lists the ids of the analytics
  whose log sources you cover. `log_sources` takes up to 100 names, and an unknown one is
  refused naming the closest matches. Names are ATT&CK's spellings, such as
  `WinEventLog:Sysmon` rather than the Sysmon channel's name; the model can retry with one
  of the suggestions.

An analytic is detectable only when every log source it needs is in your list, and one that
names no log source at all is never detectable. When you also pass `platforms`, an analytic
counts as detectable only if it is applicable too, in the list and in `summary`.

Channels are not compared. Naming a log asserts you collect it, and the analytic's channel
says which events within it matter. Case is ignored, because ATT&CK 19.2 spells four names
two ways (`macos:unifiedlog` and `macOS:unifiedlog`, for one): either spelling matches both.

Each list is present only when its filter was given (absent: not judged), and is empty when
none qualify. `summary` counts the mitigations and the analytics before `cat_i`, with how
many are applicable and detectable when you passed the matching filter.

### What do an actor's coverage counts mean?

With `include_defenses`, `techniques_for_actor` adds the same ids to each technique:

- the mitigation and detection strategy ids;
- `analytics` as an id-to-platforms map, without the names `defenses_for_technique` gives;
- `applicable` and `detectable` id lists. With `platforms`, each technique's `detectable`
  is a subset of its `applicable`, as in `defenses_for_technique`.
- `gaps`, the names of the coverage classes below that the technique falls in, in the order
  listed. `detectable` is not a gap, so a technique with nothing missing has an empty list.

The answer also gets a top-level `mitigations` map naming each M-id once, and a `coverage`
block in `summary`, placed right before `cat_i`, ahead of the mitigation and detection
counts. The three count different things. `summary.mitigations` counts references across
techniques, so a mitigation on two techniques counts twice. `summary.detection` counts
analytics, and `coverage` counts techniques.

`coverage` holds:

- `techniques`: how many the actor uses.
- `without_mitigation`: techniques ATT&CK offers no mitigation for.
- `mitigated_without_rules`: techniques with a mitigation but no control that has rules in
  the scoped STIG (at the requested CAT levels, when you pass `severity`); present only when
  a system was scoped.
- `without_applicable_analytic`: no analytic for the platforms you named; present only with
  `platforms`.
- `detectable`: at least one analytic is satisfied by your `log_sources`, counting only
  applicable ones when you named `platforms`.
- `undetectable`: none is; present with `detectable`, only with `log_sources`.

The last three are judged in that order, so with both filters each technique falls in
exactly one of them. Read `coverage` for the counts, then each technique's `gaps` for which
techniques make them up. The server has already applied these rules, so there is nothing to
derive from `controls` or `analytics`.

### Which tools does each conversation use?

- **Security controls assessor**: `techniques_for_actor` with the actor, the system,
  `include_defenses`, `platforms` and your `log_sources`. Then `defense_details` on the
  M-ids of the techniques whose `gaps` name `mitigated_without_rules` (what safeguard is
  missing from the STIG), and on the DET-ids of those naming `undetectable` (which log
  sources would close the gap).
- **System owner**: `defenses_for_technique` with the system, `cat_i` first, and
  `finding_details` for DISA's steps. `protect.mitigations` names ATT&CK's safeguards
  beside the controls, and `defense_details(["M1032"], technique_id="T1078")` gives MITRE's
  reason it matters here. When a control has no rules in the scoped STIG, the technique's
  mitigations say what to implement by other means.
- **SOC analyst, detection engineer or threat hunter**: `techniques_for_actor` with
  `include_defenses` and the `log_sources` you have. Then `defense_details` on the DET-ids
  of the `undetectable` techniques; each analytic's `log_sources` say what to collect, and
  its `mutable_elements` what to tune. The enabling steps for a log source are in the
  vendor's documentation, not here. The STIG rules that turn on auditing are in
  `finding_details` like any other rule. This server does not link them to analytics,
  because the data does not.
- **Any of them, for CAT II or III titles**: the same call again with `severity` naming
  those CATs, as described under
  [What do CAT I, II, and III mean?](#what-do-cat-i-ii-and-iii-mean-and-why-is-the-answer-ordered-that-way)

### Why is an analytic not detectable when I collect its log?

Because it needs more than one. An analytic that correlates `WinEventLog:Security` with
`WinEventLog:Sysmon` is listed in `detectable` only when both are in `log_sources`. Call
`defense_details` on the AN-id to see every log source it names.

## Where an answer's facts came from

### Which artifacts did this answer come from, and can I check it myself?

`defenses_for_technique`, `techniques_for_actor` and `finding_details` responses carry
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
`resolved_systems` entries (the placeholder row synthesized for a `benchmark_ids` value the
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

Answers from `defenses_for_technique`, `techniques_for_actor` and `finding_details`
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

### What does it mean when a STIG is no longer current?

A resolved benchmark that is not confirmed-current library guidance gets a note in
`notes` explaining why, in one of four forms (`label` below is the benchmark id followed
by its release label, the same token `finding_details` exposes as `stig_release`):

- **DISA retired it**: `DISA marked label deprecated on <date>.` DISA sets this status
  itself, inside the XCCDF; it can appear even on a benchmark the current library still
  ships.
- **It came from a sunset archive**: `label came from a sunset compilation and is not in
  <library artifact>.`
- **It was supplied locally**: `label (<release info>) was supplied as a local artifact
  and is not in <library artifact>. It may be newer than that compilation or retained
  from an earlier one.`
- **There is no library to compare against**: `This knowledge base was built without a
  library compilation, so whether label is current guidance cannot be determined.`

A benchmark absent from the library is not necessarily retired. Nothing inside a STIG's
own XCCDF distinguishes "DISA stopped shipping this" from any other reason it might be
missing, so these notes state a verifiable fact about where the benchmark came from, not
a claim about why. A current library benchmark that is not deprecated gets no currency
note at all, since nothing about it needs qualifying. To find out the actual reason a
specific benchmark is absent from the library, see "Why a benchmark disappeared" in
[docs/operations.md](operations.md).

## Glossary

- **Analytic (AN- id)**: an ATT&CK description of one way to detect a technique on one
  platform, naming the log sources and events it reads, such as `AN1543`.
- **ATT&CK**: MITRE's public catalog of how attackers operate: techniques, the groups that
  use them, mitigations and detections.
- **Benchmark**: one STIG, usually for one product and major version, named by an id such as
  `RHEL_9_STIG`. `list_stigs` lists the ids this knowledge base holds.
- **CAT I, II, III**: DISA's severity categories for a STIG rule: high, medium and low.
- **CCI (Control Correlation Identifier)**: DISA's id linking a STIG rule to the 800-53
  control it implements, such as `CCI-000366`.
- **Control**: a safeguard in NIST SP 800-53, such as AC-2 (Account Management). An
  enhancement strengthens its base control and is written with a number in brackets, such
  as AC-6(9).
- **CSF (Cybersecurity Framework)**: NIST's framework of six functions: Govern, Identify,
  Protect, Detect, Respond and Recover. The answer's `protect` and `detect` parts are named
  for two of them.
- **CTID (Center for Threat-Informed Defense)**: publishes the mapping from ATT&CK
  techniques to the 800-53 controls that mitigate them.
- **Data component**: the kind of activity a log source records, such as process creation,
  as ATT&CK names it.
- **Detection strategy (DET- id)**: ATT&CK's approach to detecting one technique, made up
  of analytics, such as `DET0560`.
- **DISA (Defense Information Systems Agency)**: the DoD agency that publishes STIGs.
- **DoD**: the US Department of Defense.
- **Finding**: a STIG rule that applies to the system you named, a requirement to check.
  It is not a failure the server detected.
- **Group (G- id)**: a threat actor ATT&CK tracks, such as APT29 (`G0016`).
- **Knowledge base**: the local database the server answers from, built from ATT&CK, the
  CTID mapping, the STIGs and the NIST catalog. It is installed once and updated from this
  project's GitHub releases.
- **Log source**: a log ATT&CK names in its analytics, such as `WinEventLog:Security`.
- **MCP (Model Context Protocol)**: the standard an AI assistant uses to call tools such as
  this server's.
- **Mitigation (M- id)**: an ATT&CK safeguard against one or more techniques, such as
  `M1032` (Multi-factor Authentication).
- **Mutable elements**: the settings in an ATT&CK analytic that you tune for your
  environment, such as `TimeWindow` or `UserContext`.
- **NIST SP 800-53 Rev. 5 (800-53r5)**: NIST's catalog of security and privacy controls,
  Revision 5.
- **Override**: a local correction to the CTID mapping, kept in `overrides.yaml` by
  whoever builds the knowledge base.
- **Platform**: an operating environment ATT&CK names, such as Windows, Linux or macOS.
- **POA&M (Plan of Action and Milestones)**: the RMF record of how and when a weakness
  will be fixed.
- **RMF (Risk Management Framework)**: the process DoD systems follow to be authorized to
  operate.
- **Rule id and V- id**: a STIG requirement has a V- id (`V-257777`) and a rule id
  (`SV-257777r1155676_rule`) naming one revision of it. DISA's XCCDF calls the V- id the
  group id, which has nothing to do with ATT&CK groups. `finding_details` accepts either.
- **Schema**: the layout of the knowledge base. A new stig-mcp version may need a knowledge
  base with a newer schema, and says so.
- **SIEM (security information and event management)**: the system that collects logs and
  runs detections against them.
- **SOC (security operations center)**: the team that monitors for and responds to attacks.
- **STIG (Security Technical Implementation Guide)**: DISA's configuration rules for one
  product, each with check and fix text.
- **STIG Library Compilation**: DISA's periodic zip of every current STIG, which this
  knowledge base is built from.
- **Sunset**: a STIG DISA no longer ships in its library, kept only from an older
  compilation.
- **Technique (T- id)**: one way attackers achieve a goal, such as T1078 (Valid Accounts).
  A sub-technique adds a number after a dot, such as T1059.001 (PowerShell).
- **XCCDF**: the XML format DISA publishes STIGs in.

## Reference

### Tools

- `defenses_for_technique(technique_id, system_description?, benchmark_ids?, severity?, platforms?, log_sources?)`
- `techniques_for_actor(actor, system_description?, benchmark_ids?, include_defenses?, severity?, platforms?, log_sources?)`
- `finding_details(ids)` returns DISA's check and fix text for findings named by rule id or V- id
- `defense_details(ids, technique_id?)` returns MITRE's text, log sources and tunables for mitigations, detection strategies and analytics named by M-, DET- or AN- id
- `resolve_system(system_description, limit?)` returns `{candidates, notes}`
- `search_techniques(query, limit?)`
- `list_stigs(filter?)`
- `install_knowledge_base(release?, path?, sha256?)`
- `check_sources()` returns `{kb_ready, not_ready, installed, newest, action, reason}`, plus `newer_schema_available` when a release needs a newer stig-mcp

### Revoked MITRE ATT&CK® ids

ATT&CK retires and renumbers techniques between releases, and published mapping sets lag
behind. The knowledge base records the `revoked-by` relationships it can resolve to a
technique the bundle still defines, so a mapping written against a retired id is applied
to its replacement instead of being dropped, and both `defenses_for_technique` and
`search_techniques` accept a retired id. Each answers for the replacement and reports the
old id in `redirected_from`. A maintainer-side tombstone still removes a pair, and its
technique id is remapped the same way, so a tombstone written against a retired id also
removes the pair the mapping set already carried on the replacement. If a mapping here
looks wrong or missing, that is fixable, just not from this side: see "Mapping overrides"
in [docs/operations.md](operations.md), written for whoever builds and maintains this
knowledge base.

### Limits

This server maps ATT&CK techniques to 800-53r5 controls to DISA STIG guidance text. It
does not scan anything, does not connect to the system you are asking about, and does not
know your actual configuration. It can tell you what the guidance says to check and fix;
it cannot tell you whether you are compliant. Reading a `check_text` back to you is not
the same as having run the check.
