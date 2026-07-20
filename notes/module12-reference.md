# Module 12 Reference

## Sections 12.6-12.8: Covered Conceptually

Given the depth of hands-on validation already completed in 12.1-12.5
(real mock Splunk/ADX servers, a genuine security methodology flaw
found and fixed, end-to-end verification), sections 12.6-12.8 are
captured conceptually rather than separately built.

That 12.1-12.5 work is recorded in `notes/module12-reference.md` in the
`mcp-hayabusa` repo (`~/mcp-hayabusa/notes/module12-reference.md`) —
sections 12.1 through 12.5 for the build itself, and "Session Notes: A
Real Security Design Flaw Found and Fixed" for the finding. This repo
holds the artifacts that work produced; that file holds the narrative.

**12.6 (Batch Report Flow):** the same persona, same mock
infrastructure, with a broader query (all hosts, all users, save to
file) instead of a targeted one. Already demonstrated the harder part
(the correlation logic and honest self-limiting) — running it
unscoped is a prompt change, not new capability.

**12.7 (Slash Command Alternative):** the persona-vs-command tradeoff
already has a real, tested precedent from Module 6/11 — same
reasoning applies here: this workflow involves genuinely varied,
follow-up-driven questions ("what did X do" → "now just the S3 calls"
→ investigate an anomaly), which is exactly what the course says
favors the persona approach over a slash command. If this became a
routine, identically-shaped daily check, converting to
/correlate-aws would be the right move — but the actual work this
session (finding and fixing a real filtering flaw through iterative
questioning) is a genuine example of why the persona pattern fit
better here.

**12.8 (Applying Elsewhere):** the pattern (persona knows two systems'
query languages + join keys + honest inference-not-join discipline)
generalizes directly. The concrete, hard-won lesson from this module's
real finding applies broadly: any cross-system correlation persona
that filters retrieval by an attacker-controllable field (user-agent,
source IP, hostname) risks silently hiding the exact activity the
correlation exists to catch. Filter for classification and reasoning:
never for retrieval. That's a durable principle beyond this specific
AWS/Splunk/ADX example — worth carrying into EDR↔Sysmon,
Entra↔Activity Log, or any future persona in this pattern.

## Additional Session Notes: Two More Real Discrepancies Found

**`--append-system-prompt-file` is undocumented but functional.** It does
not appear in `claude --help`, which lists only `--append-system-prompt
<prompt>` and `--system-prompt <prompt>` as standalone flags; the `-file`
variants show up solely inside prose describing other flags. Reading the
help output alone suggests the flag doesn't exist. Testing it shows it
does — a persona file passed via `--append-system-prompt-file` is
genuinely applied to the session, verified by passing a file whose only
instruction was to emit a marker token, and seeing the token come back.
The Module 11 personas (threat-hunter, ir-responder, detection-engineer)
and this module's cross-siem persona all rely on it and all work
correctly; no substitute is needed. `--append-system-prompt "$(Get-Content
<path> -Raw)"` is an equivalent fallback if the flag is ever removed. **The
discrepancy here is documentation, not capability** — and the near-miss was
concluding "the flag doesn't exist" from `--help` without running it once.

**PowerShell profile split (5.1 vs. 7) silently broke the aliases.**
Windows maintains separate profile files for Windows PowerShell 5.1
and PowerShell 7 (pwsh) — a function added to one is invisible in the
other. The claude-xsiem alias was correctly written but only to the
5.1 profile; a fresh pwsh 7 session (Claude Code's actual reported
shell) never saw it. Fixed via dot-sourcing: the pwsh 7 profile now
loads the 5.1 profile (path derived from $PROFILE, guarded by
Test-Path), making the 5.1 file the single source of truth for all
four persona aliases.

**A verification lesson worth keeping:** the first attempt to confirm
this fix "worked" by manually dot-sourcing the profile file and
checking the functions existed — which only proves the file is
syntactically valid, not that a real new shell session actually loads
it. The correct test (opening a genuinely fresh shell and calling the
alias) was what actually caught and confirmed the bug. Testing the
right thing matters as much as testing at all.

The same lesson explains the first item above: `--help` was read as
evidence about capability, when only running the flag could settle it.
Both near-misses came from checking something adjacent to the claim
rather than the claim itself.

### Updated running count

This module surfaced two additional real discrepancies beyond the
userAgent filtering methodology flaw — the undocumented
`--append-system-prompt-file` flag and the PowerShell profile split —
bringing this module's total to three. Module 11's notes record "five
distinct findings across those four modules" (3, 7 x2, 8, 11), so the
course total is **eight**, not nine — five prior plus this module's
three. The flag entry is a documentation gap rather than a broken
capability; it is counted because the gap is real and actively
misleading, not because anything is broken.
