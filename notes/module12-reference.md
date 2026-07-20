# Module 12 Reference

## Sections 12.6-12.8: Covered Conceptually

Given the depth of hands-on validation already completed in 12.1-12.5
(real mock Splunk/ADX servers, a genuine security methodology flaw
found and fixed, end-to-end verification), sections 12.6-12.8 are
captured conceptually rather than separately built:

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
