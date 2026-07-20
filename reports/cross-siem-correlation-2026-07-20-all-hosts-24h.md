# Cross-SIEM Correlation Report — Unscoped 24h Batch Run

**Scope:** all hosts, all users; Sysmon `index=sysmon` + CloudTrail `CloudTrail` table; window 2026-07-19T02:40:49Z → 2026-07-20T02:40:49Z (last 24h, run at 2026-07-20T02:40:49Z); correlation window ±60s.

Retrieved: 4 Sysmon `aws.exe` process-create events (1 host, 1 user), 5 CloudTrail events (1 account, 1 identity). The CloudTrail side was fetched unfiltered by client or source IP — see *Method notes*.

There is no shared join key between these two systems. Every pairing below is **inferred** from time proximity, CLI-verb-to-API-name mapping, user-agent, and source IP. None of them is a database join, and none should be read as a confirmed match.

---

## Correlation table (Matched)

| Time (UTC) | Host | Command | CloudTrail event | Δ | Confidence |
|---|---|---|---|---|---|
| 2026-07-19T23:00:03.412Z | condef-win11a | `aws sts get-caller-identity` | `GetCallerIdentity` (sts) @ 23:00:05.900Z | +2.49s | high |
| 2026-07-20T00:00:41.088Z | condef-win11a | `aws s3 ls` | `ListBuckets` (s3) @ 00:00:44.210Z | +3.12s | high |
| 2026-07-20T00:30:12.664Z | condef-win11a | `aws iam list-users` | `ListUsers` (iam) @ 00:30:14.980Z | +2.32s | high |

**Why high confidence on each:** verb-to-API mapping is exact (`get-caller-identity`→`GetCallerIdentity`, `iam list-users`→`ListUsers`, and `aws s3 ls` with no argument correctly yields `ListBuckets` rather than `ListObjectsV2`); Δ is 2–4s, well inside the window and consistent with normal CLI-to-delivery latency; `userAgent` is `aws-cli/2.15.30 Python/3.11.8 Windows/10 exe/AMD64`, matching the host OS and the CLI FileVersion 2.15.30 recorded by Sysmon; `sourceIPAddress` is `198.51.100.23` on all three; `readOnly: true` is correct for all three read commands. No competing candidate event fell inside ±60s of any of these, so the pairings are unambiguous as well as plausible.

These three events establish **198.51.100.23 as the workstation's egress IP** and `AKIAIOSFODNN7EXAMPLE` as the key in use on-host. That baseline is what makes the unmatched CloudTrail section below meaningful.

---

## Unmatched Sysmon (aws.exe ran, no API event)

| Time (UTC) | Host | Command | Hypothesis | How to confirm |
|---|---|---|---|---|
| 2026-07-20T01:15:27.005Z | condef-win11a | `aws configure list` | **Expected — not suspicious.** `aws configure` is local-only: it reads `~/.aws/config` and `~/.aws/credentials` and makes no API call. The absence of a CloudTrail event is correct behaviour, not a gap. | No CloudTrail confirmation is possible or needed. If intent matters, a Sysmon FileCreate/FileAccess event (EventID 11/ Sysmon config permitting) on `%USERPROFILE%\.aws\credentials` around 01:15:27Z would show whether the profile was merely listed or the credential file was read. |

One caveat worth stating rather than burying: `aws configure list` **prints the access key ID (truncated) and the profile source** to stdout. Coming 25 minutes before the first off-host use of these credentials, it is consistent with an operator confirming which key is loaded — and equally consistent with an attacker enumerating available credentials before exfiltrating them. It is not evidence on its own, but it is the last on-host action before the account goes off-host, and it should not be dismissed just because a missing CloudTrail event is expected here.

---

## Unmatched CloudTrail (API event, no host process)

| Time (UTC) | Event | Source IP | Identity | Hypothesis | How to confirm |
|---|---|---|---|---|---|
| 2026-07-20T01:40:08.140Z | `CreateAccessKey` (iam) — **`readOnly: false`** | **203.0.113.47** | `condef-admin` / `arn:aws:iam::123456789012:user/condef-admin`, key `AKIAIOSFODNN7EXAMPLE` | **Credential theft with persistence.** Same identity and same access key as the three matched on-host events, same `aws-cli/2.15.30` user-agent — but from an IP that is not the workstation's egress IP, with no `aws.exe` process on any host to explain it. The user-agent matching the host's CLI while the IP does not is consistent with an attacker replaying stolen static credentials, the UA being trivially settable. Creating a *new* access key is a persistence move: it survives rotation of the original stolen key. | Pull the `responseElements.accessKeyId` from the full CloudTrail record for eventID `32d72b14-e9da-5785-b799-b7159f3898a1` and confirm it equals `AKIAI44QH8DHBEXAMPLE` (the key used 8 min later). Check VPN/firewall/proxy logs for any session assigning 203.0.113.47 to a legitimate user. Query Sysmon network-connect (EventID 3) across all hosts for 203.0.113.47. Confirm with the account owner whether a key was provisioned at this time. |
| 2026-07-20T01:48:33.470Z | `GetSecretValue` (secretsmanager) — `readOnly: true` | **203.0.113.47** | `condef-admin`, key **`AKIAI44QH8DHBEXAMPLE`** (different key) | **Use of the newly created key to reach secrets.** Same source IP as the `CreateAccessKey` 8m25s earlier, but a *different* access key and a completely different user-agent: `Boto3/1.34.51 … os/linux#5.15.0 … lang/python#3.11.6`. A Linux Boto3 client, where every on-host event in this window was Windows CLI. This is the second half of the chain — the key minted at 01:40 being exercised at 01:48 to read secret material. | Retrieve `requestParameters.secretId` for eventID `3e6c87e5-5890-5db0-abe6-9c04fc3a8109` to identify which secret was read and scope the blast radius. Confirm `AKIAI44QH8DHBEXAMPLE` was created by the 01:40 call. Sweep the full 24h of CloudTrail for all activity by `AKIAI44QH8DHBEXAMPLE` — this report's window may not contain the whole session. |

---

## Summary

**Lead finding — the non-read-only unmatched event.** `CreateAccessKey` at 2026-07-20T01:40:08Z is a write operation, from 203.0.113.47, with no host process behind it. Eight minutes later `GetSecretValue` fires from the same IP using a *different* access key and a Linux Boto3 user-agent. Read together these form a coherent chain: credentials belonging to `condef-admin` were used away from the workstation, a second access key was minted to establish persistence independent of the original key, and that new key was immediately used to read secrets.

The evidentiary strength here comes from what the matched pairings established. Because three separate on-host CLI commands all surfaced from 198.51.100.23, that IP is a well-grounded baseline for the workstation — which makes the two events from 203.0.113.47, carrying the same identity and (for the first) the same user-agent but no corresponding process, the strongest indicator of credential theft available in this data set. Note that filtering the CloudTrail retrieval by user-agent would have kept `CreateAccessKey` but silently dropped the Boto3 `GetSecretValue`, and filtering by source IP would have dropped both, in each case leaving a report that looked clean rather than truncated.

**What is explained:** all three read-only CLI commands on condef-win11a pair cleanly with their APIs. The one unmatched Sysmon event (`aws configure list`) is local-only and its missing CloudTrail event is expected, not a gap.

**What remains unexplained:** who controlled 203.0.113.47, how `AKIAIOSFODNN7EXAMPLE` reached that host, and which secret was read at 01:48:33Z. Nothing in either telemetry source answers these.

**Caveat on scope:** this run covers a single host and a single identity. That is what the two systems returned for the window — it is not independent confirmation that no other host or identity was involved, since the Sysmon query matched only `Image=*aws.exe` and would not show credentials used via SDK, PowerShell AWS module, or a browser console session on another host.

**What I would query next, in priority order:**

1. Full CloudTrail record for both unmatched events — `responseElements.accessKeyId` on the `CreateAccessKey` call and `requestParameters.secretId` on the `GetSecretValue` call. Both are single lookups and both materially change scope.
2. All 24h CloudTrail activity for `AKIAI44QH8DHBEXAMPLE` and for `sourceIPAddress == "203.0.113.47"` — as a *post-retrieval classification* over a time-bounded pull, to find the rest of the session.
3. Widen the CloudTrail window to 7d for `condef-admin` to find first appearance of 203.0.113.47 and establish when the compromise began.
4. Sysmon across **all** hosts for EventID 3 (network connect) to 203.0.113.47, and for non-`aws.exe` AWS SDK activity (`python.exe`, `powershell.exe` with AWS modules) that this run's `Image=*aws.exe` filter excluded by construction.
5. On condef-win11a: Sysmon EventID 11/23 on `%USERPROFILE%\.aws\credentials` for the hours before 01:40Z, to test the exfiltration hypothesis at the host end.

**Suggested immediate containment** (outside the scope of this report, stated because the finding is active): disable `AKIAI44QH8DHBEXAMPLE` and `AKIAIOSFODNN7EXAMPLE`, and review all `condef-admin` access keys against a known-good inventory.

---

## Method notes

- CloudTrail was retrieved narrowed **by time only** — not by `userAgent` and not by `sourceIPAddress`. Both fields are attacker-controlled; filtering on either hides off-host use of stolen credentials. In this run that decision is what surfaced the Boto3 `GetSecretValue` event.
- Correlation window held at **±60s throughout**; it was not widened. No pairing in this report depends on a window wider than 4 seconds.
- The three matched pairings had no competing candidates inside ±60s, so ambiguity did not need to be resolved by proximity alone.
- Δ values are consistently +2 to +3s, indicating no meaningful CloudTrail delivery lag in this data set. The unmatched events are therefore genuinely unmatched rather than artifacts of a tight window against a lagging feed.

---

## Queries used

Splunk (SPL, via REST oneshot) — unscoped, no host or user filter:

```bash
curl.exe -s -X POST "$SPLUNK_URL/services/search/jobs" \
  -d "search=search index=sysmon Image=*aws.exe" \
  -d "earliest_time=-24h" -d "exec_mode=oneshot" -d "output_mode=json"
```

ADX (KQL) — unscoped, narrowed by time only:

```bash
curl.exe -s -X POST "$ADX_CLUSTER/v1/rest/query" \
  -H "Content-Type: application/json" \
  -d '{"db":"'"$ADX_DATABASE"'","csl":"CloudTrail | where eventTime > ago(24h) | order by eventTime asc"}'
```

Endpoints read from environment: `SPLUNK_URL`, `ADX_CLUSTER`, `ADX_DATABASE`. All three were set; no credentials were required by these endpoints and none appear in this report. Access key IDs shown above are identifiers present in the CloudTrail records, not secret material.

Both queries returned HTTP 200 with non-empty result sets; the empty result underlying every "no match" claim above is the ±60s correlation scan over these two retrievals, not an unqueried absence.
