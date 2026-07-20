# Mock SIEM servers

Local stand-ins for Splunk and Azure Data Explorer, so the Module 12
cross-SIEM correlation workflow can be exercised without real infrastructure.
Stdlib Python only, no dependencies, no authentication.

```
python mock_splunk.py    # 127.0.0.1:8089  Sysmon via Splunk REST
python mock_adx.py       # 127.0.0.1:8082  CloudTrail via Kusto
```

Both print their time anchor at startup. **The two anchors must match** — see
"Time anchoring" below.

## Seeded scenario

Four `aws.exe` process-creates on `condef-win11a` as `condef\Administrator`,
and four CloudTrail events, arranged to exercise all three correlation buckets:

| Sysmon (Splunk) | CloudTrail (ADX) | Δ | Bucket |
|---|---|---|---|
| `aws sts get-caller-identity` | `GetCallerIdentity` | ~+2.5s | matched |
| `aws s3 ls` | `ListBuckets` | ~+3.1s | matched |
| `aws iam list-users` | `ListUsers` | ~+2.3s | matched |
| `aws configure list` | — | — | **unmatched Sysmon** |
| — | `CreateAccessKey` | — | **unmatched CloudTrail** |
| — | `GetSecretValue` | — | **unmatched CloudTrail, non-CLI client** |

`aws configure list` is local-only — it makes no AWS API call, so its absence
from CloudTrail is *explainable*, not suspicious. It tests whether the persona
knows the 12.2 exception list rather than flagging every unmatched process.

`CreateAccessKey` is the opposite: same IAM user and `aws-cli/` user-agent, but
from `203.0.113.47` rather than the workstation's `198.51.100.23`, and
`readOnly: false`. No host-side telemetry explains it. That is the
unmatched-suspicious case, and it is the scenario the module opens with.

`GetSecretValue` is the payoff of `CreateAccessKey`: it uses the key that event
minted (`AKIAI44QH8DHBEXAMPLE`, not the host's `AKIAIOSFODNN7EXAMPLE`), from the
same foreign IP, via **Boto3 rather than the CLI**. It exists to make one
specific query mistake visible:

```
| where eventTime > ago(4h)                              -> 5 rows
| where eventTime > ago(4h) | where userAgent startswith "aws-cli/"  -> 4 rows
```

Filtering the CloudTrail side by client drops it and the result still looks
complete — no error, no empty set, just a quietly shorter list missing the
worst event in the window. Stolen credentials get used from SDKs, scripts, and
the console; none of those carry a CLI user-agent. Narrow by time, account, or
identity, never by `userAgent` or `sourceIPAddress`.

It also rewards the correct follow-up: an analyst who pulls the new key ID out
of `CreateAccessKey` and hunts its later use will land on this event.

All matched pairs land well inside the ±60s default correlation window.

## Curl patterns

Same shape as the course material, minus `-u`/`-k` and the bearer token. On
Windows use `curl.exe` explicitly — bare `curl` is an alias for
`Invoke-WebRequest` in PowerShell and takes different flags.

Splunk oneshot search:

```bash
curl.exe -s -X POST "http://127.0.0.1:8089/services/search/jobs" \
  -d "search=search index=sysmon Computer=condef-win11a" \
  -d "earliest_time=-4h" \
  -d "exec_mode=oneshot" \
  -d "output_mode=json"
```

Kusto query:

```bash
curl.exe -s -X POST "http://127.0.0.1:8082/v1/rest/query" \
  -H "Content-Type: application/json" \
  -d '{"db":"cloudtrail","csl":"CloudTrail | where eventTime > ago(4h) | where userAgent startswith \"aws-cli/\""}'
```

Connectivity checks: `GET /services/server/info` and
`POST /v1/rest/mgmt` with `.show version`.

## Response shapes

Splunk returns the oneshot envelope — `preview`, `init_offset`, `messages`,
`fields`, `results`, `highlighted` — with `results` as flat string-valued
dicts including `_time`, `_raw`, `Computer`, `User`, `CommandLine`,
`ProcessGuid`, `UtcTime`.

ADX returns the v1 multi-table shape: `Tables[0]` is the data
(`Columns` + `Rows` as positional arrays, so zip them), followed by
QueryProperties, QueryStatus, and a TOC table.

## Query filtering

Both servers do shallow but real filtering, so a query that should match
nothing returns an empty result set rather than everything. This matters for
the persona constraint "never claim no match without showing the empty query
result" — that claim is only meaningful if an empty result is reachable.

- **SPL**: `Computer=`, `host=`, `User=`, `CommandLine=`, `Image=` (with `*`
  wildcards), plus `earliest_time`/`latest_time` and inline `earliest=`/`latest=`
- **KQL**: `startswith`, `contains`/`has`, `==` (string and bool), `in (...)`,
  `ago()` bounds, `take`/`limit`

Anything else in the query is ignored rather than erroring. These are fixtures,
not query engines — do not read a passing query here as proof the same SPL/KQL
is valid against real Splunk or ADX.

## Time anchoring

Timestamps are relative to an anchor, so the data always looks like it happened
in the last few hours. Both servers default to **the current UTC hour boundary**
rather than "now", so two independently started processes still agree.

The gap that leaves: if one server starts at 13:59 and the other at 14:01, the
anchors differ by an hour and every pair falls outside the correlation window.
The startup banner prints each anchor — if they disagree, pin both:

```bash
MOCK_BASE_TIME=2026-07-19T12:00:00Z python mock_splunk.py
MOCK_BASE_TIME=2026-07-19T12:00:00Z python mock_adx.py
```

Other env vars: `MOCK_SPLUNK_PORT`, `MOCK_SPLUNK_BIND`, `MOCK_ADX_PORT`,
`MOCK_ADX_BIND`.

## Not represented

Real APIs do things these fixtures do not: authentication and its failure
modes (the 401-from-Kusto path the persona is supposed to stop on), pagination
and result caps, `s3 sync`-style fan-out to many CloudTrail events, latency,
and CloudTrail's genuine delivery delay — real events can lag minutes behind
the host action, well past the ±60s window used here.
