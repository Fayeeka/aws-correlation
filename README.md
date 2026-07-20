# aws-correlation

A test harness for a cross-SIEM correlation persona — an LLM analyst that
stitches host telemetry (Sysmon in Splunk) together with cloud telemetry
(CloudTrail in Azure Data Explorer) into one account of what happened.

The two systems share no join key. Correlation is done by reasoning — time
proximity, CLI-to-API-name mapping, user-agent, source IP — not by a database
join. That makes the persona's *method* the thing under test, and it needs
data to be tested against. This repo is that data.

```
persona/cross-siem.md    the analyst persona under test
mock-server/             stdlib-only Splunk and ADX stand-ins
reports/                 correlation output (gitignored)
```

## Running it

Two servers, no dependencies, no authentication:

```bash
python mock-server/mock_splunk.py    # 127.0.0.1:8089  Sysmon via Splunk REST
python mock-server/mock_adx.py       # 127.0.0.1:8082  CloudTrail via Kusto
```

Both print a time anchor at startup and **the two must match** — see
[mock-server/README.md](mock-server/README.md) for the anchoring rules, seeded
scenario, query-filtering support, and curl patterns.

## The finding this repo is built around

While testing the persona against these fixtures, one query pattern turned out
to be quietly dangerous. It is the reason the seed data is shaped the way it is.

The tempting way to cut noise from the CloudTrail side is to keep only events
that came from the AWS CLI, since that is what the host was running:

```kql
CloudTrail | where eventTime > ago(4h) | where userAgent startswith "aws-cli/"
```

Against the seeded window that returns 4 rows. Without the `userAgent` clause it
returns 5.

The dropped row is `GetSecretValue` — the worst event in the window. It was
called with an access key that a `CreateAccessKey` event minted minutes earlier,
from an IP that is not the workstation's, via Boto3 rather than the CLI. It is
the actual credential theft, and the client filter is exactly what hides it.

**The failure mode is that nothing looks wrong.** No error, no empty result set,
no warning — just a slightly shorter list that still contains all the events you
expected to see. The filter's premise is that stolen credentials keep being used
the way they were originally used, and that premise is false: credentials lifted
from a host get replayed from SDKs, scripts, CI runners, and the console, none
of which carry a CLI user-agent. Filtering on the client discards precisely the
off-host use that the correlation workflow exists to surface.

`sourceIPAddress` fails the same way and for the same reason. Both fields are
attacker-controlled, so neither is safe as a retrieval filter.

The rule that follows: **narrow by time, account, or identity — never by client
or source IP.** User-agent and source IP are still useful, but as *classifiers*
applied to events already retrieved, where a mismatch is a signal rather than a
silent deletion. An event that fails those checks is more interesting than one
that passes.

This is encoded in `persona/cross-siem.md` as a non-negotiable constraint, and
the fixtures exist to make a violation of it observable — the seeded data is
arranged so that the wrong query returns a plausible, complete-looking, wrong
answer.

## Scope

These are fixtures, not query engines. Both servers do shallow but real
filtering — enough that a query which should match nothing returns an empty
result set rather than everything, which is what makes the persona's "never
claim no match without showing the empty query result" constraint meaningful.
They do not implement SPL or KQL. A query passing here is not evidence that the
same query is valid against real Splunk or ADX.

Not represented: authentication and its failure modes, pagination and result
caps, latency, and CloudTrail's genuine delivery delay — real events can lag
minutes behind the host action, well past the ±60s correlation window used here.
