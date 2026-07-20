#!/usr/bin/env python3
"""Mock Azure Data Explorer (Kusto) query API for cross-SIEM correlation testing.

Mimics the /v1/rest/query endpoint and returns synthetic CloudTrail events in
ADX's v1 multi-table JSON shape, so the curl patterns from Module 12 work
unchanged apart from the URL and dropping the bearer token.

No authentication: any Authorization header is accepted and ignored.

Run:  python mock_adx.py             (listens on 127.0.0.1:8082)

Timestamps are anchored to the current UTC hour boundary so that this server
and mock_splunk.py agree even when started a few minutes apart. Set
MOCK_BASE_TIME (ISO 8601 UTC) on BOTH servers for an exact shared anchor.
"""

import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("MOCK_ADX_PORT", "8082"))
BIND = os.environ.get("MOCK_ADX_BIND", "127.0.0.1")

USER_AGENT = "aws-cli/2.15.30 Python/3.11.8 Windows/10 exe/AMD64 prompt/off"
# Non-CLI client: what an SDK script looks like, rather than the aws CLI.
SDK_USER_AGENT = (
    "Boto3/1.34.51 md/Botocore#1.34.51 ua/2.0 os/linux#5.15.0 md/arch#x86_64 "
    "lang/python#3.11.6 cfg/retry-mode#legacy Botocore/1.34.51"
)
WORKSTATION_IP = "198.51.100.23"   # condef-win11a egress
FOREIGN_IP = "203.0.113.47"        # not the workstation
IAM_USER = "condef-admin"
IAM_ARN = f"arn:aws:iam::123456789012:user/{IAM_USER}"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
# The key minted by the CreateAccessKey event below, then used from off-host.
STOLEN_KEY = "AKIAI44QH8DHBEXAMPLE"


def base_time():
    """Shared anchor: current UTC hour boundary, or MOCK_BASE_TIME if set."""
    override = os.environ.get("MOCK_BASE_TIME")
    if override:
        parsed = datetime.fromisoformat(override.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


# Offsets mirror mock_splunk.py's seed, landing 2-3s after each process-create.
#   1-3: matched pairs (Sysmon aws.exe -> CloudTrail API call)
#   4:   NO corresponding Sysmon event, from a foreign IP, and not read-only
#        -- the unmatched-CloudTrail test case
#   5:   the key minted by #4, used from off-host via an SDK rather than the
#        CLI. Its user-agent does NOT start with "aws-cli/", so any query that
#        filters on the client drops it silently and the result still looks
#        complete -- the failure mode that filter is meant to demonstrate.
# The Sysmon `aws configure list` event has no entry here on purpose: it is a
# local-only command that never calls an AWS API.
SEED = [
    {
        "minutes": 180, "seconds": 5.900,
        "eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com",
        "sourceIPAddress": WORKSTATION_IP, "readOnly": True,
        "errorCode": "", "errorMessage": "",
    },
    {
        "minutes": 120, "seconds": 44.210,
        "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
        "sourceIPAddress": WORKSTATION_IP, "readOnly": True,
        "errorCode": "", "errorMessage": "",
    },
    {
        "minutes": 90, "seconds": 14.980,
        "eventName": "ListUsers", "eventSource": "iam.amazonaws.com",
        "sourceIPAddress": WORKSTATION_IP, "readOnly": True,
        "errorCode": "", "errorMessage": "",
    },
    {
        "minutes": 20, "seconds": 8.140,
        "eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com",
        "sourceIPAddress": FOREIGN_IP, "readOnly": False,
        "errorCode": "", "errorMessage": "",
    },
    {
        "minutes": 12, "seconds": 33.470,
        "eventName": "GetSecretValue", "eventSource": "secretsmanager.amazonaws.com",
        "sourceIPAddress": FOREIGN_IP, "readOnly": True,
        "errorCode": "", "errorMessage": "",
        "userAgent": SDK_USER_AGENT, "accessKeyId": STOLEN_KEY,
    },
]

COLUMNS = [
    ("eventTime", "DateTime", "datetime"),
    ("eventName", "String", "string"),
    ("eventSource", "String", "string"),
    ("awsRegion", "String", "string"),
    ("sourceIPAddress", "String", "string"),
    ("userAgent", "String", "string"),
    ("userIdentityType", "String", "string"),
    ("userIdentityUserName", "String", "string"),
    ("userIdentityArn", "String", "string"),
    ("userIdentityAccessKeyId", "String", "string"),
    ("errorCode", "String", "string"),
    ("errorMessage", "String", "string"),
    ("readOnly", "Boolean", "bool"),
    ("eventID", "String", "string"),
    ("requestID", "String", "string"),
]


def build_events(anchor):
    events = []
    for index, entry in enumerate(SEED):
        dt = anchor - timedelta(minutes=entry["minutes"]) + timedelta(seconds=entry["seconds"])
        events.append({
            "_dt": dt,  # internal only
            "eventTime": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}0Z",
            "eventName": entry["eventName"],
            "eventSource": entry["eventSource"],
            "awsRegion": "us-east-1",
            "sourceIPAddress": entry["sourceIPAddress"],
            "userAgent": entry.get("userAgent", USER_AGENT),
            "userIdentityType": "IAMUser",
            "userIdentityUserName": IAM_USER,
            "userIdentityArn": IAM_ARN,
            "userIdentityAccessKeyId": entry.get("accessKeyId", ACCESS_KEY),
            "errorCode": entry["errorCode"],
            "errorMessage": entry["errorMessage"],
            "readOnly": entry["readOnly"],
            "eventID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"event-{index}")),
            "requestID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"request-{index}")),
        })
    return events


AGO = re.compile(r"ago\((\d+)([smhd])\)")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def apply_query(events, csl):
    """Best-effort KQL filtering: startswith/==/in plus an ago() time bound.

    Shallow by design, but real enough that a non-matching query returns a
    genuinely empty row set instead of silently returning everything.
    """
    results = events

    match = AGO.search(csl)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=amount * UNIT_SECONDS[unit])
        results = [e for e in results if e["_dt"] >= cutoff]

    for field, prefix in re.findall(r'(\w+)\s+startswith\s+"([^"]*)"', csl):
        results = [
            e for e in results
            if str(e.get(field, "")).lower().startswith(prefix.lower())
        ]

    for field, contained in re.findall(r'(\w+)\s+(?:contains|has)\s+"([^"]*)"', csl):
        results = [
            e for e in results if contained.lower() in str(e.get(field, "")).lower()
        ]

    for field, value in re.findall(r'(\w+)\s*==\s*"([^"]*)"', csl):
        results = [e for e in results if str(e.get(field, "")) == value]

    for field, value in re.findall(r"(\w+)\s*==\s*(true|false)\b", csl):
        results = [e for e in results if e.get(field) is (value == "true")]

    for field, values in re.findall(r'(\w+)\s+in\s*\(([^)]*)\)', csl):
        wanted = {v.strip().strip('"\'') for v in values.split(",") if v.strip()}
        results = [e for e in results if str(e.get(field, "")) in wanted]

    match = re.search(r"\|\s*take\s+(\d+)|\|\s*limit\s+(\d+)", csl)
    if match:
        results = results[: int(match.group(1) or match.group(2))]

    return results


def v1_response(rows_table):
    """ADX v1 shape: data table, then query properties, status, and a TOC."""
    return {
        "Tables": [
            rows_table,
            {
                "TableName": "Table_1",
                "Columns": [
                    {"ColumnName": "Value", "DataType": "String", "ColumnType": "string"},
                ],
                "Rows": [[json.dumps({"Visualization": None})]],
            },
            {
                "TableName": "Table_2",
                "Columns": [
                    {"ColumnName": "Timestamp", "DataType": "DateTime", "ColumnType": "datetime"},
                    {"ColumnName": "Severity", "DataType": "Int32", "ColumnType": "int"},
                    {"ColumnName": "StatusCode", "DataType": "Int32", "ColumnType": "int"},
                    {"ColumnName": "StatusDescription", "DataType": "String", "ColumnType": "string"},
                ],
                "Rows": [[
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f0Z"),
                    4, 0, "Query completed successfully",
                ]],
            },
            {
                "TableName": "Table_3",
                "Columns": [
                    {"ColumnName": "Ordinal", "DataType": "Int64", "ColumnType": "long"},
                    {"ColumnName": "Kind", "DataType": "String", "ColumnType": "string"},
                    {"ColumnName": "Name", "DataType": "String", "ColumnType": "string"},
                    {"ColumnName": "Id", "DataType": "String", "ColumnType": "string"},
                    {"ColumnName": "PrettyName", "DataType": "String", "ColumnType": "string"},
                ],
                "Rows": [
                    [0, "QueryResult", "PrimaryResult", "", ""],
                    [1, "QueryProperties", "@ExtendedProperties", "", ""],
                    [2, "QueryStatus", "QueryStatus", "", ""],
                ],
            },
        ],
    }


def data_table(results):
    return {
        "TableName": "Table_0",
        "Columns": [
            {"ColumnName": name, "DataType": dtype, "ColumnType": ctype}
            for name, dtype, ctype in COLUMNS
        ],
        "Rows": [[event[name] for name, _, _ in COLUMNS] for event in results],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Kusto/1.0 (mock)"

    def log_message(self, fmt, *args):
        print(f"[adx] {self.address_string()} {fmt % args}")

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message, status=400):
        self._send_json(
            {"error": {"code": "BadRequest", "message": message,
                       "@type": "Kusto.Data.Exceptions.KustoBadRequestException"}},
            status,
        )

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")

        try:
            body = json.loads(raw_body) if raw_body.strip() else {}
        except json.JSONDecodeError as exc:
            self._error(f"Request body is not valid JSON: {exc}")
            return

        csl = (body.get("csl") or body.get("query") or "").strip()

        if path == "/v1/rest/mgmt":
            # `.show version` is the usual connectivity check.
            self._send_json(v1_response({
                "TableName": "Table_0",
                "Columns": [
                    {"ColumnName": "BuildVersion", "DataType": "String", "ColumnType": "string"},
                    {"ColumnName": "ServiceType", "DataType": "String", "ColumnType": "string"},
                ],
                "Rows": [["1.0.0.0 (mock)", "Engine"]],
            }))
            return

        if path != "/v1/rest/query":
            self._error(f"Unknown endpoint {path}", 404)
            return

        if not csl:
            self._error("Request is missing the 'csl' property")
            return

        results = apply_query(build_events(base_time()), csl)
        print(f"[adx] csl={csl!r} -> {len(results)} row(s)")
        self._send_json(v1_response(data_table(results)))

    def do_GET(self):
        self._error("Use POST /v1/rest/query", 405)


def main():
    # Unbuffered-ish stdout: without this the banner and request log are
    # invisible when the server runs in the background with stdout piped.
    sys.stdout.reconfigure(line_buffering=True)
    anchor = base_time()
    print(f"Mock Azure Data Explorer on http://{BIND}:{PORT}")
    print(f"  POST /v1/rest/query          (body: {{\"db\":..., \"csl\":...}})")
    print(f"  POST /v1/rest/mgmt           (connectivity check)")
    print(f"  time anchor: {anchor.isoformat()}  <- must match mock_splunk.py")
    print(f"  {len(SEED)} seeded CloudTrail events; auth is not required")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
