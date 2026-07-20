#!/usr/bin/env python3
"""Mock Splunk REST API for cross-SIEM correlation testing.

Mimics the /services/search/jobs oneshot endpoint closely enough that the
curl patterns from Module 12 work unchanged apart from the URL and dropping
-u/-k. Returns synthetic Sysmon Event ID 1 (process create) records for
aws.exe invocations on condef-win11a.

No authentication: any Authorization header is accepted and ignored.

Run:  python mock_splunk.py           (listens on 127.0.0.1:8089)

Timestamps are anchored to the current UTC hour boundary so that this server
and mock_adx.py agree even when started a few minutes apart. Set MOCK_BASE_TIME
(ISO 8601 UTC) on BOTH servers if you need an exact shared anchor -- see the
note printed at startup.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("MOCK_SPLUNK_PORT", "8089"))
BIND = os.environ.get("MOCK_SPLUNK_BIND", "127.0.0.1")

COMPUTER = "condef-win11a"
USER = "condef\\Administrator"
AWS_EXE = r"C:\Program Files\Amazon\AWSCLIV2\aws.exe"
PARENT_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def base_time():
    """Shared anchor: current UTC hour boundary, or MOCK_BASE_TIME if set."""
    override = os.environ.get("MOCK_BASE_TIME")
    if override:
        parsed = datetime.fromisoformat(override.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


# Offsets are relative to the anchor. Each entry becomes one Sysmon EID 1 event.
# Event 4 (aws configure list) is local-only -- it makes no AWS API call, so it
# has no CloudTrail counterpart by design (the unmatched-Sysmon test case).
SEED = [
    {
        "minutes": 180, "seconds": 3.412,
        "cmd": "aws sts get-caller-identity",
        "pid": 6244, "guid": "{b3c1f0a2-9d4e-6890-0e00-000000001a44}",
    },
    {
        "minutes": 120, "seconds": 41.088,
        "cmd": "aws s3 ls",
        "pid": 7712, "guid": "{b3c1f0a2-9dc1-6890-1f00-000000001e20}",
    },
    {
        "minutes": 90, "seconds": 12.664,
        "cmd": "aws iam list-users",
        "pid": 4188, "guid": "{b3c1f0a2-9e07-6890-2a00-00000000105c}",
    },
    {
        "minutes": 45, "seconds": 27.005,
        "cmd": "aws configure list",
        "pid": 5936, "guid": "{b3c1f0a2-9e5b-6890-3b00-000000001730}",
    },
]


def event_time(entry, anchor):
    return anchor - timedelta(minutes=entry["minutes"]) + timedelta(seconds=entry["seconds"])


def build_events(anchor):
    """Render the seed data as Splunk-style flat result dicts."""
    events = []
    for entry in SEED:
        dt = event_time(entry, anchor)
        utc_time = dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
        raw = (
            "Process Create:\n"
            f"RuleName: -\nUtcTime: {utc_time}\nProcessGuid: {entry['guid']}\n"
            f"ProcessId: {entry['pid']}\nImage: {AWS_EXE}\n"
            "FileVersion: 2.15.30\nDescription: AWS Command Line Interface\n"
            "Product: AWS CLI\nCompany: Amazon Web Services\n"
            f"CommandLine: {entry['cmd']}\nCurrentDirectory: C:\\Users\\Administrator\\\n"
            f"User: {USER}\nIntegrityLevel: High\n"
            f"ParentImage: {PARENT_EXE}\nParentCommandLine: powershell.exe\n"
        )
        events.append({
            "_time": dt.isoformat(timespec="milliseconds"),
            "_raw": raw,
            "EventCode": "1",
            "EventID": "1",
            "Computer": COMPUTER,
            "host": COMPUTER,
            "User": USER,
            "UtcTime": utc_time,
            "Image": AWS_EXE,
            "CommandLine": entry["cmd"],
            "ProcessId": str(entry["pid"]),
            "ProcessGuid": entry["guid"],
            "ParentImage": PARENT_EXE,
            "ParentCommandLine": "powershell.exe",
            "CurrentDirectory": "C:\\Users\\Administrator\\",
            "IntegrityLevel": "High",
            "LogonId": "0x2f1a4b",
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "_dt": dt,  # internal only, stripped before serialising
        })
    return events


RELATIVE_TIME = re.compile(r"-(\d+)([smhd])")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_earliest(value):
    """Turn a Splunk relative time modifier (-4h, -30m, ...) into a datetime."""
    if not value:
        return None
    value = value.strip()
    if value in ("0", "@d"):
        return None
    match = RELATIVE_TIME.search(value)
    if not match:
        return None
    amount, unit = int(match.group(1)), match.group(2)
    return datetime.now(timezone.utc) - timedelta(seconds=amount * UNIT_SECONDS[unit])


def field_filter(search, field):
    """Extract a `field=value` constraint from an SPL string, if present."""
    pattern = re.compile(
        rf'\b{field}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\']+))', re.IGNORECASE
    )
    match = pattern.search(search)
    if not match:
        return None
    return next(g for g in match.groups() if g is not None)


def matches_glob(value, pattern):
    """Splunk-style `*` wildcard matching, case-insensitive."""
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(regex, value, re.IGNORECASE) is not None


def apply_search(events, search, earliest, latest):
    """Best-effort SPL filtering: host/user/command-line plus a time window.

    This is deliberately shallow -- it is enough for the correlation workflow
    to produce genuinely empty results when a query does not match, so that
    "no match" can be demonstrated rather than asserted.
    """
    results = events

    for field in ("Computer", "host"):
        wanted = field_filter(search, field)
        if wanted:
            results = [e for e in results if matches_glob(e["Computer"], wanted)]

    wanted_user = field_filter(search, "User")
    if wanted_user:
        # SPL escapes backslashes in quoted strings; normalise before comparing.
        normalised = wanted_user.replace("\\\\", "\\")
        results = [e for e in results if matches_glob(e["User"], normalised)]

    for field in ("CommandLine", "Image", "process"):
        wanted = field_filter(search, field)
        if wanted:
            results = [
                e for e in results
                if matches_glob(e.get(field, e["CommandLine"]), wanted)
            ]

    start = parse_earliest(earliest) or parse_earliest(field_filter(search, "earliest"))
    if start:
        results = [e for e in results if e["_dt"] >= start]

    end = parse_earliest(latest) or parse_earliest(field_filter(search, "latest"))
    if end:
        results = [e for e in results if e["_dt"] <= end]

    return results


def oneshot_payload(results):
    fields = []
    seen = set()
    for event in results:
        for key in event:
            if key != "_dt" and key not in seen:
                seen.add(key)
                fields.append({"name": key})
    return {
        "preview": False,
        "init_offset": 0,
        "messages": [],
        "fields": fields,
        "results": [
            {k: v for k, v in event.items() if k != "_dt"} for event in results
        ],
        "highlighted": {},
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Splunkd/9.2.0 (mock)"

    def log_message(self, fmt, *args):
        print(f"[splunk] {self.address_string()} {fmt % args}")

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/services/server/info", "/services/server/info/server-info"):
            self._send_json({
                "entry": [{
                    "name": "server-info",
                    "content": {
                        "version": "9.2.0",
                        "serverName": "mock-splunk",
                        "isFree": False,
                        "isTrial": False,
                    },
                }],
            })
            return
        self._send_json({"messages": [{"type": "ERROR", "text": "Not found"}]}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path.rstrip("/") != "/services/search/jobs":
            self._send_json(
                {"messages": [{"type": "ERROR", "text": f"Unknown endpoint {path}"}]}, 404
            )
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw_body, keep_blank_values=True)
        # Query-string params are honoured too, matching real splunkd behaviour.
        params.update(parse_qs(urlparse(self.path).query, keep_blank_values=True))

        search = (params.get("search") or [""])[0]
        if not search.strip():
            self._send_json(
                {"messages": [{"type": "FATAL", "text": "Missing search parameter"}]}, 400
            )
            return

        exec_mode = (params.get("exec_mode") or ["oneshot"])[0]
        if exec_mode != "oneshot":
            self._send_json(
                {"messages": [{
                    "type": "ERROR",
                    "text": f"mock supports exec_mode=oneshot only (got {exec_mode})",
                }]}, 400
            )
            return

        earliest = (params.get("earliest_time") or [""])[0]
        latest = (params.get("latest_time") or [""])[0]

        events = build_events(base_time())
        results = apply_search(events, search, earliest, latest)
        print(f"[splunk] search={search!r} -> {len(results)} result(s)")
        self._send_json(oneshot_payload(results))


def main():
    # Unbuffered-ish stdout: without this the banner and request log are
    # invisible when the server runs in the background with stdout piped.
    sys.stdout.reconfigure(line_buffering=True)
    anchor = base_time()
    print(f"Mock Splunk REST API on http://{BIND}:{PORT}")
    print(f"  POST /services/search/jobs   (exec_mode=oneshot, output_mode=json)")
    print(f"  GET  /services/server/info   (connectivity check)")
    print(f"  time anchor: {anchor.isoformat()}  <- must match mock_adx.py")
    print(f"  {len(SEED)} seeded aws.exe events on {COMPUTER}; auth is not required")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
