import sqlite3
import hashlib
import json
import re
import statistics
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, unquote

# ZAP plugin IDs → your schema fields
PLUGIN_MAP = {
    40018: {"payloadCategory": "error-based",      "payloadDbDialect": "generic"},
    40019: {"payloadCategory": "boolean-based",    "payloadDbDialect": "generic"},
    40020: {"payloadCategory": "time-based-blind", "payloadDbDialect": "generic"},
    40021: {"payloadCategory": "union-based",      "payloadDbDialect": "generic"},
    40022: {"payloadCategory": "stacked-queries",  "payloadDbDialect": "generic"},
}

# Dialect detection from payload content
DIALECT_PATTERNS = {
    "postgresql": [r"pg_sleep", r"::int", r"CAST\(.*AS\s+INT\)", r"pg_query"],
    "mysql":      [r"SLEEP\(", r"BENCHMARK\(", r"information_schema"],
    "mssql":      [r"WAITFOR\s+DELAY", r"xp_cmdshell", r"sysobjects"],
    "oracle":     [r"dbms_pipe", r"v\$version", r"dual"],
    "sqlite":     [r"sqlite_version", r"randomblob"],
}

# Known DB error strings for z3Hints
ERROR_PATTERNS = {
    "postgresql": [r"pg_query\(\)", r"invalid input syntax", r"unterminated quoted"],
    "mysql":      [r"You have an error in your SQL syntax", r"mysql_fetch"],
    "mssql":      [r"Unclosed quotation mark", r"SqlException"],
    "oracle":     [r"ORA-\d{5}", r"quoted string not properly terminated"],
    "generic":    [r"SQL syntax", r"sqlite3", r"ODBC Driver"],
}

def detect_dialect(payload: str) -> str:
    for dialect, patterns in DIALECT_PATTERNS.items():
        if any(re.search(p, payload, re.IGNORECASE) for p in patterns):
            return dialect
    return "generic"

def detect_error(response_body: str, dialect: str) -> tuple[bool, str | None]:
    patterns = ERROR_PATTERNS.get(dialect, []) + ERROR_PATTERNS["generic"]
    for p in patterns:
        m = re.search(p, response_body, re.IGNORECASE)
        if m:
            # Extract surrounding context, not the full body
            start = max(0, m.start() - 40)
            end   = min(len(response_body), m.end() + 80)
            return True, response_body[start:end].strip()
    return False, None

def content_hash(body: str) -> str:
    return hashlib.md5(body.encode()).hexdigest()[:8]

def extract_injected_param(req_header: str, alert_param: str) -> str:
    # ZAP alert carries the param name directly — use it
    return alert_param or "unknown"

def extract_rtt_stats(rtts: list[float]) -> tuple[float, float]:
    if len(rtts) < 2:
        return rtts[0] if rtts else 0, 0
    return statistics.mean(rtts), statistics.stdev(rtts)

def build_records(db_path: str) -> list[dict]:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # Pull all SQLi alerts joined to their triggering history record
    cur.execute("""
        SELECT
            a.alertid, a.pluginid, a.param, a.attack, a.confidence,
            h.histid, h.reqheader, h.reqbody,
            h.resheader, h.resbody, h.rtt, h.timestamp
        FROM alert a
        JOIN history h ON a.histid = h.histid
        WHERE a.pluginid IN (40018, 40019, 40020, 40021, 40022)
        ORDER BY h.timestamp ASC
    """)
    alert_rows = cur.fetchall()

    # Pull ALL history for baseline lookup (same host+path, no injection)
    cur.execute("""
        SELECT histid, reqheader, reqbody, resheader, resbody, rtt, timestamp
        FROM history
        WHERE reqheader NOT LIKE '%ZAP%attack%'
        ORDER BY timestamp ASC
    """)
    all_history = cur.fetchall()
    con.close()

    # Index clean history by (host, path) for fast baseline lookup
    baseline_index = defaultdict(list)
    for row in all_history:
        first_line = row["reqheader"].split("\r\n")[0]
        parts = first_line.split(" ")
        if len(parts) < 2:
            continue
        parsed = urlparse(parts[1])
        key = (parsed.netloc, parsed.path)
        baseline_index[key].append(row)

    records = []

    for alert in alert_rows:
        plugin_meta = PLUGIN_MAP.get(alert["pluginid"], {
            "payloadCategory": "unknown",
            "payloadDbDialect": "generic"
        })

        payload    = unquote(alert["attack"] or "")
        dialect    = detect_dialect(payload) or plugin_meta["payloadDbDialect"]
        category   = plugin_meta["payloadCategory"]
        param      = extract_injected_param(alert["reqheader"], alert["param"])
        res_body   = alert["resbody"] or ""
        res_header = alert["resheader"] or ""

        # Parse HTTP status
        status_match = re.match(r"HTTP/[\d.]+ (\d+)", res_header)
        http_status  = int(status_match.group(1)) if status_match else 0

        # Find baseline records for this endpoint
        first_line = alert["reqheader"].split("\r\n")[0].split(" ")
        parsed     = urlparse(first_line[1]) if len(first_line) > 1 else None
        ep_key     = (parsed.netloc, parsed.path) if parsed else ("", "")
        baselines  = baseline_index.get(ep_key, [])

        baseline_id  = str(baselines[0]["histid"]) if baselines else None
        baseline_rtts = [b["rtt"] for b in baselines[:5]]  # use up to 5 clean samples
        baseline_rtt, baseline_stddev = extract_rtt_stats(baseline_rtts) if baseline_rtts else (None, None)

        # Compute rtt stats
        rtt       = alert["rtt"]
        rtt_delta = rtt - baseline_rtt if baseline_rtt else None
        rtt_sigmas = (rtt_delta / baseline_stddev) if (rtt_delta and baseline_stddev) else None
        sleep_ms  = None
        sleep_frac = None
        if category == "time-based-blind":
            m = re.search(r"(?:pg_sleep|SLEEP|WAITFOR DELAY '[0-9:]*)\(?([0-9.]+)", payload, re.IGNORECASE)
            if m:
                sleep_ms   = float(m.group(1)) * 1000
                sleep_frac = round(rtt / sleep_ms, 3) if sleep_ms else None

        # Error detection
        error_found, error_string = detect_error(res_body, dialect)

        # Content hash for boolean-based
        body_hash    = content_hash(res_body)
        body_length  = len(res_body)

        record = {
            "id":               str(alert["histid"]),
            "role":             "sleep-payload" if category == "time-based-blind" else "attack",
            "payloadCategory":  category,
            "payloadDbDialect": dialect,
            "injectedParam":    param,
            "injectedValue":    payload,
            "evidenceClass":    "requires-baseline" if category in (
                                    "time-based-blind", "boolean-based", "second-order"
                                ) else "self-contained",
            "baselineId":       baseline_id,
            "baselineRtt":      baseline_rtt,
            "trueConditionId":  None,
            "falseConditionId": None,
            "sentinelValue":    None,
            "expectedSleepMs":  sleep_ms,

            "requestHeader":    alert["reqheader"],
            "requestBody":      alert["reqbody"] or "",
            "responseHeader":   res_header,
            "responseBody":     res_body,
            "rtt":              rtt,
            "timestamp":        str(alert["timestamp"]),

            # Flat z3Hints — all fields always present
            "z3Hints": {
                "type":                  category,
                "httpStatus":            http_status,
                "rttBaseline":           baseline_rtt,
                "rttStdDev":             baseline_stddev,
                "rttDelta":              rtt_delta,
                "rttSigmas":             round(rtt_sigmas, 2) if rtt_sigmas else None,
                "sleepFraction":         sleep_frac,
                "partialExecution":      bool(sleep_frac and sleep_frac < 0.8) if sleep_frac else None,
                "contentLengthBaseline": None,
                "contentHashBaseline":   None,
                "contentLengthTrue":     None,
                "contentHashTrue":       None,
                "contentLengthFalse":    None,
                "contentHashFalse":      None,
                "errorPatternFound":     error_found,
                "errorString":           error_string,
                "dbVersionLeaked":       bool(re.search(r"\d+\.\d+\.\d+", error_string or "")),
            }
        }
        records.append(record)

    # Second pass: wire boolean true/false pairs
    # ZAP fires alert 40019 twice for the same param — true then false condition
    _pair_boolean_records(records)

    return records


def _pair_boolean_records(records: list[dict]):
    """
    Group boolean records by (host, path, param), then assign
    true/false condition IDs and fill content hash fields.
    """
    groups = defaultdict(list)
    for r in records:
        if r["payloadCategory"] != "boolean-based":
            continue
        first_line = r["requestHeader"].split("\r\n")[0].split(" ")
        parsed = urlparse(first_line[1]) if len(first_line) > 1 else None
        key = (parsed.netloc if parsed else "", parsed.path if parsed else "", r["injectedParam"])
        groups[key].append(r)

    for key, group in groups.items():
        if len(group) < 2:
            continue
        # Heuristic: longer response = true condition
        group.sort(key=lambda r: len(r["responseBody"]), reverse=True)
        true_rec, false_rec = group[0], group[1]

        for r in group:
            r["trueConditionId"]  = true_rec["id"]
            r["falseConditionId"] = false_rec["id"]
            r["z3Hints"]["contentLengthTrue"]     = len(true_rec["responseBody"])
            r["z3Hints"]["contentHashTrue"]       = content_hash(true_rec["responseBody"])
            r["z3Hints"]["contentLengthFalse"]    = len(false_rec["responseBody"])
            r["z3Hints"]["contentHashFalse"]      = content_hash(false_rec["responseBody"])
            # Baseline hash comes from the baseline record lookup (separate pass)


if __name__ == "__main__":
    import sys
    db_path  = sys.argv[1] if len(sys.argv) > 1 else "~/.ZAP/session.db"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "sqli_records.json"

    records = build_records(db_path)
    with open(out_path, "w") as f:
        json.dump(records, f, indent=2)

    print(f"Wrote {len(records)} records → {out_path}")