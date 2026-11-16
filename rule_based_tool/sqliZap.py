import logging
import json
import os
import re
import time
from collections import Counter
from html import escape
from urllib.parse import urlsplit

import requests
import zapv2
from dotenv import load_dotenv

load_dotenv(".env", override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zap-sqli-scan")
AUTH_COOKIE_RULE = "auth-cookie-header"


def _zap_proxy_config() -> dict[str, str]:
    host = os.getenv("ZAP_HOST", "127.0.0.1")
    port = os.getenv("ZAP_PORT", "8080")
    proxy = f"http://{host}:{port}"
    return {"http": proxy, "https": proxy}


def _target_verify_tls() -> bool:
    raw = os.getenv("TARGET_VERIFY_TLS", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _parse_status(raw_status: str) -> int | None:
    """Return integer progress when possible, otherwise None for API error tokens."""
    try:
        return int(raw_status)
    except (TypeError, ValueError):
        return None


def _message_first_line(raw_header: str | None) -> str:
    if not raw_header:
        return ""
    return raw_header.splitlines()[0] if raw_header.splitlines() else ""


def _header_value(raw_header: str | None, header_name: str) -> str:
    if not raw_header:
        return ""

    match = re.search(rf"(?im)^{re.escape(header_name)}:\s*(.+)$", raw_header)
    return match.group(1).strip() if match else ""


def _header_int_value(raw_header: str | None, header_name: str) -> int | None:
    value = _header_value(raw_header, header_name)
    if not value:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_request_line(raw_header: str | None) -> tuple[str, str, str]:
    first_line = _message_first_line(raw_header)
    if not first_line:
        return "", "", ""

    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return "", "", ""

    method = parts[0]
    path = parts[1]
    http_version = parts[2] if len(parts) > 2 else ""
    return method, path, http_version


def _parse_response_line(raw_header: str | None) -> tuple[str, str, str]:
    first_line = _message_first_line(raw_header)
    if not first_line:
        return "", "", ""

    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return "", "", ""

    http_version = parts[0]
    status_code = parts[1]
    reason = parts[2] if len(parts) > 2 else ""
    return http_version, status_code, reason


def _format_request_header(method: str, url: str, headers: dict[str, str], http_version: str = "HTTP/1.1") -> str:
    parsed_url = urlsplit(url)
    path = parsed_url.path or "/"
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"

    header_lines = [f"{method} {path} {http_version}"]
    for header_name, header_value in headers.items():
        header_lines.append(f"{header_name}: {header_value}")
    return "\r\n".join(header_lines) + "\r\n\r\n"


def _format_response_header(status_code: int, reason: str, headers: dict[str, str], http_version: str = "HTTP/1.1") -> str:
    header_lines = [f"{http_version} {status_code} {reason}".rstrip()]
    for header_name, header_value in headers.items():
        header_lines.append(f"{header_name}: {header_value}")
    return "\r\n".join(header_lines) + "\r\n\r\n"


def _build_traffic_record(
    *,
    record_id: str,
    kind: str,
    request_header: str,
    request_body: str,
    response_header: str,
    response_body: str,
    rtt: str = "",
    timestamp: str = "",
    url: str = "",
    final_url: str = "",
) -> dict:
    request_method, request_path, request_http_version = _parse_request_line(request_header)
    response_http_version, response_status_code, response_reason = _parse_response_line(response_header)

    return {
        "id": record_id,
        "kind": kind,
        "url": url,
        "finalUrl": final_url,
        "requestHeader": request_header,
        "requestHeaderLength": len(request_header),
        "requestBody": request_body,
        "requestBodyLength": len(request_body),
        "requestMethod": request_method,
        "requestPath": request_path,
        "requestHttpVersion": request_http_version,
        "requestContentType": _header_value(request_header, "Content-Type"),
        "requestContentLengthHeader": _header_int_value(request_header, "Content-Length"),
        "responseHeader": response_header,
        "responseHeaderLength": len(response_header),
        "responseBody": response_body,
        "responseBodyLength": len(response_body),
        "responseHttpVersion": response_http_version,
        "responseStatusCode": response_status_code,
        "responseReason": response_reason,
        "responseContentType": _header_value(response_header, "Content-Type"),
        "responseContentLengthHeader": _header_int_value(response_header, "Content-Length"),
        "rtt": rtt,
        "timestamp": timestamp,
    }


def _log_new_scan_messages(
    zap: zapv2.ZAPv2,
    scan_id: str,
    seen_ids: set[str],
    max_log_per_poll: int = 10,
) -> None:
    """Log newly observed scan traffic summaries while scan is running."""
    try:
        message_ids = zap.ascan.messages_ids(scan_id)
    except Exception as exc:
        logger.warning("Could not fetch scan message IDs: %s", exc)
        return

    new_ids = [str(mid) for mid in message_ids if str(mid) not in seen_ids]
    if not new_ids:
        return

    logger.info(
        "Observed %d new HTTP messages in this poll (total tracked: %d)",
        len(new_ids),
        len(seen_ids) + len(new_ids),
    )

    for message_id in new_ids:
        seen_ids.add(message_id)

    for message_id in new_ids[:max_log_per_poll]:
        try:
            message = zap.core.message(message_id)
        except Exception:
            continue

        req_line = _message_first_line(message.get("requestHeader", ""))
        resp_line = _message_first_line(message.get("responseHeader", ""))
        logger.info("msg=%s | %s | %s", message_id, req_line, resp_line)

    remaining = len(new_ids) - max_log_per_poll
    if remaining > 0:
        logger.info("... %d additional new messages not shown in this poll", remaining)


def _export_scan_messages(
    zap: zapv2.ZAPv2,
    scan_id: str,
    output_file: str,
    leading_records: list[dict] | None = None,
) -> None:
    """Export full request/response records for this scan to JSON."""
    try:
        message_ids = [str(mid) for mid in zap.ascan.messages_ids(scan_id)]
    except Exception as exc:
        logger.warning("Unable to fetch message IDs for export: %s", exc)
        return

    messages = list(leading_records or [])
    for message_id in message_ids:
        try:
            message = zap.core.message(message_id)
        except Exception:
            continue

        messages.append(
            _build_traffic_record(
                record_id=message_id,
                kind="scan",
                request_header=message.get("requestHeader", ""),
                request_body=message.get("requestBody", ""),
                response_header=message.get("responseHeader", ""),
                response_body=message.get("responseBody", ""),
                rtt=message.get("rtt", ""),
                timestamp=message.get("timestamp", ""),
                url=message.get("url", ""),
                final_url=message.get("url", ""),
            )
        )

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(messages, f, indent=2)

    logger.info("Saved %d scan HTTP messages to %s", len(messages), output_file)


def _log_alert_summary(alerts: list[dict]) -> None:
    if not alerts:
        logger.info("No alerts found for the target URL")
        return

    risk_counts = Counter(alert.get("risk", "Unknown") for alert in alerts)
    logger.info("Found %d total alerts", len(alerts))
    logger.info(
        "Risk summary | High: %d | Medium: %d | Low: %d | Informational: %d | Unknown: %d",
        risk_counts.get("High", 0),
        risk_counts.get("Medium", 0),
        risk_counts.get("Low", 0),
        risk_counts.get("Informational", 0),
        risk_counts.get("Unknown", 0),
    )

    logger.info("Top alerts (up to 10):")
    for idx, alert in enumerate(alerts[:10], start=1):
        logger.info(
            "%d. [%s] %s | URL: %s",
            idx,
            alert.get("risk", "Unknown"),
            alert.get("alert", "Unnamed alert"),
            alert.get("url", "N/A"),
        )


def _probe_target_url(target_url: str) -> None:
    """Log redirect/auth hints to explain empty scans early."""
    try:
        response = requests.get(
            target_url,
            timeout=8,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
    except requests.RequestException as exc:
        logger.warning("Could not probe target URL before scan: %s", exc)
        return

    final_url = str(response.url)
    logger.info("Target probe | status=%s | final_url=%s", response.status_code, final_url)

    if "login" in final_url.lower():
        logger.warning(
            "Target redirects to a login page. ZAP is likely scanning unauthenticated content, "
            "which often yields 0 SQLi alerts."
        )


def _extract_user_token(html_text: str) -> str | None:
    match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', html_text)
    return match.group(1) if match else None


def _try_login_and_set_cookie_rule(zap: zapv2.ZAPv2, target_url: str) -> str | None:
    login_url = os.getenv("TARGET_LOGIN_URL", "http://localhost:9090/login.php")
    username = os.getenv("TARGET_USERNAME", "admin")
    password = os.getenv("TARGET_PASSWORD", "password")
    username_field = os.getenv("TARGET_USERNAME_FIELD", "username")
    password_field = os.getenv("TARGET_PASSWORD_FIELD", "password")
    submit_field = os.getenv("TARGET_LOGIN_SUBMIT_FIELD", "Login")
    submit_value = os.getenv("TARGET_LOGIN_SUBMIT_VALUE", "Login")

    if not username or not password:
        logger.info("Login credentials not provided; running unauthenticated scan")
        return None

    logger.info("Attempting authenticated login via %s", login_url)
    if "/vulnerabilities/" in login_url.lower():
        logger.warning(
            "TARGET_LOGIN_URL appears to be an app page, not the login endpoint. "
            "Use the actual login URL such as /login.php."
        )
    session = requests.Session()
    session.proxies.update(_zap_proxy_config())

    try:
        login_page = session.get(
            login_url,
            timeout=10,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
        payload = {
            username_field: username,
            password_field: password,
            submit_field: submit_value,
        }

        user_token = _extract_user_token(login_page.text)
        if user_token:
            payload["user_token"] = user_token

        login_response = session.post(
            login_url,
            data=payload,
            timeout=10,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
    except requests.RequestException as exc:
        logger.warning("Login request failed: %s", exc)
        return None

    final_url = str(login_response.url).lower()
    if "login" in final_url:
        logger.warning("Login appears unsuccessful; final URL still points to login page")
        return None

    cookie_parts = []
    has_security_cookie = False
    for cookie in session.cookies:
        if cookie.name == "security":
            cookie_parts.append("security=low")
            has_security_cookie = True
        else:
            cookie_parts.append(f"{cookie.name}={cookie.value}")

    if not cookie_parts:
        logger.warning(
            "Login completed but no cookies were captured. "
            "Check login URL and field names in env vars."
        )
        return None

    if not has_security_cookie:
        cookie_parts.append("security=low")

    cookie_header = "; ".join(cookie_parts)

    try:
        zap.replacer.remove_rule(AUTH_COOKIE_RULE)
    except Exception:
        pass

    zap.replacer.add_rule(
        AUTH_COOKIE_RULE,
        "true",
        "REQ_HEADER",
        "false",
        "Cookie",
        cookie_header,
    )
    logger.info("Authenticated session cookie injected into ZAP requests")
    return cookie_header


def _prime_target_via_proxy(target_url: str, cookie_header: str | None = None) -> bool:
    """Prime URL via direct requests through ZAP proxy to seed Sites tree before active scan."""
    session = requests.Session()
    session.proxies.update(_zap_proxy_config())
    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    try:
        response = session.get(
            target_url,
            headers=headers,
            timeout=12,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
    except requests.RequestException as exc:
        logger.warning("Target priming request failed: %s", exc)
        return False

    logger.info(
        "Primed target through proxy | status=%s | final_url=%s",
        response.status_code,
        response.url,
    )
    return True


def _seed_target_with_params(target_url: str, cookie_header: str | None = None) -> None:
    """Send a parameterized request through ZAP so Active Scan can fuzz known params."""
    seeded_url = target_url.rstrip("/") + "?id=1&Submit=Submit"
    session = requests.Session()
    session.proxies.update(_zap_proxy_config())
    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    try:
        session.get(
            seeded_url,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
        logger.info("Seeded ZAP Sites tree with parameterized URL: %s", seeded_url)
        time.sleep(2)
    except requests.RequestException as exc:
        logger.warning("Failed to seed target URL: %s", exc)


def _capture_baseline_request(target_url: str, cookie_header: str | None = None) -> dict | None:
    baseline_url = os.getenv("TARGET_BASELINE_URL", target_url)
    session = requests.Session()
    session.proxies.update(_zap_proxy_config())
    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    try:
        response = session.get(
            baseline_url,
            headers=headers,
            timeout=12,
            allow_redirects=True,
            verify=_target_verify_tls(),
        )
    except requests.RequestException as exc:
        logger.warning("Baseline request failed: %s", exc)
        return None

    prepared_request = response.request
    request_headers = dict(prepared_request.headers)
    response_headers = dict(response.headers)
    request_header = _format_request_header(
        prepared_request.method,
        prepared_request.url,
        request_headers,
    )
    request_body = prepared_request.body or ""
    if isinstance(request_body, bytes):
        request_body = request_body.decode(errors="replace")

    response_header = _format_response_header(
        response.status_code,
        response.reason or "",
        response_headers,
    )
    response_body = response.text

    record = _build_traffic_record(
        record_id="baseline",
        kind="baseline",
        request_header=request_header,
        request_body=request_body,
        response_header=response_header,
        response_body=response_body,
        rtt=f"{response.elapsed.total_seconds():.6f}",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        url=baseline_url,
        final_url=str(response.url),
    )
    logger.info(
        "Captured baseline request | status=%s | final_url=%s | response_length=%d",
        response.status_code,
        response.url,
        len(response_body),
    )
    return record


def _build_html_report(alerts: list[dict], target_url: str) -> str:
        risk_counts = Counter(alert.get("risk", "Unknown") for alert in alerts)

        def risk_badge_class(risk: str) -> str:
                return {
                        "High": "risk-high",
                        "Medium": "risk-medium",
                        "Low": "risk-low",
                        "Informational": "risk-info",
                }.get(risk, "risk-unknown")

        rows = []
        for alert in alerts:
                risk = escape(str(alert.get("risk", "Unknown")))
                name = escape(str(alert.get("alert", alert.get("name", "Unnamed alert"))))
                url = escape(str(alert.get("url", "N/A")))
                method = escape(str(alert.get("method", "N/A")))
                param = escape(str(alert.get("param", "")))
                cweid = escape(str(alert.get("cweid", "N/A")))
                confidence = escape(str(alert.get("confidence", "N/A")))
                description = escape(str(alert.get("description", ""))).replace("\n", "<br>")
                solution = escape(str(alert.get("solution", ""))).replace("\n", "<br>")
                reference = escape(str(alert.get("reference", ""))).replace("\n", "<br>")

                rows.append(
                        f"""
                        <tr>
                            <td><span class=\"risk-badge {risk_badge_class(risk)}\">{risk}</span></td>
                            <td>{name}</td>
                            <td>{method}</td>
                            <td><a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a></td>
                            <td>{param}</td>
                            <td>{cweid}</td>
                            <td>{confidence}</td>
                            <td>{description}</td>
                            <td>{solution}</td>
                            <td>{reference}</td>
                        </tr>
                        """
                )

        rows_html = "\n".join(rows) if rows else "<tr><td colspan='10'>No alerts found.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
    <title>ZAP Scan Report</title>
    <style>
        :root {{
            --bg: #f5f7fb;
            --card: #ffffff;
            --text: #102a43;
            --muted: #627d98;
            --border: #d9e2ec;
            --high: #c81e1e;
            --medium: #b45309;
            --low: #1d4ed8;
            --info: #0f766e;
            --unknown: #475569;
        }}
        body {{
            margin: 0;
            font-family: "Segoe UI", Tahoma, sans-serif;
            background: linear-gradient(180deg, #eef3fb 0%, var(--bg) 100%);
            color: var(--text);
        }}
        .wrap {{ max-width: 1300px; margin: 0 auto; padding: 24px; }}
        .card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
            padding: 18px;
            margin-bottom: 18px;
        }}
        h1 {{ margin: 0 0 8px; font-size: 1.7rem; }}
        .muted {{ color: var(--muted); }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
        .stat {{
            padding: 8px 12px;
            border-radius: 999px;
            font-weight: 700;
            border: 1px solid var(--border);
            background: #f8fafc;
        }}
        .table-wrap {{ overflow: auto; }}
        table {{ width: 100%; border-collapse: collapse; min-width: 1100px; }}
        th, td {{ border: 1px solid var(--border); padding: 10px; vertical-align: top; text-align: left; }}
        th {{ background: #f0f4f8; position: sticky; top: 0; z-index: 1; }}
        .risk-badge {{
            color: #fff;
            font-weight: 700;
            font-size: 0.8rem;
            border-radius: 999px;
            padding: 4px 10px;
            display: inline-block;
        }}
        .risk-high {{ background: var(--high); }}
        .risk-medium {{ background: var(--medium); }}
        .risk-low {{ background: var(--low); }}
        .risk-info {{ background: var(--info); }}
        .risk-unknown {{ background: var(--unknown); }}
        a {{ color: #0b5ed7; }}
    </style>
</head>
<body>
    <div class=\"wrap\">
        <div class=\"card\">
            <h1>ZAP Active Scan Report</h1>
            <div class=\"muted\">Target: {escape(target_url)}</div>
            <div class=\"muted\">Generated: {escape(time.strftime("%Y-%m-%d %H:%M:%S"))}</div>
            <div class=\"stats\">
                <div class=\"stat\">Total: {len(alerts)}</div>
                <div class=\"stat\">High: {risk_counts.get("High", 0)}</div>
                <div class=\"stat\">Medium: {risk_counts.get("Medium", 0)}</div>
                <div class=\"stat\">Low: {risk_counts.get("Low", 0)}</div>
                <div class=\"stat\">Informational: {risk_counts.get("Informational", 0)}</div>
                <div class=\"stat\">Unknown: {risk_counts.get("Unknown", 0)}</div>
            </div>
        </div>

        <div class=\"card table-wrap\">
            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Alert</th>
                        <th>Method</th>
                        <th>URL</th>
                        <th>Param</th>
                        <th>CWE</th>
                        <th>Confidence</th>
                        <th>Description</th>
                        <th>Solution</th>
                        <th>Reference</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""


def main() -> None:
    logger.info("Connecting to ZAP API")
    zap = zapv2.ZAPv2(
        apikey=os.getenv("ZAP_API_KEY", ""),
        proxies=_zap_proxy_config(),
    )

    logger.info("Fetching active scan rules")
    scanners = zap.ascan.scanners()
    logger.info("Found %d active scan rules", len(scanners))

    logger.info("Disabling all active scan rules")
    for rule in scanners:
        rule_id = rule["id"]
        zap.ascan.disable_scanners(rule_id)
        logger.info("Disabled rule: %s (%s)", rule_id, rule.get("name", "unknown"))

    sqli_rules = ["40018", "40019", "40020", "40021", "40022", "40024"]
    logger.info("Enabling SQLi rules: %s", ", ".join(sqli_rules))
    zap.ascan.enable_scanners(",".join(sqli_rules))
    logger.info("Setting SQLi scanner attack strength=HIGH and alert threshold=LOW")
    for rule_id in sqli_rules:
        zap.ascan.set_scanner_attack_strength(id=rule_id, attackstrength="HIGH")
        zap.ascan.set_scanner_alert_threshold(id=rule_id, alertthreshold="LOW")

    target_url = os.getenv("TARGET_URL", "http://localhost:9090/vulnerabilities/sqli/")
    auth_cookie_header = _try_login_and_set_cookie_rule(zap, target_url)
    baseline_record = _capture_baseline_request(target_url, auth_cookie_header)
    _seed_target_with_params(target_url, auth_cookie_header)
    _probe_target_url(target_url)
    logger.info("Starting active scan for: %s", target_url)
    scan_id = zap.ascan.scan(url=target_url, recurse=True)
    logger.info("Scan start response: %s", scan_id)

    if scan_id == "url_not_found":
        logger.warning(
            "Target URL was not in ZAP Sites tree. Priming target manually through proxy and retrying."
        )
        _prime_target_via_proxy(target_url, auth_cookie_header)
        time.sleep(2)

        logger.info("Retrying active scan after manual priming")
        scan_id = zap.ascan.scan(url=target_url, recurse=True)
        logger.info("Active scan retry response: %s", scan_id)

    if not str(scan_id).isdigit():
        logger.error(
            "ZAP did not return a valid scan ID. Response: %s. "
            "Check target URL scope/access and ensure ZAP can reach the host.",
            scan_id,
        )
        return

    logger.info("Polling scan progress every 3 seconds")
    seen_message_ids: set[str] = set()
    while True:
        _log_new_scan_messages(zap, scan_id, seen_message_ids)

        raw_status = zap.ascan.status(scan_id)
        status = _parse_status(raw_status)
        if status is None:
            logger.error(
                "ZAP returned non-numeric scan status: %s for scan ID %s. "
                "The scan may not exist or may have failed to start.",
                raw_status,
                scan_id,
            )
            return
        logger.info("Scan progress: %d%%", status)
        if status >= 100:
            break
        time.sleep(3)

    logger.info("Scan complete")

    traffic_file = "zap_scan_traffic.json"
    leading_records = [baseline_record] if baseline_record else []
    _export_scan_messages(zap, scan_id, traffic_file, leading_records=leading_records)

    logger.info("Fetching scan alerts from ZAP")
    alerts = zap.core.alerts(baseurl=target_url, start=0, count=9999)
    _log_alert_summary(alerts)

    alerts_file = "zap_alerts.json"
    with open(alerts_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)
    logger.info("Saved alerts to %s", alerts_file)

    html_report_file = "zap_report.html"
    html_report = _build_html_report(alerts, target_url)
    with open(html_report_file, "w", encoding="utf-8") as f:
        f.write(html_report)
    logger.info("Saved HTML report to %s", html_report_file)


if __name__ == "__main__":
    main()