"""LogShark core — log parsing, adapters, and analysis."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol

logger = logging.getLogger("logshark")

IPV4_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):\d+\b")
IPV6_BRACKET_RE = re.compile(r"\[([0-9a-fA-F:]+)\]:\d+")
IPV6_BARE_RE = re.compile(r"\b([0-9a-fA-F]{0,4}:+[0-9a-fA-F:]{2,})\b")

SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
ISO_TS_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

LINUX_AUTH_FROM_RE = re.compile(r"(?:from|rhost=)\s*(\S+)", re.IGNORECASE)
WINDOWS_SRC_ADDR_RE = re.compile(
    r"Source Network Address:\s*(\S+)", re.IGNORECASE
)
WINDOWS_XML_IP_RE = re.compile(
    r'<Data Name="IpAddress">([^<]+)</Data>', re.IGNORECASE
)
FIREWALL_SRC_RE = re.compile(
    r"(?:src|saddr|source_ip)\s*=\s*(\S+)", re.IGNORECASE
)
FIREWALL_SRC_LABEL_RE = re.compile(
    r"Src IP:\s*(\S+)", re.IGNORECASE
)

DEFAULT_JSON_IP_KEYS = (
    "source.ip",
    "client.ip",
    "src_ip",
    "remote_addr",
    "source_ip",
    "client_ip",
)

AUTO_DETECT_SAMPLE_LINES = 50


def normalize_ip(raw: str) -> Optional[str]:
    """Validate and return normalized IP string, or None."""
    if not raw or raw in ("-", "NULL", "null", "localhost"):
        return None
    candidate = raw.strip().rstrip(".,;)]}")
    if candidate.startswith("["):
        candidate = candidate[1:]
    if candidate.endswith("]"):
        candidate = candidate[:-1]
    if ":" in candidate and candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":")[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def is_localhost(ip: str) -> bool:
    if ip.lower() == "localhost":
        return True
    normalized = normalize_ip(ip)
    if normalized is None:
        return False
    addr = ipaddress.ip_address(normalized)
    return addr.is_loopback


def extract_ip(line: str) -> Optional[str]:
    """Generic IP extraction fallback: IPv6 bracket, IPv4:port, bare tokens."""
    match = IPV6_BRACKET_RE.search(line)
    if match:
        result = normalize_ip(match.group(1))
        if result:
            return result

    match = IPV4_PORT_RE.search(line)
    if match:
        result = normalize_ip(match.group(1))
        if result:
            return result

    for match in IPV6_BARE_RE.finditer(line):
        result = normalize_ip(match.group(1))
        if result:
            return result

    for token in line.split():
        cleaned = token.strip(".,;()[]{}\"'")
        if ":" in cleaned and cleaned.count(":") == 1 and "." in cleaned:
            cleaned = cleaned.split(":")[0]
        result = normalize_ip(cleaned)
        if result:
            return result
    return None


def parse_datetime_flexible(value: str) -> Optional[datetime]:
    """Parse common timestamp string formats."""
    value = value.strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ):
        try:
            return datetime.strptime(value.replace("Z", ""), fmt.replace("Z", ""))
        except ValueError:
            continue
    return None


def parse_timestamp(line: str, default_year: Optional[int] = None) -> Optional[datetime]:
    """Extract timestamp from a log line using shared helpers."""
    if default_year is None:
        default_year = datetime.now().year

    iso_match = ISO_TS_RE.search(line)
    if iso_match:
        parsed = parse_datetime_flexible(iso_match.group("ts"))
        if parsed:
            return parsed

    syslog_match = SYSLOG_TS_RE.match(line)
    if syslog_match:
        month = SYSLOG_MONTHS.get(syslog_match.group("mon"))
        if month:
            try:
                return datetime.strptime(
                    f"{default_year} {month:02d} {int(syslog_match.group('day')):02d} "
                    f"{syslog_match.group('time')}",
                    "%Y %m %d %H:%M:%S",
                )
            except ValueError:
                pass

    date_match = re.search(r"#\s*Date:\s*(.+)", line)
    if date_match:
        parsed = parse_datetime_flexible(date_match.group(1).strip())
        if parsed:
            return parsed

    xml_match = re.search(
        r'SystemTime="(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"',
        line,
    )
    if xml_match:
        parsed = parse_datetime_flexible(xml_match.group(1))
        if parsed:
            return parsed

    return None


def get_nested_value(data: dict, dot_path: str) -> Optional[str]:
    if dot_path in data:
        value = data[dot_path]
        return None if value is None else str(value)
    current: object = data
    for part in dot_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    if current is None:
        return None
    return str(current)


class LogFormatAdapter(Protocol):
    name: str

    def is_failure_event(self, line: str) -> bool: ...

    def extract_source_ip(self, line: str) -> Optional[str]: ...

    def parse_timestamp(self, line: str) -> Optional[datetime]: ...


@dataclass
class AdapterConfig:
    failure_pattern: Optional[re.Pattern[str]] = None
    ip_field: Optional[str] = None


class CustomAdapter:
    name = "custom"

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    def is_failure_event(self, line: str) -> bool:
        if "LOGIN FAILED" in line:
            return True
        if self.config.failure_pattern and self.config.failure_pattern.search(line):
            return True
        return False

    def extract_source_ip(self, line: str) -> Optional[str]:
        return extract_ip(line)

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        return parse_timestamp(line)


class LinuxAuthAdapter:
    name = "linux-auth"

    FAILURE_MARKERS = (
        "failed password",
        "invalid user",
        "authentication failure",
    )

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    def is_failure_event(self, line: str) -> bool:
        lower = line.lower()
        if any(marker in lower for marker in self.FAILURE_MARKERS):
            return True
        if self.config.failure_pattern and self.config.failure_pattern.search(line):
            return True
        return False

    def extract_source_ip(self, line: str) -> Optional[str]:
        match = LINUX_AUTH_FROM_RE.search(line)
        if match:
            token = match.group(1)
            if token.lower().startswith("port"):
                return None
            return normalize_ip(token.split("port")[0].strip()) or extract_ip(line)
        return extract_ip(line)

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        return parse_timestamp(line)


class SyslogAdapter(LinuxAuthAdapter):
    name = "syslog"


class Windows4625Adapter:
    name = "windows-4625"

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config
        self._in_4625_block = False

    def is_failure_event(self, line: str) -> bool:
        if re.search(r"Event ID:\s*4625", line, re.IGNORECASE):
            self._in_4625_block = True
            if "Source Network Address" in line:
                return True
            return False
        if re.search(r"Event ID:\s*\d+", line, re.IGNORECASE):
            self._in_4625_block = False
            return False
        if self._in_4625_block and re.search(
            r"Source Network Address:", line, re.IGNORECASE
        ):
            return True
        if self.config.failure_pattern and self.config.failure_pattern.search(line):
            return True
        return False

    def extract_source_ip(self, line: str) -> Optional[str]:
        match = WINDOWS_SRC_ADDR_RE.search(line)
        if match:
            result = normalize_ip(match.group(1))
            if result:
                return result
        match = WINDOWS_XML_IP_RE.search(line)
        if match:
            result = normalize_ip(match.group(1))
            if result:
                return result
        return extract_ip(line)

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        return parse_timestamp(line)


class FirewallAdapter:
    name = "firewall"

    FAILURE_MARKERS = ("deny", "drop", "reject", "blocked")

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    def is_failure_event(self, line: str) -> bool:
        lower = line.lower()
        if any(marker in lower for marker in self.FAILURE_MARKERS):
            return True
        if self.config.failure_pattern and self.config.failure_pattern.search(line):
            return True
        return False

    def extract_source_ip(self, line: str) -> Optional[str]:
        for pattern in (FIREWALL_SRC_RE, FIREWALL_SRC_LABEL_RE):
            match = pattern.search(line)
            if match:
                token = match.group(1)
                if ":" in token and token.count(":") == 1 and "." in token:
                    token = token.split(":")[0]
                result = normalize_ip(token)
                if result:
                    return result
        return extract_ip(line)

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        return parse_timestamp(line)


class JsonAdapter:
    name = "json"

    FAILURE_KEYS = (
        ("event", "outcome", "failure"),
        ("result", "fail"),
        ("result", "failure"),
        ("action", "login"),
    )

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config

    def _parse_json(self, line: str) -> Optional[dict]:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def is_failure_event(self, line: str) -> bool:
        data = self._parse_json(line)
        if data is None:
            return False
        if self.config.failure_pattern and self.config.failure_pattern.search(line):
            return True
        outcome = get_nested_value(data, "event.outcome")
        if outcome and outcome.lower() == "failure":
            action = get_nested_value(data, "event.action")
            if action is None or action.lower() in ("login", "logon", "auth", "authentication"):
                return True
        result = data.get("result")
        if isinstance(result, str) and result.lower() in ("fail", "failure", "failed"):
            return True
        action = data.get("action")
        if isinstance(action, str) and action.lower() in ("login", "logon"):
            if str(data.get("success", "")).lower() in ("false", "0"):
                return True
            if str(data.get("status", "")).lower() in ("fail", "failure", "failed"):
                return True
        return False

    def extract_source_ip(self, line: str) -> Optional[str]:
        data = self._parse_json(line)
        if data is None:
            return None
        if self.config.ip_field:
            value = get_nested_value(data, self.config.ip_field)
            if value:
                result = normalize_ip(value)
                if result:
                    return result
        for key in DEFAULT_JSON_IP_KEYS:
            value = get_nested_value(data, key)
            if value:
                result = normalize_ip(value)
                if result:
                    return result
        return extract_ip(line)

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        data = self._parse_json(line)
        if data:
            for key in ("@timestamp", "timestamp", "time", "event.created"):
                value = get_nested_value(data, key)
                if value:
                    parsed = parse_datetime_flexible(value.replace("T", "T"))
                    if parsed:
                        return parsed
        return parse_timestamp(line)


ADAPTERS: dict[str, type] = {
    "custom": CustomAdapter,
    "linux-auth": LinuxAuthAdapter,
    "syslog": SyslogAdapter,
    "windows-4625": Windows4625Adapter,
    "firewall": FirewallAdapter,
    "json": JsonAdapter,
}


def create_adapter(name: str, config: AdapterConfig) -> LogFormatAdapter:
    if name not in ADAPTERS:
        raise ValueError(f"Unknown log format: {name}")
    return ADAPTERS[name](config)


def detect_format(lines: list[str]) -> str:
    """Auto-detect log format from sample lines."""
    scores: Counter[str] = Counter()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            scores["json"] += 3
        if re.search(r"Event ID:\s*4625", line, re.IGNORECASE):
            scores["windows-4625"] += 3
        if "Source Network Address" in line:
            scores["windows-4625"] += 2
        lower = line.lower()
        if "sshd" in lower and (
            "failed password" in lower or "authentication failure" in lower
        ):
            scores["linux-auth"] += 3
        if any(m in lower for m in ("deny", "drop", "reject")) and re.search(
            r"(?:src|saddr|source_ip)\s*=", line, re.IGNORECASE
        ):
            scores["firewall"] += 3
        if "LOGIN FAILED" in line:
            scores["custom"] += 3

    if scores:
        chosen = scores.most_common(1)[0][0]
        logger.debug("Auto-detect scores: %s; chosen=%s", dict(scores), chosen)
        return chosen
    logger.debug("Auto-detect found no signals; defaulting to custom")
    return "custom"


@dataclass
class AnalysisResult:
    suspicious_ips: list[tuple[str, int]]
    all_counts: dict[str, int]
    total_failed_lines: int
    unique_ips: int
    skipped_unparseable: int
    skipped_localhost: int
    skipped_time_filter: int
    lines_read: int
    log_format: str
    source_file: str
    threshold: int
    elapsed_seconds: float = 0.0


@dataclass
class AnalysisOptions:
    threshold: int = 1
    log_format: str = "auto"
    failure_pattern: Optional[str] = None
    ip_field: Optional[str] = None
    exclude_local: bool = False
    since: Optional[datetime] = None
    until: Optional[datetime] = None


def in_time_window(
    ts: Optional[datetime],
    since: Optional[datetime],
    until: Optional[datetime],
) -> bool:
    if since is None and until is None:
        return True
    if ts is None:
        logger.debug("No timestamp on line; including by default")
        return True
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True


def analyze_log(
    path_to_log_file: str,
    adapter: LogFormatAdapter,
    options: AnalysisOptions,
    resolved_format: str,
) -> AnalysisResult:
    counts: Counter[str] = Counter()
    total_failed = 0
    skipped_unparseable = 0
    skipped_localhost = 0
    skipped_time_filter = 0
    lines_read = 0
    seen_ips: set[str] = set()

    with open(path_to_log_file, "r", encoding="utf-8") as file:
        for line in file:
            lines_read += 1
            if lines_read % 10000 == 0:
                logger.debug("Progress: read %d lines", lines_read)

            if not adapter.is_failure_event(line):
                continue

            ts = adapter.parse_timestamp(line)
            if not in_time_window(ts, options.since, options.until):
                skipped_time_filter += 1
                logger.debug(
                    "Line %d excluded by time filter (ts=%s)", lines_read, ts
                )
                continue

            total_failed += 1
            logger.debug(
                "Line %d matched failure event: %s",
                lines_read,
                line.strip()[:200],
            )

            extracted_ip = adapter.extract_source_ip(line)
            if not extracted_ip:
                skipped_unparseable += 1
                logger.warning(
                    "Line %d: failure event with no extractable IP: %s",
                    lines_read,
                    line.strip()[:200],
                )
                continue

            if options.exclude_local and is_localhost(extracted_ip):
                skipped_localhost += 1
                logger.debug(
                    "Line %d: skipped localhost IP %s", lines_read, extracted_ip
                )
                continue

            if extracted_ip not in seen_ips:
                seen_ips.add(extracted_ip)
                logger.debug("New IP address: %s", extracted_ip)

            counts[extracted_ip] += 1

    suspicious = [
        (ip, count)
        for ip, count in counts.most_common()
        if count >= options.threshold
    ]
    for ip, count in counts.items():
        if count < options.threshold:
            logger.debug("IP %s below threshold (%d < %d)", ip, count, options.threshold)
        else:
            logger.info(
                "IP %s exceeds threshold (%d >= %d)", ip, count, options.threshold
            )

    return AnalysisResult(
        suspicious_ips=suspicious,
        all_counts=dict(counts),
        total_failed_lines=total_failed,
        unique_ips=len(counts),
        skipped_unparseable=skipped_unparseable,
        skipped_localhost=skipped_localhost,
        skipped_time_filter=skipped_time_filter,
        lines_read=lines_read,
        log_format=resolved_format,
        source_file=path_to_log_file,
        threshold=options.threshold,
    )


def write_json_report(path: str, result: AnalysisResult) -> None:
    payload = {
        "threshold": result.threshold,
        "source_file": result.source_file,
        "log_format": result.log_format,
        "summary": {
            "total_failed_lines": result.total_failed_lines,
            "unique_ips": result.unique_ips,
            "above_threshold": len(result.suspicious_ips),
            "skipped_unparseable": result.skipped_unparseable,
            "skipped_localhost": result.skipped_localhost,
            "skipped_time_filter": result.skipped_time_filter,
            "lines_read": result.lines_read,
            "elapsed_seconds": result.elapsed_seconds,
        },
        "suspicious_ips": [
            {"ip": ip, "count": count} for ip, count in result.suspicious_ips
        ],
        "all_counts": result.all_counts,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    logger.info("Wrote JSON report: %s", path)
    logger.debug("JSON report keys: %s", list(payload.keys()))


def write_csv_report(path: str, result: AnalysisResult, threshold_only: bool = False) -> None:
    rows = (
        result.suspicious_ips
        if threshold_only
        else sorted(result.all_counts.items(), key=lambda x: (-x[1], x[0]))
    )
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ip", "count"])
        for ip, count in rows:
            writer.writerow([ip, count])
    logger.info("Wrote CSV report: %s (%d rows)", path, len(rows))


def write_blocklist(path: str, result: AnalysisResult) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for ip, _count in sorted(result.suspicious_ips, key=lambda x: x[0]):
            fh.write(f"{ip}\n")
    logger.info("Wrote blocklist: %s (%d IPs)", path, len(result.suspicious_ips))
