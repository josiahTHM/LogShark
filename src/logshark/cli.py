"""LogShark CLI — command-line interface."""

from __future__ import annotations

import argparse
import logging
import logging.config
import os
import re
import sys
import time
from typing import Optional

from logshark import __version__
from logshark.core import (
    ADAPTERS,
    AUTO_DETECT_SAMPLE_LINES,
    AdapterConfig,
    AnalysisOptions,
    AnalysisResult,
    analyze_log,
    create_adapter,
    detect_format,
    parse_datetime_flexible,
    write_blocklist,
    write_csv_report,
    write_json_report,
)

logger = logging.getLogger("logshark")


def setup_logging(log_file: str, verbose: bool) -> None:
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    handlers: dict[str, dict] = {
        "file": {
            "class": "logging.FileHandler",
            "level": "DEBUG",
            "formatter": "standard",
            "filename": log_file,
            "mode": "a",
            "encoding": "utf-8",
        },
    }
    root_handlers = ["file"]
    if verbose:
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "standard",
            "stream": "ext://sys.stderr",
        }
        root_handlers.append("console")

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                },
            },
            "handlers": handlers,
            "loggers": {
                "logshark": {
                    "handlers": root_handlers,
                    "level": "DEBUG",
                    "propagate": False,
                },
            },
            "root": {"level": "WARNING"},
        }
    )


def parse_cli_datetime(value: str):
    parsed = parse_datetime_flexible(value)
    if parsed is None:
        raise argparse.ArgumentTypeError(
            f"Invalid datetime '{value}'. Use YYYY-MM-DD HH:MM:SS or ISO-8601."
        )
    return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    formats = ["auto"] + list(ADAPTERS.keys())
    parser = argparse.ArgumentParser(
        prog="logshark",
        description="LogShark — analyze failed login and denied access events in log files.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("log_file", help="Path to the input log file")
    parser.add_argument(
        "-t", "--threshold", type=int, default=1,
        help="Minimum failure count to flag an IP (default: 1)",
    )
    parser.add_argument(
        "-f", "--format", choices=formats, default="auto",
        help="Log format or auto-detect (default: auto)",
    )
    parser.add_argument(
        "-p", "--failure-pattern",
        help="Extra regex to mark failure lines (org-specific)",
    )
    parser.add_argument(
        "-i", "--ip-field",
        help="JSON dot-path for source IP (e.g. source.ip)",
    )
    parser.add_argument(
        "-x", "--exclude-local", action="store_true",
        help="Ignore 127.0.0.1, ::1, and localhost",
    )
    parser.add_argument(
        "-s", "--since", type=parse_cli_datetime,
        help="Only count lines on/after this datetime",
    )
    parser.add_argument(
        "-u", "--until", type=parse_cli_datetime,
        help="Only count lines on/before this datetime",
    )
    parser.add_argument("-j", "--output-json", metavar="PATH", help="Write JSON report")
    parser.add_argument("-c", "--output-csv", metavar="PATH", help="Write CSV report")
    parser.add_argument(
        "-b", "--blocklist-out", metavar="PATH",
        help="Write blocklist (one IP per line)",
    )
    parser.add_argument(
        "-n", "--top", type=int,
        help="Limit printed results to top N offenders",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress stdout; rely on files/logs only",
    )
    parser.add_argument(
        "-l", "--log-file", dest="audit_log", default="logs/app.log",
        help="Analyzer operational log path (default: logs/app.log)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Echo DEBUG messages to stderr",
    )
    return parser


def print_results(result: AnalysisResult, top: Optional[int]) -> None:
    suspicious = result.suspicious_ips
    if top is not None:
        suspicious = suspicious[:top]

    if suspicious:
        print(
            f"The following IP addresses exceeded the threshold of "
            f"{result.threshold} times:"
        )
        for ip, count in suspicious:
            print(f"  {ip}  ({count} failures)")
    else:
        print(
            f"No IP addresses exceeded the threshold of {result.threshold} times."
        )

    print(
        f"Summary: {result.total_failed_lines} failure events, "
        f"{result.unique_ips} unique IPs, "
        f"{len(result.suspicious_ips)} above threshold"
    )


def main(args: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    parsed = parser.parse_args(args)

    if parsed.threshold < 1:
        parser.error("threshold must be >= 1")

    setup_logging(parsed.audit_log, parsed.verbose)

    if not os.path.exists(parsed.log_file):
        logger.error("Log file not found: %s", parsed.log_file)
        print(f"Error: log file not found: {parsed.log_file}", file=sys.stderr)
        return 1

    logger.info("Starting analysis of %s", parsed.log_file)
    logger.debug(
        "Config: threshold=%d format=%s exclude_local=%s since=%s until=%s "
        "json=%s csv=%s blocklist=%s top=%s",
        parsed.threshold,
        parsed.format,
        parsed.exclude_local,
        parsed.since,
        parsed.until,
        parsed.output_json,
        parsed.output_csv,
        parsed.blocklist_out,
        parsed.top,
    )

    failure_re = (
        re.compile(parsed.failure_pattern) if parsed.failure_pattern else None
    )
    config = AdapterConfig(failure_pattern=failure_re, ip_field=parsed.ip_field)
    options = AnalysisOptions(
        threshold=parsed.threshold,
        log_format=parsed.format,
        failure_pattern=parsed.failure_pattern,
        ip_field=parsed.ip_field,
        exclude_local=parsed.exclude_local,
        since=parsed.since,
        until=parsed.until,
    )

    with open(parsed.log_file, "r", encoding="utf-8") as fh:
        sample_lines = []
        for _ in range(AUTO_DETECT_SAMPLE_LINES):
            line = fh.readline()
            if not line:
                break
            sample_lines.append(line)

    if parsed.format == "auto":
        resolved_format = detect_format(sample_lines)
    else:
        resolved_format = parsed.format

    adapter = create_adapter(resolved_format, config)
    logger.info("Using log format: %s", resolved_format)
    start = time.monotonic()
    result = analyze_log(parsed.log_file, adapter, options, resolved_format)
    result.elapsed_seconds = time.monotonic() - start

    logger.info(
        "Finished processing %s: %d failure events, %d unique IPs, "
        "%d above threshold (%.2fs)",
        parsed.log_file,
        result.total_failed_lines,
        result.unique_ips,
        len(result.suspicious_ips),
        result.elapsed_seconds,
    )
    logger.debug(
        "Skipped: unparseable=%d localhost=%d time_filter=%d lines_read=%d",
        result.skipped_unparseable,
        result.skipped_localhost,
        result.skipped_time_filter,
        result.lines_read,
    )

    if parsed.output_json:
        try:
            write_json_report(parsed.output_json, result)
        except OSError as exc:
            logger.error("Failed to write JSON report: %s", exc)
            return 1

    if parsed.output_csv:
        try:
            write_csv_report(parsed.output_csv, result)
        except OSError as exc:
            logger.error("Failed to write CSV report: %s", exc)
            return 1

    if parsed.blocklist_out:
        try:
            write_blocklist(parsed.blocklist_out, result)
        except OSError as exc:
            logger.error("Failed to write blocklist: %s", exc)
            return 1

    if not parsed.quiet:
        print_results(result, parsed.top)

    return 0
