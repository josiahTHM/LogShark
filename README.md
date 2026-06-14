# 🦈 LogShark

LogShark is a Python CLI tool that scans host and network logs for failed authentication and denied access events, counts occurrences by source IP, and flags addresses that exceed a configurable threshold.

Supports real-world log formats (Linux auth, Windows Event 4625, firewall, JSON/NDJSON, and custom app logs), full IPv4/IPv6 parsing, time-window filtering, and export to JSON, CSV, or a firewall-ready blocklist.

## Requirements

- Python 3.10+
- No third-party dependencies (stdlib only)

## Architecture

```text
                    +------------------+
                    |  Input log file  |
                    +--------+---------+
                             |
                             v
                    +------------------+
                    |   argparse CLI   |
                    |  (-t -f -s -u…)  |
                    +--------+---------+
                             |
                             v
              +------------------------------+
              |  Format detect (-f auto) or  |
              |  explicit adapter selection  |
              +--------------+---------------+
                             |
                             v
              +------------------------------+
              |      LogFormatAdapter        |
              |  custom | linux-auth | json  |
              |  windows-4625 | firewall …   |
              +--------------+---------------+
                             |
              +--------------+--------------+
              |                             |
              v                             v
   +--------------------+        +-------------------+
   | is_failure_event?  |        | parse_timestamp   |
   | (per log format)   |        | (syslog/ISO/JSON) |
   +---------+----------+        +---------+---------+
             | no                          |
             +-----------> skip            |
             | yes                         |
             v                             v
   +--------------------+        +-------------------+
   | extract_source_ip  |        | --since / --until |
   | (field-aware)      |        |   time filter     |
   +---------+----------+        +---------+---------+
             |                             |
             v                             |
   +--------------------+                  |
   | extract_ip fallback|                  |
   | (IPv4 / IPv6)      |                  |
   +---------+----------+                  |
             |                             |
             +-------------+---------------+
                           |
                           v
                +---------------------+
                | collections.Counter |
                |   count per IP      |
                +----------+----------+
                           |
                           v
                +---------------------+
                | count >= threshold? |
                +----------+----------+
                           |
         +-----------------+------------------+
         |                 |                  |
         v                 v                  v
 +---------------+ +---------------+ +---------------+
 | Stdout        | | -j JSON       | | -b blocklist  |
 | (IP + counts) | | -c CSV        | |               |
 +---------------+ +---------------+ +---------------+

  Parallel: logs/app.log (-l)  <-- DEBUG operational trace of entire run
```

| Path                                    | Role                                         |
| --------------------------------------- | -------------------------------------------- |
| **Input log** (positional CLI argument) | Security log you analyze                     |
| `**app.log`** (`-l`)                    | How the analyzer ran (DEBUG operational log) |
| `**-j` / `-c` / `-b` outputs**          | JSON, CSV, or blocklist reports              |


## Quick start
```bash
# Basic usage: log_file -f format -t threshold
python3 LogShark.py custom_log.txt -f custom -t 3

# Linux auth brute-force check (skip loopback)
python3 LogShark.py auth.log -f linux-auth -t 2 -x

# Auto-detect format
python3 LogShark.py firewall.log -t 2
```

**Note:** `log_file` is a required positional argument (the path to the log you analyze). `-f` is the log **format**, not the file path.

## CLI reference

```text
python3 LogShark.py <log_file> -f <format> -t <threshold> [options]
python3 LogShark.py log_file [options]
```

Or invoke via the program name shown in help: `LogShark`.


| Long flag           | Short | Description                                             |
| ------------------- | ----- | ------------------------------------------------------- |
| `--threshold`       | `-t`  | Minimum failure count to flag an IP (default: `1`)      |
| `--format`          | `-f`  | Log format or `auto` (default: `auto`)                  |
| `--failure-pattern` | `-p`  | Extra regex to mark failure lines                       |
| `--ip-field`        | `-i`  | JSON dot-path for source IP (e.g. `source.ip`)          |
| `--exclude-local`   | `-x`  | Ignore `127.0.0.1`, `::1`, and `localhost`              |
| `--since`           | `-s`  | Only count events on/after this datetime                |
| `--until`           | `-u`  | Only count events on/before this datetime               |
| `--output-json`     | `-j`  | Write full JSON report to `PATH`                        |
| `--output-csv`      | `-c`  | Write `ip,count` CSV to `PATH`                          |
| `--blocklist-out`   | `-b`  | Write one IP per line (for firewall import)             |
| `--top`             | `-n`  | Limit printed results to top N offenders                |
| `--quiet`           | `-q`  | Suppress stdout                                         |
| `--log-file`        | `-l`  | Analyzer operational log path (default: `logs/app.log`) |
| `--verbose`         | `-v`  | Echo DEBUG messages to stderr                           |


Datetime values for `-s` / `-u` accept formats such as `2026-05-17 12:00:00` or ISO-8601 (`2026-05-17T12:00:00Z`).

## Supported log formats

Use `-f auto` to sniff the first 50 lines, or pick a format explicitly.


| Format         | Typical source                         | Failure signals                                             | IP location                           |
| -------------- | -------------------------------------- | ----------------------------------------------------------- | ------------------------------------- |
| `custom`       | App / assignment logs                  | `LOGIN FAILED`                                              | `ip:port` or bare IP in line          |
| `linux-auth`   | `/var/log/auth.log`, `/var/log/secure` | `Failed password`, `Invalid user`, `authentication failure` | `from 203.0.113.5 port …`, `rhost=`   |
| `windows-4625` | Security event export                  | Event ID `4625`                                             | `Source Network Address:`             |
| `syslog`       | `/var/log/syslog`, `/var/log/messages` | Same as linux-auth in message body                          | Same as linux-auth                    |
| `firewall`     | iptables, pfSense, etc.                | `Deny`, `DROP`, `REJECT`, `blocked`                         | `src=`, `saddr=`, `source_ip=`        |
| `json`         | EDR, cloud, NDJSON                     | `event.outcome:failure`, login actions                      | `source.ip`, `client.ip`, `src_ip`, … |


IP extraction uses format-specific field rules first, then a generic fallback that handles IPv4, IPv6, `[ipv6]:port`, and `ipv4:port` forms.

## Example commands

```bash
# Threshold report with counts on stdout
python3 LogShark.py custom_log.txt -t 3

# Windows Security export (4625 failed logons)
python3 LogShark.py windows_4625.txt -f windows-4625 -t 2

# Firewall deny storm with exports
python3 LogShark.py firewall.log -f firewall -t 2 \
  -j report.json -c report.csv -b blocklist.txt

# Time-bounded analysis
python3 LogShark.py auth.log -f linux-auth \
  -s "2026-05-17 12:01:05" -u "2026-05-17 12:01:07" -t 1

# JSON events with custom IP field
python3 LogShark.py events.ndjson -f json -i source.ip -t 2
```

## Output

### Stdout (default)

```text
example:
The following IP addresses exceeded the threshold of 3 times:
  10.9.5.2  (3 failures)
  172.16.0.10  (3 failures)
Summary: 10 failure events, 5 unique IPs, 2 above threshold
```

Use `-q` to suppress stdout and rely on files or `app.log` only.

### JSON report (`-j`)

Includes `threshold`, `source_file`, `log_format`, `summary`, `suspicious_ips`, and `all_counts`.

### CSV report (`-c`)

Columns: `ip`, `count` — all IPs sorted by count descending.

### Blocklist (`-b`)

One IP per line for IPs at or above the threshold, suitable for firewall deny rules or SIEM import.

## Operational logging (app.log)

The analyzer writes a **DEBUG-level operational trace** to `logs/app.log` by default (override with `-l`). This file records how LogShark ran — config, format detection, matched lines, skipped events, exports, and timing — **not** the security events from the input log.

- **INFO**: Run summaries, format chosen, IPs above threshold, export paths
- **DEBUG**: Per-line parsing detail, new IPs, time-filter skips, progress every 10,000 lines
- **WARNING**: Failure lines with no extractable IP
- **ERROR**: Missing input file, export write failures

Use `-v` to mirror DEBUG output to stderr for live troubleshooting.
```

## License

Educational / personal project — **🦈 LogShark**.
