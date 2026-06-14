import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import logshark.core as analyzer
from logshark.cli import main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


class ExtractIpTests(unittest.TestCase):
    def test_ipv4_with_port(self):
        self.assertEqual(
            analyzer.extract_ip("LOGIN FAILED from 10.9.5.2:8080"),
            "10.9.5.2",
        )

    def test_public_ipv4(self):
        self.assertEqual(
            analyzer.extract_ip("connect 203.0.113.5:443 failed"),
            "203.0.113.5",
        )

    def test_private_172(self):
        self.assertEqual(
            analyzer.extract_ip("from 172.16.0.1:22"),
            "172.16.0.1",
        )

    def test_ipv6_bracket(self):
        self.assertEqual(
            analyzer.extract_ip("client [2001:db8::1]:443 login"),
            "2001:db8::1",
        )

    def test_ipv6_bare(self):
        self.assertEqual(
            analyzer.extract_ip("from 2001:db8::5 port 49152"),
            "2001:db8::5",
        )

    def test_loopback(self):
        self.assertEqual(analyzer.extract_ip("from ::1 port 22"), "::1")

    def test_no_ip(self):
        self.assertIsNone(analyzer.extract_ip("no address here"))


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.config = analyzer.AdapterConfig()

    def test_linux_auth_from_field(self):
        adapter = analyzer.LinuxAuthAdapter(self.config)
        line = (
            "May 17 12:01:03 server sshd[1234]: Failed password for invalid user "
            "admin from 203.0.113.5 port 55221 ssh2"
        )
        self.assertTrue(adapter.is_failure_event(line))
        self.assertEqual(adapter.extract_source_ip(line), "203.0.113.5")

    def test_linux_auth_rhost(self):
        adapter = analyzer.LinuxAuthAdapter(self.config)
        line = (
            "May 17 12:01:08 server sshd[1239]: pam_unix(sshd:auth): "
            "authentication failure; logname= uid=0 rhost=172.16.0.44"
        )
        self.assertTrue(adapter.is_failure_event(line))
        self.assertEqual(adapter.extract_source_ip(line), "172.16.0.44")

    def test_windows_4625(self):
        adapter = analyzer.Windows4625Adapter(self.config)
        lines = [
            "Event ID: 4625",
            "Source Network Address: 198.51.100.22",
        ]
        self.assertFalse(adapter.is_failure_event(lines[0]))
        self.assertTrue(adapter.is_failure_event(lines[1]))
        self.assertEqual(adapter.extract_source_ip(lines[1]), "198.51.100.22")

    def test_firewall_src_not_dst(self):
        adapter = analyzer.FirewallAdapter(self.config)
        line = (
            "May 17 12:05:00 fw01 kernel: Deny TCP "
            "src=185.122.44.10 dst=10.0.0.5 spt=55221 dpt=22"
        )
        self.assertTrue(adapter.is_failure_event(line))
        self.assertEqual(adapter.extract_source_ip(line), "185.122.44.10")

    def test_firewall_iso_with_port(self):
        adapter = analyzer.FirewallAdapter(self.config)
        line = "2026-05-17T12:05:03Z deny tcp src=203.0.113.5:54321 dst=10.0.0.5:22"
        self.assertEqual(adapter.extract_source_ip(line), "203.0.113.5")

    def test_json_failure(self):
        adapter = analyzer.JsonAdapter(self.config)
        line = (
            '{"event.action":"login","event.outcome":"failure",'
            '"source.ip":"203.0.113.5","user.name":"admin"}'
        )
        self.assertTrue(adapter.is_failure_event(line))
        self.assertEqual(adapter.extract_source_ip(line), "203.0.113.5")

    def test_json_success_ignored(self):
        adapter = analyzer.JsonAdapter(self.config)
        line = (
            '{"event.action":"login","event.outcome":"success",'
            '"source.ip":"10.0.0.1","user.name":"admin"}'
        )
        self.assertFalse(adapter.is_failure_event(line))

    def test_custom_login_failed(self):
        adapter = analyzer.CustomAdapter(self.config)
        line = "2026-05-17 12:00:01 LOGIN FAILED user=admin from 192.168.5.51:443"
        self.assertTrue(adapter.is_failure_event(line))
        self.assertEqual(adapter.extract_source_ip(line), "192.168.5.51")


class AutoDetectTests(unittest.TestCase):
    def test_detect_linux_auth(self):
        lines = (FIXTURES / "auth.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(analyzer.detect_format(lines), "linux-auth")

    def test_detect_firewall(self):
        lines = (FIXTURES / "firewall.log").read_text(encoding="utf-8").splitlines()
        self.assertEqual(analyzer.detect_format(lines), "firewall")

    def test_detect_json(self):
        lines = (FIXTURES / "events.ndjson").read_text(encoding="utf-8").splitlines()
        self.assertEqual(analyzer.detect_format(lines), "json")

    def test_detect_custom(self):
        lines = (FIXTURES / "custom_log.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(analyzer.detect_format(lines), "custom")


class AnalyzeLogTests(unittest.TestCase):
    def _analyze_fixture(self, name: str, fmt: str, threshold: int = 2, **kwargs):
        path = str(FIXTURES / name)
        config = analyzer.AdapterConfig()
        options = analyzer.AnalysisOptions(threshold=threshold, **kwargs)
        adapter = analyzer.create_adapter(fmt, config)
        return analyzer.analyze_log(path, adapter, options, fmt)

    def test_custom_threshold(self):
        result = self._analyze_fixture("custom_log.txt", "custom", threshold=3)
        self.assertEqual(result.all_counts["192.168.5.51"], 2)
        self.assertEqual(result.all_counts["10.9.5.2"], 3)
        suspicious = dict(result.suspicious_ips)
        self.assertIn("10.9.5.2", suspicious)
        self.assertNotIn("192.168.5.51", suspicious)

    def test_linux_auth_fixture(self):
        result = self._analyze_fixture("auth.log", "linux-auth", threshold=2)
        self.assertEqual(result.all_counts["203.0.113.5"], 2)
        self.assertEqual(result.all_counts["2001:db8::5"], 3)
        self.assertEqual(result.all_counts["172.16.0.44"], 2)

    def test_exclude_local(self):
        result = self._analyze_fixture(
            "custom_log.txt", "custom", threshold=1, exclude_local=True
        )
        self.assertNotIn("127.0.0.1", result.all_counts)
        self.assertGreater(result.skipped_localhost, 0)

    def test_time_filter_syslog(self):
        result = self._analyze_fixture(
            "auth.log",
            "linux-auth",
            threshold=1,
            since=datetime(2026, 5, 17, 12, 1, 5),
            until=datetime(2026, 5, 17, 12, 1, 7),
        )
        self.assertEqual(result.total_failed_lines, 3)
        self.assertIn("2001:db8::5", result.all_counts)
        self.assertNotIn("203.0.113.5", result.all_counts)

    def test_windows_fixture(self):
        result = self._analyze_fixture("windows_4625.txt", "windows-4625", threshold=1)
        self.assertEqual(result.all_counts["198.51.100.22"], 2)
        self.assertEqual(result.all_counts["203.0.113.9"], 1)

    def test_firewall_fixture(self):
        result = self._analyze_fixture("firewall.log", "firewall", threshold=2)
        self.assertEqual(result.all_counts["185.122.44.10"], 3)
        self.assertEqual(result.all_counts["203.0.113.5"], 2)

    def test_json_fixture(self):
        result = self._analyze_fixture("events.ndjson", "json", threshold=2)
        self.assertEqual(result.all_counts["203.0.113.5"], 3)
        self.assertEqual(result.all_counts["198.51.100.50"], 1)


class CliTests(unittest.TestCase):
    def test_missing_file_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = os.path.join(tmp, "audit.log")
            rc = main(["/nonexistent/path/to/log.txt", "-l", audit])
        self.assertEqual(rc, 1)

    def test_json_csv_blocklist_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, "report.json")
            csv_path = os.path.join(tmp, "report.csv")
            block_path = os.path.join(tmp, "blocklist.txt")
            log_path = os.path.join(tmp, "audit.log")
            rc = main([
                str(FIXTURES / "custom_log.txt"),
                "-f", "custom",
                "-t", "3",
                "-j", json_path,
                "-c", csv_path,
                "-b", block_path,
                "-l", log_path,
                "-q",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(block_path))
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["log_format"], "custom")
            self.assertIn("10.9.5.2", data["all_counts"])
            with open(block_path, encoding="utf-8") as fh:
                blocklist = fh.read().splitlines()
            self.assertIn("10.9.5.2", blocklist)
            audit = Path(log_path).read_text(encoding="utf-8")
            self.assertIn("DEBUG", audit)
            self.assertIn("Starting analysis", audit)

    def test_verbose_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "audit.log")
            stderr = io.StringIO()
            with patch.object(sys, "stderr", stderr):
                rc = main([
                    str(FIXTURES / "custom_log.txt"),
                    "-f", "custom",
                    "-t", "1",
                    "-l", log_path,
                    "-v",
                    "-q",
                ])
            self.assertEqual(rc, 0)
            self.assertIn("DEBUG", stderr.getvalue())

    def test_stdout_with_counts(self):
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            rc = main([
                str(FIXTURES / "custom_log.txt"),
                "-f", "custom",
                "-t", "3",
                "-l", os.devnull,
            ])
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("exceeded the threshold", output)
        self.assertIn("failures", output)
        self.assertIn("Summary:", output)

    def test_version_flag(self):
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("0.1.0", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
