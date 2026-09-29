import base64
import csv
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import monitor


ROOT = Path(__file__).resolve().parents[1]
GIB = 1024**3
WIN_C = "C:" + chr(92)
WIN_D = "D:" + chr(92)


def remote_env(index=1, user="monitor-user"):
    return {
        f"INSTANCE_{index}_NAME": "Disk host",
        f"INSTANCE_{index}_IP": "192.0.2.10",
        f"INSTANCE_{index}_CHAT_ID": "-1001",
        f"INSTANCE_{index}_KEY": "/placeholder/key.pem",
        f"INSTANCE_{index}_SSH_USER": user,
    }


def metrics(disks, disk_used=None, disk_total=None, disk_error=None):
    primary = disks[0]
    return {
        "cpu": 10,
        "mem_used": 20,
        "mem_total": 8,
        "disk_used": primary["used"] if disk_used is None else disk_used,
        "disk_total": primary["total"] if disk_total is None else disk_total,
        "disk_error": disk_error if disk_error is not None else primary.get("error"),
        "disks": disks,
        "net_sent": 1,
        "net_recv": 2,
        "uptime": "1 day",
        "per_core": [10],
    }


def disk(path, used, total=100, free=40, error=None):
    return {"path": path, "used": used, "total": total, "free": free, "error": error}


class DiskConfigurationTests(unittest.TestCase):
    def test_explicit_windows_and_deduplicated_paths_keep_primary(self):
        env = remote_env(user="db-monitor")
        env["INSTANCE_1_OS"] = "windows"
        env["INSTANCE_1_DISK_PATHS"] = r"D:\SQLData;C:\;D:\sqldata;E:\SQLLogs"
        with mock.patch.object(monitor.os.path, "isfile", return_value=True):
            instance = monitor.load_instances(env)[0]

        self.assertTrue(instance["is_windows"])
        self.assertEqual(instance["disk_paths"], [WIN_C, r"D:\SQLData", r"E:\SQLLogs"])
        self.assertEqual(instance["ssh_user"], "db-monitor")

    def test_legacy_inference_and_absent_disk_settings_keep_defaults_and_order(self):
        windows = remote_env(user="Administrator")
        linux = remote_env(index=2, user="ubuntu")
        linux.update({
            "INSTANCE_2_NAME": "Linux host",
            "INSTANCE_2_IP": "192.0.2.11",
            "INSTANCE_2_CHAT_ID": "-1002",
            "INSTANCE_2_KEY": "/placeholder/linux.pem",
        })
        local = {
            "INSTANCE_3_NAME": "Local host",
            "INSTANCE_3_IP": "localhost",
            "INSTANCE_3_CHAT_ID": "-1003",
        }
        with mock.patch.object(monitor.os.path, "isfile", return_value=True):
            instances = monitor.load_instances({**windows, **linux, **local})

        self.assertEqual([item["index"] for item in instances], [1, 2, 3])
        self.assertEqual(instances[0]["disk_paths"], [WIN_C])
        self.assertFalse(instances[1]["is_windows"])
        self.assertEqual(instances[1]["disk_paths"], ["/"])
        self.assertTrue(instances[2]["is_local"])
        self.assertEqual(instances[2]["disk_paths"], ["/"])

    def test_invalid_os_and_empty_extra_path_are_instance_specific(self):
        invalid_os = remote_env()
        invalid_os["INSTANCE_1_OS"] = "bsd"
        invalid_paths = remote_env()
        invalid_paths["INSTANCE_1_DISK_PATHS"] = r"D:\Data;;E:\Logs"
        with mock.patch.object(monitor.os.path, "isfile", return_value=True):
            with self.assertRaisesRegex(ValueError, r"INSTANCE_1_OS.*Disk host"):
                monitor.load_instances(invalid_os)
            with self.assertRaisesRegex(ValueError, r"INSTANCE_1_DISK_PATHS.*Disk host"):
                monitor.load_instances(invalid_paths)


class DiskCollectionTests(unittest.TestCase):
    def test_remote_linux_and_windows_preserve_distinct_path_results_and_primary(self):
        fixtures = [
            ({"is_windows": False, "disk_paths": ["/", "/data"]}, [disk("/", 32, 200, 136), disk("/data", 61, 500, 195)]),
            ({"is_windows": True, "disk_paths": [WIN_C, WIN_D]}, [disk(WIN_C, 23, 100, 77), disk(WIN_D, 94, 1000, 60)]),
        ]
        for instance, disks in fixtures:
            with self.subTest(is_windows=instance["is_windows"]):
                output = metrics(disks)
                with mock.patch.object(monitor, "ssh_run", return_value=json.dumps(output)) as ssh:
                    collected = monitor.get_remote_metrics(instance)
                self.assertEqual(collected["disks"], disks)
                self.assertEqual(collected["disk_used"], disks[0]["used"])
                self.assertEqual(collected["disk_total"], disks[0]["total"])
                command = ssh.call_args.args[1]
                self.assertIn("python " if instance["is_windows"] else "python3 ", command)
                self.assertIn("b64decode", command)

    def test_local_explicit_windows_uses_c_drive_primary_and_linux_keeps_root(self):
        windows = monitor.load_instances({
            "INSTANCE_1_NAME": "Local Windows host",
            "INSTANCE_1_IP": "localhost",
            "INSTANCE_1_CHAT_ID": "-1001",
            "INSTANCE_1_OS": "windows",
            "INSTANCE_1_DISK_PATHS": f"{WIN_C};{WIN_D}",
        })[0]
        usage_by_path = {
            "/": SimpleNamespace(percent=11, total=100 * GIB, free=89 * GIB),
            WIN_C: SimpleNamespace(percent=37, total=200 * GIB, free=126 * GIB),
            WIN_D: SimpleNamespace(percent=72, total=1000 * GIB, free=280 * GIB),
        }
        calls = []

        def disk_usage(path):
            calls.append(path)
            if path == WIN_C and getattr(disk_usage, "fail_primary", False):
                raise PermissionError("primary drive unavailable")
            return usage_by_path[path]

        with (
            mock.patch.object(monitor.psutil, "cpu_percent", return_value=[15, 25]),
            mock.patch.object(monitor.psutil, "virtual_memory", return_value=SimpleNamespace(percent=36, total=8 * GIB)),
            mock.patch.object(monitor.psutil, "net_io_counters", return_value=SimpleNamespace(bytes_sent=1024, bytes_recv=2048)),
            mock.patch.object(monitor.psutil, "boot_time", return_value=1),
            mock.patch.object(monitor.psutil, "disk_usage", side_effect=disk_usage),
        ):
            collected = monitor.get_metrics(windows)
            self.assertEqual(calls, [WIN_C, WIN_D])
            self.assertEqual([result["path"] for result in collected["disks"]], [WIN_C, WIN_D])
            self.assertEqual(collected["disk_used"], 37)
            self.assertEqual(collected["disk_total"], 200)

            calls.clear()
            disk_usage.fail_primary = True
            failed_primary = monitor.get_metrics(windows)
            self.assertEqual(calls, [WIN_C, WIN_D])
            self.assertIsNone(failed_primary["disk_used"])
            self.assertIsNone(failed_primary["disk_total"])
            self.assertIn("primary drive unavailable", failed_primary["disk_error"])
            self.assertEqual(failed_primary["disks"][1]["used"], 72)

            calls.clear()
            linux_default = monitor.get_metrics({"is_local": True})

        self.assertEqual(calls, ["/"])
        self.assertEqual(linux_default["disks"][0]["path"], "/")
        self.assertEqual(linux_default["disk_used"], 11)

    def test_local_extra_disk_failure_does_not_discard_core_or_primary_metrics(self):
        usage = SimpleNamespace(percent=41, total=200 * GIB, free=118 * GIB)
        with (
            mock.patch.object(monitor.psutil, "cpu_percent", return_value=[15, 25]),
            mock.patch.object(monitor.psutil, "virtual_memory", return_value=SimpleNamespace(percent=36, total=8 * GIB)),
            mock.patch.object(monitor.psutil, "net_io_counters", return_value=SimpleNamespace(bytes_sent=1024, bytes_recv=2048)),
            mock.patch.object(monitor.psutil, "boot_time", return_value=1),
            mock.patch.object(monitor.psutil, "disk_usage", side_effect=[usage, PermissionError("access denied")]),
        ):
            collected = monitor.get_local_metrics(["/", "/protected"])

        self.assertEqual(collected["cpu"], 20)
        self.assertEqual(collected["mem_used"], 36)
        self.assertEqual(collected["disk_used"], 41)
        self.assertEqual(collected["disk_total"], 200)
        self.assertIsNone(collected["disks"][1]["used"])
        self.assertIn("access denied", collected["disks"][1]["error"])

    def test_generated_remote_code_encodes_paths_as_data_and_needs_no_zoneinfo(self):
        attack_path = r"D:\data'); __import__('os').system('touch /tmp/disk-pwned') #"
        command = monitor.build_metrics_cmd(True, [WIN_C, attack_path])
        script_match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", command)
        self.assertIsNotNone(script_match)
        script = base64.b64decode(script_match.group(1)).decode("utf-8")
        compile(script, "remote_metrics", "exec")
        target_match = re.search(r'targets = json.loads\(base64.b64decode\("([A-Za-z0-9+/=]+)"\)', script)
        self.assertIsNotNone(target_match)
        self.assertEqual(json.loads(base64.b64decode(target_match.group(1))), [WIN_C, attack_path])
        self.assertNotIn(attack_path, command)
        self.assertNotIn("ZoneInfo", script)
        self.assertIn("except Exception as exc", script)

    def test_generated_linux_and_windows_collectors_execute_ordered_path_results(self):
        attack_path = r"D:\data'); __import__('os').system('touch /tmp/disk-pwned') #"
        cases = [
            (False, "/", "/data"),
            (True, WIN_C, WIN_D),
        ]
        for is_windows, primary_path, secondary_path in cases:
            with self.subTest(is_windows=is_windows):
                command = monitor.build_metrics_cmd(
                    is_windows, [primary_path, secondary_path, attack_path]
                )
                script_match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", command)
                self.assertIsNotNone(script_match)
                script = base64.b64decode(script_match.group(1)).decode("utf-8")
                self.assertNotIn(attack_path, command)

                disk_calls = []

                def disk_usage(path):
                    disk_calls.append(path)
                    if path == primary_path:
                        raise PermissionError("primary access denied")
                    return SimpleNamespace(
                        percent=61 if path == secondary_path else 88,
                        total=(500 if path == secondary_path else 20) * GIB,
                        free=(195 if path == secondary_path else 3) * GIB,
                    )

                fake_psutil = SimpleNamespace(
                    cpu_percent=lambda interval, percpu: [10, 30],
                    virtual_memory=lambda: SimpleNamespace(percent=36, total=8 * GIB),
                    net_io_counters=lambda: SimpleNamespace(
                        bytes_sent=3 * 1024**2, bytes_recv=4 * 1024**2
                    ),
                    boot_time=lambda: 1,
                    disk_usage=disk_usage,
                )
                output = io.StringIO()
                with (
                    mock.patch.dict("sys.modules", {"psutil": fake_psutil}),
                    mock.patch.object(os, "system") as system_call,
                    redirect_stdout(output),
                ):
                    exec(compile(script, "generated_metrics", "exec"), {"__name__": "__main__"})

                system_call.assert_not_called()
                collected = json.loads(output.getvalue())
                self.assertEqual(disk_calls, [primary_path, secondary_path, attack_path])
                self.assertEqual(
                    [result["path"] for result in collected["disks"]],
                    [primary_path, secondary_path, attack_path],
                )
                self.assertIsNone(collected["disk_used"])
                self.assertIsNone(collected["disk_total"])
                self.assertIn("primary access denied", collected["disk_error"])
                self.assertIsNone(collected["disks"][0]["used"])
                self.assertEqual(collected["disks"][1]["used"], 61)
                self.assertEqual(collected["disks"][1]["total"], 500)
                self.assertEqual(collected["disks"][2]["used"], 88)
                self.assertEqual(collected["cpu"], 20)
                self.assertEqual(collected["per_core"], [10, 30])
                self.assertEqual(collected["mem_used"], 36)
                self.assertEqual(collected["mem_total"], 8)
                self.assertEqual(collected["net_sent"], 3)
                self.assertEqual(collected["net_recv"], 4)

    def test_ssh_core_failure_remains_distinct_from_disk_failure(self):
        instance = {"is_windows": True, "disk_paths": [WIN_C, WIN_D]}
        with mock.patch.object(monitor, "ssh_run", return_value=None):
            self.assertIsNone(monitor.get_remote_metrics(instance))


class DiskPresentationAndAlertTests(unittest.TestCase):
    def setUp(self):
        self.instance = {
            "name": "DB host", "chat_id": "-1001", "is_local": False,
            "is_windows": True, "disk_paths": [WIN_C, WIN_D],
        }
        self.old_instances = monitor.INSTANCES
        monitor.INSTANCES = [self.instance]

    def tearDown(self):
        monitor.INSTANCES = self.old_instances

    def test_only_same_high_path_gets_sustained_disk_alert(self):
        first = metrics([disk(WIN_C, 30), disk(WIN_D, 95)])
        second = metrics([disk(WIN_C, 25), disk(WIN_D, 96)])
        with (
            mock.patch.object(monitor, "get_metrics", side_effect=[first, second]),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(monitor.time, "sleep"),
        ):
            monitor._check_all_alerts_worker()

        self.assertEqual(send.call_count, 1)
        self.assertIn(WIN_D, send.call_args.args[1])
        self.assertIn("HIGH DISK", send.call_args.args[1])
        self.assertNotIn(f"HIGH DISK: `{WIN_C}`", send.call_args.args[1])

    def test_persistent_unreadable_path_is_reported_and_high_to_failure_is_incomplete(self):
        failed = disk(WIN_D, None, None, None, "access denied")
        primary = disk(WIN_C, 25)
        first = metrics([primary, failed])
        second = metrics([primary, failed])
        with (
            mock.patch.object(monitor, "get_metrics", return_value=first),
            mock.patch.object(monitor, "send_message") as send,
        ):
            monitor.cmd_disk("-1001", self.instance)
        self.assertTrue(any(WIN_D in call.args[1] and "unavailable" in call.args[1] for call in send.call_args_list))

        with (
            mock.patch.object(monitor, "get_metrics", side_effect=[first, second]),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(monitor.time, "sleep"),
        ):
            monitor._check_all_alerts_worker()
        alert = send.call_args.args[1]
        self.assertIn("DISK CHECK", alert)
        self.assertIn("both samples", alert)
        self.assertNotIn("HIGH DISK", alert)

        high = metrics([primary, disk(WIN_D, 96)])
        with (
            mock.patch.object(monitor, "get_metrics", side_effect=[high, first]),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(monitor.time, "sleep"),
        ):
            monitor._check_all_alerts_worker()
        self.assertEqual(send.call_count, 1)
        self.assertIn("DISK CHECK", send.call_args.args[1])
        self.assertNotIn("HIGH DISK", send.call_args.args[1])

    def test_high_then_low_is_not_a_sustained_path_alert(self):
        high = metrics([disk(WIN_C, 91), disk(WIN_D, 95)])
        low = metrics([disk(WIN_C, 20), disk(WIN_D, 60)])
        with (
            mock.patch.object(monitor, "get_metrics", side_effect=[high, low]),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(monitor.time, "sleep"),
        ):
            monitor._check_all_alerts_worker()
        self.assertEqual(send.call_count, 0)

    def test_old_csv_and_unavailable_primary_keep_schema_and_history_readable(self):
        fields = ["instance", "timestamp", "cpu", "mem_used", "mem_total", "disk_used", "disk_total", "net_sent", "net_recv", "uptime"]
        old_row = {
            "instance": "DB host", "timestamp": "2025-01-01 00:00:00", "cpu": "4",
            "mem_used": "5", "mem_total": "8", "disk_used": "50", "disk_total": "100",
            "net_sent": "1", "net_recv": "2", "uptime": "1 day",
        }
        unavailable = metrics([
            disk(WIN_C, None, None, None, "drive unavailable"),
            disk(WIN_D, 72, 1000, 280),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "metrics_log.csv"
            with log_file.open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow(old_row)
            with (
                mock.patch.object(monitor, "__file__", str(Path(tmp) / "monitor.py")),
                mock.patch.object(monitor, "get_metrics", return_value=unavailable),
                mock.patch.object(monitor, "now_ph", return_value=monitor.datetime(2026, 1, 1, tzinfo=monitor.PH_TZ)),
            ):
                monitor.log_all_metrics()
                with mock.patch.object(monitor, "send_message") as history_send:
                    monitor.cmd_history("-1001", self.instance)
                history_message = history_send.call_args.args[1]

            with log_file.open(newline="") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, fields)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["disk_used"], "50")
            self.assertEqual(rows[1]["disk_used"], "")
            self.assertIn("primary disk only", history_message)
            self.assertIn("Primary disk: `Unavailable`", history_message)

            def assert_independent_report(label, invoke, core_fields=()):
                with self.subTest(report=label):
                    with (
                        mock.patch.object(monitor, "get_metrics", return_value=unavailable),
                        mock.patch.object(monitor, "now_ph", return_value=monitor.datetime(2026, 1, 1, tzinfo=monitor.PH_TZ)),
                        mock.patch.object(monitor, "send_message") as send,
                    ):
                        invoke()

                    self.assertEqual(send.call_count, 1)
                    self.assertEqual(send.call_args.args[0], "-1001")
                    message = send.call_args.args[1]
                    self.assertIn(label, message)
                    self.assertIn("Disk paths", message)
                    self.assertIn(f"`{WIN_C}`: unavailable", message)
                    self.assertIn(
                        f"`{WIN_D}`: `72%` used | `280 GB` free of `1000 GB`", message
                    )
                    for field in core_fields:
                        self.assertIn(field, message)

            assert_independent_report(
                "Disk Details", lambda: monitor.cmd_disk("-1001", self.instance)
            )
            assert_independent_report(
                "Quick Status",
                lambda: monitor.cmd_status("-1001", self.instance),
                ("CPU: `10%`", "RAM: `20%`"),
            )
            report_core = (
                "*CPU:*    `10%`",
                "*Memory:* `20%` of `8 GB`",
                "*Sent:*   `1 MB`",
                "*Recv:*   `2 MB`",
                "`1 day`",
            )
            assert_independent_report(
                "Full Report",
                lambda: monitor.cmd_report("-1001", self.instance),
                report_core,
            )
            assert_independent_report(
                "Scheduled Report", monitor.send_scheduled_reports, report_core
            )


class DiskDeploymentDocumentationTests(unittest.TestCase):
    def test_example_and_readme_document_explicit_windows_disk_targets_without_sql_credentials(self):
        example = (ROOT / ".env.example").read_text()
        readme = (ROOT / "README.md").read_text()
        self.assertIn("INSTANCE_3_OS=windows", example)
        self.assertIn("INSTANCE_3_DISK_PATHS=", example)
        self.assertIn("INSTANCE_3_OS=windows", readme)
        self.assertIn("INSTANCE_<N>_DISK_PATHS", readme)
        self.assertIn("/disk", readme)
        self.assertIn("SQL engine", readme.replace("\n", " "))
        for forbidden in ("SQL_PASSWORD", "SQL_USER", "DB_PASSWORD"):
            self.assertNotIn(forbidden, example + readme)
        self.assertNotIn("AKIA12345677878", example)
        self.assertNotIn("ASDEASBDASEWQEQFSFAGADH", example)


if __name__ == "__main__":
    unittest.main()
