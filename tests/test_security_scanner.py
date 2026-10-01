"""
Regression coverage for BUILD-SEC-NET-01 (evidence-based network collection).

REG-SEC-NET-01-1 — user cases A–G, IPv6/loopback, Docker lookup failure and
ambiguity, mixed benign/adverse evidence, and local/remote classification
equivalence.
REG-SEC-NET-01-2 — more than 20 sockets cannot hide an adverse item, failed or
invalid SSH responses are never clean, a Docker error is never clean, and the
generated remote command is safe and parseable by a POSIX shell.
"""

import base64
import gzip
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import llm_analyzer
import monitor
import security_scanner


ROOT = Path(__file__).resolve().parents[1]

BOT_EXE = "/home/ubuntu/dev/monitor_bot/venv/python"
BOT_SCRIPT = "/home/ubuntu/dev/monitor_bot/monitor.py"
BOT_USER = "ubuntu"
BOT_DESTINATION = "203.0.113.10"
TAILSCALE_EXE = "/usr/bin/tailscaled"
TAILSCALE_DESTINATION = "100.100.100.100"
OTEL_CONTAINER = "otel-collector"
OTEL_IMAGE = "sha256:0tel0collector0image0pin"


def config(**overrides):
    base = {
        "bot_exe": BOT_EXE,
        "bot_script": BOT_SCRIPT,
        "bot_user": BOT_USER,
        "bot_https_destinations": [BOT_DESTINATION],
        "tailscaled_exe": TAILSCALE_EXE,
        "tailscaled_user": BOT_USER,
        "tailscaled_https_destinations": [TAILSCALE_DESTINATION],
        "otel_container_name": OTEL_CONTAINER,
        "otel_image_id": OTEL_IMAGE,
    }
    base.update(overrides)
    return base


def addr(ip, port):
    return SimpleNamespace(ip=ip, port=port)


def sock(local_ip, local_port, remote=None, state="ESTABLISHED", pid=None, kind="tcp"):
    return SimpleNamespace(
        laddr=addr(local_ip, local_port) if local_ip is not None else None,
        raddr=addr(remote[0], remote[1]) if remote else None,
        status=state,
        type=1 if kind == "tcp" else 2,
        pid=pid,
    )


def owner(pid, name, exe, cmdline, user=BOT_USER, ppid=1, parent_exe="/usr/sbin/init"):
    return {
        "pid": pid, "ppid": ppid, "name": name, "exe": exe,
        "cmdline": cmdline, "user": user, "parent_exe": parent_exe,
    }


def container(name=OTEL_CONTAINER, image="otel/collector:0.1", image_id=OTEL_IMAGE,
              host_ip="127.0.0.1", published="13133", target="13133", running=True):
    return {
        "id": "c0ffee" + name, "name": name, "image": image, "image_id": image_id,
        "running": running,
        "ports": {"%s/tcp" % target: ([{"HostIp": host_ip, "HostPort": published}]
                                      if published else None)},
    }


def as_conn(item):
    """Turn a collected-evidence dict into the psutil-shaped socket object."""
    if not isinstance(item, dict):
        return item
    return SimpleNamespace(
        laddr=addr(item["local_ip"], item["local_port"]) if item.get("local_ip") else None,
        raddr=addr(item["remote_ip"], item["remote_port"]) if item.get("remote_ip") else None,
        status=item.get("state", "ESTABLISHED"),
        type=1 if item.get("protocol") == "tcp" else 2,
        pid=item.get("pid"),
    )


def local_scan(raw, security_config=None, containers=None, docker_status="available",
               docker_error=None, scan_status=None):
    """Run only the local network collector with deterministic evidence."""
    findings = security_scanner._base_findings("AURORA", "local")
    process_map = {item.get("pid"): item.get("owner") for item in raw if item.get("pid")}
    with (
        mock.patch.object(security_scanner, "_local_process_map", return_value=(process_map, [])),
        mock.patch.object(security_scanner.psutil, "net_connections",
                          return_value=[as_conn(item) for item in raw]),
        mock.patch.object(
            security_scanner, "_docker_snapshot",
            return_value=(containers or [], docker_status, docker_error),
        ),
    ):
        if scan_status is None:
            security_scanner._scan_network_local(findings, security_config or {})
        else:
            security_scanner._finalize_network(
                findings, raw, containers or [], docker_status,
                [docker_error] if docker_error else [], security_config or {}, scan_status,
            )
    return findings


def only(observations, **match):
    matched = []
    for observation in observations:
        if all(observation.get(key) == value for key, value in match.items()):
            matched.append(observation)
    return matched


def fake_psutil(sockets, processes, users=()):
    """Minimal psutil stand-in shared by the local mocks and the remote script."""
    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    def process_iter(attrs=None):
        for info in processes:
            yield SimpleNamespace(info=info)

    return SimpleNamespace(
        net_connections=lambda kind="inet": list(sockets),
        process_iter=process_iter,
        users=lambda: list(users),
        NoSuchProcess=NoSuchProcess,
        AccessDenied=AccessDenied,
    )


def raw_sockets(cases):
    return [case["raw"] for case in cases]


DOCKER_PROXY = owner(
    500, "docker-proxy", "/usr/bin/docker-proxy", ["docker-proxy", "-host-port", "127.0.0.1:13133"],
    user="root", parent_exe="/usr/bin/dockerd",
)
NGINX = owner(700, "nginx", "/usr/sbin/nginx", ["nginx: worker process"], user="www-data")
BOT_PROCESS = owner(900, "python", BOT_EXE, [BOT_EXE, BOT_SCRIPT], user=BOT_USER)
TAILSCALED = owner(950, "tailscaled", TAILSCALE_EXE, [TAILSCALE_EXE], user=BOT_USER)
UNKNOWN_SCRIPT = owner(980, "python3", "/usr/bin/python3", ["python3", "/tmp/unknown.py"], user="www-data")
INIT = owner(1, "systemd", "/sbin/init", ["/sbin/init"], user="root", ppid=0)
# Windows-shaped owners used by the Windows regressions below.
SVCHOST = owner(700, "svchost.exe", "C:\\Windows\\System32\\svchost.exe",
                ["svchost.exe", "-k", "netsvcs"], user="NT AUTHORITY\\SYSTEM")
SQLSERVR = owner(900, "sqlservr.exe", "C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe",
                 ["sqlservr.exe"], user="NT SERVICE\\MSSQLSERVER")
WINDOWS_SCRIPT = owner(980, "python.exe", "C:\\Users\\svc\\python.exe",
                       ["python.exe", "-c", "payload"], user="WIN-WEB\\svc")


def psutil_info(process_owner):
    """Convert a normalized owner record into psutil process_iter attribute names."""
    return {
        "pid": process_owner["pid"], "ppid": process_owner["ppid"],
        "name": process_owner["name"], "exe": process_owner["exe"],
        "cmdline": list(process_owner["cmdline"]), "username": process_owner["user"],
        "cpu_percent": 0.0, "memory_percent": 0.1, "status": "running",
    }


class VerifiedOtelCaseTests(unittest.TestCase):
    """Case A / E: the same container proof is expected on loopback, exposed elsewhere."""

    def test_loopback_docker_proxy_publication_is_expected_and_local_only(self):
        raw = [{
            "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        }]
        findings = local_scan(raw, config(), [container()])
        observation = only(findings["network"]["observations"], local_port=13133)[0]

        self.assertEqual(observation["classification"], "expected")
        self.assertEqual(observation["bind_scope"], "loopback-only")
        self.assertEqual(observation["confidence"], "high")
        self.assertEqual(observation["container"]["name"], OTEL_CONTAINER)
        self.assertEqual(observation["container"]["target_port"], 13133)
        self.assertIn("exactly one running container publishes", observation["reason"])
        self.assertEqual(findings["network"]["risk"]["level"], "negligible")
        self.assertEqual(findings["network"]["scan_status"], "complete")
        self.assertEqual(findings["network"]["unexpected_listening"], [])

    def test_ipv6_loopback_publication_is_also_local_only(self):
        raw = [{
            "protocol": "tcp", "local_ip": "::1", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        }]
        findings = local_scan(raw, config(), [container(host_ip="::1")])
        observation = only(findings["network"]["observations"], local_port=13133)[0]

        self.assertEqual(observation["classification"], "expected")
        self.assertEqual(observation["bind_scope"], "loopback-only")

    def test_wildcard_bind_of_the_same_publication_is_exposed_and_needs_review(self):
        for bind in ("0.0.0.0", "::"):
            with self.subTest(bind=bind):
                raw = [{
                    "protocol": "tcp", "local_ip": bind, "local_port": 13133,
                    "remote_ip": None, "remote_port": None, "state": "LISTEN",
                    "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
                }]
                findings = local_scan(raw, config(), [container(host_ip=bind)])
                observation = only(findings["network"]["observations"], local_port=13133)[0]

                self.assertEqual(observation["classification"], "needs_review")
                self.assertEqual(observation["bind_scope"], "all-interfaces")
                self.assertIn("reachable from the network", observation["reason"])
                self.assertGreaterEqual(
                    _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
                self.assertEqual(
                    findings["network"]["unexpected_listening"],
                    [{"port": 13133, "addr": "%s:13133" % bind}],
                )

    def test_docker_proxy_name_without_publication_evidence_is_reviewed(self):
        raw = [{
            "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        }]
        findings = local_scan(raw, config(), [])

        observation = only(findings["network"]["observations"], local_port=13133)[0]
        self.assertEqual(observation["classification"], "needs_review")
        self.assertIn("proof is missing", observation["reason"])
        self.assertIsNone(observation["container"])

    def test_ambiguous_publications_and_failed_docker_lookup_are_reviewed(self):
        raw = [{
            "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        }]
        ambiguous = local_scan(raw, config(), [container(), container(name="otel-collector-two")])
        self.assertEqual(
            only(ambiguous["network"]["observations"], local_port=13133)[0]["classification"],
            "needs_review",
        )
        self.assertIn("ambiguous",
                      only(ambiguous["network"]["observations"], local_port=13133)[0]["reason"])

        failed = local_scan(
            raw, config(), [], docker_status="error",
            docker_error="Docker identity lookup failed: permission denied",
        )
        observation = only(failed["network"]["observations"], local_port=13133)[0]
        self.assertEqual(observation["classification"], "needs_review")
        self.assertIn("permission denied", " ".join(failed["network"]["scan_gaps"]))
        self.assertEqual(failed["network"]["scan_status"], "partial")
        self.assertEqual(failed["network"]["risk"]["posture"], "incomplete")
        self.assertGreaterEqual(_risk_order(failed["network"]["risk"]["level"]), _risk_order("medium"))

    def test_wrong_container_name_or_unpinned_image_is_reviewed(self):
        raw = [{
            "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        }]
        other_name = local_scan(raw, config(), [container(name="impostor-collector")])
        self.assertIn(
            "not the configured collector",
            only(other_name["network"]["observations"], local_port=13133)[0]["reason"],
        )

        other_image = local_scan(
            raw, config(), [container(image="alpine:latest", image_id="sha256:deadbeef")])
        self.assertIn(
            "does not match the pinned image",
            only(other_image["network"]["observations"], local_port=13133)[0]["reason"],
        )


class ListenerAndDirectionTests(unittest.TestCase):
    """Cases B / G: local 443 with a high remote peer is inbound, not outbound."""

    def setUp(self):
        self.raw = [
            {
                "protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 443,
                "remote_ip": None, "remote_port": None, "state": "LISTEN",
                "is_listener": True, "pid": 700, "owner": NGINX,
            },
            {
                "protocol": "tcp", "local_ip": "203.0.113.9", "local_port": 443,
                "remote_ip": "198.51.100.7", "remote_port": 54001, "state": "ESTABLISHED",
                "is_listener": False, "pid": 700, "owner": NGINX,
            },
        ]
        self.findings = local_scan(self.raw, config())
        self.observations = self.findings["network"]["observations"]

    def test_listener_and_server_side_socket_are_inbound_with_high_confidence(self):
        listener = only(self.observations, is_listener=True)[0]
        peer = only(self.observations, is_listener=False)[0]

        for observation in (listener, peer):
            self.assertEqual(observation["direction"], "inbound")
            self.assertEqual(observation["classification"], "informational")
            self.assertEqual(observation["confidence"], "high")
        self.assertEqual(listener["bind_scope"], "all-interfaces")
        self.assertIn("reach", listener["reason"])
        self.assertIn("confirm the exposure is intended", listener["reason"])
        self.assertEqual(listener["process"]["exe"], "/usr/sbin/nginx")

    def test_legacy_external_list_never_contains_inbound_server_side_traffic(self):
        self.assertEqual(self.findings["network"]["external_connections"], [])

    def test_accepted_socket_reason_describes_a_connection_not_a_listener(self):
        listener = only(self.observations, is_listener=True)[0]
        peer = only(self.observations, is_listener=False)[0]

        # The real listener still describes itself as the listener it is.
        self.assertIn("nginx owns this listener", listener["reason"])
        # The accepted server-side socket is peer traffic, not a listener.
        self.assertNotIn("owns this listener", peer["reason"])
        self.assertIn("accepted inbound connection", peer["reason"])
        self.assertIn("198.51.100.7:54001", peer["reason"])
        self.assertNotIn("peer connection(s) observed", peer["reason"])
        self.assertEqual(self.findings["network"]["unexpected_listening"], [])
        self.assertEqual(
            self.findings["network"]["totals"],
            {"observations": 2, "listeners": 1, "inbound": 2, "outbound": 0, "uncertain": 0},
        )
        self.assertEqual(
            self.findings["network"]["category_counts"]["informational"], 2
        )

    def test_ambiguous_listener_without_observed_peers_stays_uncertain(self):
        lonely = local_scan([self.raw[0]], config())
        self.assertEqual(lonely["network"]["observations"][0]["direction"], "uncertain")

    def test_unidentified_exposed_listener_is_reviewed_and_raises_risk(self):
        raw = [dict(self.raw[0], pid=None, owner=security_scanner._unknown_owner(None))]
        findings = local_scan(raw, config())
        observation = findings["network"]["observations"][0]

        self.assertEqual(observation["classification"], "needs_review")
        self.assertEqual(observation["bind_scope"], "all-interfaces")
        self.assertGreaterEqual(
            _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
        self.assertEqual(
            findings["network"]["unexpected_listening"],
            [{"port": 443, "addr": "0.0.0.0:443"}],
        )


class BotClientTests(unittest.TestCase):
    """Case C: only the exact configured executable, script, user and destination."""

    def bot_socket(self, process, remote=(BOT_DESTINATION, 443), local_port=53124):
        return [{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": local_port,
            "remote_ip": remote[0], "remote_port": remote[1], "state": "ESTABLISHED",
            "is_listener": False, "pid": process["pid"], "owner": process,
        }]

    def test_exact_identity_and_destination_is_expected(self):
        findings = local_scan(self.bot_socket(BOT_PROCESS), config())
        observation = findings["network"]["observations"][0]

        self.assertEqual(observation["direction"], "outbound")
        self.assertEqual(observation["classification"], "expected")
        self.assertEqual(observation["confidence"], "high")
        self.assertEqual(observation["evidence"]["matched_destination"], BOT_DESTINATION)
        self.assertIn("not cryptographically attested", observation["reason"])
        self.assertEqual(findings["network"]["risk"]["level"], "negligible")

    def test_wrong_script_owner_or_destination_is_reviewed(self):
        wrong_script = local_scan(self.bot_socket(dict(
            BOT_PROCESS, cmdline=[BOT_EXE, "/home/ubuntu/dev/monitor_bot/other.py"])), config())
        wrong_owner = local_scan(self.bot_socket(dict(BOT_PROCESS, user="www-data")), config())
        wrong_destination = local_scan(
            self.bot_socket(BOT_PROCESS, remote=("198.51.100.77", 443)), config())
        wrong_port = local_scan(
            self.bot_socket(BOT_PROCESS, remote=(BOT_DESTINATION, 8443)), config())
        low_local_port = local_scan(
            self.bot_socket(BOT_PROCESS, local_port=443), config())
        other_process_same_destination = local_scan(
            self.bot_socket(UNKNOWN_SCRIPT, remote=(BOT_DESTINATION, 443)), config())

        for label, findings in [
            ("script", wrong_script), ("owner", wrong_owner),
            ("destination", wrong_destination), ("port", wrong_port),
            ("low local port", low_local_port),
            ("other process, same destination", other_process_same_destination),
        ]:
            with self.subTest(deviation=label):
                observation = findings["network"]["observations"][0]
                self.assertNotEqual(observation["classification"], "expected")
                self.assertGreaterEqual(
                    _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))

        self.assertIn("not an ephemeral client port",
                      low_local_port["network"]["observations"][0]["reason"])

    def test_same_destination_from_another_process_is_never_inherited_trust(self):
        findings = local_scan(
            self.bot_socket(UNKNOWN_SCRIPT, remote=(BOT_DESTINATION, 443)), config())
        observation = findings["network"]["observations"][0]

        self.assertNotEqual(observation["classification"], "expected")
        self.assertEqual(observation["classification"], "needs_review")
        self.assertIn("not matched to any configured service destination", observation["reason"])
        self.assertNotIn("matched_destination", observation["evidence"])


class TailscaleClientTests(unittest.TestCase):
    """Case D: the configured executable and destination decide, the name does not."""

    def tailscale_socket(self, process, remote=(TAILSCALE_DESTINATION, 443)):
        return [{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44012,
            "remote_ip": remote[0], "remote_port": remote[1], "state": "ESTABLISHED",
            "is_listener": False, "pid": process["pid"], "owner": process,
        }]

    def test_configured_client_with_configured_destination_is_expected(self):
        findings = local_scan(self.tailscale_socket(TAILSCALED), config())
        observation = findings["network"]["observations"][0]

        self.assertEqual(observation["classification"], "expected")
        self.assertEqual(observation["evidence"]["matched_destination"], TAILSCALE_DESTINATION)
        self.assertEqual(findings["network"]["risk"]["level"], "negligible")

    def test_name_only_or_unpinned_destination_is_reviewed(self):
        impostor = owner(951, "tailscaled", "/tmp/tailscaled", ["/tmp/tailscaled"], user=BOT_USER)
        unpinned = local_scan(self.tailscale_socket(TAILSCALED, remote=("198.51.100.5", 443)),
                              config())
        unconfigured = local_scan(
            self.tailscale_socket(TAILSCALED),
            config(tailscaled_exe=None),
        )

        self.assertIn("not the configured", only(
            local_scan(self.tailscale_socket(impostor), config())["network"]["observations"]
        )[0]["reason"])
        self.assertIn("configured Tailscale destinations", unpinned["network"]["observations"][0]["reason"])
        self.assertIn("no INSTANCE", unconfigured["network"]["observations"][0]["reason"])
        for findings in (unpinned, unconfigured):
            self.assertNotEqual(
                findings["network"]["observations"][0]["classification"], "expected")
            self.assertGreaterEqual(
                _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))


class UnknownScriptTests(unittest.TestCase):
    """Case F: an unrecognised script talking to an unexpected service port."""

    def test_unknown_script_client_to_unknown_port_is_suspicious(self):
        raw = [{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44999,
            "remote_ip": "198.51.100.44", "remote_port": 4444, "state": "ESTABLISHED",
            "is_listener": False, "pid": 980, "owner": UNKNOWN_SCRIPT,
        }]
        findings = local_scan(raw, config())
        observation = findings["network"]["observations"][0]

        self.assertEqual(observation["classification"], "suspicious")
        self.assertEqual(observation["direction"], "outbound")
        self.assertIn("/tmp/unknown.py", observation["reason"])
        self.assertEqual(observation["evidence"]["script"], "/tmp/unknown.py")
        self.assertGreaterEqual(_risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
        self.assertNotEqual(findings["network"]["risk"]["level"], "high")
        self.assertEqual(
            findings["network"]["external_connections"],
            [{"local": "10.0.1.5:44999", "remote": "198.51.100.44:4444"}],
        )

    def test_single_deviation_is_not_escalated_to_high_without_corroboration(self):
        raw = [{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44999,
            "remote_ip": "198.51.100.44", "remote_port": 4444, "state": "ESTABLISHED",
            "is_listener": False, "pid": 980, "owner": UNKNOWN_SCRIPT,
        }]
        findings = local_scan(raw, config())
        self.assertEqual(findings["network"]["risk"]["level"], "medium")

        findings["auth_log"] = ["sshd[1]: Failed password for root from 198.51.100.44"]
        findings["network"]["risk"] = security_scanner._assess_network_risk(
            findings["network"]["observations"], "complete",
            findings["network"]["scan_gaps"], findings,
        )
        self.assertEqual(findings["network"]["risk"]["level"], "high")
        self.assertIn("authentication log entries", findings["network"]["risk"]["reasons"][-1])


class MixedEvidenceTests(unittest.TestCase):
    """Benign observations are retained while adverse ones still raise risk."""

    def setUp(self):
        self.raw = [
            {
                "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
                "remote_ip": None, "remote_port": None, "state": "LISTEN",
                "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
            },
            {
                "protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 443,
                "remote_ip": None, "remote_port": None, "state": "LISTEN",
                "is_listener": True, "pid": 700, "owner": NGINX,
            },
            {
                "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 53124,
                "remote_ip": BOT_DESTINATION, "remote_port": 443, "state": "ESTABLISHED",
                "is_listener": False, "pid": 900, "owner": BOT_PROCESS,
            },
            {
                "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44999,
                "remote_ip": "198.51.100.44", "remote_port": 4444, "state": "ESTABLISHED",
                "is_listener": False, "pid": 980, "owner": UNKNOWN_SCRIPT,
            },
        ]
        self.findings = local_scan(self.raw, config(), [container()])
        self.network = self.findings["network"]

    def test_benign_and_adverse_observations_are_both_retained_with_counts(self):
        counts = self.network["category_counts"]
        self.assertEqual(counts["expected"], 2)
        self.assertEqual(counts["informational"], 1)
        self.assertEqual(counts["suspicious"], 1)
        self.assertEqual(self.network["totals"]["observations"], 4)
        self.assertGreaterEqual(_risk_order(self.network["risk"]["level"]), _risk_order("medium"))
        self.assertTrue(security_scanner.has_any_findings(self.findings))

    def test_every_observation_carries_evidence_and_identity_fields(self):
        required = {
            "protocol", "state", "local_ip", "local_port", "remote_ip", "remote_port",
            "direction", "bind_scope", "pid", "process", "container", "classification",
            "confidence", "reason", "evidence",
        }
        for observation in self.network["observations"]:
            self.assertTrue(required.issubset(observation), observation)
            self.assertTrue(observation["reason"])
            self.assertIn(observation["direction"], security_scanner.DIRECTIONS)
            self.assertIn(observation["bind_scope"], security_scanner.BIND_SCOPES)
            self.assertIn(observation["classification"], security_scanner.CLASSIFICATIONS)
            self.assertIn("name", observation["process"])
            self.assertIn("exe", observation["process"])
            self.assertIn("cmdline", observation["process"])
            self.assertIn("user", observation["process"])

    def test_unresolved_outbound_stays_reviewed_instead_of_presumed_safe(self):
        raw = [{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 41000,
            "remote_ip": "198.51.100.99", "remote_port": 443, "state": "ESTABLISHED",
            "is_listener": False, "pid": 990,
            "owner": owner(990, "curl", "/usr/bin/curl", ["curl", "https://example.test"], user="ubuntu"),
        }]
        findings = local_scan(raw, config())
        observation = findings["network"]["observations"][0]

        self.assertEqual(observation["classification"], "needs_review")
        self.assertIn("not matched to any configured service", observation["reason"])
        self.assertGreaterEqual(_risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))

    def test_no_configuration_never_fabricates_an_expected_status(self):
        findings = local_scan(self.raw, {}, [container()])
        for observation in findings["network"]["observations"]:
            self.assertNotEqual(observation["classification"], "expected")
        self.assertGreaterEqual(
            _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))

    def test_legacy_findings_without_observations_are_still_readable(self):
        legacy = security_scanner._base_findings("legacy", "remote")
        legacy["network"] = {
            "unexpected_listening": [{"port": 13133, "addr": "0.0.0.0:13133"}],
            "external_connections": [{"local": "10.0.1.5:49812", "remote": "52.217.43.100:443"}],
        }
        self.assertTrue(security_scanner.has_any_findings(legacy))


class VolumeTests(unittest.TestCase):
    """REG-SEC-NET-01-2: an adverse item after more than twenty sockets is not hidden."""

    def test_more_than_twenty_sockets_cannot_hide_a_late_adverse_item(self):
        raw = []
        for index in range(24):
            raw.append({
                "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 40000 + index,
                "remote_ip": "198.51.100.%d" % (index + 1), "remote_port": 443,
                "state": "ESTABLISHED", "is_listener": False, "pid": 1000 + index,
                "owner": owner(1000 + index, "curl", "/usr/bin/curl",
                               ["curl"], user="ubuntu"),
            })
        raw.append({
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44999,
            "remote_ip": "198.51.100.44", "remote_port": 4444, "state": "ESTABLISHED",
            "is_listener": False, "pid": 980, "owner": UNKNOWN_SCRIPT,
        })
        raw.append({
            "protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 13133,
            "remote_ip": None, "remote_port": None, "state": "LISTEN",
            "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
        })

        findings = local_scan(raw, config(), [container(host_ip="0.0.0.0")])
        network = findings["network"]

        self.assertEqual(len(network["observations"]), 26)
        self.assertEqual(len(network["external_connections"]), 25)
        self.assertEqual(network["category_counts"]["suspicious"], 1)
        self.assertEqual(network["category_counts"]["needs_review"], 25)
        adverse = only(network["observations"], classification="suspicious")
        self.assertEqual(len(adverse), 1)
        self.assertEqual(adverse[0]["remote_port"], 4444)
        self.assertGreaterEqual(_risk_order(network["risk"]["level"]), _risk_order("medium"))


class RemoteCollectionTests(unittest.TestCase):
    """REG-SEC-NET-01-2: remote failures are never reported as a clean scan."""

    def collect(self, output):
        return security_scanner.collect_remote(
            {"name": "AURORA"}, lambda inst, cmd: output, config(),
        )

    def test_ssh_failure_is_a_failed_scan_with_unknown_posture(self):
        findings = self.collect(None)

        self.assertEqual(findings["error"], "SSH unreachable")
        self.assertEqual(findings["network"]["scan_status"], "failed")
        self.assertEqual(findings["network"]["risk"]["posture"], "failed")
        self.assertGreaterEqual(
            _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
        self.assertTrue(security_scanner.has_any_findings(findings))
        self.assertNotEqual(findings["network"]["risk"]["level"], "negligible")

    def test_missing_or_invalid_remote_response_is_not_clean(self):
        for output in ("", "not json at all", json.dumps({"processes": {}})):
            with self.subTest(output=output[:24]):
                findings = self.collect(output)
                self.assertIsNotNone(findings["error"])
                self.assertEqual(findings["network"]["scan_status"], "failed")
                self.assertEqual(findings["network"]["risk"]["posture"], "failed")
                self.assertGreaterEqual(
                    _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))

    def test_nonzero_exit_keeps_the_evidence_and_reduces_confidence(self):
        payload = json.dumps({
            "network": {
                "raw_observations": [{
                    "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
                    "remote_ip": None, "remote_port": None, "state": "LISTEN",
                    "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
                }],
                "docker_containers": [container()],
                "docker_status": "available",
                "scan_status": "complete",
                "scan_gaps": [],
            },
            "processes": {}, "users": {}, "files": {}, "services": {},
            "cron": {}, "auth_log": [],
        })
        findings = self.collect(payload + "\n__AURORA_SECURITY_EXIT__=1")

        observation = findings["network"]["observations"][0]
        self.assertIn("exited nonzero", findings["error"])
        self.assertEqual(observation["classification"], "expected")
        self.assertEqual(observation["confidence"], "medium")
        self.assertEqual(findings["network"]["scan_status"], "failed")
        self.assertGreaterEqual(
            _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))

    def test_remote_collector_command_is_passed_and_static(self):
        captured = {}

        def runner(inst, cmd):
            captured["cmd"] = cmd
            return None

        security_scanner.collect_remote({"name": "AURORA"}, runner, config())
        self.assertEqual(captured["cmd"], security_scanner._build_remote_command())
        self.assertNotIn(BOT_SCRIPT, captured["cmd"])


class RemoteCommandSafetyTests(unittest.TestCase):
    """REG-SEC-NET-01-2: the generated SSH command is safe, parseable, and honest."""

    def setUp(self):
        self.command = security_scanner._build_remote_command()

    def test_command_carries_the_script_as_base64_data_not_shell_text(self):
        match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", self.command)
        self.assertIsNotNone(match)
        script = base64.b64decode(match.group(1)).decode("utf-8")
        compile(script, "remote_security", "exec")
        self.assertIn("import psutil", script)
        self.assertTrue(self.command.rstrip().endswith('exit "$rc"'))

    def test_command_contains_no_untrusted_interpolation(self):
        hostile = "'; touch /tmp/pwned; echo '"
        with mock.patch.dict(os.environ, {"AURORA_TEST": hostile}, clear=False):
            command = security_scanner._build_remote_command()
        self.assertNotIn(hostile, command)
        self.assertNotIn("/tmp/pwned", command)
        self.assertEqual(command, self.command)

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell unavailable")
    def test_command_is_parseable_and_reports_exit_status_under_a_posix_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "python3"
            stub.write_text(
                "#!/bin/sh\nprintf '%s' \"$AURORA_STUB_BODY\"\nprintf '\\npartial\\n'\n"
                "exit ${AURORA_STUB_CODE:-0}\n"
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ.get('PATH', '')}")

            parsed = subprocess.run(
                ["sh", "-n", "-c", self.command], env=env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(parsed.returncode, 0, parsed.stderr)

            ok = subprocess.run(
                ["sh", "-c", self.command], env=dict(env, AURORA_STUB_BODY='{"network":{}}'),
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn('{"network":{}}', ok.stdout)
            self.assertTrue(ok.stdout.rstrip().endswith("__AURORA_SECURITY_EXIT__=0"))

            failed = subprocess.run(
                ["sh", "-c", self.command], env=dict(env, AURORA_STUB_CODE="3"),
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(failed.returncode, 3, failed.stderr)
            self.assertTrue(failed.stdout.rstrip().endswith("__AURORA_SECURITY_EXIT__=3"))


class RemoteClassificationEquivalenceTests(unittest.TestCase):
    """REG-SEC-NET-01-1: the remote program reaches the same classification locally."""

    def setUp(self):
        self.sockets = [
            sock("127.0.0.1", 13133, state="LISTEN", pid=500),
            sock("0.0.0.0", 443, state="LISTEN", pid=700),
            sock("203.0.113.9", 443, remote=("198.51.100.7", 54001), pid=700),
            sock("10.0.1.5", 53124, remote=(BOT_DESTINATION, 443), pid=900),
            sock("10.0.1.5", 44999, remote=("198.51.100.44", 4444), pid=980),
        ]
        self.processes = [
            dict(DOCKER_PROXY), dict(NGINX), dict(BOT_PROCESS), dict(UNKNOWN_SCRIPT),
            dict(INIT),
        ]

    def run_remote_script(self, tmp):
        docker = Path(tmp) / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "if sys.argv[1:3] == ['ps', '--no-trunc']:\n"
            "    print('c0ffee')\n"
            "else:\n"
            "    print(json.dumps([{\n"
            "        'Id': 'c0ffee',\n"
            "        'Name': '/%s',\n"
            "        'Image': '%s',\n"
            "        'Config': {'Image': 'otel/collector:0.1'},\n"
            "        'State': {'Running': True},\n"
            "        'NetworkSettings': {'Ports': {'13133/tcp': "
            "[{'HostIp': '127.0.0.1', 'HostPort': '13133'}]}}\n"
            "    }]))\n" % (OTEL_CONTAINER, OTEL_IMAGE)
        )
        docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
        env = dict(os.environ, PATH=f"{tmp}:{os.environ.get('PATH', '')}")
        script = base64.b64decode(
            re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)",
                      security_scanner._build_remote_command()).group(1)
        ).decode("utf-8")

        output = io.StringIO()
        fake = fake_psutil(self.sockets, [psutil_info(p) for p in self.processes])
        with (
            mock.patch.dict(sys.modules, {"psutil": fake}),
            mock.patch.object(os, "environ", env),
            mock.patch.dict(os.environ, env, clear=True),
            redirect_stdout(output),
        ):
            exec(compile(script, "remote_security", "exec"), {"__name__": "__main__"})
        return json.loads(output.getvalue())

    def test_remote_program_output_classifies_identically_to_the_local_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = self.run_remote_script(tmp)
        body = json.dumps(payload) + "\n__AURORA_SECURITY_EXIT__=0"
        remote = security_scanner.collect_remote(
            {"name": "AURORA"}, lambda inst, cmd: body, config(),
        )

        findings = security_scanner._base_findings("AURORA", "local")
        with (
            mock.patch.object(security_scanner, "_local_process_map",
                              return_value=({info["pid"]: info for info in self.processes}, [])),
            mock.patch.object(security_scanner.psutil, "net_connections",
                              return_value=self.sockets),
            mock.patch.object(security_scanner, "_docker_snapshot",
                              return_value=([container()], "available", None)),
        ):
            security_scanner._scan_network_local(findings, config())

        def signature(network):
            return sorted(
                (
                    obs["local_ip"], obs["local_port"], obs["remote_ip"],
                    obs["remote_port"], obs["protocol"], obs["direction"],
                    obs["bind_scope"], obs["is_listener"], obs["classification"],
                    obs["confidence"],
                    obs["container"]["name"] if obs["container"] else None,
                )
                for obs in network["observations"]
            )

        self.assertEqual(signature(remote["network"]), signature(findings["network"]))
        self.assertEqual(remote["network"]["risk"]["level"], findings["network"]["risk"]["level"])
        self.assertEqual(
            remote["network"]["category_counts"], findings["network"]["category_counts"])
        self.assertEqual(
            remote["network"]["external_connections"], findings["network"]["external_connections"])
        self.assertEqual(remote["error"], None)

    def test_remote_docker_error_is_never_a_clean_posture(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = Path(tmp) / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stderr.write('permission denied while trying to connect to the Docker "
                "daemon socket\\n')\n"
                "sys.exit(1)\n"
            )
            docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ.get('PATH', '')}")
            script = base64.b64decode(
                re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)",
                          security_scanner._build_remote_command()).group(1)
            ).decode("utf-8")
            output = io.StringIO()
            with (
                mock.patch.dict(sys.modules, {"psutil": fake_psutil(
                    self.sockets, [psutil_info(p) for p in self.processes])}),
                mock.patch.dict(os.environ, env, clear=True),
                redirect_stdout(output),
            ):
                exec(compile(script, "remote_security", "exec"), {"__name__": "__main__"})

        payload = json.loads(output.getvalue())
        body = json.dumps(payload) + "\n__AURORA_SECURITY_EXIT__=0"
        remote = security_scanner.collect_remote(
            {"name": "AURORA"}, lambda inst, cmd: body, config(),
        )

        self.assertEqual(remote["network"]["docker_status"], "error")
        self.assertIn("permission denied", " ".join(remote["network"]["scan_gaps"]))
        self.assertEqual(remote["network"]["scan_status"], "partial")
        self.assertGreaterEqual(
            _risk_order(remote["network"]["risk"]["level"]), _risk_order("medium"))


class DockerSnapshotTests(unittest.TestCase):
    """The Docker helper is argv based, timed, and reports failures explicitly."""

    def test_docker_lookup_failure_is_reported_not_swallowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker = Path(tmp) / "docker"
            docker.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n")
            docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=f"{tmp}:{os.environ.get('PATH', '')}")
            with mock.patch.dict(os.environ, env, clear=True):
                containers, status, error = security_scanner._docker_snapshot()

        self.assertEqual(status, "error")
        self.assertEqual(containers, [])
        self.assertIn("Docker identity lookup failed", error)

    def test_missing_docker_binary_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PATH=tmp)
            with mock.patch.dict(os.environ, env, clear=True):
                containers, status, error = security_scanner._docker_snapshot()

        self.assertEqual(status, "unavailable")
        self.assertEqual(containers, [])
        self.assertIn("Docker identity lookup failed", error)


class InstanceSecurityConfigTests(unittest.TestCase):
    """Per-instance identity settings are opt-in, validated, and instance scoped."""

    def base_env(self):
        return {
            "INSTANCE_1_NAME": "AURORA", "INSTANCE_1_IP": "localhost",
            "INSTANCE_1_CHAT_ID": "-1001",
        }

    def test_defaults_are_empty_and_never_fabricate_identity(self):
        instance = monitor.load_instances(self.base_env())[0]
        self.assertEqual(instance["security"], {
            "bot_exe": None, "bot_script": None, "bot_user": None,
            "bot_https_destinations": [], "tailscaled_exe": None,
            "tailscaled_user": None, "tailscaled_https_destinations": [],
            "otel_container_name": None, "otel_image_id": None,
        })

    def test_configured_values_are_read_and_destinations_parsed(self):
        env = self.base_env()
        env.update({
            "INSTANCE_1_SECURITY_BOT_EXE": BOT_EXE,
            "INSTANCE_1_SECURITY_BOT_SCRIPT": BOT_SCRIPT,
            "INSTANCE_1_SECURITY_BOT_USER": BOT_USER,
            "INSTANCE_1_SECURITY_BOT_HTTPS_DESTINATIONS": "203.0.113.10;198.51.100.0/24",
            "INSTANCE_1_SECURITY_OTEL_CONTAINER_NAME": OTEL_CONTAINER,
            "INSTANCE_1_SECURITY_OTEL_IMAGE_ID": OTEL_IMAGE,
        })
        security = monitor.load_instances(env)[0]["security"]
        self.assertEqual(security["bot_exe"], BOT_EXE)
        self.assertEqual(security["bot_https_destinations"],
                         ["203.0.113.10", "198.51.100.0/24"])
        self.assertEqual(security["otel_container_name"], OTEL_CONTAINER)
        self.assertIsNone(security["tailscaled_exe"])

    def test_empty_or_invalid_settings_fail_loudly_for_that_instance(self):
        empty = self.base_env()
        empty["INSTANCE_1_SECURITY_BOT_EXE"] = "   "
        invalid = self.base_env()
        invalid["INSTANCE_1_SECURITY_BOT_HTTPS_DESTINATIONS"] = "203.0.113.10;;198.51.100.5"
        not_an_address = self.base_env()
        not_an_address["INSTANCE_1_SECURITY_TAILSCALED_HTTPS_DESTINATIONS"] = "not-an-address"
        for env, pattern in (
            (empty, "BOT_EXE"),
            (invalid, "BOT_HTTPS_DESTINATIONS"),
            (not_an_address, "TAILSCALED_HTTPS_DESTINATIONS"),
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern + ".*AURORA"):
                    monitor.load_instances(env)

    def test_documentation_lists_the_optional_settings_without_live_values(self):
        example = (ROOT / ".env.example").read_text()
        readme = (ROOT / "README.md").read_text()
        for suffix in (
            "SECURITY_BOT_EXE", "SECURITY_BOT_SCRIPT", "SECURITY_BOT_USER",
            "SECURITY_BOT_HTTPS_DESTINATIONS", "SECURITY_TAILSCALED_EXE",
            "SECURITY_TAILSCALED_USER", "SECURITY_TAILSCALED_HTTPS_DESTINATIONS",
            "SECURITY_OTEL_CONTAINER_NAME", "SECURITY_OTEL_IMAGE_ID",
        ):
            with self.subTest(setting=suffix):
                self.assertIn(suffix, example)
                self.assertIn(suffix, readme)
        for forbidden in ("AKIA", "ASDEASBDASEWQEQFSFAGADH", "121.58.203.121"):
            self.assertNotIn(forbidden, example)
        self.assertIn("never reported as clean", readme)

    def test_documented_settings_match_the_parsed_configuration_keys(self):
        """REG-REV-NET-008: the docs and reasons name the keys the parser reads."""
        readme = (ROOT / "README.md").read_text()
        example = (ROOT / ".env.example").read_text()
        source = (ROOT / "security_scanner.py").read_text()
        security = monitor.load_instances(self.base_env())[0]["security"]
        parsed = {
            "SECURITY_BOT_EXE": "bot_exe", "SECURITY_BOT_SCRIPT": "bot_script",
            "SECURITY_BOT_USER": "bot_user",
            "SECURITY_BOT_HTTPS_DESTINATIONS": "bot_https_destinations",
            "SECURITY_TAILSCALED_EXE": "tailscaled_exe",
            "SECURITY_TAILSCALED_USER": "tailscaled_user",
            "SECURITY_TAILSCALED_HTTPS_DESTINATIONS": "tailscaled_https_destinations",
            "SECURITY_OTEL_CONTAINER_NAME": "otel_container_name",
            "SECURITY_OTEL_IMAGE_ID": "otel_image_id",
        }

        # Every documented key is a real parsed field, unset by default.
        self.assertEqual(set(security), set(parsed.values()))
        self.assertEqual(set(value for value in security.values() if value), set())
        for suffix, field in parsed.items():
            with self.subTest(setting=suffix):
                self.assertIn("INSTANCE_<N>_" + suffix, readme)
                self.assertIn("INSTANCE_1_" + suffix, example)
        self.assertIn("INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME", source)
        self.assertIn("INSTANCE_<N>_SECURITY_TAILSCALED_EXE", source)
        # The unconfigured case is documented as a deliberate fail-safe.
        self.assertIn("MEDIUM", readme)
        self.assertIn("MEDIUM", example)
        self.assertIn("fail-safe", readme)
        self.assertIn("FAIL-SAFE", example)
        # No default identity and no destination inferred from the command line.
        self.assertNotIn("sys.argv", source)
        self.assertNotIn("os.environ.get(\"INSTANCE", source)

    def test_unconfigured_instance_reports_review_with_medium_risk(self):
        raw = [
            {
                "protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
                "remote_ip": None, "remote_port": None, "state": "LISTEN",
                "is_listener": True, "pid": 500, "owner": DOCKER_PROXY,
            },
            {
                "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 53124,
                "remote_ip": "203.0.113.10", "remote_port": 443, "state": "ESTABLISHED",
                "is_listener": False, "pid": 900, "owner": BOT_PROCESS,
            },
        ]
        empty = {key: None for key in config()}
        empty["bot_https_destinations"] = []
        empty["tailscaled_https_destinations"] = []
        findings = local_scan(raw, empty, [container()])
        risk = findings["network"]["risk"]

        self.assertEqual(risk["level"], "medium")
        for observation in findings["network"]["observations"]:
            self.assertIn(observation["classification"],
                          ("needs_review", "expected", "informational", "benign"))
        otel = only(findings["network"]["observations"], local_port=13133)[0]
        self.assertIn("INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME", otel["reason"])
        self.assertIn("INSTANCE_<N>_SECURITY_OTEL_IMAGE_ID", otel["reason"])

    def test_no_global_ip_trust_exception_remains_in_the_scanner(self):
        source = (ROOT / "security_scanner.py").read_text()
        self.assertNotIn("121.58.203.121", source)
        self.assertNotIn("from security_whitelist import SAFE_PORTS", source)
        self.assertNotIn("SAFE_EXTERNAL_IPS", source.replace(
            "SAFE_PORTS, SAFE_EXTERNAL_IPS, ...", ""))


class AuthLogCollectionTests(unittest.TestCase):
    """
    REG-REV-NET-003 — the local auth-log collector never narrows what it captured.

    PAM authentication failures, pre-auth connection/disconnection events from a
    remote source, and account/credential changes all reach the findings, so
    `has_any_findings`, corroboration, the prompt and the report can see them.
    """

    AUTH_LINES = [
        "Sep 29 10:00:01 AURORA sshd[2101]: Accepted publickey for ubuntu from 10.0.0.9 "
        "port 52100 ssh2",
        "Sep 29 10:00:04 AURORA sshd[2103]: pam_unix(sshd:auth): authentication failure; "
        "logname= ubuntu uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.44 user=root",
        "Sep 29 10:00:05 AURORA sshd[2103]: Connection closed by authenticating user root "
        "198.51.100.44 port 41322 [preauth]",
        "Sep 29 10:00:06 AURORA sshd[2103]: Disconnected from authenticating user root "
        "198.51.100.44 port 41322:11 [preauth]",
        "Sep 29 10:00:07 AURORA sshd[2104]: Failed password for invalid user admin from "
        "198.51.100.44 port 41324 ssh2",
    ]

    def test_local_collector_keeps_every_captured_auth_log_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_log = Path(tmp) / "auth.log"
            auth_log.write_text("\n".join(self.AUTH_LINES) + "\n")
            real_run = security_scanner._run_local

            def run_on_fixture(command):
                return real_run(command.replace("/var/log/auth.log", str(auth_log)))

            findings = security_scanner._base_findings("AURORA", "local")
            with mock.patch.object(security_scanner, "_run_local",
                                   side_effect=run_on_fixture):
                security_scanner._scan_auth_log_local(findings)

        collected = findings["auth_log"]
        self.assertEqual(collected, self.AUTH_LINES)
        for line in self.AUTH_LINES:
            with self.subTest(line=line):
                self.assertIn(line, collected)
        for expected in (
            "pam_unix(sshd:auth): authentication failure",
            "Connection closed by authenticating user root",
            "Disconnected from authenticating user root",
            "Failed password for invalid user",
        ):
            with self.subTest(expected=expected):
                self.assertTrue(
                    any(expected in line for line in collected),
                    "auth evidence %r was narrowed out of collection" % expected,
                )
        self.assertTrue(security_scanner.has_any_findings(findings))

    def test_collected_auth_lines_still_drive_corroboration(self):
        findings = local_scan([{
            "protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 44999,
            "remote_ip": "198.51.100.44", "remote_port": 4444, "state": "ESTABLISHED",
            "is_listener": False, "pid": 980, "owner": UNKNOWN_SCRIPT,
        }], config())
        self.assertEqual(findings["network"]["observations"][0]["classification"],
                         "suspicious")
        findings["auth_log"] = list(self.AUTH_LINES)

        risk = security_scanner._assess_network_risk(
            findings["network"]["observations"], "complete", [], findings)

        self.assertIn("authentication log entries", risk["corroboration"])
        self.assertEqual(risk["level"], "high")


# ─── REQUIRED REGRESSIONS REG-11 / REG-12 ─────────────────

# Tokens that may only ever appear in a LINUX program. None of them may reach the
# Windows command, and none of them may reach the Windows program either.
LINUX_ONLY_TOKENS = (
    "systemctl", "crontab", "/var/log/auth.log", "find /etc", "/bin", "/sbin",
    "/usr/bin", "/usr/sbin", "printf", "$?", "; exit",
)
# The two payload keys the central policy reads. They are the ONLY place the
# word may appear in the Windows program: a key name, never a command.
WINDOWS_PAYLOAD_KEYS = ("docker_containers", "docker_status")


def decode_remote_program(command, default=""):
    """
    The Python program a generated security command carries, or `default`.

    One implementation for every decoder in both security test modules, so the
    Windows (gzip-compressed) and Linux (plain base64) forms cannot drift into
    two subtly different readings of the same command. The form is decided by
    the command text itself, not by the caller's expectation of it.
    """
    match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", command)
    if match is None:
        return default
    raw = base64.b64decode(match.group(1))
    return gzip.decompress(raw).decode("utf-8") if "gzip.decompress(" in command \
        else raw.decode("utf-8")


def _windows_program():
    program = decode_remote_program(
        security_scanner._build_remote_command_windows())
    assert program, "the Windows command carries no base64 program"
    return program


def _strip_windows_payload_keys(program):
    return program.replace("docker_containers", "").replace("docker_status", "")


def _run_windows_program(sockets, processes, users=()):
    """
    Execute the DECODED Windows program against a fake psutil.

    The program text is what actually runs, so the payload under test is the one
    the Windows host would produce. Nothing here reaches a real Windows host, a
    real `powershell`, or the network.
    """
    module = fake_psutil(sockets, processes, users)
    program = _windows_program()
    stdout = io.StringIO()
    with (
        mock.patch.dict(sys.modules, {"psutil": module}),
        redirect_stdout(stdout),
    ):
        exec(compile(program, "remote_security_windows", "exec"),
             {"__name__": "__main__"})
    raw = stdout.getvalue()
    body, marker, trailer = raw.rpartition("\n__AURORA_SECURITY_EXIT__=")
    assert marker == "\n__AURORA_SECURITY_EXIT__=", "the trailer format changed"
    return raw, json.loads(body), trailer.strip()


# cmd.exe refuses a command line longer than this. It is the whole reason the
# Windows transport is compressed at all, so the test that guards the transport
# pins the number rather than trusting it to stay remembered.
WINDOWS_COMMAND_LIMIT = 8191

# Captured from `_build_remote_command()` at HEAD f9d1c2d2 and pinned verbatim.
# It is the Linux transport's own value, so a Windows-transport change cannot
# recompute it from the code it is supposed to be checking: `_REMOTE_SCRIPT` and
# `_build_remote_command()` must stay byte-identical, ending `exit "$rc"`.
PINNED_LINUX_COMMAND = (
    'python3 -c "import base64;exec(base64.b64decode(\''
    'aW1wb3J0IGpzb24sIG9zLCBzb2NrZXQsIHN1YnByb2Nlc3MKZnJvbSBkYXRldGltZSBpbXBvcnQgZGF0ZXRpbWUKaW1w'
    'b3J0IHBzdXRpbAoKU1VTUF9OQU1FUyA9IHsnbmMnLCduZXRjYXQnLCduY2F0Jywnbm1hcCcsJ21hc3NjYW4nLCdzb2Nh'
    'dCcsJ3htcmlnJywnY2dtaW5lcicsJ21pbmVyZCcsJ2V0aG1pbmVyJywnbXNmY29uc29sZScsJ2h5ZHJhJywnc3FsbWFw'
    'Jywnam9obicsJ2hhc2hjYXQnLCdtaW1pa2F0eid9ClNVU1BfUEFUSFMgPSBbJy90bXAvJywnL2Rldi9zaG0vJywnL3Zh'
    'ci90bXAvJywnL3J1bi9zaG0vJ10KU0FGRV9aT01CSUVTID0geydjaHJvbWUnLCdjaHJvbWl1bScsJ25vZGUnLCdweXRo'
    'b24nfQoKZmluZGluZ3MgPSB7CiAgICAncHJvY2Vzc2VzJzogeydoaWdoX2NwdSc6IFtdLCAnaGlnaF9tZW0nOiBbXSwg'
    'J3N1c3BpY2lvdXNfbmFtZSc6IFtdLCAnc3VzcGljaW91c19wYXRoJzogW10sICd6b21iaWVzJzogW119LAogICAgJ25l'
    'dHdvcmsnOiB7J3Jhd19vYnNlcnZhdGlvbnMnOiBbXSwgJ2RvY2tlcl9jb250YWluZXJzJzogW10sICdkb2NrZXJfc3Rh'
    'dHVzJzogJ25vdF9yZXF1aXJlZCcsCiAgICAgICAgICAgICAgICAnc2Nhbl9zdGF0dXMnOiAnY29tcGxldGUnLCAnc2Nh'
    'bl9nYXBzJzogW119LAogICAgJ3VzZXJzJzogeydsb2dnZWRfaW4nOiBbXX0sCiAgICAnZmlsZXMnOiB7J3JlY2VudGx5'
    'X21vZGlmaWVkX3N5c3RlbSc6IFtdfSwKICAgICdzZXJ2aWNlcyc6IHsnZmFpbGVkJzogW10sICduZXdfdW5pdHMnOiBb'
    'XX0sCiAgICAnY3Jvbic6IHsnZW50cmllcyc6IFtdfSwKICAgICdhdXRoX2xvZyc6IFtdLAp9CgpkZWYgX2Jhc2VfbmFt'
    'ZShwYXRoKToKICAgIHJldHVybiBvcy5wYXRoLmJhc2VuYW1lKHN0cihwYXRoIG9yICcnKS5yc3RyaXAoJy8nKSkgaWYg'
    'cGF0aCBlbHNlICcnCgpkZWYgX2RvY2tlcl9wcm94eShvd25lcik6CiAgICBvd25lciA9IG93bmVyIG9yIHt9CiAgICBy'
    'ZXR1cm4gKF9iYXNlX25hbWUob3duZXIuZ2V0KCduYW1lJykpID09ICdkb2NrZXItcHJveHknCiAgICAgICAgICAgIG9y'
    'IF9iYXNlX25hbWUob3duZXIuZ2V0KCdleGUnKSkgPT0gJ2RvY2tlci1wcm94eScKICAgICAgICAgICAgb3IgX2Jhc2Vf'
    'bmFtZShvd25lci5nZXQoJ3BhcmVudF9leGUnKSkgaW4gKCdkb2NrZXJkJywgJ2RvY2tlcicpKQoKZGVmIHJ1bihjbWQp'
    'OgogICAgdHJ5OgogICAgICAgIHJlc3VsdCA9IHN1YnByb2Nlc3MucnVuKGNtZCwgc2hlbGw9VHJ1ZSwgY2FwdHVyZV9v'
    'dXRwdXQ9VHJ1ZSwgdGV4dD1UcnVlLCB0aW1lb3V0PTEwKQogICAgICAgIHJldHVybiByZXN1bHQuc3Rkb3V0LnN0cmlw'
    'KCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuICcnCgpwcm9jZXNzX21hcCA9IHt9CnRyeToKICAg'
    'IGZvciBwcm9jZXNzIGluIHBzdXRpbC5wcm9jZXNzX2l0ZXIoWydwaWQnLCdwcGlkJywnbmFtZScsJ2V4ZScsJ2NtZGxp'
    'bmUnLCd1c2VybmFtZScsJ2NwdV9wZXJjZW50JywnbWVtb3J5X3BlcmNlbnQnLCdzdGF0dXMnXSk6CiAgICAgICAgdHJ5'
    'OgogICAgICAgICAgICBpID0gcHJvY2Vzcy5pbmZvCiAgICAgICAgICAgIHBpZCA9IGkuZ2V0KCdwaWQnKQogICAgICAg'
    'ICAgICBuYW1lID0gaS5nZXQoJ25hbWUnKSBvciAnJwogICAgICAgICAgICBleGUgPSBpLmdldCgnZXhlJykgb3IgJycK'
    'ICAgICAgICAgICAgdXNlciA9IGkuZ2V0KCd1c2VybmFtZScpIG9yICcnCiAgICAgICAgICAgIHByb2Nlc3NfbWFwW3Bp'
    'ZF0gPSB7J3BpZCc6IHBpZCwgJ3BwaWQnOiBpLmdldCgncHBpZCcpLCAnbmFtZSc6IG5hbWUgb3IgJ3Vua25vd24nLAog'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdleGUnOiBleGUgb3IgJ3Vua25vd24nLCAnY21kbGluZSc6IGku'
    'Z2V0KCdjbWRsaW5lJykgb3IgW10sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ3VzZXInOiB1c2VyIG9y'
    'ICd1bmtub3duJywgJ3BhcmVudF9leGUnOiAndW5rbm93bid9CiAgICAgICAgICAgIGNwdSA9IGkuZ2V0KCdjcHVfcGVy'
    'Y2VudCcpIG9yIDAKICAgICAgICAgICAgbWVtID0gaS5nZXQoJ21lbW9yeV9wZXJjZW50Jykgb3IgMAogICAgICAgICAg'
    'ICBpZiAoaS5nZXQoJ3N0YXR1cycpIG9yICcnKSA9PSAnem9tYmllJyBhbmQgbm90IGFueSh6IGluIG5hbWUubG93ZXIo'
    'KSBmb3IgeiBpbiBTQUZFX1pPTUJJRVMpOgogICAgICAgICAgICAgICAgZmluZGluZ3NbJ3Byb2Nlc3NlcyddWyd6b21i'
    'aWVzJ10uYXBwZW5kKHsncGlkJzogcGlkLCAnbmFtZSc6IG5hbWV9KQogICAgICAgICAgICBpZiBjcHUgPj0gNTA6CiAg'
    'ICAgICAgICAgICAgICBmaW5kaW5nc1sncHJvY2Vzc2VzJ11bJ2hpZ2hfY3B1J10uYXBwZW5kKHsncGlkJzogcGlkLCAn'
    'bmFtZSc6IG5hbWUsICdjcHUnOiByb3VuZChjcHUsIDEpLCAndXNlcic6IHVzZXIsICdleGUnOiBleGV9KQogICAgICAg'
    'ICAgICBpZiBtZW0gPj0gMzA6CiAgICAgICAgICAgICAgICBmaW5kaW5nc1sncHJvY2Vzc2VzJ11bJ2hpZ2hfbWVtJ10u'
    'YXBwZW5kKHsncGlkJzogcGlkLCAnbmFtZSc6IG5hbWUsICdtZW0nOiByb3VuZChtZW0sIDEpLCAndXNlcic6IHVzZXIs'
    'ICdleGUnOiBleGV9KQogICAgICAgICAgICBpZiBuYW1lLmxvd2VyKCkgaW4gU1VTUF9OQU1FUzoKICAgICAgICAgICAg'
    'ICAgIGZpbmRpbmdzWydwcm9jZXNzZXMnXVsnc3VzcGljaW91c19uYW1lJ10uYXBwZW5kKHsncGlkJzogcGlkLCAnbmFt'
    'ZSc6IG5hbWUsICdleGUnOiBleGUsICd1c2VyJzogdXNlcn0pCiAgICAgICAgICAgIGlmIGV4ZSBhbmQgYW55KGV4ZS5z'
    'dGFydHN3aXRoKHBhdGgpIGZvciBwYXRoIGluIFNVU1BfUEFUSFMpOgogICAgICAgICAgICAgICAgZmluZGluZ3NbJ3By'
    'b2Nlc3NlcyddWydzdXNwaWNpb3VzX3BhdGgnXS5hcHBlbmQoeydwaWQnOiBwaWQsICduYW1lJzogbmFtZSwgJ2V4ZSc6'
    'IGV4ZSwgJ3VzZXInOiB1c2VyfSkKICAgICAgICBleGNlcHQgKHBzdXRpbC5Ob1N1Y2hQcm9jZXNzLCBwc3V0aWwuQWNj'
    'ZXNzRGVuaWVkKToKICAgICAgICAgICAgZmluZGluZ3NbJ25ldHdvcmsnXVsnc2Nhbl9nYXBzJ10uYXBwZW5kKCdTb21l'
    'IHByb2Nlc3MgaWRlbnRpdHkgZmllbGRzIHdlcmUgaW5hY2Nlc3NpYmxlJykKICAgICAgICBleGNlcHQgRXhjZXB0aW9u'
    'IGFzIGV4YzoKICAgICAgICAgICAgZmluZGluZ3NbJ25ldHdvcmsnXVsnc2Nhbl9nYXBzJ10uYXBwZW5kKCdQcm9jZXNz'
    'IGlkZW50aXR5IGxvb2t1cCBmYWlsZWQ6ICcgKyB0eXBlKGV4YykuX19uYW1lX18pCmV4Y2VwdCBFeGNlcHRpb24gYXMg'
    'ZXhjOgogICAgZmluZGluZ3NbJ25ldHdvcmsnXVsnc2Nhbl9nYXBzJ10uYXBwZW5kKCdQcm9jZXNzIGVudW1lcmF0aW9u'
    'IGZhaWxlZDogJyArIHR5cGUoZXhjKS5fX25hbWVfXyArICc6ICcgKyBzdHIoZXhjKSkKZm9yIG93bmVyIGluIHByb2Nl'
    'c3NfbWFwLnZhbHVlcygpOgogICAgcGFyZW50ID0gcHJvY2Vzc19tYXAuZ2V0KG93bmVyLmdldCgncHBpZCcpKQogICAg'
    'aWYgcGFyZW50OgogICAgICAgIG93bmVyWydwYXJlbnRfZXhlJ10gPSBwYXJlbnQuZ2V0KCdleGUnKSBvciAndW5rbm93'
    'bicKCnRyeToKICAgIGNvbm5lY3Rpb25zID0gcHN1dGlsLm5ldF9jb25uZWN0aW9ucyhraW5kPSdpbmV0JykKZXhjZXB0'
    'IEV4Y2VwdGlvbiBhcyBleGM6CiAgICBjb25uZWN0aW9ucyA9IFtdCiAgICBmaW5kaW5nc1snbmV0d29yayddWydzY2Fu'
    'X2dhcHMnXS5hcHBlbmQoJ1NvY2tldCBlbnVtZXJhdGlvbiBmYWlsZWQ6ICcgKyB0eXBlKGV4YykuX19uYW1lX18gKyAn'
    'OiAnICsgc3RyKGV4YykpCmZvciBjb25uIGluIGNvbm5lY3Rpb25zOgogICAgdHJ5OgogICAgICAgIGRlZiBwYXJ0cyhh'
    'ZGRyZXNzKToKICAgICAgICAgICAgaWYgbm90IGFkZHJlc3M6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZSwgTm9u'
    'ZQogICAgICAgICAgICBpZiBpc2luc3RhbmNlKGFkZHJlc3MsICh0dXBsZSwgbGlzdCkpOgogICAgICAgICAgICAgICAg'
    'cmV0dXJuIChzdHIoYWRkcmVzc1swXSkgaWYgYWRkcmVzcyBlbHNlIE5vbmUpLCAoYWRkcmVzc1sxXSBpZiBsZW4oYWRk'
    'cmVzcykgPiAxIGVsc2UgTm9uZSkKICAgICAgICAgICAgcmV0dXJuIGdldGF0dHIoYWRkcmVzcywgJ2lwJywgTm9uZSks'
    'IGdldGF0dHIoYWRkcmVzcywgJ3BvcnQnLCBOb25lKQogICAgICAgIGxvY2FsX2lwLCBsb2NhbF9wb3J0ID0gcGFydHMo'
    'Y29ubi5sYWRkcikKICAgICAgICByZW1vdGVfaXAsIHJlbW90ZV9wb3J0ID0gcGFydHMoY29ubi5yYWRkcikKICAgICAg'
    'ICBjb25uX3R5cGUgPSBnZXRhdHRyKGNvbm4sICd0eXBlJywgTm9uZSkKICAgICAgICBwcm90b2NvbCA9ICd0Y3AnIGlm'
    'IGNvbm5fdHlwZSA9PSBzb2NrZXQuU09DS19TVFJFQU0gZWxzZSAoJ3VkcCcgaWYgY29ubl90eXBlID09IHNvY2tldC5T'
    'T0NLX0RHUkFNIGVsc2UgJ3Vua25vd24nKQogICAgICAgIHN0YXRlID0gc3RyKGdldGF0dHIoY29ubiwgJ3N0YXR1cycs'
    'ICcnKSBvciAnVU5LTk9XTicpCiAgICAgICAgaXNfbGlzdGVuZXIgPSBzdGF0ZSA9PSAnTElTVEVOJyBvciAocHJvdG9j'
    'b2wgPT0gJ3VkcCcgYW5kIGxvY2FsX2lwIGlzIG5vdCBOb25lIGFuZCByZW1vdGVfaXAgaXMgTm9uZSkKICAgICAgICBw'
    'aWQgPSBnZXRhdHRyKGNvbm4sICdwaWQnLCBOb25lKQogICAgICAgIG93bmVyID0gcHJvY2Vzc19tYXAuZ2V0KHBpZCwg'
    'eydwaWQnOiBwaWQsICdwcGlkJzogTm9uZSwgJ25hbWUnOiAndW5rbm93bicsICdleGUnOiAndW5rbm93bicsCiAgICAg'
    'ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2NtZGxpbmUnOiBbXSwgJ3VzZXInOiAndW5rbm93bicsICdw'
    'YXJlbnRfZXhlJzogJ3Vua25vd24nfSkKICAgICAgICBmaW5kaW5nc1snbmV0d29yayddWydyYXdfb2JzZXJ2YXRpb25z'
    'J10uYXBwZW5kKHsncHJvdG9jb2wnOiBwcm90b2NvbCwgJ2xvY2FsX2lwJzogbG9jYWxfaXAsCiAgICAgICAgICAgICds'
    'b2NhbF9wb3J0JzogbG9jYWxfcG9ydCwgJ3JlbW90ZV9pcCc6IHJlbW90ZV9pcCwgJ3JlbW90ZV9wb3J0JzogcmVtb3Rl'
    'X3BvcnQsCiAgICAgICAgICAgICdzdGF0ZSc6IHN0YXRlLCAnaXNfbGlzdGVuZXInOiBpc19saXN0ZW5lciwgJ3BpZCc6'
    'IHBpZCwgJ293bmVyJzogb3duZXJ9KQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgZmluZGluZ3Nb'
    'J25ldHdvcmsnXVsnc2Nhbl9nYXBzJ10uYXBwZW5kKCdTb2NrZXQgcmVjb3JkIHVuYXZhaWxhYmxlOiAnICsgdHlwZShl'
    'eGMpLl9fbmFtZV9fKQoKaWYgYW55KGl0ZW0uZ2V0KCdsb2NhbF9wb3J0JykgPT0gMTMxMzMgb3IgX2RvY2tlcl9wcm94'
    'eShpdGVtLmdldCgnb3duZXInKSBvciB7fSkgZm9yIGl0ZW0gaW4gZmluZGluZ3NbJ25ldHdvcmsnXVsncmF3X29ic2Vy'
    'dmF0aW9ucyddKToKICAgIHRyeToKICAgICAgICBsaXN0ZWQgPSBzdWJwcm9jZXNzLnJ1bihbJ2RvY2tlcicsJ3BzJywn'
    'LS1uby10cnVuYycsJy0tcXVpZXQnXSwgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGV4dD1UcnVlLCB0aW1lb3V0PTgpCiAg'
    'ICAgICAgaWYgbGlzdGVkLnJldHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgZmluZGluZ3NbJ25ldHdvcmsnXVsnZG9j'
    'a2VyX3N0YXR1cyddID0gJ2Vycm9yJwogICAgICAgICAgICBmaW5kaW5nc1snbmV0d29yayddWydzY2FuX2dhcHMnXS5h'
    'cHBlbmQoJ0RvY2tlciBpZGVudGl0eSBsb29rdXAgZmFpbGVkOiAnICsgKGxpc3RlZC5zdGRlcnIgb3IgbGlzdGVkLnN0'
    'ZG91dCBvciAnbm9uemVybyBleGl0Jykuc3RyaXAoKVs6MjQwXSkKICAgICAgICBlbHNlOgogICAgICAgICAgICBmaW5k'
    'aW5nc1snbmV0d29yayddWydkb2NrZXJfc3RhdHVzJ10gPSAnYXZhaWxhYmxlJwogICAgICAgICAgICBmb3IgY29udGFp'
    'bmVyX2lkIGluIGxpc3RlZC5zdGRvdXQuc3BsaXRsaW5lcygpOgogICAgICAgICAgICAgICAgaWYgbm90IGNvbnRhaW5l'
    'cl9pZC5zdHJpcCgpOgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBpbnNwZWN0ZWQg'
    'PSBzdWJwcm9jZXNzLnJ1bihbJ2RvY2tlcicsJ2luc3BlY3QnLGNvbnRhaW5lcl9pZC5zdHJpcCgpXSwgY2FwdHVyZV9v'
    'dXRwdXQ9VHJ1ZSwgdGV4dD1UcnVlLCB0aW1lb3V0PTgpCiAgICAgICAgICAgICAgICBpZiBpbnNwZWN0ZWQucmV0dXJu'
    'Y29kZSAhPSAwOgogICAgICAgICAgICAgICAgICAgIGZpbmRpbmdzWyduZXR3b3JrJ11bJ2RvY2tlcl9zdGF0dXMnXSA9'
    'ICdwYXJ0aWFsJwogICAgICAgICAgICAgICAgICAgIGZpbmRpbmdzWyduZXR3b3JrJ11bJ3NjYW5fZ2FwcyddLmFwcGVu'
    'ZCgnRG9ja2VyIGluc3BlY3QgZmFpbGVkOiAnICsgKGluc3BlY3RlZC5zdGRlcnIgb3IgaW5zcGVjdGVkLnN0ZG91dCBv'
    'ciAnbm9uemVybyBleGl0Jykuc3RyaXAoKVs6MjQwXSkKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAg'
    'ICAgICAgdmFsdWUgPSBqc29uLmxvYWRzKGluc3BlY3RlZC5zdGRvdXQpCiAgICAgICAgICAgICAgICBpZiBub3QgaXNp'
    'bnN0YW5jZSh2YWx1ZSwgbGlzdCkgb3IgbGVuKHZhbHVlKSAhPSAxOgogICAgICAgICAgICAgICAgICAgIHJhaXNlIFZh'
    'bHVlRXJyb3IoJ2luc3BlY3QgZGlkIG5vdCByZXR1cm4gb25lIGNvbnRhaW5lcicpCiAgICAgICAgICAgICAgICBpdGVt'
    'ID0gdmFsdWVbMF0KICAgICAgICAgICAgICAgIGZpbmRpbmdzWyduZXR3b3JrJ11bJ2RvY2tlcl9jb250YWluZXJzJ10u'
    'YXBwZW5kKHsnaWQnOiBpdGVtLmdldCgnSWQnKSwKICAgICAgICAgICAgICAgICAgICAnbmFtZSc6IHN0cihpdGVtLmdl'
    'dCgnTmFtZScsJycpKS5sc3RyaXAoJy8nKSwKICAgICAgICAgICAgICAgICAgICAnaW1hZ2UnOiBpdGVtLmdldCgnQ29u'
    'ZmlnJywge30pLmdldCgnSW1hZ2UnKSwgJ2ltYWdlX2lkJzogaXRlbS5nZXQoJ0ltYWdlJyksCiAgICAgICAgICAgICAg'
    'ICAgICAgJ3J1bm5pbmcnOiBpdGVtLmdldCgnU3RhdGUnLCB7fSkuZ2V0KCdSdW5uaW5nJykgaXMgVHJ1ZSwKICAgICAg'
    'ICAgICAgICAgICAgICAncG9ydHMnOiBpdGVtLmdldCgnTmV0d29ya1NldHRpbmdzJywge30pLmdldCgnUG9ydHMnKSBv'
    'ciB7fX0pCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICBmaW5kaW5nc1snbmV0d29yayddWydkb2Nr'
    'ZXJfc3RhdHVzJ10gPSAnZXJyb3InCiAgICAgICAgZmluZGluZ3NbJ25ldHdvcmsnXVsnc2Nhbl9nYXBzJ10uYXBwZW5k'
    'KCdEb2NrZXIgaWRlbnRpdHkgbG9va3VwIGZhaWxlZDogJyArIHR5cGUoZXhjKS5fX25hbWVfXyArICc6ICcgKyBzdHIo'
    'ZXhjKSkKCmlmIGZpbmRpbmdzWyduZXR3b3JrJ11bJ3NjYW5fZ2FwcyddOgogICAgZmluZGluZ3NbJ25ldHdvcmsnXVsn'
    'c2Nhbl9zdGF0dXMnXSA9ICdwYXJ0aWFsJwoKZm9yIHUgaW4gcHN1dGlsLnVzZXJzKCk6CiAgICBmaW5kaW5nc1sndXNl'
    'cnMnXVsnbG9nZ2VkX2luJ10uYXBwZW5kKHsnbmFtZSc6IHUubmFtZSwgJ3Rlcm1pbmFsJzogdS50ZXJtaW5hbCwgJ2hv'
    'c3QnOiB1Lmhvc3QsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAnc3RhcnRlZCc6IHN0'
    'cihkYXRldGltZS5mcm9tdGltZXN0YW1wKHUuc3RhcnRlZCkpfSkKbW9kID0gcnVuKCJmaW5kIC9ldGMgL2JpbiAvc2Jp'
    'biAvdXNyL2JpbiAvdXNyL3NiaW4gLW5ld2VyIC90bXAgLXR5cGUgZiAtcHJpbnRmICclVCsgJXBcbicgMj4vZGV2L251'
    'bGwgfCBzb3J0IC1yIHwgaGVhZCAtMjAiKQpmaW5kaW5nc1snZmlsZXMnXVsncmVjZW50bHlfbW9kaWZpZWRfc3lzdGVt'
    'J10gPSBtb2Quc3BsaXRsaW5lcygpIGlmIG1vZCBlbHNlIFtdCmZhaWxlZCA9IHJ1bignc3lzdGVtY3RsIGxpc3QtdW5p'
    'dHMgLS10eXBlPXNlcnZpY2UgLS1zdGF0ZT1mYWlsZWQgLS1uby1wYWdlciAtLW5vLWxlZ2VuZCAyPi9kZXYvbnVsbCB8'
    'IGhlYWQgLTIwJykKZmluZGluZ3NbJ3NlcnZpY2VzJ11bJ2ZhaWxlZCddID0gZmFpbGVkLnNwbGl0bGluZXMoKSBpZiBm'
    'YWlsZWQgZWxzZSBbXQpuZXdfdW5pdHMgPSBydW4oImZpbmQgL2V0Yy9zeXN0ZW1kIC91c3IvbGliL3N5c3RlbWQgLW5h'
    'bWUgJyouc2VydmljZScgLW5ld2VyIC90bXAgLXR5cGUgZiAyPi9kZXYvbnVsbCB8IGhlYWQgLTIwIikKZmluZGluZ3Nb'
    'J3NlcnZpY2VzJ11bJ25ld191bml0cyddID0gbmV3X3VuaXRzLnNwbGl0bGluZXMoKSBpZiBuZXdfdW5pdHMgZWxzZSBb'
    'XQpjcm9uID0gcnVuKCdjcm9udGFiIC1sIDI+L2Rldi9udWxsOyBscyAvZXRjL2Nyb24uZC8gMj4vZGV2L251bGw7IGxz'
    'IC92YXIvc3Bvb2wvY3Jvbi9jcm9udGFicy8gMj4vZGV2L251bGwnKQpmaW5kaW5nc1snY3JvbiddWydlbnRyaWVzJ10g'
    'PSBjcm9uLnNwbGl0bGluZXMoKSBpZiBjcm9uIGVsc2UgW10KYXV0aCA9IHJ1bigiZ3JlcCAtRWkgJ2ZhaWxlZHxpbnZh'
    'bGlkfGVycm9yfHN1ZG98dXNlcmFkZHx1c2VyZGVsfHBhc3N3ZCcgL3Zhci9sb2cvYXV0aC5sb2cgMj4vZGV2L251bGwg'
    'fCB0YWlsIC01MCIpCmZpbmRpbmdzWydhdXRoX2xvZyddID0gYXV0aC5zcGxpdGxpbmVzKCkgaWYgYXV0aCBlbHNlIFtd'
    'CnByaW50KGpzb24uZHVtcHMoZmluZGluZ3MpKQo='
    '\'))"; rc=$?; printf \'\\n__AURORA_SECURITY_EXIT__=%s\\n\' "$rc"; exit "$rc"'
)


class RegWindowsTransportTests(unittest.TestCase):
    """
    REG-WIN-TRANSPORT-1 — the Windows command fits cmd.exe and still runs the
    exact Windows program.

    Plain base64 of the 9,427-byte program produced a 12,624-character command,
    so cmd.exe truncated it mid-base64 and returned nothing at all. The transport
    is compressed; this test proves the command fits, that it carries the real
    program, that nothing needs a third-party module to decode it, and that the
    Linux transport beside it was not touched in the process.
    """

    def payload(self, command):
        match = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", command)
        self.assertIsNotNone(match, "the Windows command carries no base64 payload")
        return match.group(1)

    def test_reg_win_transport_1_the_command_fits_and_decodes_to_the_program(self):
        """REG-WIN-TRANSPORT-1: under the limit, and byte-for-byte the program."""
        command = security_scanner._build_remote_command_windows()
        payload = self.payload(command)

        # 1. The command fits the shell that will run it.
        self.assertLess(len(command), WINDOWS_COMMAND_LIMIT)

        # 2. The guard is meaningful: the plain-base64 form this replaced would
        #    NOT have fit, so the size assertion is not vacuously true.
        plain = ("python -c \"exec(__import__('base64').b64decode('"
                 + base64.b64encode(
                     security_scanner._REMOTE_SCRIPT_WINDOWS.encode("utf-8")).decode("ascii")
                 + "'))\"")
        self.assertGreater(len(plain), WINDOWS_COMMAND_LIMIT)
        self.assertLess(len(command), len(plain))

        # 3. What the Windows host will execute is the Windows program, exactly.
        decoded = gzip.decompress(base64.b64decode(payload))
        self.assertEqual(decoded.decode("utf-8"), security_scanner._REMOTE_SCRIPT_WINDOWS)
        compile(decoded.decode("utf-8"), "windows_security", "exec")

        # 4. The transport is visible and inert as far as the shell is concerned.
        self.assertIn("gzip.decompress(", command)
        self.assertIn("b64decode('", command)
        self.assertRegex(payload, r"^[A-Za-z0-9+/=]+$")
        for token in LINUX_ONLY_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, command)

        # 5. Only the Python standard library is needed to decode it.
        self.assertIn("import base64,gzip;", command)

    def test_reg_win_transport_1_the_command_is_byte_deterministic(self):
        """REG-WIN-TRANSPORT-1: gzip mtime=0, so the command is reproducible."""
        self.assertEqual(security_scanner._build_remote_command_windows(),
                         security_scanner._build_remote_command_windows())

    def test_reg_win_transport_1_the_linux_transport_is_untouched(self):
        """REG-WIN-TRANSPORT-1 (preservation guard): Linux is byte-identical."""
        self.assertEqual(security_scanner._build_remote_command(), PINNED_LINUX_COMMAND)
        self.assertTrue(PINNED_LINUX_COMMAND.rstrip().endswith('exit "$rc"'))
        self.assertIn("python3 -c \"import base64;exec(base64.b64decode('",
                      PINNED_LINUX_COMMAND)
        self.assertNotIn("gzip", PINNED_LINUX_COMMAND)
        self.assertIs(security_scanner.collect_remote, security_scanner.collect_remote_linux)


class RegWindowsProgramTests(unittest.TestCase):
    """
    REG-11 — the Windows collector carries no Linux-only command.

    Runtime blocker: Windows-native command BEHAVIOUR cannot be exercised on the
    Linux build host, so the assertions here cover the generated text and the
    parse-back path only.
    """

    def powershell_stub(self, tmp, message="access denied"):
        """A `powershell` on PATH that reports access denied for every query."""
        stub = Path(tmp) / "powershell"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stderr.write(%r)\n"
            "sys.exit(1)\n" % message
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        return dict(os.environ, PATH=f"{tmp}:{os.environ.get('PATH', '')}")

    def test_reg_11_the_windows_program_has_no_linux_only_command(self):
        """REG-11: no Linux-only command or path literal, and it compiles."""
        command = security_scanner._build_remote_command_windows()
        program = _windows_program()

        self.assertIn("b64decode('", command)
        for token in LINUX_ONLY_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token, command)
                self.assertNotIn(token, program)
        # "docker" survives only as the two payload keys the policy reads.
        self.assertNotIn("docker", _strip_windows_payload_keys(program))
        for key in WINDOWS_PAYLOAD_KEYS:
            with self.subTest(payload_key=key):
                self.assertIn(key, program)
        self.assertIn("not_applicable", program)
        compile(program, "remote_security_windows", "exec")

    def test_reg_11_unavailable_categories_are_declared_and_never_silent(self):
        """REG-11: the program names what it could not collect, and it parses back."""
        program = _windows_program()
        sockets = [sock("127.0.0.1", 13133, state="LISTEN", pid=500),
                   sock("0.0.0.0", 443, state="LISTEN", pid=700)]
        processes = [dict(SVCHOST), dict(INIT)]

        with tempfile.TemporaryDirectory() as tmp:
            env = self.powershell_stub(tmp)
            output = io.StringIO()
            with (
                mock.patch.dict(sys.modules, {"psutil": fake_psutil(
                    sockets, [psutil_info(item) for item in processes])}),
                mock.patch.dict(os.environ, env, clear=True),
                redirect_stdout(output),
            ):
                exec(compile(program, "remote_security_windows", "exec"),
                     {"__name__": "__main__"})

        raw = output.getvalue()
        body, marker, trailer = raw.rpartition("\n__AURORA_SECURITY_EXIT__=")
        self.assertEqual(marker, "\n__AURORA_SECURITY_EXIT__=")
        self.assertEqual(trailer.strip(), "0")
        payload = json.loads(body)

        # The uncollected categories are named, not silently returned as empty.
        self.assertTrue(payload["unavailable"])
        for category in ("cron", "files", "services", "auth_log"):
            with self.subTest(category=category):
                self.assertIn(category, payload["unavailable"])
        self.assertEqual(payload["cron"]["entries"], [])
        self.assertEqual(payload["files"]["recently_modified_system"], [])
        self.assertIn("access denied", " ".join(payload["network"]["scan_gaps"]))
        self.assertNotEqual(payload["network"]["scan_status"], "complete")

        findings = security_scanner.collect_remote_windows(
            {"name": "WINDBOX"},
            lambda inst, cmd: raw, config(),
        )
        self.assertNotEqual(findings["network"]["scan_status"], "complete")
        self.assertEqual(findings["network"]["risk"]["posture"], "incomplete")
        self.assertGreaterEqual(_risk_order(findings["network"]["risk"]["level"]),
                                _risk_order("medium"))
        self.assertIsNone(findings["error"])
        self.assertTrue(findings["network"]["scan_gaps"])
        self.assertTrue(security_scanner.has_any_findings(findings))


class RegWindowsPolicyEquivalenceTests(unittest.TestCase):
    """
    REG-12 — Windows evidence is classified by the UNCHANGED central policy.

    The reference is computed by feeding the same raw list through
    _finalize_network on this host, so a Windows-vs-Linux divergence in
    classification, direction, bind scope or confidence fails here.
    """

    RAW = [
        {"protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 13133,
         "remote_ip": None, "remote_port": None, "state": "LISTEN",
         "is_listener": True, "pid": 500, "owner": DOCKER_PROXY},
        {"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 443,
         "remote_ip": None, "remote_port": None, "state": "LISTEN",
         "is_listener": True, "pid": 700, "owner": SVCHOST},
        {"protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 3389,
         "remote_ip": None, "remote_port": None, "state": "LISTEN",
         "is_listener": True, "pid": 700, "owner": SVCHOST},
        {"protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 53124,
         "remote_ip": "203.0.113.99", "remote_port": 443, "state": "ESTABLISHED",
         "is_listener": False, "pid": 900, "owner": SQLSERVR},
        {"protocol": "tcp", "local_ip": "10.0.1.5", "local_port": 4444,
         "remote_ip": None, "remote_port": None, "state": "LISTEN",
         "is_listener": True, "pid": 980, "owner": WINDOWS_SCRIPT},
    ]

    def payload(self):
        return {
            "os_type": "windows",
            "processes": {}, "users": {}, "files": {},
            "services": {"failed": [], "new_units": []}, "cron": {"entries": []},
            "auth_log": [],
            "network": {"raw_observations": [dict(item) for item in self.RAW],
                        "docker_containers": [], "docker_status": "not_applicable",
                        "scan_status": "complete", "scan_gaps": []},
        }

    def signature(self, network):
        return sorted(
            (obs["local_ip"], obs["local_port"], obs["remote_ip"], obs["remote_port"],
             obs["protocol"], obs["direction"], obs["bind_scope"], obs["is_listener"],
             obs["classification"], obs["confidence"],
             obs["container"]["name"] if obs["container"] else None)
            for obs in network["observations"]
        )

    def collect(self, body):
        return security_scanner.collect_remote_windows(
            {"name": "WINDBOX"},
            lambda inst, cmd: body, config(),
        )

    def test_reg_12_windows_evidence_reaches_the_unchanged_policy(self):
        """REG-12: identical signature, counts, totals and risk as the local path."""
        payload = self.payload()
        remote = self.collect(json.dumps(payload) + "\n__AURORA_SECURITY_EXIT__=0")

        reference = security_scanner._base_findings("WINDBOX", "local")
        security_scanner._finalize_network(
            reference, [dict(item) for item in self.RAW], [], "not_applicable", [],
            config(), "complete",
        )

        self.assertIsNone(remote["error"])
        self.assertEqual(self.signature(remote["network"]), self.signature(reference["network"]))
        self.assertEqual(remote["network"]["category_counts"],
                         reference["network"]["category_counts"])
        self.assertEqual(remote["network"]["totals"], reference["network"]["totals"])
        self.assertEqual(remote["network"]["risk"]["level"],
                         reference["network"]["risk"]["level"])
        self.assertEqual(remote["network"]["risk"]["posture"],
                         reference["network"]["risk"]["posture"])
        self.assertEqual(remote["network"]["external_connections"],
                         reference["network"]["external_connections"])
        self.assertEqual(remote["network"]["unexpected_listening"],
                         reference["network"]["unexpected_listening"])
        # A Windows service binary on a private interface is reviewed, never
        # expected: no KNOWN_SERVICES entry is invented for it.
        listener = only(remote["network"]["observations"], local_port=3389)[0]
        self.assertEqual(listener["classification"], "needs_review")
        self.assertEqual(listener["bind_scope"], "private-interface")

    def test_reg_14_a_realistic_windows_temp_exe_is_matched_or_declared_absent(self):
        """
        REV-WIN-002: the temp-path signal fires on a real Windows path.

        Drive-letter and UNC forms both begin with characters a bare
        `\\\\AppData\\Local\\Temp\\` prefix can never match, so `startswith` made
        this signal permanently empty. Either it matches, or `processes` is
        declared unavailable and the scan is not presented as complete.
        """
        dropper = owner(4242, "dropper.exe",
                        "C:\\Users\\svc\\AppData\\Local\\Temp\\dropper.exe",
                        ["dropper.exe"], user="WIN-WEB\\svc")
        unc = owner(4243, "dropper.exe",
                    "\\\\host\\share\\AppData\\Local\\Temp\\dropper.exe",
                    ["dropper.exe"], user="WIN-WEB\\svc")
        windows_temp = owner(4244, "dropper.exe",
                             "C:\\Windows\\Temp\\dropper.exe",
                             ["dropper.exe"], user="WIN-WEB\\svc")
        processes = [psutil_info(dropper), psutil_info(unc),
                     psutil_info(windows_temp), dict(SVCHOST), dict(INIT)]

        with tempfile.TemporaryDirectory() as tmp:
            env = RegWindowsProgramTests().powershell_stub(tmp)
            with mock.patch.dict(os.environ, env, clear=True):
                _raw, payload, trailer = _run_windows_program(
                    [sock("0.0.0.0", 443, state="LISTEN", pid=700)], processes)

        self.assertEqual(trailer, "0")
        matched = [item["exe"].lower() for item in payload["processes"]["suspicious_path"]]
        self.assertEqual(len(matched), 3)
        for expected in (dropper["exe"], unc["exe"], windows_temp["exe"]):
            self.assertIn(expected.lower(), matched)

        findings = security_scanner.collect_remote_windows(
            {"name": "WINDBOX"}, lambda inst, cmd: _raw, config())
        paths = findings["processes"]["suspicious_path"]
        self.assertEqual(len(paths), 3)
        # The match reaches the consumer that silently lost the signal before.
        assessment = llm_analyzer.build_assessment(findings)
        self.assertEqual(assessment["non_network"]["suspicious_processes"], 3)
        self.assertTrue(security_scanner.has_any_findings(findings))

    def test_reg_15_the_named_unavailability_survives_a_full_gap_budget(self):
        """
        REV-WIN-001: the operator always learns WHICH categories are unavailable.

        Six denied process identities produce six identical per-item gaps. The
        report's gap budget must still carry the statement naming `cron`, `files`,
        `services` and `auth_log`, and must not spend itself on duplicates.
        """
        report = llm_analyzer.format_assessment

        def denied(count):
            """A psutil stand-in denying `count` process identities."""
            class Denied(Exception):
                pass

            base = fake_psutil([sock("0.0.0.0", 443, state="LISTEN", pid=700)],
                               [psutil_info(SVCHOST), psutil_info(INIT)])
            allowed = list(base.process_iter())

            def process_iter(attrs=None):
                for info in allowed:
                    yield SimpleNamespace(info=info)
                for index in range(count):
                    yield SimpleNamespace(info=property(lambda self: (_ for _ in ()).throw(
                        base.AccessDenied("access denied"))))
            base.process_iter = process_iter
            return base, Denied

        for count in (0, 4, 5, 6, 12):
            with self.subTest(denied_identities=count):
                module, _denied = denied(count)
                with tempfile.TemporaryDirectory() as tmp:
                    env = RegWindowsProgramTests().powershell_stub(tmp)
                    with mock.patch.dict(os.environ, env, clear=True):
                        with mock.patch.dict(sys.modules, {"psutil": module}):
                            raw, payload, _trailer = _run_windows_program(
                                [sock("0.0.0.0", 443, state="LISTEN", pid=700)], [])

                # The payload itself is unchanged in shape and still honest.
                self.assertNotEqual(payload["network"]["scan_status"], "complete")
                for category in ("cron", "files", "services", "auth_log"):
                    self.assertIn(category, payload["unavailable"])

                findings = security_scanner.collect_remote_windows(
                    {"name": "WINDBOX"}, lambda inst, cmd: raw, config())
                self.assertNotEqual(findings["network"]["scan_status"], "complete")
                self.assertEqual(findings["network"]["risk"]["posture"], "incomplete")

                # Host-derived text is markdown-escaped (SAFE-11); assert against
                # what a Telegram client actually renders.
                text = re.sub(r"\\([_*`\[\]])", r"\1",
                              "\n".join(report(findings, "2026-09-29 12:00:00")))
                for category in ("cron", "files", "services", "auth_log"):
                    with self.subTest(denied_identities=count, category=category):
                        self.assertIn(category, text)
                gap_lines = [line for line in text.splitlines()
                             if line.startswith("⚠️ Evidence gap:")]
                self.assertLessEqual(len(gap_lines), llm_analyzer.MAX_RENDERED_GAPS)
                # Duplicates collapse into one counted line; the budget is never
                # spent on five identical lines.
                repeated = [line for line in set(gap_lines) if gap_lines.count(line) > 1]
                self.assertLessEqual(len(repeated), 1)
                for line in repeated:
                    self.assertIn("(repeated ", line)

    def test_reg_12_every_windows_failure_shape_is_a_failed_scan(self):
        """REG-12: SSH loss, a missing trailer, a nonzero trailer and junk all fail."""
        good = json.dumps(self.payload()) + "\n__AURORA_SECURITY_EXIT__=0"
        shapes = {
            "ssh unreachable": None,
            "missing trailer": json.dumps(self.payload()),
            "nonzero trailer": json.dumps(self.payload()) + "\n__AURORA_SECURITY_EXIT__=3",
            "unparsable payload": "not json at all",
            "payload without network evidence": json.dumps({"processes": {}}),
        }
        for label, body in shapes.items():
            with self.subTest(failure=label):
                findings = self.collect(body)

                self.assertIsNotNone(findings["error"])
                self.assertEqual(findings["network"]["scan_status"], "failed")
                self.assertEqual(findings["network"]["risk"]["posture"], "failed")
                self.assertGreaterEqual(
                    _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
                self.assertTrue(security_scanner.has_any_findings(findings))
        self.assertIsNone(self.collect(good)["error"])
        self.assertEqual(self.collect(good)["network"]["risk"]["posture"], "complete")


class RegWindowsEmptyOutputTests(unittest.TestCase):
    """
    REG-WIN-TRANSPORT-2 — an empty response and a lost trailer are told apart.

    Both used to collapse into "response is missing its exit status", so a Windows
    command cmd.exe truncated and a protocol bug looked identical to whoever read
    the report. Every case here is fail-closed; what changes is only WHICH message
    the operator gets.
    """

    GOOD_PAYLOAD = {
        "os_type": "windows",
        "processes": {}, "users": {}, "files": {},
        "services": {"failed": [], "new_units": []}, "cron": {"entries": []},
        "auth_log": [],
        "network": {"raw_observations": [], "docker_containers": [],
                    "docker_status": "not_applicable",
                    "scan_status": "complete", "scan_gaps": []},
    }

    def collect(self, body):
        return security_scanner.collect_remote_windows(
            {"name": "WINDBOX"}, lambda inst, cmd: body, config())

    def assert_fail_closed(self, findings):
        self.assertIsNotNone(findings["error"])
        self.assertEqual(findings["network"]["scan_status"], "failed")
        self.assertEqual(findings["network"]["risk"]["posture"], "failed")
        self.assertGreaterEqual(
            _risk_order(findings["network"]["risk"]["level"]), _risk_order("medium"))
        self.assertTrue(security_scanner.has_any_findings(findings))

    def test_reg_win_transport_2_no_output_is_not_a_missing_trailer(self):
        """REG-WIN-TRANSPORT-2: empty stdout names ITSELF, and still fails."""
        for label, body in {"empty": "", "whitespace": "  \n\t \r\n "}.items():
            with self.subTest(response=label):
                findings = self.collect(body)

                self.assertIn("produced no output", findings["error"])
                self.assertNotIn("missing its exit status", findings["error"])
                self.assert_fail_closed(findings)

    def test_reg_win_transport_2_a_missing_trailer_keeps_its_own_message(self):
        """REG-WIN-TRANSPORT-2: valid JSON, no trailer — unchanged wording."""
        findings = self.collect(json.dumps(self.GOOD_PAYLOAD))

        self.assertEqual(findings["error"],
                         "Remote security scanner response is missing its exit status")
        self.assert_fail_closed(findings)

    def test_reg_win_transport_2_the_other_failure_shapes_are_unchanged(self):
        """REG-WIN-TRANSPORT-2: nonzero trailer, junk and SSH loss still fail."""
        good = json.dumps(self.GOOD_PAYLOAD)
        shapes = {
            "nonzero trailer": (good + "\n__AURORA_SECURITY_EXIT__=3",
                                "Remote security scanner exited nonzero"),
            "unparsable payload": ("not json at all",
                                   "Remote security scanner response is missing its exit status"),
            "payload without network evidence": (json.dumps({"processes": {}}),
                                                 "Remote security scanner response is missing its exit status"),
            "ssh unreachable": (None, "SSH unreachable"),
        }
        for label, (body, expected) in shapes.items():
            with self.subTest(failure=label):
                findings = self.collect(body)

                self.assertEqual(findings["error"], expected)
                self.assert_fail_closed(findings)

    def test_reg_win_transport_2_a_real_payload_is_still_a_clean_pass(self):
        """REG-WIN-TRANSPORT-2: the new branch does not touch the success path."""
        findings = self.collect(json.dumps(self.GOOD_PAYLOAD)
                                + "\n__AURORA_SECURITY_EXIT__=0")

        self.assertIsNone(findings["error"])
        self.assertEqual(findings["network"]["scan_status"], "complete")
        self.assertEqual(findings["network"]["risk"]["posture"], "complete")


class RegWindowsStderrDiagnosticTests(unittest.TestCase):
    """
    REG-WIN-TRANSPORT-3 — a remote that died before printing is diagnosable.

    stdout alone cannot say why a Windows host returned nothing, so the security
    path now reads the SSH stderr and exit status too. What reaches the report is
    a short sanitized fragment: never key material, a token, a path, a username
    or a hostname, and never more than ~240 characters.
    """

    GOOD_PAYLOAD = RegWindowsEmptyOutputTests.GOOD_PAYLOAD

    # One realistic remote failure: a Windows Python that cannot even start the
    # program, with a key path, a username and a hostname in the message.
    TRACEBACK = (
        'Traceback (most recent call last):\n'
        '  File "C:\\Users\\Administrator\\AppData\\Local\\Temp\\run.py", line 1, in <module>\n'
        '    exec(gzip.decompress(base64.b64decode(\'H4sIAAAAAAAA\')))\n'
        'ModuleNotFoundError: No module named \'gzip\'\n'
        'AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE on win-box.example.com'
    )
    FORBIDDEN = (
        "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=AKIA",
        "C:\\Users\\Administrator", "AppData", "Administrator",
        "win-box.example.com", "/tmp/", "-----BEGIN",
    )

    def collect(self, result):
        return security_scanner.collect_remote_windows(
            {"name": "WINDBOX"}, lambda inst, cmd: result, config())

    def assert_fail_closed(self, findings):
        self.assertIsNotNone(findings["error"])
        self.assertEqual(findings["network"]["scan_status"], "failed")
        self.assertEqual(findings["network"]["risk"]["posture"], "failed")
        self.assertTrue(security_scanner.has_any_findings(findings))

    def detailed(self, stdout="", stderr="", exit_status=None):
        return monitor.SSHResult(stdout, stderr, exit_status, False)

    def test_reg_win_transport_3_stderr_reaches_the_findings_sanitized(self):
        """REG-WIN-TRANSPORT-3: the reason is present, short and inert."""
        findings = self.collect(self.detailed(stderr=self.TRACEBACK, exit_status=1))

        error = findings["error"]
        self.assertIn("produced no output", error)
        # Something recognizable survived: this is a diagnosis, not a blackout.
        self.assertIn("Traceback", error)
        self.assertIn("ModuleNotFoundError", error)
        for secret in self.FORBIDDEN:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, error)
        # The remote's own exit status is part of the diagnosis.
        self.assertIn("exit status 1", error)
        self.assert_fail_closed(findings)

    def test_reg_win_transport_3_the_diagnostic_is_capped(self):
        """REG-WIN-TRANSPORT-3: stderr cannot grow the message without bound."""
        cap = security_scanner._REMOTE_DIAGNOSTIC_CAP
        findings = self.collect(self.detailed(
            stderr="SyntaxError: " + ("'token=ghp_secretvalue' " * 60), exit_status=1))

        error = findings["error"]
        # The message is the fixed wording plus a capped, escaped fragment.
        self.assertLessEqual(len(error), len("Remote security scanner produced no output: ") + cap)
        self.assertIn("SyntaxError", error)
        self.assertNotIn("ghp_secretvalue", error)

    def test_reg_win_transport_3_a_plain_runner_still_works_unchanged(self):
        """
        REG-WIN-TRANSPORT-3: a plain str-or-None runner is still accepted.

        The existing collection tests already pass a lambda returning a plain
        string; this is the backward-compatibility contract stated directly, so a
        later change to shape detection cannot silently break it.
        """
        good = json.dumps(self.GOOD_PAYLOAD) + "\n__AURORA_SECURITY_EXIT__=0"
        findings = security_scanner.collect_remote_windows(
            {"name": "WINDBOX"}, lambda inst, cmd: good, config())

        self.assertIsNone(findings["error"])
        self.assertEqual(findings["network"]["scan_status"], "complete")
        # The unreachable sentinel and an empty string stay distinguishable.
        self.assertEqual(
            security_scanner.collect_remote_windows(
                {"name": "WINDBOX"}, lambda inst, cmd: None, config())["error"],
            "SSH unreachable")

    def test_reg_win_transport_3_a_nonzero_remote_status_stays_fail_closed(self):
        """REG-WIN-TRANSPORT-3: a nonzero remote result never looks clean."""
        good = json.dumps(self.GOOD_PAYLOAD) + "\n__AURORA_SECURITY_EXIT__=0"
        for label, result in {
            "no output at all": self.detailed(stderr="boom", exit_status=2),
            "payload but nonzero exit": self.detailed(good, stderr="warning", exit_status=2),
        }.items():
            with self.subTest(shape=label):
                findings = self.collect(result)

                self.assert_fail_closed(findings)

    def test_reg_win_transport_3_a_silent_remote_is_not_invented(self):
        """REG-WIN-TRANSPORT-3: no stderr means no invented diagnostic."""
        findings = self.collect(self.detailed())

        self.assertEqual(findings["error"], "Remote security scanner produced no output")

    def test_reg_win_transport_3_the_diagnostic_is_markdown_escaped_in_the_report(self):
        """
        REG-WIN-TRANSPORT-3: the fragment reaches Telegram through escape_markdown.

        The reason is host-derived text, so the render sites must escape it or the
        API can reject the whole chunk. Asserted against what a client renders, not
        against the formatter's source.
        """
        findings = self.collect(self.detailed(
            stderr='SyntaxError: invalid syntax (x_1 = *a`, [b] = *c)', exit_status=1))
        self.assertIn("_", findings["error"])

        chunks = llm_analyzer.format_assessment(findings, "2026-09-29 12:00:00")
        text = re.sub(r"\\([_*`\[\]])", r"\1", "\n".join(chunks))
        self.assertIn("produced no output", text)
        self.assertIn("SyntaxError", text)
        # The fragment's own reserved characters are escaped, so what a client
        # renders is the same text the collector produced rather than a mangled
        # or truncated one: the code-span delimiters stay balanced and no bracket
        # survives to open a link.
        for chunk in chunks:
            for char in ("`", "_"):
                with self.subTest(char=char):
                    self.assertEqual(
                        len(re.findall(r"(?<!\\)" + re.escape(char), chunk)) % 2, 0, chunk)
            with self.subTest(char="["):
                self.assertEqual(len(re.findall(r"(?<!\\)\[", chunk)), 0, chunk)
            self.assertLessEqual(len(chunk), llm_analyzer.MAX_TELEGRAM_CHUNK)

    def test_reg_win_transport_3_sanitize_remote_diagnostic_directly(self):
        """REG-WIN-TRANSPORT-3: each sensitive class is removed on its own."""
        cases = {
            "private key": ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKC\n"
                            "-----END RSA PRIVATE KEY-----", "MIIEowIBAAKC"),
            "env assignment": ("MY_API_TOKEN=s3cr3tvalue123", "s3cr3tvalue123"),
            "password": ("password: hunter2xyz", "hunter2xyz"),
            "windows path": (r"C:\Windows\System32\winevt\Logs\System.evtx", "System32"),
            "unc path": (r"\\fileserver\share\secret.txt", "fileserver"),
            "posix path": ("/home/ubuntu/dev/monitor_bot/venv/keys/win.pem", "monitor_bot"),
            "username": ("Authentication failed for user svc-deploy", "svc-deploy"),
            "ipv4 host": ("Connection to 203.0.113.10 refused", "203.0.113.10"),
            "hostname": ("unknown host win-box.example.com", "win-box.example.com"),
            "long blob": ("payload " + "A" * 64, "A" * 64),
        }
        for label, (text, secret) in cases.items():
            with self.subTest(class_=label):
                cleaned = security_scanner.sanitize_remote_diagnostic(text)

                self.assertNotIn(secret, cleaned)
                self.assertLessEqual(len(cleaned),
                                     security_scanner._REMOTE_DIAGNOSTIC_CAP)
        # Nothing and nothing useful never crash, and never invent a reason.
        for value in (None, "", "   \n\t ", 0):
            self.assertEqual(security_scanner.sanitize_remote_diagnostic(value), "")

    def test_reg_win_transport_3_ssh_run_keeps_its_signature_and_result(self):
        """
        REG-WIN-TRANSPORT-3: ssh_run is unchanged for every existing caller.

        It still returns stdout on success and None on any failure, from the same
        single connection, and it still logs remote stderr.
        """
        import paramiko

        inst = {"ip": "203.0.113.10", "ssh_user": "Administrator",
                "key": "/keys/win.pem"}

        class Channel:
            def __init__(self, status):
                self.status = status

            def recv_exit_status(self):
                return self.status

        class Stream:
            def __init__(self, text):
                self.text = text

            def read(self):
                return self.text.encode()

            @property
            def channel(self):
                return Channel(self.exit_status)

        class Client:
            exit_status = 0

            def __init__(self):
                self.commands = []
                self.connections = 0
                self.closed = 0

            def set_missing_host_key_policy(self, policy):
                pass

            def connect(self, ip, username=None, pkey=None, timeout=None):
                self.connections += 1

            def exec_command(self, command):
                self.commands.append(command)
                stdout, stderr = Stream("payload\n"), Stream("a warning\n")
                stdout.exit_status = stderr.exit_status = Client.exit_status
                return None, stdout, stderr

            def close(self):
                self.closed += 1

        client = Client()
        with mock.patch.object(monitor.paramiko, "SSHClient", lambda: client), \
                mock.patch.object(monitor, "load_private_key", lambda path: object()):
            stdout = monitor.ssh_run(inst, "whoami")
            self.assertEqual(stdout, "payload")
            # ONE connection and ONE command: the refactor bought diagnostics
            # without a second round trip.
            self.assertEqual(client.connections, 1)
            self.assertEqual(client.commands, ["whoami"])
            self.assertEqual(client.closed, 1)

            detailed = monitor.ssh_run_detailed(inst, "whoami")
            self.assertEqual(detailed.stdout, "payload")
            self.assertEqual(detailed.stderr, "a warning")
            self.assertEqual(detailed.exit_status, 0)
            self.assertFalse(detailed.unreachable)
            self.assertEqual(client.connections, 2)

            # A failure is still exactly None, from both entry points.
            Client.exit_status = 0
            with mock.patch.object(monitor, "load_private_key",
                                   mock.Mock(side_effect=paramiko.SSHException("down"))):
                self.assertIsNone(monitor.ssh_run(inst, "whoami"))
                failed = monitor.ssh_run_detailed(inst, "whoami")
                self.assertIsNone(failed.stdout)
                self.assertTrue(failed.unreachable)


def _risk_order(level):
    order = ["negligible", "low", "medium", "high", "critical"]
    self_level = level if level in order else "negligible"
    return order.index(self_level)


if __name__ == "__main__":
    unittest.main()
