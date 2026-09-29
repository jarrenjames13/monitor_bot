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


def _risk_order(level):
    order = ["negligible", "low", "medium", "high", "critical"]
    self_level = level if level in order else "negligible"
    return order.index(self_level)


if __name__ == "__main__":
    unittest.main()
