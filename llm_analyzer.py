"""
llm_analyzer.py
───────────────
Takes the structured security findings dict from security_scanner.py,
builds a detailed prompt, and calls AWS Bedrock (Llama 3.3 70B) for
a security analyst-style report.

The report covers:
  • Summary of suspicious signals
  • Process / network / auth correlation
  • Risk rating (Low / Medium / High / Critical)
  • Actionable recommendations

Prompt format: Llama 3 special tokens
  <|begin_of_text|>
  <|start_header_id|>system<|end_header_id|>    — system persona
  <|eot_id|>                                     — end of turn
  <|start_header_id|>user<|end_header_id|>       — user message
  <|eot_id|>
  <|start_header_id|>assistant<|end_header_id|>  — model generates from here
"""

import json
import os
import re
import traceback

import aioboto3
from dotenv import load_dotenv

load_dotenv()

MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.meta.llama3-3-70b-instruct-v1:0")

MAX_AUTH_LOG_LINES = 30   # cap to avoid blowing token budget
MAX_CONNECTIONS    = 15
MAX_TELEGRAM_CHUNK = 4000
# Telegram rejects any sendMessage body longer than this with HTTP 400. Nothing
# handed to send_message may be longer, including whatever prefix is prepended.
TELEGRAM_MAX_MESSAGE = 4096
# Budget for the lower-priority (expected/informational) evidence only. Adverse
# observations are never dropped to stay inside it.
MAX_OBSERVATION_LINES = 60
MAX_OMITTED_ADVERSE_LISTED = 10

RISK_ORDER = ["negligible", "low", "medium", "high", "critical"]
RISK_ICONS = {
    "negligible": "✅", "low": "🟢", "medium": "⚠️", "high": "🔴", "critical": "🚨",
}
ADVERSE_CATEGORIES = ("suspicious", "high_risk", "needs_review", "unknown")
VERIFIED_CATEGORIES = ("expected", "informational", "benign")
# bind_scope values that make a socket reachable from outside the host.
EXPOSED_BIND_SCOPES = ("all-interfaces", "public-interface", "unknown")

SECTION_TITLES = (
    "Suspicious / Requires Review",
    "Expected Network Activity",
    "Externally Exposed Listeners",
    "Local-Only Listeners",
    "Outbound Connections",
    "Inbound Connections",
)
AUTH_FAILURE_WORDS = (
    "failed", "invalid", "refused", "error", "useradd", "userdel", "passwd",
    "authentication failure", "unable to authenticate", "sudo:",
)
SUSPICIOUS_CRON_HINTS = ("/tmp/", "/dev/shm/", "/var/tmp/", "curl", "wget", "| bash", "|bash", "nc ")

# Telegram is called with parse_mode="Markdown" (legacy). A reserved character
# that reaches a chunk unescaped — an underscore in a path, a backtick or a
# bracket in a log line — can make the API reject the whole chunk, including the
# risk line. Every host-derived value is therefore escaped at render time.
MARKDOWN_RESERVED = re.compile(r"([_*`\[\]])")


def escape_markdown(value) -> str:
    """Escape Telegram Markdown reserved characters in host-derived text."""
    return MARKDOWN_RESERVED.sub(r"\\\1", str(value))


# ─── LLAMA 3 SPECIAL TOKENS ───────────────────────────────
BOS          = "<|begin_of_text|>"
EOT          = "<|eot_id|>"
HDR_OPEN     = "<|start_header_id|>"
HDR_CLOSE    = "<|end_header_id|>"

def _turn(role: str, content: str) -> str:
    """Wrap content in a Llama 3 role turn."""
    return f"{HDR_OPEN}{role}{HDR_CLOSE}\n\n{content}{EOT}"

def _assistant_header() -> str:
    """Open the assistant turn — model generates after this."""
    return f"{HDR_OPEN}assistant{HDR_CLOSE}\n\n"


# ─── DETERMINISTIC ASSESSMENT ─────────────────────────────
# The assessment is computed from the collected evidence only. The model may
# comment on it, but it never produces or changes the authoritative numbers.

def _risk_max(current, candidate):
    if candidate not in RISK_ORDER:
        return current
    if current not in RISK_ORDER:
        return candidate
    return candidate if RISK_ORDER.index(candidate) > RISK_ORDER.index(current) else current


def _legacy_observation(record, kind):
    """Legacy network records carry no identity or direction evidence."""
    return {
        "kind": kind,
        "addr": record.get("addr"),
        "local": record.get("local"),
        "remote": record.get("remote"),
        "port": record.get("port"),
        "endpoint": record.get("addr") or record.get("remote") or "unknown",
        "classification": "needs_review",
        "confidence": "low",
        "direction": "uncertain",
        "bind_scope": "unknown",
        "reason": (
            "legacy record has no owning process, bind scope, or direction evidence, "
            "so it cannot be attributed or oriented"
        ),
    }


def _observations_for(findings):
    """Prefer classified observations; label legacy records as uncertain."""
    network = findings.get("network") or {}
    observations = network.get("observations")
    if observations is not None:
        return list(observations), False
    legacy = []
    for record in network.get("unexpected_listening", []) or []:
        legacy.append(_legacy_observation(record, "listener"))
    for record in network.get("external_connections", []) or []:
        legacy.append(_legacy_observation(record, "connection"))
    return legacy, True


def _adverse_auth_lines(findings):
    return [
        line for line in (findings.get("auth_log") or [])
        if any(word in str(line).lower() for word in AUTH_FAILURE_WORDS)
    ]


def _adverse_cron_lines(findings):
    adverse = []
    for line in (findings.get("cron") or {}).get("entries", []) or []:
        text = str(line).strip()
        if not text or text.startswith("#"):
            continue
        if any(hint in text.lower() for hint in SUSPICIOUS_CRON_HINTS):
            adverse.append(text)
    return adverse


def _non_network_assessment(findings):
    processes = findings.get("processes") or {}
    suspicious_processes = list(processes.get("suspicious_name") or []) + \
        list(processes.get("suspicious_path") or [])
    failed_services = list((findings.get("services") or {}).get("failed") or [])
    new_units = list((findings.get("services") or {}).get("new_units") or [])
    auth_lines = _adverse_auth_lines(findings)
    cron_lines = _adverse_cron_lines(findings)

    reasons = []
    level = "negligible"
    if suspicious_processes:
        level = "medium"
        reasons.append(
            "%d process(es) match known attack tooling or run from a temporary "
            "directory" % len(suspicious_processes))
    if cron_lines:
        level = _risk_max(level, "medium")
        reasons.append("%d cron entry/entries download or run code from a temporary path" % len(cron_lines))
    corroboration = []
    if failed_services:
        corroboration.append("%d failed service(s)" % len(failed_services))
    if new_units:
        corroboration.append("%d recently created service unit(s)" % len(new_units))
    if auth_lines:
        corroboration.append("%d authentication failure/account change line(s)" % len(auth_lines))
    if corroboration:
        reasons.append("corroborated by " + ", ".join(corroboration))
    if suspicious_processes and len(corroboration) >= 2:
        level = "high"
    elif suspicious_processes and corroboration:
        level = "high"
    if processes.get("high_cpu") or processes.get("high_mem") or processes.get("zombies"):
        level = _risk_max(level, "low")
        reasons.append("resource or zombie process signals need review but are not adverse by themselves")
    return {
        "level": level,
        "reasons": reasons,
        "suspicious_processes": len(suspicious_processes),
        "failed_services": len(failed_services),
        "new_units": len(new_units),
        "adverse_auth_lines": len(auth_lines),
        "adverse_cron_lines": len(cron_lines),
    }


def build_assessment(findings: dict) -> dict:
    """Deterministic, evidence-based assessment of one scan."""
    network = findings.get("network") or {}
    scanner_risk = network.get("risk") or {}
    observations, legacy = _observations_for(findings)
    counts = network.get("category_counts") or {}
    if not counts:
        counts = {}
        for observation in observations:
            name = observation.get("classification", "unknown")
            counts[name] = counts.get(name, 0) + 1
    totals = network.get("totals") or {}
    directions = {"inbound": 0, "outbound": 0, "uncertain": 0}
    for observation in observations:
        direction = observation.get("direction")
        if direction in directions:
            directions[direction] += 1

    posture = scanner_risk.get("posture") or network.get("scan_status") or "unknown"
    reasons = list(scanner_risk.get("reasons") or [])
    non_network = _non_network_assessment(findings)
    reasons.extend(non_network["reasons"])

    adverse = [obs for obs in observations if obs.get("classification") in ADVERSE_CATEGORIES]
    level = scanner_risk.get("level") or "negligible"
    if adverse and not reasons:
        level = _risk_max(level, "medium")
        reasons.append(
            "%d network observation(s) could not be verified against a configured "
            "identity" % len(adverse))
    if legacy and observations and all(
            obs.get("direction") == "uncertain" for obs in observations):
        level = _risk_max(level, "medium")
        reasons.append(
            "%d legacy network record(s) have no identity or direction evidence" % len(observations))
    if findings.get("error"):
        level = _risk_max(level, "medium")
        reasons.append("scanner error: %s" % findings["error"])
    if posture in ("failed", "incomplete", "partial", "unknown"):
        if not observations or adverse or findings.get("error"):
            level = _risk_max(level, "medium")
        reasons.append("evidence posture is %s, so completeness cannot be claimed" % posture)
    level = _risk_max(level, non_network["level"])

    return {
        "instance": findings.get("instance", "Unknown"),
        "collected": findings.get("collected", "N/A"),
        "risk": level if level in RISK_ORDER else "medium",
        "posture": posture,
        "reasons": reasons or ["no adverse signal was found in the collected evidence"],
        "categories": counts,
        "totals": totals or {"observations": len(observations)},
        "directions": directions,
        "adverse": len(adverse),
        "legacy_records": legacy,
        "non_network": non_network,
        "error": findings.get("error"),
        "scanner_risk": scanner_risk,
    }


SENSITIVE_ARG_NAMES = {
    "password", "passwd", "token", "secret", "api-key", "access-key", "credential",
    "auth", "authorization", "private-key", "session",
}


def _redact_args(args):
    """Defence in depth: never render a secret-looking argument value."""
    safe, redact_next = [], False
    for raw in args or []:
        arg = str(raw)
        if redact_next:
            safe.append("[REDACTED]")
            redact_next = False
            continue
        key, separator, _ = arg.partition("=")
        normalized = key.lstrip("-").lower().replace("_", "-")
        if normalized in SENSITIVE_ARG_NAMES or any(
                word in normalized for word in ("password", "token", "secret", "credential", "api-key")):
            if separator:
                safe.append(f"{key}=[REDACTED]")
            else:
                safe.append(arg)
                redact_next = True
        else:
            safe.append(arg)
    return safe


def _observation_line(observation, with_reason=False, for_markdown=False):
    """
    Render one classified observation.

    `for_markdown` escapes every host-derived value for Telegram's Markdown
    parse mode; the prompt builder leaves the raw values untouched.
    """
    def field(value):
        return escape_markdown(value) if for_markdown else str(value)

    process = observation.get("process") or {}
    if observation.get("local"):
        endpoint = observation["local"]
    elif observation.get("local_ip") or observation.get("local_port"):
        endpoint = "%s:%s" % (observation.get("local_ip"), observation.get("local_port"))
    else:
        endpoint = _legacy_endpoint(observation)
    remote = observation.get("remote")
    if not remote and observation.get("remote_ip"):
        remote = "%s:%s" % (observation.get("remote_ip"), observation.get("remote_port"))
    detail = "%s %s → %s %s" % (
        field(observation.get("protocol") or "protocol unknown"), field(endpoint),
        field(remote or "-"), field(observation.get("direction", "?")),
    )
    extras = ["state=%s pid=%s" % (field(observation.get("state", "UNKNOWN")),
                                   field(observation.get("pid", "unknown")))]
    evidence = observation.get("evidence") or {}
    if evidence.get("matched_destination"):
        extras.append("matched-destination=%s" % field(evidence["matched_destination"]))
    if evidence.get("docker_status"):
        extras.append("docker-status=%s" % field(evidence["docker_status"]))
    if process.get("name") or observation.get("port"):
        extras.append("owner=%s exe=%s user=%s" % (
            field(process.get("name", "unknown")), field(process.get("exe", "unknown")),
            field(process.get("user", "unknown"))))
        if process.get("cmdline"):
            extras.append("cmd=%s" % field(
                " ".join(_redact_args(process["cmdline"]))[:160]))
    if observation.get("container"):
        container = observation["container"]
        extras.append("container=%s image=%s target=%s" % (
            field(container.get("name")), field(container.get("image")),
            field(container.get("target_port"))))
    if observation.get("bind_scope"):
        extras.append("bind=%s" % field(observation["bind_scope"]))
    line = r"%s \[%s\] conf=%s %s" % (
        _category_marker(observation.get("classification")),
        field(observation.get("classification", "unknown")),
        field(observation.get("confidence", "low")),
        detail,
    )
    if extras:
        line += " | " + " | ".join(extras)
    if with_reason and observation.get("reason"):
        line += " — %s" % field(str(observation["reason"])[:240])
    return line


def _category_marker(category):
    return {
        "suspicious": "🔴", "high_risk": "🚨", "needs_review": "⚠️",
        "expected": "✅", "informational": "ℹ️", "benign": "✅", "unknown": "❓",
    }.get(category, "•")


def _legacy_endpoint(observation):
    if observation.get("addr"):
        return observation["addr"]
    if observation.get("local"):
        return observation["local"]
    return "unknown"


def _ordered_observations(observations):
    """Adverse evidence first, benign last; the report never hides an adverse item."""
    priority = {"high_risk": 0, "suspicious": 1, "needs_review": 2, "unknown": 3,
                "expected": 4, "informational": 5, "benign": 6}
    return sorted(
        enumerate(observations),
        key=lambda pair: (priority.get(pair[1].get("classification"), 3), pair[0]),
    )


def _observation_endpoint(observation):
    """Short, stable identity of one observation, used to enumerate omissions."""
    if observation.get("local"):
        endpoint = observation["local"]
    elif observation.get("local_ip") or observation.get("local_port"):
        endpoint = "%s:%s" % (observation.get("local_ip"), observation.get("local_port"))
    else:
        endpoint = _legacy_endpoint(observation)
    remote = observation.get("remote")
    if not remote and observation.get("remote_ip"):
        remote = "%s:%s" % (observation.get("remote_ip"), observation.get("remote_port"))
    return "%s %s %s" % (observation.get("protocol") or "protocol unknown", endpoint,
                        remote or "-")


def _select_observations(observations):
    """
    Choose what the report can carry.

    Adverse evidence (suspicious, high_risk, needs_review, unknown) is always
    shown: MAX_OBSERVATION_LINES is a budget for the expected/informational
    remainder only. Returns (shown, omitted, omitted_adverse) in the same
    adverse-first order, so the caller can describe exactly what it left out.
    """
    ordered = _ordered_observations(observations)
    adverse = [pair for pair in ordered
               if pair[1].get("classification") in ADVERSE_CATEGORIES]
    lower_priority = [pair for pair in ordered
                      if pair[1].get("classification") not in ADVERSE_CATEGORIES]
    budget = max(0, MAX_OBSERVATION_LINES - len(adverse))
    kept = {pair[0] for pair in adverse} | {pair[0] for pair in lower_priority[:budget]}
    shown = [pair for pair in ordered if pair[0] in kept]
    omitted = [pair for pair in ordered if pair[0] not in kept]
    omitted_adverse = [pair for pair in adverse if pair[0] not in kept]
    return shown, omitted, omitted_adverse


def _section_members(shown):
    """
    Partition the shown observations into the operator-facing sections.

    This is a pure view: nothing is reclassified and nothing is dropped. An
    observation may appear in more than one section (for example a verified
    loopback collector is both expected activity and a local-only listener).
    Inbound is never projected into outbound, and a listener that is reachable
    from outside the host is never listed as expected activity.
    """
    members = {title: [] for title in SECTION_TITLES}
    undecided = []
    for pair in shown:
        observation = pair[1]
        classification = observation.get("classification")
        bind_scope = observation.get("bind_scope")
        listener = bool(observation.get("is_listener"))
        direction = observation.get("direction")
        if classification in ADVERSE_CATEGORIES:
            members["Suspicious / Requires Review"].append(pair)
        if classification in VERIFIED_CATEGORIES and bind_scope not in EXPOSED_BIND_SCOPES:
            members["Expected Network Activity"].append(pair)
        if listener:
            members["Externally Exposed Listeners" if bind_scope in EXPOSED_BIND_SCOPES
                    else "Local-Only Listeners"].append(pair)
        if direction == "outbound":
            members["Outbound Connections"].append(pair)
        elif direction == "inbound":
            members["Inbound Connections"].append(pair)
        elif not listener:
            # Never dropped, never given a direction it does not have.
            undecided.append(pair)
    return members, undecided


def _render_observation(observation):
    """One observation line plus its recorded reason."""
    lines = [_observation_line(observation, for_markdown=True)]
    if observation.get("reason"):
        lines.append("    ↳ %s" % escape_markdown(str(observation["reason"])[:300]))
    return lines


def _split_lines(lines, limit):
    chunks, current = [], ""
    for line in lines:
        addition = line + "\n"
        if current and len(current) + len(addition) > limit:
            chunks.append(current.rstrip())
            current = ""
        current += addition
    if current.strip():
        chunks.append(current.rstrip())
    return chunks or [""]


def _category_summary(counts):
    parts = [f"{name} {counts[name]}" for name in sorted(counts) if counts.get(name)]
    return " · ".join(parts) if parts else "none"


def format_assessment(findings: dict, timestamp: str | None = None) -> list[str]:
    """Authoritative, deterministic security assessment as Telegram chunks."""
    assessment = build_assessment(findings)
    observations, _ = _observations_for(findings)
    timestamp = timestamp or assessment["collected"]
    risk = assessment["risk"]
    header = (
        f"🔐 *Security Report — {escape_markdown(assessment['instance'])}*\n"
        f"🕐 `{escape_markdown(timestamp)}`\n"
        f"{'─' * 38}\n"
        f"*Authoritative assessment (deterministic)*\n"
        f"{RISK_ICONS.get(risk, '⚠️')} Risk: `{escape_markdown(risk.upper())}` | evidence posture: "
        f"`{escape_markdown(assessment['posture'])}`\n"
        "Reasons:\n"
        + "".join(f"  • {escape_markdown(reason)}\n" for reason in assessment["reasons"])
    )

    lines = [header]
    if assessment["error"]:
        lines.append(
            f"❌ Scanner error: `{escape_markdown(str(assessment['error'])[:200])}`")
    if assessment["legacy_records"]:
        lines.append(
            "ℹ️ These records come from the legacy network lists: they have no owner, "
            "bind scope, or direction evidence and are shown as uncertain.")

    network = findings.get("network") or {}
    if observations:
        shown, omitted, omitted_adverse = _select_observations(observations)
        members, undecided = _section_members(shown)
        total = assessment["totals"].get("observations", len(observations))
        adverse_total = assessment["adverse"]
        lines.append(
            "\n🌐 *Network evidence* — %d observation(s)%s\n"
            "Categories: %s\n"
            "Directions: inbound %s · outbound %s · uncertain %s"
            % (total,
               ", %d omitted for length" % len(omitted) if omitted else "",
               escape_markdown(_category_summary(assessment["categories"])),
               assessment["directions"]["inbound"], assessment["directions"]["outbound"],
               assessment["directions"]["uncertain"])
        )
        for title in SECTION_TITLES:
            entries = members[title]
            lines.append("\n*%s* — %d item(s)" % (title, len(entries)))
            if not entries:
                lines.append("  (none)")
            for _, observation in entries:
                lines.extend(_render_observation(observation))
        if undecided:
            lines.append(
                "\n⚠️ Direction not established — %d socket(s) are listed above without an "
                "outbound or inbound section:" % len(undecided))
            for _, observation in undecided:
                lines.extend(_render_observation(observation))
        if omitted:
            lines.append(
                "⚠️ Truncated for message length: %d of %d observation(s) not shown "
                "(%d expected/informational, %d review/unknown, %d suspicious/high-risk)."
                % (len(omitted), total, len(omitted) - len(omitted_adverse),
                   len([pair for pair in omitted_adverse
                        if pair[1].get("classification") in ("needs_review", "unknown")]),
                   len([pair for pair in omitted_adverse
                        if pair[1].get("classification") in ("suspicious", "high_risk")])))
        if len(shown) > MAX_OBSERVATION_LINES:
            lines.append(
                "⚠️ The adverse evidence alone exceeds the %d-line display budget; "
                "%d adverse item(s) were shown anyway so none is hidden."
                % (MAX_OBSERVATION_LINES, assessment["adverse"]))
        if omitted or omitted_adverse:
            lines.append(
                "⚠️ Adverse omissions: %d of %d adverse observation(s) not shown%s"
                % (len(omitted_adverse), adverse_total,
                   " — " + ", ".join(
                       escape_markdown(_observation_endpoint(pair[1]))
                       for pair in omitted_adverse[:MAX_OMITTED_ADVERSE_LISTED])
                   + (" …" if len(omitted_adverse) > MAX_OMITTED_ADVERSE_LISTED else "")
                   if omitted_adverse else ""))
        for gap in (network.get("scan_gaps") or [])[:5]:
            lines.append("⚠️ Evidence gap: %s" % escape_markdown(str(gap)[:200]))
    else:
        lines.append("\n🌐 *Network evidence* — no socket evidence was collected.")

    non_network = assessment["non_network"]
    lines.append(
        "\n⚙️ *Other evidence*\n"
        f"  Suspicious process matches: {non_network['suspicious_processes']}\n"
        f"  Failed services: {non_network['failed_services']} | new units: {non_network['new_units']}\n"
        f"  Adverse auth lines: {non_network['adverse_auth_lines']} | adverse cron entries: "
        f"{non_network['adverse_cron_lines']}\n"
        f"  High CPU: {len((findings.get('processes') or {}).get('high_cpu') or [])} | "
        f"High memory: {len((findings.get('processes') or {}).get('high_mem') or [])} | "
        f"Zombies: {len((findings.get('processes') or {}).get('zombies') or [])}")
    for label, key in (("Suspicious process", "suspicious_name"),
                       ("Suspicious path", "suspicious_path"),
                       ("Failed service", "failed_services")):
        for item in ((findings.get("processes") or {}).get(key)
                     or (findings.get("services") or {}).get(key) or [])[:5]:
            lines.append("  • %s: %s" % (label, escape_markdown(str(item)[:180])))
    if non_network["adverse_auth_lines"]:
        for line in _adverse_auth_lines(findings)[:5]:
            lines.append("  • Auth: %s" % escape_markdown(str(line)[:180]))
    if non_network["adverse_cron_lines"]:
        for line in _adverse_cron_lines(findings)[:5]:
            lines.append("  • Cron: %s" % escape_markdown(str(line)[:180]))
    users = (findings.get("users") or {}).get("logged_in") or []
    if users:
        lines.append("  • Logged in: %s" % ", ".join(
            escape_markdown("%s@%s" % (user.get("name"), user.get("host")
                                       or user.get("terminal") or "local"))
            for user in users[:5]))


    lines.append(
        "\nℹ️ The risk above is computed from the collected evidence. Any AI commentary "
        "that follows is advisory only and cannot change it.")
    return _split_lines(lines, MAX_TELEGRAM_CHUNK)


def _qualify_model_rating(text):
    """Mark any model risk rating so it never reads as the authoritative rating."""
    qualified = []
    for line in str(text).splitlines():
        lowered = line.lower()
        bare_rating = bool(re.fullmatch(r"[\W_]*(negligible|low|medium|high|critical)[\W_]*",
                                        line.strip(), re.IGNORECASE))
        mentions_rating = "risk" in lowered and any(
            word in lowered for word in RISK_ORDER[1:])
        if (bare_rating or mentions_rating) and "advisory" not in lowered \
                and "authoritative" not in lowered:
            line = line.rstrip() + " _(model opinion, advisory only)_"
        qualified.append(line)
    return "\n".join(qualified)


def format_advisory(inst_name: str, llm_output: str, timestamp: str) -> list[str]:
    """Chunks for the Bedrock commentary, clearly marked advisory."""
    if not str(llm_output).strip():
        return ["ℹ️ No AI commentary was returned. The authoritative assessment above stands."]
    banner = (
        f"🤖 *AI commentary — advisory only*\n"
        f"🖥️ Instance: `{escape_markdown(inst_name)}`\n"
        f"🕐 {escape_markdown(timestamp)}\n"
        "⚠️ Advisory text cannot lower or raise the authoritative risk shown above.\n"
        f"{'─' * 38}\n"
    )
    # The banner rides on every chunk, so it is budgeted inside the split.
    return format_telegram_report(
        inst_name, _qualify_model_rating(llm_output), timestamp, prefix=banner)


# ─── PROMPT BUILDER ───────────────────────────────────────


def build_prompt(findings: dict) -> str:
    inst_name = findings.get("instance", "Unknown")
    collected = findings.get("collected", "N/A")
    error     = findings.get("error")

    system_msg = (
        "You are a senior AWS cloud security analyst. "
        "You receive structured telemetry from an automated EC2 security scanner and produce "
        "a concise, actionable Markdown security report. "
        "Be precise, avoid speculation beyond what the data supports, and always prioritise "
        "the highest-risk signals first. "
        "The deterministic assessment supplied with the telemetry is authoritative: describe "
        "and explain it, never contradict it, and never restate a different risk rating as if "
        "it were authoritative. Label your own opinion as advisory."
    )

    # ── Error / unreachable case ──────────────────────────
    if error:
        user_msg = (
            f"The monitoring agent for EC2 instance '{inst_name}' reported an error "
            f"at {collected}: {error}\n\n"
            "Write a short security note covering:\n"
            "1. What this unreachability event means\n"
            "2. Most likely causes (network, crash, misconfiguration, compromise)\n"
            "3. Immediate recommended follow-up actions with specific commands"
        )
        return (
            BOS
            + _turn("system", system_msg)
            + _turn("user", user_msg)
            + _assistant_header()
        )

    # ── Unpack findings ───────────────────────────────────
    procs       = findings.get("processes", {})
    high_cpu    = procs.get("high_cpu", [])
    high_mem    = procs.get("high_mem", [])
    susp_name   = procs.get("suspicious_name", [])
    susp_path   = procs.get("suspicious_path", [])
    zombies     = procs.get("zombies", [])

    net         = findings.get("network", {})
    listening   = net.get("unexpected_listening", [])
    ext_conns   = net.get("external_connections", [])[:MAX_CONNECTIONS]
    assessment  = build_assessment(findings)
    classified_observations, classified_legacy = _observations_for(findings)
    obs_lines = [
        _observation_line(obs, with_reason=True)
        for _, obs in _ordered_observations(classified_observations)[:MAX_CONNECTIONS]
    ]

    users       = findings.get("users", {}).get("logged_in", [])
    mod_files   = findings.get("files", {}).get("recently_modified_system", [])
    failed_svcs = findings.get("services", {}).get("failed", [])
    new_units   = findings.get("services", {}).get("new_units", [])
    cron_entries = findings.get("cron", {}).get("entries", [])
    auth_log    = findings.get("auth_log", [])[:MAX_AUTH_LOG_LINES]

    # ── Formatters ────────────────────────────────────────
    def fmt_list(items, serializer=None):
        if not items:
            return "  (none)"
        if serializer:
            return "\n".join(f"  • {serializer(i)}" for i in items)
        return "\n".join(f"  • {i}" for i in items)

    def proc_str(p):
        cpu = p.get("cpu", "")
        mem = p.get("mem", "")
        detail = f"CPU={cpu}%" if cpu else f"MEM={mem}%"
        return (
            f"PID={p.get('pid')} name={p.get('name')} "
            f"{detail} user={p.get('user')} exe={p.get('exe', '?')}"
        )

    def conn_str(c):
        return f"{c.get('local', '?')} → {c.get('remote', '?')}"

    def user_str(u):
        return (
            f"{u.get('name')} on {u.get('terminal', '?')} "
            f"from {u.get('host', 'local')} since {u.get('started', '?')}"
        )

    def zombie_str(z):
        return f"PID={z.get('pid')} name={z.get('name')}"

    def port_str(l):
        return f"port={l.get('port')} addr={l.get('addr')}"

    def assessment_block():
        rows = [
            f"AUTHORITATIVE RISK (deterministic, not yours to change): "
            f"{assessment['risk'].upper()}",
            f"EVIDENCE POSTURE: {assessment['posture']}",
            "REASONS:",
        ]
        rows.extend(f"  - {reason}" for reason in assessment["reasons"])
        rows.append(
            "CATEGORY COUNTS: " + _category_summary(assessment["categories"])
            + " | DIRECTIONS: inbound %d, outbound %d, uncertain %d"
            % (assessment["directions"]["inbound"], assessment["directions"]["outbound"],
               assessment["directions"]["uncertain"])
        )
        if assessment["error"]:
            rows.append(f"SCANNER ERROR: {assessment['error']}")
        if classified_legacy:
            rows.append(
                "NOTE: these network records come from the legacy lists and carry no owner, "
                "bind scope, or direction evidence; treat them as uncertain, not as proof of "
                "a direction or of compromise."
            )
        return "\n".join(rows)

    # ── Build the user message ────────────────────────────
    sections = [
        f"Analyse the following automated security scan for EC2 instance **{inst_name}** "
        f"collected at {collected}.\n",

        "═══════════════════════════════════════════════\n"
        "SECTION 1 — PROCESS ANOMALIES\n"
        "═══════════════════════════════════════════════\n\n"
        f"High CPU Processes (≥50%):\n{fmt_list(high_cpu, proc_str)}\n\n"
        f"High Memory Processes (≥30%):\n{fmt_list(high_mem, proc_str)}\n\n"
        f"Processes With Suspicious Names (known attack tools / miners):\n{fmt_list(susp_name, proc_str)}\n\n"
        f"Processes Running From Suspicious Paths (/tmp, /dev/shm, etc.):\n{fmt_list(susp_path, proc_str)}\n\n"
        f"Zombie Processes:\n{fmt_list(zombies, zombie_str)}",

        "═══════════════════════════════════════════════\n"
        "SECTION 2 — CLASSIFIED NETWORK EVIDENCE\n"
        "═══════════════════════════════════════════════\n\n"
        f"{assessment_block()}\n\n"
        "Each observation below is already classified by the collector. It records the "
        "protocol, the endpoints, the direction, the bind scope, the owning process, and any "
        "verified container publication.\n"
        f"{fmt_list(obs_lines)}\n\n"
        "Legacy 'Unexpected Listening Ports' projection (no owner, no direction evidence):\n"
        f"{fmt_list(listening, port_str)}\n\n"
        "Legacy 'External Connections' projection (direction and identity unverified; this "
        "projection may include accepted inbound connections):\n"
        f"{fmt_list(ext_conns, conn_str)}",

        "═══════════════════════════════════════════════\n"
        "SECTION 3 — LOGGED-IN USERS\n"
        "═══════════════════════════════════════════════\n\n"
        f"{fmt_list(users, user_str)}",

        "═══════════════════════════════════════════════\n"
        "SECTION 4 — FILE SYSTEM CHANGES\n"
        "═══════════════════════════════════════════════\n\n"
        f"Recently Modified System Files (/etc, /bin, /sbin, /usr/bin, /usr/sbin):\n{fmt_list(mod_files)}",

        "═══════════════════════════════════════════════\n"
        "SECTION 5 — SERVICES & CRON\n"
        "═══════════════════════════════════════════════\n\n"
        f"Failed Systemd Services:\n{fmt_list(failed_svcs)}\n\n"
        f"Newly Created Systemd Units:\n{fmt_list(new_units)}\n\n"
        f"Cron / Scheduled Tasks:\n{fmt_list(cron_entries)}",

        "═══════════════════════════════════════════════\n"
        "SECTION 6 — AUTHENTICATION LOG (last 30 relevant lines)\n"
        "═══════════════════════════════════════════════\n\n"
        f"{fmt_list(auth_log)}",

        "═══════════════════════════════════════════════\n"
        "YOUR TASK\n"
        "═══════════════════════════════════════════════\n\n"
        "Analyse ALL of the above data holistically. "
        "Produce a structured security report with exactly these sections:\n\n"
        "1. **EXECUTIVE SUMMARY** — 3–4 sentence plain-English overview of the instance's "
        "security posture right now.\n\n"
        "2. **RISK RATING** — Restate the authoritative risk from the assessment block "
        "verbatim, then add your own reasoning in 1–2 sentences. If you disagree with the "
        "authoritative rating, say so explicitly as advisory commentary instead of issuing a "
        "different authoritative rating.\n\n"
        "3. **FINDINGS & CORRELATION** — For each notable signal explain:\n"
        "   - What was observed\n"
        "   - Why it is (or is not) suspicious\n"
        "   - How it correlates with other signals "
        "(e.g. suspicious process + unexpected outbound connection + auth failures = possible C2 activity)\n\n"
        "4. **TOP RECOMMENDATIONS** — Numbered, ordered by priority. "
        "Be specific and include shell commands where helpful.\n\n"
        "5. **BENIGN EXPLANATIONS** — List findings that are likely false positives and explain why.\n\n"
        "IMPORTANT CONTEXT:\n"
        "- The deterministic risk, posture, categories, and reasons in the assessment block "
        "are authoritative and already reflect the collected evidence. Do not restate a "
        "different rating as authoritative.\n"
        "- A port number, an IP address, an ephemeral local port, a process name, or a "
        "container name is never proof of identity or of malicious intent. Judge each "
        "observation from its recorded direction, bind scope, owner identity, and reason.\n"
        "- Inbound and outbound are derived from listener matching, not from address shape. "
        "A public remote address on a server-side socket is inbound traffic, not exfiltration.\n"
        "- Unresolved evidence means the identity could not be confirmed; report it as needing "
        "review rather than as compromise. Do not claim a host is compromised without "
        "corroborating evidence in this data.\n"
        "- An incomplete or failed scan cannot be reported as clean, even when nothing "
        "adverse was observed.\n"
        "- Do not assume any address is a known administrator or a trusted service; identity "
        "is established only from the recorded evidence.\n"
        "- TLS peer identity, certificate details, and DNS names are not available from this "
        "data, so do not infer the identity of a remote endpoint beyond its address.\n",
        "Keep the report concise but thorough. Use Markdown formatting.",
    ]

    user_msg = "\n\n".join(sections)

    return (
        BOS
        + _turn("system", system_msg)
        + _turn("user", user_msg)
        + _assistant_header()
    )


# ─── BEDROCK CALLER ───────────────────────────────────────

def _get_session():
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    
    if not access_key or not secret_key:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in .env")
    
    return aioboto3.Session(
        region_name=os.getenv("AWS_REGION", "us-west-2"),
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )


async def analyze_with_bedrock(findings: dict) -> str:
    """
    Build a Llama 3 formatted prompt from findings and send to Bedrock.
    Returns the model's text response, or an error message string.
    """
    prompt = build_prompt(findings)

    try:
        session = _get_session()
        async with session.client("bedrock-runtime") as client:
            response = await client.invoke_model(
                modelId=MODEL_ID,
                body=json.dumps({
                    "prompt":      prompt,
                    "max_gen_len": 4096,
                    "temperature": 0.3,   # lower = more factual / consistent
                    "top_p":       0.9,
                }),
            )
            raw    = await response["body"].read()
            result = json.loads(raw)
            print ("stop reason:", result.get("stop_reason"))
            print ("tokens used:", result.get("tokens_used"))

            return result.get("generation", "").strip()

    except Exception as e:
        traceback.print_exc()
        return f"❌ Bedrock analysis failed: {e}"


# ─── TELEGRAM MESSAGE FORMATTER ───────────────────────────

def format_telegram_report(inst_name: str, llm_output: str, timestamp: str,
                           prefix: str = "") -> list[str]:
    """
    Telegram messages are limited to 4096 chars.
    Format the LLM output for better readability in Telegram and split into chunks.
    `prefix` is repeated on every chunk, so its length is reserved inside the
    split budget instead of being added to an already split chunk.
    Returns a list of message strings ready to send.
    """
    # Clean up and format the LLM output for Telegram
    formatted = _format_for_telegram(llm_output)
    
    header = (
        f"🔐 *Security Report*\n"
        f"🖥️ Instance: `{escape_markdown(inst_name)}`\n"
        f"🕐 {escape_markdown(timestamp)}\n"
        f"{'─' * 38}\n\n"
    )

    full_text = header + formatted
    chunks    = []
    # Headroom for Markdown escaping, never above what Telegram accepts.
    limit     = max(1, min(MAX_TELEGRAM_CHUNK, TELEGRAM_MAX_MESSAGE) - len(prefix))

    while len(full_text) > limit:
        # Try to split on section boundaries first (###), then paragraphs, then any newline
        split_at = full_text.rfind("\n### ", 0, limit)
        if split_at == -1:
            split_at = full_text.rfind("\n\n", 0, limit)
        if split_at == -1:
            split_at = full_text.rfind("\n", 0, limit)
        if split_at == -1:
            split_at = limit
            
        chunk = full_text[:split_at].rstrip()
        chunks.append(chunk)
        full_text = full_text[split_at:].lstrip("\n")

    if full_text:
        chunks.append(full_text.rstrip())

    return [prefix + chunk for chunk in chunks]


def _format_for_telegram(text: str) -> str:
    """
    Format markdown text for better Telegram readability.
    - Converts section headers to more compact format
    - Adds appropriate emojis for visual scanning
    - Formats bullet points and numbered lists
    - Preserves code blocks and emphasis
    """
    lines = text.split('\n')
    formatted_lines = []
    
    for line in lines:
        # Skip empty lines at the start
        if not formatted_lines and not line.strip():
            continue
            
        # Format main section headers (## or ###)
        if line.startswith('### '):
            section_title = line.replace('### ', '').strip()
            emoji = _get_section_emoji(section_title)
            formatted_lines.append(f"\n{emoji} *{section_title.upper()}*")
            continue
        elif line.startswith('## '):
            section_title = line.replace('## ', '').strip()
            emoji = _get_section_emoji(section_title)
            formatted_lines.append(f"\n{emoji} *{section_title.upper()}*")
            continue
        elif line.startswith('# '):
            section_title = line.replace('# ', '').strip()
            emoji = _get_section_emoji(section_title)
            formatted_lines.append(f"\n{emoji} *{section_title.upper()}*")
            continue
            
        # Format numbered lists (recommendations)
        if line.strip() and line.strip()[0].isdigit() and '. ' in line[:5]:
            formatted_lines.append(line)
            continue
            
        # Format bullet points
        if line.strip().startswith('- '):
            formatted_lines.append(line.replace('- ', '  • ', 1))
            continue
        elif line.strip().startswith('* '):
            formatted_lines.append(line.replace('* ', '  • ', 1))
            continue
            
        # Preserve other lines
        formatted_lines.append(line)
    
    result = '\n'.join(formatted_lines)
    
    # Clean up excessive newlines (more than 2 in a row)
    while '\n\n\n' in result:
        result = result.replace('\n\n\n', '\n\n')
    
    return result.strip()


def _get_section_emoji(section_title: str) -> str:
    """Return appropriate emoji for section title."""
    title_lower = section_title.lower()
    
    if 'executive' in title_lower or 'summary' in title_lower:
        return '📋'
    elif 'risk' in title_lower or 'rating' in title_lower:
        return '⚠️'
    elif 'finding' in title_lower or 'correlation' in title_lower:
        return '🔍'
    elif 'recommendation' in title_lower or 'action' in title_lower:
        return '💡'
    elif 'benign' in title_lower or 'false' in title_lower or 'explanation' in title_lower:
        return '✅'
    elif 'network' in title_lower:
        return '🌐'
    elif 'process' in title_lower:
        return '⚙️'
    elif 'user' in title_lower or 'auth' in title_lower:
        return '👤'
    elif 'file' in title_lower:
        return '📁'
    elif 'service' in title_lower or 'cron' in title_lower:
        return '🔧'
    else:
        return '▪️'