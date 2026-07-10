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
import traceback

import aioboto3
from dotenv import load_dotenv

load_dotenv()

MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.meta.llama3-3-70b-instruct-v1:0")

MAX_AUTH_LOG_LINES = 30   # cap to avoid blowing token budget
MAX_CONNECTIONS    = 15

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
        "the highest-risk signals first."
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
        "SECTION 2 — NETWORK ANOMALIES\n"
        "═══════════════════════════════════════════════\n\n"
        f"Unexpected Listening Ports (outside common safe set):\n{fmt_list(listening, port_str)}\n\n"
        f"Active External (Public IP) Outbound Connections:\n{fmt_list(ext_conns, conn_str)}",

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
        "2. **RISK RATING** — One of: ✅ LOW | ⚠️ MEDIUM | 🔴 HIGH | 🚨 CRITICAL. "
        "Justify the rating in 1–2 sentences.\n\n"
        "3. **FINDINGS & CORRELATION** — For each notable signal explain:\n"
        "   - What was observed\n"
        "   - Why it is (or is not) suspicious\n"
        "   - How it correlates with other signals "
        "(e.g. suspicious process + unexpected outbound connection + auth failures = possible C2 activity)\n\n"
        "4. **TOP RECOMMENDATIONS** — Numbered, ordered by priority. "
        "Be specific and include shell commands where helpful.\n\n"
        "5. **BENIGN EXPLANATIONS** — List findings that are likely false positives and explain why.\n\n"
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

def format_telegram_report(inst_name: str, llm_output: str, timestamp: str) -> list[str]:
    """
    Telegram messages are limited to 4096 chars.
    Format the LLM output for better readability in Telegram and split into chunks.
    Returns a list of message strings ready to send.
    """
    # Clean up and format the LLM output for Telegram
    formatted = _format_for_telegram(llm_output)
    
    header = (
        f"🔐 *Security Report*\n"
        f"🖥️ Instance: `{inst_name}`\n"
        f"🕐 {timestamp}\n"
        f"{'─' * 38}\n\n"
    )

    full_text = header + formatted
    chunks    = []
    limit     = 4000  # leave headroom for Markdown escaping

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

    return chunks


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