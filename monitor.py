import paramiko
import psutil
import os
import json
import requests
import schedule
import time
import csv
import threading
from datetime import datetime
from dotenv import load_dotenv

# ─── LOAD ENV ─────────────────────────────────────────────
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

CPU_ALERT_THRESHOLD    = int(os.getenv("CPU_ALERT_THRESHOLD", 80))
MEMORY_ALERT_THRESHOLD = int(os.getenv("MEMORY_ALERT_THRESHOLD", 85))
DISK_ALERT_THRESHOLD   = int(os.getenv("DISK_ALERT_THRESHOLD", 90))
REPORT_INTERVAL        = int(os.getenv("REPORT_INTERVAL", 30))

if not BOT_TOKEN:
    raise ValueError("❌ BOT_TOKEN must be set in .env file")

# ─── INSTANCE → GROUP MAPPING ─────────────────────────────
INSTANCES = []
i = 1
while True:
    name     = os.getenv(f"INSTANCE_{i}_NAME")
    ip       = os.getenv(f"INSTANCE_{i}_IP")
    chat_id  = os.getenv(f"INSTANCE_{i}_CHAT_ID")
    key      = os.getenv(f"INSTANCE_{i}_KEY", "").strip()
    ssh_user = os.getenv(f"INSTANCE_{i}_SSH_USER", "").strip()

    if not name or not ip or not chat_id:
        break

    is_local = ip.strip() in ("localhost", "127.0.0.1")

    # Validate remote instances
    if not is_local:
        if not key:
            raise ValueError(f"❌ INSTANCE_{i}_KEY is required for remote instance '{name}'")
        if not ssh_user:
            raise ValueError(f"❌ INSTANCE_{i}_SSH_USER is required for remote instance '{name}'")
        if not os.path.isfile(key):
            raise ValueError(f"❌ Key file not found for '{name}': {key}")

    # Detect Windows by SSH user
    is_windows = ssh_user.lower() in ("administrator", "admin") if ssh_user else False

    INSTANCES.append({
        "name":       name.strip(),
        "ip":         ip.strip(),
        "chat_id":    chat_id.strip(),
        "key":        key if not is_local else None,
        "ssh_user":   ssh_user if not is_local else None,
        "is_local":   is_local,
        "is_windows": is_windows,
        "index":      i
    })
    i += 1

if not INSTANCES:
    raise ValueError("❌ No instances configured in .env file")

# Build lookup: chat_id → instance
CHAT_TO_INSTANCE = {inst["chat_id"]: inst for inst in INSTANCES}

print(f"[CONFIG] Loaded {len(INSTANCES)} instance(s):")
for inst in INSTANCES:
    if inst["is_local"]:
        mode = "local (psutil)"
    elif inst["is_windows"]:
        mode = f"Windows SSH | user={inst['ssh_user']} | key={inst['key']}"
    else:
        mode = f"Linux SSH | user={inst['ssh_user']} | key={inst['key']}"
    print(f"  {inst['index']}. {inst['name']} ({inst['ip']}) → {mode} → chat {inst['chat_id']}")

# ─── TELEGRAM ─────────────────────────────────────────────

def send_message(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("[ERROR] No internet connection.")
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

# ─── KEY LOADER ───────────────────────────────────────────

def load_private_key(key_path):
    """
    Auto-detect and load any SSH private key type:
    ED25519, RSA, ECDSA.
    Returns the key object or raises an exception.
    """
    key_types = [
        ("ED25519", paramiko.Ed25519Key),
        ("RSA",     paramiko.RSAKey),
        ("ECDSA",   paramiko.ECDSAKey),
    ]
    last_error = None
    for key_name, key_class in key_types:
        try:
            key = key_class.from_private_key_file(key_path)
            print(f"[SSH] Loaded {key_name} key: {key_path}")
            return key
        except paramiko.SSHException as e:
            last_error = f"{key_name}: {e}"
            continue
        except Exception as e:
            last_error = f"{key_name}: {e}"
            continue
    raise ValueError(f"❌ Could not load key '{key_path}'. Last error: {last_error}")

# ─── SSH RUNNER ───────────────────────────────────────────

def ssh_run(inst, cmd):
    """Open SSH connection using the instance's own user and key, run a command."""
    try:
        key    = load_private_key(inst["key"])
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            inst["ip"],
            username=inst["ssh_user"],
            pkey=key,
            timeout=10
        )
        _, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode().strip()
        error  = stderr.read().decode().strip()
        client.close()
        if error:
            print(f"[WARN] stderr from {inst['ip']}: {error}")
        return output
    except paramiko.AuthenticationException:
        print(f"[ERROR] Auth failed for {inst['ip']} (user: {inst['ssh_user']})")
        return None
    except paramiko.SSHException as e:
        print(f"[ERROR] SSH error for {inst['ip']}: {e}")
        return None
    except FileNotFoundError:
        print(f"[ERROR] Key file not found: {inst['key']}")
        return None
    except ValueError as e:
        print(f"[ERROR] {e}")
        return None
    except Exception as e:
        print(f"[ERROR] Could not connect to {inst['ip']}: {e}")
        return None

# ─── METRICS ──────────────────────────────────────────────

def get_local_metrics():
    """Get metrics directly using psutil — no SSH needed."""
    cpu    = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk   = psutil.disk_usage('/')
    net    = psutil.net_io_counters()
    boot   = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot

    return {
        "cpu":        cpu,
        "mem_used":   memory.percent,
        "mem_total":  round(memory.total / (1024**3), 1),
        "disk_used":  disk.percent,
        "disk_total": round(disk.total / (1024**3), 1),
        "net_sent":   round(net.bytes_sent / (1024**2), 1),
        "net_recv":   round(net.bytes_recv / (1024**2), 1),
        "uptime":     str(uptime).split('.')[0],
        "per_core":   psutil.cpu_percent(interval=1, percpu=True)
    }


def build_metrics_cmd(is_windows):
    """Build the remote metrics command for Linux or Windows."""
    python  = "python" if is_windows else "python3"
    disk    = "C:\\\\" if is_windows else "/"
    return (
        f"{python} -c \""
        "import psutil, json, datetime;"
        "mem=psutil.virtual_memory();"
        f"disk=psutil.disk_usage('{disk}');"
        "net=psutil.net_io_counters();"
        "boot=datetime.datetime.fromtimestamp(psutil.boot_time());"
        "uptime=str(datetime.datetime.now()-boot).split('.')[0];"
        "print(json.dumps({"
        "'cpu':psutil.cpu_percent(interval=1),"
        "'mem_used':mem.percent,"
        "'mem_total':round(mem.total/(1024**3),1),"
        "'disk_used':disk.percent,"
        "'disk_total':round(disk.total/(1024**3),1),"
        "'net_sent':round(net.bytes_sent/(1024**2),1),"
        "'net_recv':round(net.bytes_recv/(1024**2),1),"
        "'uptime':uptime,"
        "'per_core':psutil.cpu_percent(interval=1,percpu=True)"
        "}))\""
    )


def build_processes_cmd(is_windows):
    """Build the remote top processes command for Linux or Windows."""
    python = "python" if is_windows else "python3"
    return (
        f"{python} -c \""
        "import psutil, json;"
        "procs=sorted(psutil.process_iter(['pid','name','cpu_percent','memory_percent']),"
        "key=lambda p:p.info['cpu_percent'],reverse=True)[:5];"
        "print(json.dumps([{"
        "'pid':p.info['pid'],'name':p.info['name'],"
        "'cpu':p.info['cpu_percent'],'mem':round(p.info['memory_percent'],1)"
        "} for p in procs]))\""
    )


def get_remote_metrics(inst):
    """Get metrics from a remote instance via SSH."""
    cmd    = build_metrics_cmd(inst["is_windows"])
    output = ssh_run(inst, cmd)
    if output is None:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse metrics from {inst['ip']}: {e}")
        print(f"[DEBUG] Raw output: {output}")
        return None


def get_metrics(inst):
    """Route to local psutil or remote SSH based on instance config."""
    if inst["is_local"]:
        return get_local_metrics()
    return get_remote_metrics(inst)


def get_processes(inst):
    """Get top 5 processes — local psutil or remote SSH."""
    if inst["is_local"]:
        procs = sorted(
            psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
            key=lambda p: p.info['cpu_percent'],
            reverse=True
        )[:5]
        return [
            {
                "pid":  p.info['pid'],
                "name": p.info['name'],
                "cpu":  p.info['cpu_percent'],
                "mem":  round(p.info['memory_percent'], 1)
            }
            for p in procs
        ]
    else:
        cmd    = build_processes_cmd(inst["is_windows"])
        output = ssh_run(inst, cmd)
        if output is None:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return None

# ─── COMMANDS ─────────────────────────────────────────────

def cmd_start(chat_id, inst):
    if inst["is_local"]:
        mode = "local"
    elif inst["is_windows"]:
        mode = "Windows (SSH)"
    else:
        mode = "Linux (SSH)"
    msg = (
        f"✅ *{inst['name']} Monitor Bot*\n\n"
        f"This group monitors: `{inst['name']}`\n"
        f"OS Mode: `{mode}`\n\n"
        f"Type /help to see all available commands."
    )
    send_message(chat_id, msg)


def cmd_help(chat_id, inst):
    msg = (
        f"🤖 *{inst['name']} Monitor Commands*\n\n"
        "/start      — Welcome message\n"
        "/status     — Quick CPU, RAM, Disk snapshot\n"
        "/report     — Full detailed report\n"
        "/cpu        — CPU usage per core\n"
        "/memory     — RAM and swap details\n"
        "/disk       — Disk usage details\n"
        "/network    — Network sent/received stats\n"
        "/processes  — Top 5 processes by CPU\n"
        "/docker     — Running Docker containers\n"
        "/uptime     — Server uptime\n"
        "/alerts     — View current alert thresholds\n"
        "/history    — Last 5 logged metric entries\n"
        "/help       — Show this help message"
    )
    send_message(chat_id, msg)


def cmd_status(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🖥 *{inst['name']} — Quick Status*\n"
        f"🕐 `{timestamp}`\n\n"
        f"CPU: `{m['cpu']}%` | RAM: `{m['mem_used']}%` | Disk: `{m['disk_used']}%`"
    )
    send_message(chat_id, msg)


def cmd_report(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"📊 *{inst['name']} — Full Report*\n"
        f"🕐 `{timestamp}`\n\n"
        f"🖥 *CPU:*    `{m['cpu']}%`\n"
        f"💾 *Memory:* `{m['mem_used']}%` of `{m['mem_total']} GB`\n"
        f"💿 *Disk:*   `{m['disk_used']}%` of `{m['disk_total']} GB`\n"
        f"📤 *Sent:*   `{m['net_sent']} MB`\n"
        f"📥 *Recv:*   `{m['net_recv']} MB`\n"
        f"⏱ *Uptime:* `{m['uptime']}`"
    )
    send_message(chat_id, msg)


def cmd_cpu(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    cores = "\n".join([f"  Core {i+1}: `{c}%`" for i, c in enumerate(m['per_core'])])
    msg = (
        f"🖥 *{inst['name']} — CPU Details*\n\n"
        f"Overall: `{m['cpu']}%`\n\n"
        f"*Per Core:*\n{cores}"
    )
    send_message(chat_id, msg)


def cmd_memory(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    msg = (
        f"💾 *{inst['name']} — Memory Details*\n\n"
        f"  Used:      `{round(m['mem_used'] * m['mem_total'] / 100, 1)} GB` (`{m['mem_used']}%`)\n"
        f"  Available: `{round((100 - m['mem_used']) * m['mem_total'] / 100, 1)} GB`\n"
        f"  Total:     `{m['mem_total']} GB`"
    )
    send_message(chat_id, msg)


def cmd_disk(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    drive = "C:\\" if inst["is_windows"] else "/"
    msg = (
        f"💿 *{inst['name']} — Disk Details*\n\n"
        f"  Drive: `{drive}`\n"
        f"  Used:  `{round(m['disk_used'] * m['disk_total'] / 100, 1)} GB` (`{m['disk_used']}%`)\n"
        f"  Free:  `{round((100 - m['disk_used']) * m['disk_total'] / 100, 1)} GB`\n"
        f"  Total: `{m['disk_total']} GB`"
    )
    send_message(chat_id, msg)


def cmd_network(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    msg = (
        f"🌐 *{inst['name']} — Network Details*\n\n"
        f"  Sent:     `{m['net_sent']} MB`\n"
        f"  Received: `{m['net_recv']} MB`"
    )
    send_message(chat_id, msg)


def cmd_processes(chat_id, inst):
    proc_list = get_processes(inst)
    if proc_list is None:
        send_message(chat_id, f"❌ Could not get processes for *{inst['name']}*.")
        return
    lines = []
    for i, p in enumerate(proc_list, 1):
        lines.append(
            f"{i}. `{p['name']}` (PID {p['pid']})\n"
            f"   CPU: `{p['cpu']}%` | RAM: `{p['mem']}%`"
        )
    msg = f"⚙ *{inst['name']} — Top 5 Processes*\n\n" + "\n\n".join(lines)
    send_message(chat_id, msg)


def cmd_uptime(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    msg = (
        f"⏱ *{inst['name']} — Uptime*\n\n"
        f"  Uptime: `{m['uptime']}`"
    )
    send_message(chat_id, msg)


def cmd_alerts(chat_id, inst):
    msg = (
        f"🔔 *Alert Thresholds — {inst['name']}*\n\n"
        f"  CPU:    `{CPU_ALERT_THRESHOLD}%`\n"
        f"  Memory: `{MEMORY_ALERT_THRESHOLD}%`\n"
        f"  Disk:   `{DISK_ALERT_THRESHOLD}%`\n\n"
        f"_Edit thresholds in your `.env` file and restart the service._"
    )
    send_message(chat_id, msg)


def get_docker_containers(inst):
    """Get running Docker containers — local subprocess or remote SSH."""
    cmd = "docker ps --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>&1"
    if inst["is_local"]:
        import subprocess
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
        except Exception as e:
            return None, str(e)
    else:
        output = ssh_run(inst, cmd)
        if output is None:
            return None, "SSH error"

    if not output or output.startswith("Cannot connect") or "permission denied" in output.lower():
        return None, output or "Docker unavailable"

    containers = []
    for line in output.splitlines():
        parts = line.split("|")
        if len(parts) == 4:
            containers.append({"id": parts[0], "name": parts[1], "status": parts[2], "image": parts[3]})
    return containers, None


def cmd_docker(chat_id, inst):
    containers, err = get_docker_containers(inst)
    if containers is None:
        send_message(chat_id, f"❌ *{inst['name']}* — Docker check failed: `{err}`")
        return
    if not containers:
        send_message(chat_id, f"🐳 *{inst['name']}* — No running containers.")
        return
    lines = [f"{i}. `{c['name']}` (`{c['id'][:12]}`)\n   {c['status']}\n   Image: `{c['image']}`"
             for i, c in enumerate(containers, 1)]
    msg = f"🐳 *{inst['name']} — Docker Containers ({len(containers)} running)*\n\n" + "\n\n".join(lines)
    send_message(chat_id, msg)


def cmd_history(chat_id, inst):
    log_file = os.path.join(os.path.dirname(__file__), "metrics_log.csv")
    if not os.path.isfile(log_file):
        send_message(chat_id, "📂 No history log found yet.")
        return
    try:
        with open(log_file, 'r') as f:
            rows = list(csv.DictReader(f))
        filtered = [r for r in rows if r.get('instance') == inst['name']]
        if not filtered:
            send_message(chat_id, f"📂 No log entries for *{inst['name']}* yet.")
            return
        last5 = filtered[-5:]
        lines = []
        for row in last5:
            lines.append(
                f"🕐 `{row['timestamp']}`\n"
                f"  CPU: `{row['cpu']}%` | RAM: `{row['mem_used']}%` | Disk: `{row['disk_used']}%`"
            )
        msg = f"📜 *{inst['name']} — Last 5 Entries*\n\n" + "\n\n".join(lines)
        send_message(chat_id, msg)
    except Exception as e:
        send_message(chat_id, f"❌ Could not read log: {e}")


# ─── COMMAND ROUTER ───────────────────────────────────────

COMMANDS = {
    "/start":     cmd_start,
    "/help":      cmd_help,
    "/status":    cmd_status,
    "/report":    cmd_report,
    "/cpu":       cmd_cpu,
    "/memory":    cmd_memory,
    "/disk":      cmd_disk,
    "/network":   cmd_network,
    "/processes": cmd_processes,
    "/docker":    cmd_docker,
    "/uptime":    cmd_uptime,
    "/alerts":    cmd_alerts,
    "/history":   cmd_history,
}


def handle_commands():
    offset = None
    print("[BOT] Listening for commands...")
    while True:
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            params = {"timeout": 30, "offset": offset}
            response = requests.get(url, params=params, timeout=35)
            data = response.json()

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                message = update.get("message", {})
                chat_id = str(message.get("chat", {}).get("id", ""))
                text    = message.get("text", "").strip().lower()

                if not chat_id:
                    continue

                inst = CHAT_TO_INSTANCE.get(chat_id)
                if inst is None:
                    print(f"[IGNORED] Unknown chat_id: {chat_id}")
                    continue

                if not text:
                    continue

                base_cmd = text.split("@")[0]

                if base_cmd in COMMANDS:
                    print(f"[CMD] {base_cmd} from {inst['name']} (chat {chat_id})")
                    COMMANDS[base_cmd](chat_id, inst)
                else:
                    send_message(chat_id, "❓ Unknown command. Type /help for the list.")

        except Exception as e:
            print(f"[ERROR] Polling error: {e}")
            time.sleep(5)


# ─── SCHEDULED TASKS ──────────────────────────────────────

def send_scheduled_reports():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for inst in INSTANCES:
        m = get_metrics(inst)
        if m is None:
            send_message(inst['chat_id'], f"❌ *{inst['name']}* unreachable during scheduled report.")
            continue
        msg = (
            f"📊 *{inst['name']} — Scheduled Report*\n"
            f"🕐 `{timestamp}`\n\n"
            f"🖥 *CPU:*    `{m['cpu']}%`\n"
            f"💾 *Memory:* `{m['mem_used']}%` of `{m['mem_total']} GB`\n"
            f"💿 *Disk:*   `{m['disk_used']}%` of `{m['disk_total']} GB`\n"
            f"📤 *Sent:*   `{m['net_sent']} MB`\n"
            f"📥 *Recv:*   `{m['net_recv']} MB`\n"
            f"⏱ *Uptime:* `{m['uptime']}`"
        )
        send_message(inst['chat_id'], msg)
    print(f"[{timestamp}] Scheduled reports sent.")


def check_all_alerts():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for inst in INSTANCES:
        m = get_metrics(inst)
        if m is None:
            send_message(inst['chat_id'], f"🔴 *{inst['name']}* is *unreachable!*\n🕐 `{timestamp}`")
            continue
        alerts = []
        if m['cpu'] >= CPU_ALERT_THRESHOLD:
            alerts.append(f"🔴 HIGH CPU: `{m['cpu']}%`")
        if m['mem_used'] >= MEMORY_ALERT_THRESHOLD:
            alerts.append(f"🔴 HIGH MEMORY: `{m['mem_used']}%`")
        if m['disk_used'] >= DISK_ALERT_THRESHOLD:
            alerts.append(f"🔴 HIGH DISK: `{m['disk_used']}%`")
        if alerts:
            msg = (
                f"⚠ *ALERT — {inst['name']}*\n"
                f"🕐 `{timestamp}`\n\n"
            ) + "\n".join(alerts)
            send_message(inst['chat_id'], msg)
            print(f"[{timestamp}] Alert sent to {inst['name']} group.")


def log_all_metrics():
    log_file   = os.path.join(os.path.dirname(__file__), "metrics_log.csv")
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fieldnames = ['instance', 'timestamp', 'cpu', 'mem_used', 'mem_total',
                  'disk_used', 'disk_total', 'net_sent', 'net_recv', 'uptime']
    file_exists = os.path.isfile(log_file)
    try:
        with open(log_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            for inst in INSTANCES:
                m = get_metrics(inst)
                if m is None:
                    continue
                writer.writerow({
                    'instance':   inst['name'],
                    'timestamp':  timestamp,
                    'cpu':        m['cpu'],
                    'mem_used':   m['mem_used'],
                    'mem_total':  m['mem_total'],
                    'disk_used':  m['disk_used'],
                    'disk_total': m['disk_total'],
                    'net_sent':   m['net_sent'],
                    'net_recv':   m['net_recv'],
                    'uptime':     m['uptime'],
                })
        print(f"[{timestamp}] Metrics logged for all instances.")
    except Exception as e:
        print(f"[ERROR] Could not write to log: {e}")


# ─── MAIN ─────────────────────────────────────────────────

schedule.every(REPORT_INTERVAL).minutes.do(send_scheduled_reports)
schedule.every(1).minutes.do(check_all_alerts)
schedule.every(5).minutes.do(log_all_metrics)

# Run command listener in background thread
thread = threading.Thread(target=handle_commands, daemon=True)
thread.start()

# Startup — notify each group
print("✅ Central EC2 Monitor starting...")
for inst in INSTANCES:
    if inst["is_local"]:
        mode = "local"
    elif inst["is_windows"]:
        mode = "Windows SSH"
    else:
        mode = "Linux SSH"
    send_message(
        inst['chat_id'],
        f"✅ *{inst['name']} Monitor Started*\n\n"
        f"📡 Mode: `{mode}`\n"
        f"🔔 Thresholds — CPU: `{CPU_ALERT_THRESHOLD}%` | RAM: `{MEMORY_ALERT_THRESHOLD}%` | Disk: `{DISK_ALERT_THRESHOLD}%`\n"
        f"📊 Reports every `{REPORT_INTERVAL}` mins\n\n"
        f"Type /help for available commands."
    )

send_scheduled_reports()
log_all_metrics()

print("Monitor running... Press Ctrl+C to stop.")
while True:
    schedule.run_pending()
    time.sleep(30)
