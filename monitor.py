import asyncio
import base64
import csv
import ipaddress
import json
import os
import subprocess
import tempfile
import threading
import time
from collections import namedtuple
from datetime import datetime
from zoneinfo import ZoneInfo

import paramiko
import psutil
import requests
import schedule
from dotenv import load_dotenv

from security_scanner import (
    collect_local,
    collect_remote_linux,
    collect_remote_windows,
    has_any_findings,
)

# ─── LOAD ENV ─────────────────────────────────────────────
PH_TZ = ZoneInfo("Asia/Manila")

BOT_TOKEN = os.getenv("BOT_TOKEN")

def now_ph():
    return datetime.now(PH_TZ)

CPU_ALERT_THRESHOLD    = int(os.getenv("CPU_ALERT_THRESHOLD", 80))
MEMORY_ALERT_THRESHOLD = int(os.getenv("MEMORY_ALERT_THRESHOLD", 85))
DISK_ALERT_THRESHOLD   = int(os.getenv("DISK_ALERT_THRESHOLD", 90))
REPORT_INTERVAL        = int(os.getenv("REPORT_INTERVAL", 30))

_metrics_lock = threading.Lock()

# ─── INSTANCE → GROUP MAPPING ─────────────────────────────
INSTANCES = []
CHAT_TO_INSTANCE = {}


def _security_setting(environ, index, suffix, name):
    """Return one optional per-instance security identity setting."""
    raw = environ.get(f"INSTANCE_{index}_SECURITY_{suffix}")
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        raise ValueError(
            f"❌ INSTANCE_{index}_SECURITY_{suffix} is set but empty for instance '{name}': "
            "remove the setting or provide a real value"
        )
    return value


def _security_destinations(environ, index, suffix, name):
    """
    Parse a service-scoped destination list. Entries are exact addresses or CIDRs
    with an optional :port suffix, separated by ';' or ','. Dynamic destinations
    are resolved on every scan by comparing the observed socket address, so a
    stale entry simply stops matching instead of silently trusting a new address.
    """
    raw = _security_setting(environ, index, suffix, name)
    if raw is None:
        return []
    entries = [item.strip() for item in raw.replace(",", ";").split(";")]
    if any(not item for item in entries):
        raise ValueError(
            f"❌ INSTANCE_{index}_SECURITY_{suffix} has an empty entry for instance "
            f"'{name}': use one address or CIDR per ';' separated entry"
        )
    for item in entries:
        address, separator, port = item.rpartition(":") if item.count(":") == 1 else (item, "", "")
        if not separator:
            address, port = item, ""
        try:
            if "/" in address:
                ipaddress.ip_network(address, strict=False)
            else:
                ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError(
                f"❌ Invalid INSTANCE_{index}_SECURITY_{suffix} entry {item!r} for "
                f"instance '{name}': expected an IP address or CIDR"
            ) from exc
        if port and not port.isdigit():
            raise ValueError(
                f"❌ Invalid INSTANCE_{index}_SECURITY_{suffix} port in entry {item!r} "
                f"for instance '{name}': expected a numeric port"
            )
    return entries


def _security_config(environ, index, name):
    """Per-instance, opt-in security identities used for network classification."""
    return {
        "bot_exe": _security_setting(environ, index, "BOT_EXE", name),
        "bot_script": _security_setting(environ, index, "BOT_SCRIPT", name),
        "bot_user": _security_setting(environ, index, "BOT_USER", name),
        "bot_https_destinations": _security_destinations(
            environ, index, "BOT_HTTPS_DESTINATIONS", name),
        "tailscaled_exe": _security_setting(environ, index, "TAILSCALED_EXE", name),
        "tailscaled_user": _security_setting(environ, index, "TAILSCALED_USER", name),
        "tailscaled_https_destinations": _security_destinations(
            environ, index, "TAILSCALED_HTTPS_DESTINATIONS", name),
        "otel_container_name": _security_setting(
            environ, index, "OTEL_CONTAINER_NAME", name),
        "otel_image_id": _security_setting(environ, index, "OTEL_IMAGE_ID", name),
    }


def load_instances(environ=None):
    """Build the ordered host inventory from an environment mapping."""
    environ = os.environ if environ is None else environ
    instances = []
    i = 1
    while True:
        name = environ.get(f"INSTANCE_{i}_NAME")
        ip = environ.get(f"INSTANCE_{i}_IP")
        chat_id = environ.get(f"INSTANCE_{i}_CHAT_ID")
        key = environ.get(f"INSTANCE_{i}_KEY", "").strip()
        ssh_user = environ.get(f"INSTANCE_{i}_SSH_USER", "").strip()

        if not name or not ip or not chat_id:
            break

        is_local = ip.strip() in ("localhost", "127.0.0.1")

        if not is_local:
            if not key:
                raise ValueError(f"❌ INSTANCE_{i}_KEY is required for remote instance '{name}'")
            if not ssh_user:
                raise ValueError(f"❌ INSTANCE_{i}_SSH_USER is required for remote instance '{name}'")
            if not os.path.isfile(key):
                raise ValueError(f"❌ Key file not found for '{name}': {key}")

        configured_os = environ.get(f"INSTANCE_{i}_OS")
        if configured_os is None:
            is_windows = ssh_user.lower() in ("administrator", "admin") if ssh_user else False
        else:
            normalized_os = configured_os.strip().lower()
            if normalized_os not in ("linux", "windows"):
                raise ValueError(
                    f"❌ Invalid INSTANCE_{i}_OS for instance '{name}': expected 'linux' or 'windows'"
                )
            is_windows = normalized_os == "windows"

        primary_path = "C:\\" if is_windows else "/"
        configured_paths = environ.get(f"INSTANCE_{i}_DISK_PATHS")
        disk_paths = [primary_path]
        seen_paths = {primary_path.casefold() if is_windows else primary_path}
        if configured_paths is not None:
            extra_paths = [path.strip() for path in configured_paths.split(";")]
            if any(not path for path in extra_paths):
                raise ValueError(
                    f"❌ Invalid INSTANCE_{i}_DISK_PATHS for instance '{name}': entries must not be empty"
                )
            for path in extra_paths:
                path_key = path.casefold() if is_windows else path
                if path_key not in seen_paths:
                    disk_paths.append(path)
                    seen_paths.add(path_key)

        instances.append({
            "name":       name.strip(),
            "ip":         ip.strip(),
            "chat_id":    chat_id.strip(),
            "key":        key if not is_local else None,
            "ssh_user":   ssh_user if not is_local else None,
            "is_local":   is_local,
            "is_windows": is_windows,
            "disk_paths": disk_paths,
            "security":   _security_config(environ, i, name.strip()),
            "index":      i
        })
        i += 1

    if not instances:
        raise ValueError("❌ No instances configured in .env file")
    return instances

# ─── TELEGRAM ─────────────────────────────────────────────

def send_message(chat_id, text, context=None):
    """
    Deliver one Telegram message.

    Returns True when Telegram accepted the message and False when the
    transport rejected it, so a caller sending several chunks can see a
    rejection instead of losing it. A rejected chunk never aborts the chunks
    that follow it.
    """
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    label = f" ({context})" if context else ""
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return True
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] No internet connection{label}.")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Telegram rejected the message{label}: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error{label}: {e}")
        return False

# ─── KEY LOADER ───────────────────────────────────────────

def load_private_key(key_path):
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

# What one SSH command produced, including the evidence ssh_run has always thrown
# away. A namedtuple (not a bare tuple) so a caller can read `result.stderr` by
# name, and it is duck-typed on that attribute by the security collector, so a
# plain str-or-None runner stays equally acceptable there.
SSHResult = namedtuple("SSHResult", ("stdout", "stderr", "exit_status", "unreachable"))


def _ssh_run_once(inst, cmd):
    """
    Run one SSH command and return its SSHResult. One connection, one round trip.

    This is the whole of what both runners do; ssh_run and ssh_run_detailed are
    two views of it, so neither can acquire a second connection or a second
    command, and a change to one cannot drift from the other.
    """
    key    = load_private_key(inst["key"])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(inst["ip"], username=inst["ssh_user"], pkey=key, timeout=10)
    try:
        _, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode().strip()
        error  = stderr.read().decode().strip()
        try:
            # The channel's own status, when the transport still has it. Absent
            # here only if the connection dropped before it arrived.
            status = stdout.channel.recv_exit_status()
        except Exception:
            status = None
    finally:
        client.close()
    return SSHResult(output, error, status, False)


def ssh_run_detailed(inst, cmd):
    """
    ssh_run's result plus the stderr and SSH exit status it discards.

    Additive and backwards compatible: the connection, the single round trip and
    the failure-to-None contract are exactly ssh_run's, so no existing caller's
    behaviour or traffic changes. It exists because a remote interpreter that
    dies before printing its payload leaves stdout empty and stdout cannot say
    why — the stderr and exit status are what make that failure diagnosable.
    """
    try:
        result = _ssh_run_once(inst, cmd)
    except paramiko.AuthenticationException:
        print(f"[ERROR] Auth failed for {inst['ip']} (user: {inst['ssh_user']})")
        return SSHResult(None, "", None, True)
    except paramiko.SSHException as e:
        print(f"[ERROR] SSH error for {inst['ip']}: {e}")
        return SSHResult(None, "", None, True)
    except FileNotFoundError:
        print(f"[ERROR] Key file not found: {inst['key']}")
        return SSHResult(None, "", None, True)
    except ValueError as e:
        print(f"[ERROR] {e}")
        return SSHResult(None, "", None, True)
    except Exception as e:
        print(f"[ERROR] Could not connect to {inst['ip']}: {e}")
        return SSHResult(None, "", None, True)
    if result.stderr:
        print(f"[WARN] stderr from {inst['ip']}: {result.stderr}")
    return result


def ssh_run(inst, cmd):
    """stdout on success, None on any failure. One connection, one round trip."""
    return ssh_run_detailed(inst, cmd).stdout


# ─── METRICS ──────────────────────────────────────────────

def _disk_targets(is_windows, disk_paths=None):
    primary_path = "C:\\" if is_windows else "/"
    targets = [primary_path]
    seen = {primary_path.casefold() if is_windows else primary_path}
    for path in disk_paths or []:
        path = str(path).strip()
        if not path:
            continue
        path_key = path.casefold() if is_windows else path
        if path_key not in seen:
            targets.append(path)
            seen.add(path_key)
    return targets


def _measure_local_disks(disk_paths):
    results = []
    for path in disk_paths:
        try:
            usage = psutil.disk_usage(path)
            results.append({
                "path": path,
                "used": usage.percent,
                "total": round(usage.total / (1024**3), 1),
                "free": round(usage.free / (1024**3), 1),
                "error": None,
            })
        except Exception as exc:
            results.append({
                "path": path,
                "used": None,
                "total": None,
                "free": None,
                "error": str(exc),
            })
    return results


def get_local_metrics(disk_paths=None, is_windows=False):
    with _metrics_lock:
        per_core = psutil.cpu_percent(interval=3, percpu=True)
        cpu      = round(sum(per_core) / len(per_core), 1)
        memory   = psutil.virtual_memory()
        net      = psutil.net_io_counters()
        boot     = datetime.fromtimestamp(psutil.boot_time(), PH_TZ)
        uptime   = now_ph() - boot
        disks    = _measure_local_disks(_disk_targets(is_windows, disk_paths))
        primary  = disks[0]

        return {
            "cpu":        cpu,
            "mem_used":   memory.percent,
            "mem_total":  round(memory.total / (1024**3), 1),
            "disk_used":  primary["used"],
            "disk_total": primary["total"],
            "disk_error": primary["error"],
            "disks":      disks,
            "net_sent":   round(net.bytes_sent / (1024**2), 1),
            "net_recv":   round(net.bytes_recv / (1024**2), 1),
            "uptime":     str(uptime).split('.')[0],
            "per_core":   per_core,
        }


def build_metrics_cmd(is_windows, disk_paths=None):
    python = "python" if is_windows else "python3"
    targets = _disk_targets(is_windows, disk_paths)
    targets_b64 = base64.b64encode(json.dumps(targets).encode("utf-8")).decode("ascii")
    script = f'''import base64, datetime, json, psutil
targets = json.loads(base64.b64decode("{targets_b64}").decode("utf-8"))
per_core = psutil.cpu_percent(interval=3, percpu=True)
cpu = round(sum(per_core) / len(per_core), 1)
mem = psutil.virtual_memory()
net = psutil.net_io_counters()
tz = datetime.timezone(datetime.timedelta(hours=8))
boot = datetime.datetime.fromtimestamp(psutil.boot_time(), tz)
uptime = str(datetime.datetime.now(tz) - boot).split(".")[0]
disks = []
for path in targets:
    try:
        usage = psutil.disk_usage(path)
        disks.append({{"path": path, "used": usage.percent,
                      "total": round(usage.total / (1024**3), 1),
                      "free": round(usage.free / (1024**3), 1), "error": None}})
    except Exception as exc:
        disks.append({{"path": path, "used": None, "total": None,
                      "free": None, "error": str(exc)}})
primary = disks[0]
print(json.dumps({{"cpu": cpu, "mem_used": mem.percent,
    "mem_total": round(mem.total / (1024**3), 1),
    "disk_used": primary["used"], "disk_total": primary["total"],
    "disk_error": primary["error"], "disks": disks,
    "net_sent": round(net.bytes_sent / (1024**2), 1),
    "net_recv": round(net.bytes_recv / (1024**2), 1),
    "uptime": uptime, "per_core": per_core}}))'''
    script_b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"{python} -c \"exec(__import__('base64').b64decode('{script_b64}'))\""


def build_processes_cmd(is_windows):
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
    cmd    = build_metrics_cmd(inst["is_windows"], inst.get("disk_paths"))
    output = ssh_run(inst, cmd)
    if output is None:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse metrics from {inst['ip']}: {e}")
        return None


def get_metrics(inst):
    if inst["is_local"]:
        return get_local_metrics(inst.get("disk_paths"), inst.get("is_windows", False))
    return get_remote_metrics(inst)


def _metrics_disks(metrics, inst=None):
    disks = metrics.get("disks")
    if disks is not None:
        return disks
    is_windows = bool(inst and inst.get("is_windows"))
    path = "C:\\" if is_windows else "/"
    used = metrics.get("disk_used")
    total = metrics.get("disk_total")
    free = round(total * (100 - used) / 100, 1) if used is not None and total is not None else None
    return [{
        "path": path,
        "used": used,
        "total": total,
        "free": free,
        "error": metrics.get("disk_error"),
    }]


def _format_disk_result(disk):
    path = str(disk.get("path", "unknown")).replace("`", "'")[:120]
    used = disk.get("used")
    total = disk.get("total")
    free = disk.get("free")
    error = str(disk.get("error") or "unavailable").replace("`", "'")[:140]
    if used is None or total is None or free is None:
        return f"• `{path}`: unavailable ({error})"
    return f"• `{path}`: `{used}%` used | `{free} GB` free of `{total} GB`"


def send_disk_message(chat_id, intro, metrics, disk_title="Disk paths", inst=None):
    """Send every path result while keeping each Telegram message below its limit."""
    lines = [_format_disk_result(disk) for disk in _metrics_disks(metrics, inst)]
    if not lines:
        lines = ["• No disk targets were returned."]
    prefix = f"{intro}\n\n💿 *{disk_title}:*\n"
    continuation = f"💿 *{disk_title} (continued):*\n"
    message = prefix
    for line in lines:
        addition = f"{line}\n"
        if len(message) + len(addition) > 3500 and message != prefix:
            send_message(chat_id, message.rstrip())
            message = continuation
        message += addition
    send_message(chat_id, message.rstrip())


def get_processes(inst):
    if inst["is_local"]:
        procs = sorted(
            psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']),
            key=lambda p: p.info['cpu_percent'],
            reverse=True
        )[:5]
        return [
            {"pid": p.info['pid'], "name": p.info['name'],
             "cpu": p.info['cpu_percent'], "mem": round(p.info['memory_percent'], 1)}
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

# ─── STANDARD COMMANDS ────────────────────────────────────

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
        "/nginx      — Nginx connection stats\n"
        "/services   — Status of critical services\n"
        "/zombie     — Check for zombie processes\n"
        "/logs       — Recent system logs\n"
        "/uptime     — Server uptime\n"
        "/alerts     — View current alert thresholds\n"
        "/history    — Last 5 logged metric entries\n"
        "/security   — 🔐 AI-powered security scan & analysis\n"
        "/help       — Show this help message"
    )
    send_message(chat_id, msg)


def cmd_status(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🖥 *{inst['name']} — Quick Status*\n"
        f"🕐 `{timestamp}`\n\n"
        f"CPU: `{m['cpu']}%` | RAM: `{m['mem_used']}%`"
    )
    send_disk_message(chat_id, msg, m, "Disk paths", inst)


def cmd_report(chat_id, inst):
    m = get_metrics(inst)
    if m is None:
        send_message(chat_id, f"❌ *{inst['name']}* is unreachable.")
        return
    timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"📊 *{inst['name']} — Full Report*\n"
        f"🕐 `{timestamp}`\n\n"
        f"🖥 *CPU:*    `{m['cpu']}%`\n"
        f"💾 *Memory:* `{m['mem_used']}%` of `{m['mem_total']} GB`\n"
        f"📤 *Sent:*   `{m['net_sent']} MB`\n"
        f"📥 *Recv:*   `{m['net_recv']} MB`\n"
        f"⏱ *Uptime:* `{m['uptime']}`"
    )
    send_disk_message(chat_id, msg, m, "Disk paths", inst)


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
    intro = f"💿 *{inst['name']} — Disk Details*"
    send_disk_message(chat_id, intro, m, "Disk paths", inst)


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
    msg = f"⏱ *{inst['name']} — Uptime*\n\n  Uptime: `{m['uptime']}`"
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
    cmd = "docker ps --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>&1"
    if inst["is_local"]:
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
            disk_used = row.get('disk_used')
            disk_text = f"{disk_used}%" if disk_used not in (None, "") else "Unavailable"
            lines.append(
                f"🕐 `{row['timestamp']}`\n"
                f"  CPU: `{row['cpu']}%` | RAM: `{row['mem_used']}%` | Primary disk: `{disk_text}`"
            )
        msg = f"📜 *{inst['name']} — Last 5 Entries (primary disk only)*\n\n" + "\n\n".join(lines)
        send_message(chat_id, msg)
    except Exception as e:
        send_message(chat_id, f"❌ Could not read log: {e}")


def get_nginx_stats(inst):
    cmd = "curl -sk https://127.0.0.1/nginx_status 2>&1 || echo 'stub_status not configured'"
    if inst["is_local"]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {e}"
    else:
        output = ssh_run(inst, cmd)
        return output if output else "SSH error"


def cmd_nginx(chat_id, inst):
    output = get_nginx_stats(inst)
    if "stub_status not configured" in output or "SSH error" in output or "Error:" in output:
        send_message(chat_id, f"⚠️ *{inst['name']} — Nginx Stats*\n\n`{output}`\n\n_Enable stub_status in nginx config_")
        return
    msg = f"🌐 *{inst['name']} — Nginx Stats*\n\n```\n{output}\n```"
    send_message(chat_id, msg)


def get_zombie_processes(inst):
    cmd = "ps aux | awk '$8==\"Z\" {print $2, $11}' | wc -l"
    if inst["is_local"]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception:
            return None
    else:
        return ssh_run(inst, cmd)


def cmd_zombie(chat_id, inst):
    count = get_zombie_processes(inst)
    if count is None:
        send_message(chat_id, f"❌ Could not check zombie processes for *{inst['name']}*.")
        return
    count = int(count.strip())
    if count == 0:
        msg = f"✅ *{inst['name']} — Zombie Processes*\n\n  No zombie processes found."
    else:
        msg = f"⚠️ *{inst['name']} — Zombie Processes*\n\n  Found: `{count}` zombie process(es)"
    send_message(chat_id, msg)


def get_service_status(inst, services):
    results = {}
    for svc in services:
        cmd = f"systemctl is-active {svc} 2>&1"
        if inst["is_local"]:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                results[svc] = result.stdout.strip()
            except Exception:
                results[svc] = "unknown"
        else:
            output = ssh_run(inst, cmd)
            results[svc] = output.strip() if output else "unknown"
    return results


def cmd_services(chat_id, inst):
    services = ["nginx", "docker", "ssh"]
    if not inst["is_local"]:
        services.append("sshd")
    statuses = get_service_status(inst, services)
    lines = []
    for svc, status in statuses.items():
        if status == "active":
            icon = "✅"
        elif status == "inactive":
            icon = "⚠️"
        else:
            icon = "❌"
        lines.append(f"{icon} `{svc}`: `{status}`")
    msg = f"⚙️ *{inst['name']} — Service Status*\n\n" + "\n".join(lines)
    send_message(chat_id, msg)


def get_recent_logs(inst, log_path="/var/log/syslog", lines=20):
    cmd = f"tail -n {lines} {log_path} 2>&1 || echo 'Log file not accessible'"
    if inst["is_local"]:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {e}"
    else:
        output = ssh_run(inst, cmd)
        return output if output else "SSH error"


def cmd_logs(chat_id, inst):
    log_path = "C:\\Windows\\System32\\winevt\\Logs\\System.evtx" if inst["is_windows"] else "/var/log/syslog"
    output = get_recent_logs(inst, log_path, 15)
    if len(output) > 3000:
        output = output[-3000:]
    msg = f"📋 *{inst['name']} — Recent Logs*\n\n```\n{output}\n```"
    send_message(chat_id, msg)


# ─── SECURITY COMMAND ─────────────────────────────────────

def _collect_security_findings(inst):
    """
    Scan one instance with its configured security identities.

    Three-way dispatch on the host type: a local host is read with psutil, a
    remote Windows host gets the Windows program, and every other remote host
    gets the Linux program. The Windows collector emits the same raw evidence, so
    the classification policy is the same on all three.
    """
    if inst["is_local"]:
        return collect_local(inst["name"], inst.get("security"))
    if inst.get("is_windows"):
        # The detailed runner, and only here: a Windows host that never ran the
        # command returns empty stdout, and stdout alone cannot say whether the
        # command line was too long, the interpreter was missing or the program
        # raised. Linux keeps the plain runner — that path is not being repaired.
        return collect_remote_windows(inst, ssh_run_detailed, inst.get("security"))
    return collect_remote_linux(inst, ssh_run, inst.get("security"))


def send_security_assessment(chat_id, inst, findings, timestamp):
    """Deliver the authoritative deterministic assessment for one scan."""
    from llm_analyzer import format_assessment

    rejected = _deliver_chunks(chat_id, inst, format_assessment(findings, timestamp),
                               "assessment")
    if rejected:
        print(f"[ERROR] {rejected} authoritative assessment chunk(s) were rejected by "
              f"Telegram for {inst['name']}; that part of the report was NOT delivered.")


def send_security_advisory(chat_id, inst, timestamp, llm_output=None, llm_error=None):
    """
    Deliver the AI commentary, clearly marked advisory, after the assessment.

    A failed, missing, or error-string response never removes or lowers the
    authoritative assessment that was already delivered.
    """
    if llm_error is not None:
        send_message(
            chat_id,
            f"❌ AI analysis unavailable for *{inst['name']}*: `{str(llm_error)[:200]}`\n"
            "The deterministic assessment above is complete and unaffected.",
        )
        return
    if llm_output is None:
        return
    from llm_analyzer import format_advisory

    rejected = _deliver_chunks(
        chat_id, inst, format_advisory(inst["name"], llm_output, timestamp), "advisory")
    if rejected:
        print(f"[ERROR] {rejected} advisory chunk(s) were rejected by Telegram for "
              f"{inst['name']}; the authoritative assessment above is unaffected.")


def _deliver_chunks(chat_id, inst, chunks, label):
    """Send every chunk, count the rejections, and never stop on one failure."""
    rejected = 0
    for index, chunk in enumerate(chunks, start=1):
        if not send_message(chat_id, chunk, context=f"{label} chunk {index}"):
            rejected += 1
    return rejected


def _call_security_model(findings):
    """Return (llm_output, llm_error) without ever raising."""
    from llm_analyzer import analyze_with_bedrock

    try:
        llm_output = asyncio.run(analyze_with_bedrock(findings))
    except Exception as e:
        return None, e
    if isinstance(llm_output, str) and llm_output.startswith("❌ Bedrock analysis failed"):
        return None, llm_output
    return llm_output, None


# ─── ON-DEMAND /security GUARD ────────────────────────────
# /security runs a full scan plus a Bedrock call, and the poll loop runs in a
# daemon thread while the nightly job runs on the main thread, so two /security
# requests really can overlap. At most one on-demand scan per (chat, instance) is
# allowed in flight; a second one is refused immediately instead of doubling the
# load. The nightly job is deliberately OUTSIDE this guard.
_security_scans_in_flight = set()
_security_scans_lock = threading.Lock()


def _security_scan_key(chat_id, inst):
    """
    Identity of one scan target: the chat plus a STABLE instance identity.

    The instance index is preferred over the display name, so two hosts that share
    a display name can never silently share a guard slot.
    """
    identity = inst.get("index") if inst.get("index") is not None else inst.get("name")
    return (str(chat_id), identity)


def _claim_security_scan(key):
    """Claim the slot without blocking; the poll loop must never stall on it."""
    with _security_scans_lock:
        if key in _security_scans_in_flight:
            return False
        _security_scans_in_flight.add(key)
        return True


def _release_security_scan(key):
    with _security_scans_lock:
        _security_scans_in_flight.discard(key)


def cmd_security(chat_id, inst):
    """
    /security — On-demand security scan for this instance.
    Gathers structured evidence via psutil/SSH, sends the authoritative
    deterministic assessment, then the advisory Bedrock commentary.

    The guard is released in a finally covering every exit path, so a failed
    collector, formatter, model call or send can never leave the instance locked.
    No lock is held while a scan, network call or model call runs.
    """
    key = _security_scan_key(chat_id, inst)
    if not _claim_security_scan(key):
        send_message(
            chat_id,
            f"⚠️ *{inst['name']}* — scan already running; this request was not started.",
        )
        return
    try:
        send_message(
            chat_id, f"🔍 *{inst['name']}* — Running security scan, please wait ~30s...")

        # 1. Collect findings
        findings = _collect_security_findings(inst)
        timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")

        # 2. Authoritative assessment first, so it survives any model failure.
        send_security_assessment(chat_id, inst, findings, timestamp)

        # 3. Advisory AI commentary
        llm_output, llm_error = _call_security_model(findings)
        send_security_advisory(chat_id, inst, timestamp, llm_output, llm_error)
    finally:
        _release_security_scan(key)


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
    "/nginx":     cmd_nginx,
    "/zombie":    cmd_zombie,
    "/services":  cmd_services,
    "/logs":      cmd_logs,
    "/security":  cmd_security,  # ← NEW
}


# ─── DURABLE TELEGRAM UPDATE OFFSET ───────────────────────
# Telegram replays any update that is still inside its retention window, so an
# offset that only ever lived in memory re-executes commands after a restart. The
# offset is persisted durably BEFORE the handler runs, so a crash mid-command can
# only ever skip a command, never run one twice.

_STATE_FILE_NAME = "telegram_offset.json"


def _state_dir():
    """
    Resolve the state directory: explicit override, XDG, then the default.

    The state directory is never inside the repository: a source checkout is not
    a runtime data directory and its contents are tracked by version control.
    """
    override = os.getenv("MONITOR_BOT_STATE_DIR")
    if override:
        return override
    xdg = os.getenv("XDG_STATE_HOME")
    if xdg:
        return os.path.join(xdg, "monitor_bot")
    return os.path.join(os.path.expanduser("~"), ".local", "state", "monitor_bot")


def _offset_path():
    return os.path.join(_state_dir(), _STATE_FILE_NAME)


def load_update_offset():
    """
    Return the persisted offset, or None when there is nothing usable yet.

    A Telegram update_id is always a positive integer, so a non-positive value
    (a hand-edited, truncated or corrupted file) is treated as absent rather than
    as an offset: getUpdates treats offset <= 0 as "from the beginning" or
    rejects it, which would either replay the whole retention window or wedge the
    poll loop forever. Nothing is repaired or rewritten here.
    """
    try:
        with open(_offset_path(), "r") as handle:
            offset = int(str(handle.read()).strip())
    except (OSError, ValueError, TypeError):
        # A missing, empty or corrupt file is simply "no offset yet": it never
        # blocks startup and never aborts the poll loop.
        return None
    return offset if offset > 0 else None


def save_update_offset(value):
    """
    Persist the offset atomically with restrictive permissions.

    A same-directory temp file is flushed and fsynced, then renamed over the
    target, so a reader never sees a half-written offset. Every failure is
    logged and swallowed: a command must still run when the state directory is
    read-only, unwritable or full.
    """
    path = _offset_path()
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        handle_fd, temporary = tempfile.mkstemp(
            dir=directory, prefix=_STATE_FILE_NAME + ".", suffix=".tmp")
        try:
            os.fchmod(handle_fd, 0o600)
            with os.fdopen(handle_fd, "w") as handle:
                handle.write(str(int(value)))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError as e:
        print(f"[WARN] Could not persist the Telegram update offset: {e}")


def _handle_update_batch(result, offset, progress=None):
    """
    Dispatch one getUpdates batch and return the next offset.

    The offset is written for each accepted update BEFORE its handler runs, so
    the durable state already covers an in-flight command. An update at or below
    the current offset is a replay and is neither executed nor re-acknowledged.

    `progress` is an optional mutable holder the CALLER owns. The helper writes
    the advanced offset into it as soon as it is durable, so a handler that
    raises cannot leave the caller holding a stale offset: the caller reads the
    holder in its own `except`, and the next poll cannot replay an update whose
    handler already ran. The offset is only ever raised, never lowered, so no
    handler outcome can rewind it.
    """
    if progress is None:
        progress = []
    for update in result or []:
        update_id = update["update_id"]
        if offset is not None and update_id < offset:
            continue
        offset = update_id + 1
        save_update_offset(offset)
        progress.append(offset)

        message = update.get("message", {})
        chat_id = str(message.get("chat", {}).get("id", ""))
        text    = message.get("text", "").strip().lower()

        if not chat_id or not text:
            continue

        inst = CHAT_TO_INSTANCE.get(chat_id)
        if inst is None:
            print(f"[IGNORED] Unknown chat_id: {chat_id}")
            continue

        base_cmd = text.split("@")[0]

        if base_cmd in COMMANDS:
            print(f"[CMD] update_id={update_id} {base_cmd} instance={inst['name']} "
                  f"(chat {chat_id})")
            COMMANDS[base_cmd](chat_id, inst)
        else:
            send_message(chat_id, "❓ Unknown command. Type /help for the list.")
    return offset


def handle_commands():
    offset = load_update_offset()
    print("[BOT] Listening for commands... (offset=%s)" % offset)
    # The holder survives a raising handler: the offset it carries is the highest
    # already-persisted value, so a poll after the failure cannot replay an update
    # whose handler already ran.
    progress = []
    while True:
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            params = {"timeout": 30, "offset": offset}
            response = requests.get(url, params=params, timeout=35)
            data = response.json()

            offset = _handle_update_batch(data.get("result", []), offset, progress)

        except Exception as e:
            if progress:
                # Never rewind: the highest offset already persisted wins.
                offset = max(x for x in (offset, progress[-1]) if x is not None)
            print(f"[ERROR] Polling error: {e}")
            time.sleep(5)


# ─── SCHEDULED TASKS ──────────────────────────────────────

def send_scheduled_reports():
    timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")
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
            f"📤 *Sent:*   `{m['net_sent']} MB`\n"
            f"📥 *Recv:*   `{m['net_recv']} MB`\n"
            f"⏱ *Uptime:* `{m['uptime']}`"
        )
        send_disk_message(inst['chat_id'], msg, m, "Disk paths", inst)
    print(f"[{timestamp}] Scheduled reports sent.")


def check_all_alerts():
    threading.Thread(target=_check_all_alerts_worker, daemon=True).start()

def _check_all_alerts_worker():
    timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")
    for inst in INSTANCES:
        m1 = get_metrics(inst)
        if m1 is None:
            send_message(inst['chat_id'], f"🔴 *{inst['name']}* is *unreachable!*\n🕐 `{timestamp}`")
            continue

        first_disks = {disk["path"]: disk for disk in _metrics_disks(m1, inst)}
        disk_needs_confirm = any(
            disk.get("used") is None or disk.get("used") >= DISK_ALERT_THRESHOLD
            for disk in first_disks.values()
        )
        needs_confirm = (
            m1['cpu'] >= CPU_ALERT_THRESHOLD or
            m1['mem_used'] >= MEMORY_ALERT_THRESHOLD or
            disk_needs_confirm
        )

        if not needs_confirm:
            continue

        print(f"[{timestamp}] Possible alert on {inst['name']}, confirming in 15s...")
        time.sleep(15)

        m2 = get_metrics(inst)
        if m2 is None:
            send_message(inst['chat_id'], f"🔴 *{inst['name']}* is *unreachable!*\n🕐 `{timestamp}`")
            continue

        alerts = []
        cpu_avg = round((m1['cpu'] + m2['cpu']) / 2, 1)
        if m1['cpu'] >= CPU_ALERT_THRESHOLD and m2['cpu'] >= CPU_ALERT_THRESHOLD:
            alerts.append(f"🔴 HIGH CPU: `{cpu_avg}%` (sustained over 15s)")

        mem_avg = round((m1['mem_used'] + m2['mem_used']) / 2, 1)
        if m1['mem_used'] >= MEMORY_ALERT_THRESHOLD and m2['mem_used'] >= MEMORY_ALERT_THRESHOLD:
            alerts.append(f"🔴 HIGH MEMORY: `{mem_avg}%` (sustained over 15s)")

        second_disks = {disk["path"]: disk for disk in _metrics_disks(m2, inst)}
        all_paths = list(first_disks)
        all_paths.extend(path for path in second_disks if path not in first_disks)
        for path in all_paths:
            first = first_disks.get(path)
            second = second_disks.get(path)
            first_failed = first is None or first.get("used") is None or first.get("error")
            second_failed = second is None or second.get("used") is None or second.get("error")
            safe_path = str(path).replace("`", "'")[:120]
            if first_failed or second_failed:
                if first_failed and second_failed:
                    state = "unavailable in both samples; disk check failed"
                else:
                    sample = "first" if first_failed else "second"
                    state = f"unavailable in the {sample} sample; disk check incomplete"
                failed_result = first if first_failed else second
                error = (failed_result or {}).get("error") or "target result missing"
                error = str(error).replace("`", "'")[:120]
                alerts.append(f"⚠ DISK CHECK: `{safe_path}` {state} (`{error}`)")
                continue
            if first["used"] >= DISK_ALERT_THRESHOLD and second["used"] >= DISK_ALERT_THRESHOLD:
                disk_avg = round((first["used"] + second["used"]) / 2, 1)
                alerts.append(
                    f"🔴 HIGH DISK: `{safe_path}` at `{disk_avg}%` (sustained over 15s)"
                )

        if alerts:
            msg = (
                f"⚠ *ALERT — {inst['name']}*\n"
                f"🕐 `{timestamp}`\n\n"
            ) + "\n".join(alerts)
            send_message(inst['chat_id'], msg)
            print(f"[{timestamp}] Alert sent to {inst['name']} group.")
        else:
            print(f"[{timestamp}] {inst['name']} spike was transient, no alert sent.")


def log_all_metrics():
    log_file   = os.path.join(os.path.dirname(__file__), "metrics_log.csv")
    timestamp  = now_ph().strftime("%Y-%m-%d %H:%M:%S")
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


# ─── NIGHTLY SECURITY JOB (11 PM PHT) ────────────────────

def run_nightly_security_analysis():
    """
    Runs at 23:00 PHT every night.
    Full security scan plus the authoritative deterministic report for every
    instance, followed by advisory Bedrock commentary.
    """
    timestamp = now_ph().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] Starting nightly security analysis for all instances...")

    for inst in INSTANCES:
        try:
            send_message(
                inst['chat_id'],
                f"🌙 *Nightly Security Intelligence Report*\n"
                f"Instance: *{inst['name']}*\n"
                f"🕐 `{timestamp}`\n\n"
                f"Scanning... this may take up to 60 seconds."
            )

            # Collect
            findings = _collect_security_findings(inst)

            # Authoritative assessment is sent before, and independently of, the model.
            send_security_assessment(inst['chat_id'], inst, findings, timestamp)

            # Advisory analysis
            llm_output, llm_error = _call_security_model(findings)
            send_security_advisory(
                inst['chat_id'], inst, timestamp, llm_output, llm_error)

            print(f"[{timestamp}] Nightly security report sent for {inst['name']}.")

        except Exception as e:
            print(f"[ERROR] Nightly security analysis failed for {inst['name']}: {e}")
            send_message(
                inst['chat_id'],
                f"❌ Nightly security analysis failed for *{inst['name']}*: `{e}`"
            )


def main():
    global BOT_TOKEN, CPU_ALERT_THRESHOLD, MEMORY_ALERT_THRESHOLD
    global DISK_ALERT_THRESHOLD, REPORT_INTERVAL, INSTANCES, CHAT_TO_INSTANCE

    load_dotenv()
    BOT_TOKEN = os.getenv("BOT_TOKEN")
    if not BOT_TOKEN:
        raise ValueError("❌ BOT_TOKEN must be set in .env file")
    CPU_ALERT_THRESHOLD = int(os.getenv("CPU_ALERT_THRESHOLD", 80))
    MEMORY_ALERT_THRESHOLD = int(os.getenv("MEMORY_ALERT_THRESHOLD", 85))
    DISK_ALERT_THRESHOLD = int(os.getenv("DISK_ALERT_THRESHOLD", 90))
    REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", 30))
    INSTANCES = load_instances()
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

    print(f"[CONFIG] Restored Telegram update offset: {load_update_offset()} "
          f"(state file: {_offset_path()})")

    # schedule.every(REPORT_INTERVAL).minutes.do(send_scheduled_reports)
    schedule.every(1).minutes.do(check_all_alerts)
    schedule.every(5).minutes.do(log_all_metrics)
    schedule.every().day.at("15:00").do(run_nightly_security_analysis)   # ← 11 PM PHT

    thread = threading.Thread(target=handle_commands, daemon=True)
    thread.start()

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
            f"🔐 Nightly security scan at `23:00 PHT`\n\n"
            f"Type /help for available commands."
        )

    log_all_metrics()

    print("Monitor running... Press Ctrl+C to stop.")
    while True:
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
