"""
security_scanner.py
───────────────────
Collects security-relevant signals from each EC2 instance using psutil (local)
or SSH (remote). Returns a structured dict of findings per instance.

Called by the scheduled 11 PM job and by the /security command.
"""

import base64
import gzip
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
from datetime import datetime

import psutil

try:
    # Only the zombie-noise allowlist is still consulted directly. The other
    # legacy lists (SAFE_PORTS, SAFE_EXTERNAL_IPS, ...) no longer preclassify or
    # suppress network evidence; see _classify_observation.
    from security_whitelist import SAFE_ZOMBIE_PATTERNS
except ImportError:
    SAFE_ZOMBIE_PATTERNS = {"chrome", "chromium", "node", "python"}

# ─── KNOWN-SAFE BASELINES ─────────────────────────────────
# Extend these lists to match your normal environment.
KNOWN_SERVICES = {
    "nginx", "docker", "sshd", "ssh", "cron", "rsyslog",
    "systemd", "systemd-journald", "systemd-logind", "systemd-networkd",
    "systemd-resolved", "systemd-udevd", "dbus", "atd", "snapd",
    "amazon-ssm-agent", "amazon-cloudwatch-agent", "ec2-instance-connect",
    "unattended-upgrades", "apt-daily", "apt-daily-upgrade",
}

SUSPICIOUS_PROC_NAMES = {
    "nc", "netcat", "ncat", "nmap", "masscan", "socat",
    "msfconsole", "msfvenom", "hydra", "sqlmap", "john", "hashcat",
    "mimikatz", "xmrig", "cgminer", "minerd", "ethminer",  # cryptominers
    "kworker",  # often impersonated
}

SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"]

SENSITIVE_DIRS = ["/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]

CPU_SPIKE_THRESHOLD = 50.0   # % — flag any single process above this
MEM_SPIKE_THRESHOLD = 30.0   # % — flag any single process above this

_lock = threading.Lock()


# ─── LOCAL COLLECTION (psutil) ────────────────────────────

def collect_local(inst_name: str, security_config: dict | None = None) -> dict:
    """Gather security signals from the local machine using psutil + subprocess."""
    findings = _base_findings(inst_name, "local")

    with _lock:
        _scan_processes_local(findings)
        _scan_network_local(findings, security_config or {})
        _scan_users_local(findings)
        _scan_files_local(findings)
        _scan_services_local(findings)
        _scan_cron_local(findings)
        _scan_auth_log_local(findings)

    return findings


def _scan_processes_local(f: dict):
    high_cpu = []
    high_mem = []
    suspicious_name = []
    suspicious_path = []
    zombies = []

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "cmdline", "username", "cpu_percent",
         "memory_percent", "status", "create_time"]
    ):
        try:
            info = proc.info
            name   = info.get("name") or ""
            exe    = info.get("exe") or ""
            cpu    = info.get("cpu_percent") or 0.0
            mem    = info.get("memory_percent") or 0.0
            status = info.get("status") or ""
            user   = info.get("username") or ""
            pid    = info.get("pid")

            # Zombie check - filter out known safe zombie processes
            if status == psutil.STATUS_ZOMBIE:
                # Check if this is from a known safe application
                is_safe_zombie = any(pattern in name.lower() for pattern in SAFE_ZOMBIE_PATTERNS)
                if not is_safe_zombie:
                    zombies.append({"pid": pid, "name": name})

            # High resource usage
            if cpu >= CPU_SPIKE_THRESHOLD:
                high_cpu.append({"pid": pid, "name": name, "cpu": round(cpu, 1), "user": user, "exe": exe})
            if mem >= MEM_SPIKE_THRESHOLD:
                high_mem.append({"pid": pid, "name": name, "mem": round(mem, 1), "user": user, "exe": exe})

            # Suspicious name match
            if name.lower() in SUSPICIOUS_PROC_NAMES:
                suspicious_name.append({"pid": pid, "name": name, "exe": exe, "user": user})

            # Running from suspicious paths
            if exe and any(exe.startswith(p) for p in SUSPICIOUS_PATHS):
                suspicious_path.append({"pid": pid, "name": name, "exe": exe, "user": user})

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    f["processes"]["high_cpu"]       = high_cpu
    f["processes"]["high_mem"]       = high_mem
    f["processes"]["suspicious_name"] = suspicious_name
    f["processes"]["suspicious_path"] = suspicious_path
    f["processes"]["zombies"]         = zombies


def _scan_network_local(f: dict, security_config: dict | None = None):
    network = f["network"]
    raw = []
    gaps = []
    process_map, process_gaps = _local_process_map()
    gaps.extend(process_gaps)
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        gaps.append(f"Socket enumeration failed: {type(exc).__name__}: {exc}")
        _finalize_network(f, raw, [], "unavailable", gaps, security_config or {}, "partial")
        return

    for conn in connections:
        try:
            local = _address_parts(conn.laddr)
            remote = _address_parts(conn.raddr)
            conn_type = getattr(conn, "type", None)
            protocol = "tcp" if conn_type == socket.SOCK_STREAM else (
                "udp" if conn_type == socket.SOCK_DGRAM else "unknown"
            )
            state = str(getattr(conn, "status", "") or "UNKNOWN")
            is_listener = state == "LISTEN" or (
                protocol == "udp" and bool(local["ip"])
                and remote["ip"] is None
            )
            pid = getattr(conn, "pid", None)
            owner = process_map.get(pid, _unknown_owner(pid))
            raw.append({
                "protocol": protocol,
                "local_ip": local["ip"],
                "local_port": local["port"],
                "remote_ip": remote["ip"],
                "remote_port": remote["port"],
                "state": state,
                "is_listener": is_listener,
                "pid": pid,
                "owner": owner,
            })
        except Exception as exc:
            gaps.append(f"Socket record unavailable: {type(exc).__name__}: {exc}")

    docker_containers = []
    docker_status = "not_required"
    if any(item.get("local_port") == 13133
           or _docker_owner_verified(item.get("owner") or {}) for item in raw):
        docker_containers, docker_status, docker_error = _docker_snapshot()
        if docker_error:
            gaps.append(docker_error)
    scan_status = "partial" if gaps else "complete"
    _finalize_network(
        f, raw, docker_containers, docker_status, gaps, security_config or {}, scan_status
    )


def _local_process_map():
    processes = {}
    gaps = []
    try:
        iterator = psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username"]
        )
        for proc in iterator:
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue
                processes[pid] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "unknown",
                    "exe": info.get("exe") or "unknown",
                    "cmdline": _sanitize_cmdline(info.get("cmdline")),
                    "user": info.get("username") or "unknown",
                    "parent_exe": "unknown",
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                gaps.append("Some process identity fields were inaccessible")
            except Exception as exc:
                gaps.append(f"Process identity lookup failed: {type(exc).__name__}")
    except Exception as exc:
        gaps.append(f"Process enumeration failed: {type(exc).__name__}: {exc}")
    for owner in processes.values():
        parent = processes.get(owner.get("ppid"))
        if parent:
            owner["parent_exe"] = parent.get("exe") or "unknown"
    return processes, list(dict.fromkeys(gaps))


def _docker_snapshot():
    """Read running-container publication metadata without invoking a shell."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--no-trunc", "--quiet"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception as exc:
        return [], "unavailable", f"Docker identity lookup failed: {type(exc).__name__}: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "nonzero exit").strip()[:240]
        return [], "error", f"Docker identity lookup failed: {detail}"

    containers = []
    for container_id in result.stdout.splitlines():
        container_id = container_id.strip()
        if not container_id:
            continue
        try:
            inspected = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True, text=True, timeout=8,
            )
        except Exception as exc:
            return containers, "partial", f"Docker inspect failed: {type(exc).__name__}: {exc}"
        if inspected.returncode != 0:
            detail = (inspected.stderr or inspected.stdout or "nonzero exit").strip()[:240]
            return containers, "partial", f"Docker inspect failed: {detail}"
        try:
            values = json.loads(inspected.stdout)
            if not isinstance(values, list) or len(values) != 1:
                raise ValueError("inspect did not return one container")
            item = values[0]
            containers.append({
                "id": item.get("Id"),
                "name": str(item.get("Name", "")).lstrip("/"),
                "image": item.get("Config", {}).get("Image"),
                "image_id": item.get("Image"),
                "running": item.get("State", {}).get("Running") is True,
                "ports": item.get("NetworkSettings", {}).get("Ports") or {},
            })
        except Exception as exc:
            return containers, "partial", f"Docker inspect response invalid: {type(exc).__name__}"
    return containers, "available", None


def _address_parts(address):
    if not address:
        return {"ip": None, "port": None}
    if isinstance(address, (tuple, list)):
        return {
            "ip": str(address[0]) if address else None,
            "port": int(address[1]) if len(address) > 1 and address[1] is not None else None,
        }
    return {
        "ip": getattr(address, "ip", None),
        "port": getattr(address, "port", None),
    }


def _sanitize_cmdline(cmdline):
    if not isinstance(cmdline, (list, tuple)):
        return []
    safe = []
    redact_next = False
    for raw_arg in cmdline:
        arg = str(raw_arg)
        if redact_next:
            safe.append("[REDACTED]")
            redact_next = False
            continue
        key, separator, value = arg.partition("=")
        normalized = key.lstrip("-").lower().replace("_", "-")
        if normalized in {"password", "passwd", "token", "secret", "api-key", "access-key", "credential"}:
            if separator:
                safe.append(f"{key}=[REDACTED]")
            else:
                safe.append(arg)
                redact_next = True
        elif separator and any(word in normalized for word in ("password", "token", "secret", "credential", "api-key")):
            safe.append(f"{key}=[REDACTED]")
        else:
            safe.append(arg)
    return safe


def _scan_users_local(f: dict):
    users = []
    for u in psutil.users():
        users.append({
            "name":     u.name,
            "terminal": u.terminal,
            "host":     u.host,
            "started":  datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S"),
        })
    f["users"]["logged_in"] = users


def _scan_files_local(f: dict):
    """Check recently modified files in sensitive system directories (last 1 hour)."""
    modified = _run_local(
        "find /etc /bin /sbin /usr/bin /usr/sbin -newer /tmp -type f "
        "-printf '%T+ %p\n' 2>/dev/null | sort -r | head -20"
    )
    f["files"]["recently_modified_system"] = modified.splitlines() if modified else []


def _scan_services_local(f: dict):
    stopped = _run_local(
        "systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | head -20"
    )
    new_units = _run_local(
        "find /etc/systemd /usr/lib/systemd -name '*.service' -newer /tmp "
        "-type f 2>/dev/null | head -20"
    )
    f["services"]["failed"]    = stopped.splitlines() if stopped else []
    f["services"]["new_units"] = new_units.splitlines() if new_units else []


def _scan_cron_local(f: dict):
    cron_output = _run_local(
        "crontab -l 2>/dev/null; "
        "ls /etc/cron.d/ 2>/dev/null; "
        "ls /var/spool/cron/crontabs/ 2>/dev/null"
    )
    f["cron"]["entries"] = cron_output.splitlines() if cron_output else []


def _scan_auth_log_local(f: dict):
    """
    Pull the last 50 auth log lines unfiltered.

    Collection never narrows the evidence: PAM authentication failures, pre-auth
    connection and disconnection events from a remote source, and account or
    credential changes all reach `auth_log`, so `has_any_findings`,
    corroboration, the prompt and the report can all see them. Benign noise is
    reduced only at presentation time.
    """
    auth = _run_local(
        "tail -50 /var/log/auth.log 2>/dev/null"
    )
    f["auth_log"] = auth.splitlines() if auth else []


def _run_local(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


# ─── REMOTE COLLECTION (SSH) ──────────────────────────────

# Shared python3 program that runs on the remote Linux host. It emits the same
# raw socket/process/container evidence the local collector produces, so the
# classification policy below is shared by both paths. A missing psutil or any
# unexpected failure leaves the process with a nonzero exit status: a failed
# remote scan is never reported as a clean scan.
_REMOTE_SCRIPT = r'''import json, os, socket, subprocess
from datetime import datetime
import psutil

SUSP_NAMES = {'nc','netcat','ncat','nmap','masscan','socat','xmrig','cgminer','minerd','ethminer','msfconsole','hydra','sqlmap','john','hashcat','mimikatz'}
SUSP_PATHS = ['/tmp/','/dev/shm/','/var/tmp/','/run/shm/']
SAFE_ZOMBIES = {'chrome','chromium','node','python'}

findings = {
    'processes': {'high_cpu': [], 'high_mem': [], 'suspicious_name': [], 'suspicious_path': [], 'zombies': []},
    'network': {'raw_observations': [], 'docker_containers': [], 'docker_status': 'not_required',
                'scan_status': 'complete', 'scan_gaps': []},
    'users': {'logged_in': []},
    'files': {'recently_modified_system': []},
    'services': {'failed': [], 'new_units': []},
    'cron': {'entries': []},
    'auth_log': [],
}

def _base_name(path):
    return os.path.basename(str(path or '').rstrip('/')) if path else ''

def _docker_proxy(owner):
    owner = owner or {}
    return (_base_name(owner.get('name')) == 'docker-proxy'
            or _base_name(owner.get('exe')) == 'docker-proxy'
            or _base_name(owner.get('parent_exe')) in ('dockerd', 'docker'))

def run(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ''

process_map = {}
try:
    for process in psutil.process_iter(['pid','ppid','name','exe','cmdline','username','cpu_percent','memory_percent','status']):
        try:
            i = process.info
            pid = i.get('pid')
            name = i.get('name') or ''
            exe = i.get('exe') or ''
            user = i.get('username') or ''
            process_map[pid] = {'pid': pid, 'ppid': i.get('ppid'), 'name': name or 'unknown',
                                'exe': exe or 'unknown', 'cmdline': i.get('cmdline') or [],
                                'user': user or 'unknown', 'parent_exe': 'unknown'}
            cpu = i.get('cpu_percent') or 0
            mem = i.get('memory_percent') or 0
            if (i.get('status') or '') == 'zombie' and not any(z in name.lower() for z in SAFE_ZOMBIES):
                findings['processes']['zombies'].append({'pid': pid, 'name': name})
            if cpu >= 50:
                findings['processes']['high_cpu'].append({'pid': pid, 'name': name, 'cpu': round(cpu, 1), 'user': user, 'exe': exe})
            if mem >= 30:
                findings['processes']['high_mem'].append({'pid': pid, 'name': name, 'mem': round(mem, 1), 'user': user, 'exe': exe})
            if name.lower() in SUSP_NAMES:
                findings['processes']['suspicious_name'].append({'pid': pid, 'name': name, 'exe': exe, 'user': user})
            if exe and any(exe.startswith(path) for path in SUSP_PATHS):
                findings['processes']['suspicious_path'].append({'pid': pid, 'name': name, 'exe': exe, 'user': user})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            findings['network']['scan_gaps'].append('Some process identity fields were inaccessible')
        except Exception as exc:
            findings['network']['scan_gaps'].append('Process identity lookup failed: ' + type(exc).__name__)
except Exception as exc:
    findings['network']['scan_gaps'].append('Process enumeration failed: ' + type(exc).__name__ + ': ' + str(exc))
for owner in process_map.values():
    parent = process_map.get(owner.get('ppid'))
    if parent:
        owner['parent_exe'] = parent.get('exe') or 'unknown'

try:
    connections = psutil.net_connections(kind='inet')
except Exception as exc:
    connections = []
    findings['network']['scan_gaps'].append('Socket enumeration failed: ' + type(exc).__name__ + ': ' + str(exc))
for conn in connections:
    try:
        def parts(address):
            if not address:
                return None, None
            if isinstance(address, (tuple, list)):
                return (str(address[0]) if address else None), (address[1] if len(address) > 1 else None)
            return getattr(address, 'ip', None), getattr(address, 'port', None)
        local_ip, local_port = parts(conn.laddr)
        remote_ip, remote_port = parts(conn.raddr)
        conn_type = getattr(conn, 'type', None)
        protocol = 'tcp' if conn_type == socket.SOCK_STREAM else ('udp' if conn_type == socket.SOCK_DGRAM else 'unknown')
        state = str(getattr(conn, 'status', '') or 'UNKNOWN')
        is_listener = state == 'LISTEN' or (protocol == 'udp' and local_ip is not None and remote_ip is None)
        pid = getattr(conn, 'pid', None)
        owner = process_map.get(pid, {'pid': pid, 'ppid': None, 'name': 'unknown', 'exe': 'unknown',
                                      'cmdline': [], 'user': 'unknown', 'parent_exe': 'unknown'})
        findings['network']['raw_observations'].append({'protocol': protocol, 'local_ip': local_ip,
            'local_port': local_port, 'remote_ip': remote_ip, 'remote_port': remote_port,
            'state': state, 'is_listener': is_listener, 'pid': pid, 'owner': owner})
    except Exception as exc:
        findings['network']['scan_gaps'].append('Socket record unavailable: ' + type(exc).__name__)

if any(item.get('local_port') == 13133 or _docker_proxy(item.get('owner') or {}) for item in findings['network']['raw_observations']):
    try:
        listed = subprocess.run(['docker','ps','--no-trunc','--quiet'], capture_output=True, text=True, timeout=8)
        if listed.returncode != 0:
            findings['network']['docker_status'] = 'error'
            findings['network']['scan_gaps'].append('Docker identity lookup failed: ' + (listed.stderr or listed.stdout or 'nonzero exit').strip()[:240])
        else:
            findings['network']['docker_status'] = 'available'
            for container_id in listed.stdout.splitlines():
                if not container_id.strip():
                    continue
                inspected = subprocess.run(['docker','inspect',container_id.strip()], capture_output=True, text=True, timeout=8)
                if inspected.returncode != 0:
                    findings['network']['docker_status'] = 'partial'
                    findings['network']['scan_gaps'].append('Docker inspect failed: ' + (inspected.stderr or inspected.stdout or 'nonzero exit').strip()[:240])
                    break
                value = json.loads(inspected.stdout)
                if not isinstance(value, list) or len(value) != 1:
                    raise ValueError('inspect did not return one container')
                item = value[0]
                findings['network']['docker_containers'].append({'id': item.get('Id'),
                    'name': str(item.get('Name','')).lstrip('/'),
                    'image': item.get('Config', {}).get('Image'), 'image_id': item.get('Image'),
                    'running': item.get('State', {}).get('Running') is True,
                    'ports': item.get('NetworkSettings', {}).get('Ports') or {}})
    except Exception as exc:
        findings['network']['docker_status'] = 'error'
        findings['network']['scan_gaps'].append('Docker identity lookup failed: ' + type(exc).__name__ + ': ' + str(exc))

if findings['network']['scan_gaps']:
    findings['network']['scan_status'] = 'partial'

for u in psutil.users():
    findings['users']['logged_in'].append({'name': u.name, 'terminal': u.terminal, 'host': u.host,
                                           'started': str(datetime.fromtimestamp(u.started))})
mod = run("find /etc /bin /sbin /usr/bin /usr/sbin -newer /tmp -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -20")
findings['files']['recently_modified_system'] = mod.splitlines() if mod else []
failed = run('systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | head -20')
findings['services']['failed'] = failed.splitlines() if failed else []
new_units = run("find /etc/systemd /usr/lib/systemd -name '*.service' -newer /tmp -type f 2>/dev/null | head -20")
findings['services']['new_units'] = new_units.splitlines() if new_units else []
cron = run('crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null; ls /var/spool/cron/crontabs/ 2>/dev/null')
findings['cron']['entries'] = cron.splitlines() if cron else []
auth = run("grep -Ei 'failed|invalid|error|sudo|useradd|userdel|passwd' /var/log/auth.log 2>/dev/null | tail -50")
findings['auth_log'] = auth.splitlines() if auth else []
print(json.dumps(findings))
'''

_EXIT_TRAILER = "\n__AURORA_SECURITY_EXIT__="


def _build_remote_command():
    """The SSH command is static shell text: the script travels as base64 data."""
    encoded = base64.b64encode(_REMOTE_SCRIPT.encode("utf-8")).decode("ascii")
    return (
        "python3 -c \"import base64;exec(base64.b64decode('" + encoded + "'))\"; "
        "rc=$?; printf '\\n__AURORA_SECURITY_EXIT__=%s\\n' \"$rc\"; exit \"$rc\""
    )


# ─── WINDOWS REMOTE COLLECTION (SSH) ───────────────────────
# A Windows host has no systemctl, no cron, no Linux auth log and no Linux
# container CLI, so the Linux program must never be sent to it. This program
# emits the SAME raw observation shape the Linux and local collectors emit, so
# the single classification policy below is shared by all three paths: Windows is
# a new COLLECTOR, never a new POLICY. A Windows-only concept has no equivalent
# here, and those categories are reported UNAVAILABLE rather than emulated, so a
# partial Windows scan is never presented as clean.
#
# monitor.ssh_run discards the SSH exit status, so this program emits its own
# __AURORA_SECURITY_EXIT__ trailer. That trailer is a SUCCESS MARKER: the program
# always prints 0 once it has produced a payload. A partial or failed collection is
# carried by the payload itself, never by the trailer — `scan_status: "partial"`
# plus the gaps that name each unavailable category — and an SSH loss, an empty
# response or an unparsable/missing payload is reported by collect_remote_windows as
# a FAILED scan via _fail_scan. A nonzero trailer therefore only ever arrives from a
# host running something other than this program. The Windows path additionally
# reads the SSH exit status and stderr (see _runner_outcome), which is why a remote
# that never ran this program is now reported as NO OUTPUT instead of as a response
# that merely lost its trailer.
_REMOTE_SCRIPT_WINDOWS = r'''import json, os, socket, subprocess
from datetime import datetime
import psutil

SUSP_NAMES = {'nc','netcat','ncat','nmap','masscan','socat','xmrig','cgminer','minerd','ethminer','msfconsole','hydra','sqlmap','john','hashcat','mimikatz'}
# A CONTAINMENT test, case-folded: a real Windows exe begins with a drive letter
# (C:\Users\Administrator\AppData\Local\Temp\x.exe) or a UNC prefix
# (\\host\share\AppData\Local\Temp\x.exe), never with a bare leading backslash, so
# startswith could never match and this signal was permanently empty. Matching is on
# the normalized (case-folded, slash-folded) string only; nothing is loosened beyond
# these three roots and no Windows path is ever added as an allowlist entry.
SUSP_PATHS = ['appdata\\local\\temp\\','windows\\temp\\','\\temp\\']
SAFE_ZOMBIES = {'chrome','chromium','node','python'}

findings = {
    'os_type': 'windows',
    'processes': {'high_cpu': [], 'high_mem': [], 'suspicious_name': [], 'suspicious_path': [], 'zombies': []},
    'network': {'raw_observations': [], 'docker_containers': [], 'docker_status': 'not_applicable',
                'scan_status': 'complete', 'scan_gaps': []},
    'users': {'logged_in': []},
    'files': {'recently_modified_system': []},
    'services': {'failed': [], 'new_units': []},
    'cron': {'entries': []},
    'auth_log': [],
    'unavailable': [],
}

UNAVAILABLE_DETAIL = {}

def unavailable(category, detail):
    """Record evidence this host cannot supply instead of returning a silent empty."""
    UNAVAILABLE_DETAIL[category] = (UNAVAILABLE_DETAIL[category] + '; ' + detail
                                    if category in UNAVAILABLE_DETAIL else detail)

def powershell(argv, timeout=25):
    """Run one Windows-native command with an argv list, never through a shell."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return None, type(exc).__name__ + ': ' + str(exc)
    if result.returncode != 0:
        return None, (result.stderr or result.stdout or 'nonzero exit').strip()[:240]
    return result.stdout, None

def _base_name(path):
    return os.path.basename(str(path or '').rstrip('\\/')) if path else ''

process_map = {}
# One denied process identity yields ONE counted gap, never one line per process:
# N identical per-item lines would fill the report's entire 5-gap budget with
# duplicate noise and push the named-unavailable statement out of view.
DENIED_IDENTITIES = 0
try:
    for process in psutil.process_iter(['pid','ppid','name','exe','cmdline','username','cpu_percent','memory_percent','status']):
        try:
            i = process.info
            pid = i.get('pid')
            name = i.get('name') or ''
            exe = i.get('exe') or ''
            user = i.get('username') or ''
            process_map[pid] = {'pid': pid, 'ppid': i.get('ppid'), 'name': name or 'unknown',
                                'exe': exe or 'unknown', 'cmdline': i.get('cmdline') or [],
                                'user': user or 'unknown', 'parent_exe': 'unknown'}
            cpu = i.get('cpu_percent') or 0
            mem = i.get('memory_percent') or 0
            if (i.get('status') or '') == 'zombie' and not any(z in name.lower() for z in SAFE_ZOMBIES):
                findings['processes']['zombies'].append({'pid': pid, 'name': name})
            if cpu >= 50:
                findings['processes']['high_cpu'].append({'pid': pid, 'name': name, 'cpu': round(cpu, 1), 'user': user, 'exe': exe})
            if mem >= 30:
                findings['processes']['high_mem'].append({'pid': pid, 'name': name, 'mem': round(mem, 1), 'user': user, 'exe': exe})
            if name.lower() in SUSP_NAMES:
                findings['processes']['suspicious_name'].append({'pid': pid, 'name': name, 'exe': exe, 'user': user})
            lowered = exe.lower().replace('/', '\\')
            if exe and any(root.lower() in lowered for root in SUSP_PATHS):
                findings['processes']['suspicious_path'].append({'pid': pid, 'name': name, 'exe': exe, 'user': user})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            DENIED_IDENTITIES += 1
        except Exception as exc:
            findings['network']['scan_gaps'].append('Process identity lookup failed: ' + type(exc).__name__)
except Exception as exc:
    findings['network']['scan_gaps'].append('Process enumeration failed: ' + type(exc).__name__ + ': ' + str(exc))
    unavailable('processes', 'process enumeration failed: ' + type(exc).__name__ + ': ' + str(exc))
if DENIED_IDENTITIES:
    findings['network']['scan_gaps'].append(
        '%d process identity field(s) were inaccessible without elevation' % DENIED_IDENTITIES)
for owner in process_map.values():
    parent = process_map.get(owner.get('ppid'))
    if parent:
        owner['parent_exe'] = parent.get('exe') or 'unknown'

connections = []
try:
    for conn in psutil.net_connections(kind='inet'):
        try:
            def parts(address):
                if not address:
                    return None, None
                if isinstance(address, (tuple, list)):
                    return (str(address[0]) if address else None), (address[1] if len(address) > 1 else None)
                return getattr(address, 'ip', None), getattr(address, 'port', None)
            local_ip, local_port = parts(conn.laddr)
            remote_ip, remote_port = parts(conn.raddr)
            conn_type = getattr(conn, 'type', None)
            protocol = 'tcp' if conn_type == socket.SOCK_STREAM else ('udp' if conn_type == socket.SOCK_DGRAM else 'unknown')
            state = str(getattr(conn, 'status', '') or 'UNKNOWN')
            is_listener = state == 'LISTEN' or (protocol == 'udp' and local_ip is not None and remote_ip is None)
            pid = getattr(conn, 'pid', None)
            owner = process_map.get(pid, {'pid': pid, 'ppid': None, 'name': 'unknown', 'exe': 'unknown',
                                          'cmdline': [], 'user': 'unknown', 'parent_exe': 'unknown'})
            connections.append({'protocol': protocol, 'local_ip': local_ip,
                'local_port': local_port, 'remote_ip': remote_ip, 'remote_port': remote_port,
                'state': state, 'is_listener': is_listener, 'pid': pid, 'owner': owner})
        except Exception as exc:
            findings['network']['scan_gaps'].append('Socket record unavailable: ' + type(exc).__name__)
except Exception as exc:
    unavailable('network', 'socket enumeration needs elevation: ' + type(exc).__name__ + ': ' + str(exc))
findings['network']['raw_observations'] = connections

# Windows has no Linux cron spool and no Linux container CLI contract here; neither
# is emulated, and neither is reported as an empty success.
findings['network']['docker_containers'] = []
findings['network']['docker_status'] = 'not_applicable'
unavailable('cron', 'no Linux cron spool exists on this host; Windows scheduled tasks are not collected by this scanner')
unavailable('files', 'the Linux sensitive-directory scan has no Windows equivalent; the Windows system directory is not walked')
unavailable('services', 'systemd units do not exist on this host; Windows service state is collected instead')

out, failure = powershell(['powershell', '-NoProfile', '-NonInteractive', '-Command',
    "Get-Service | Where-Object { $_.Status -ne 'Running' } | "
    "Select-Object -ExpandProperty Name"])
if failure is not None:
    unavailable('services', 'Get-Service failed: ' + failure)
else:
    findings['services']['failed'] = [line.strip() for line in out.splitlines() if line.strip()][:20]

event_failures = []
for event_id in (4624, 4625, 4720, 4726):
    out, failure = powershell(['powershell', '-NoProfile', '-NonInteractive', '-Command',
        "(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=%d} -MaxEvents 25 "
        "-ErrorAction Stop | Select-Object -First 25 | "
        "ForEach-Object { $_.TimeCreated.ToString() + ' ' + $_.Id + ' ' + "
        "($_.Message -replace \"`r|`n\", ' ') })" % event_id], timeout=30)
    if failure is not None:
        event_failures.append('%d: %s' % (event_id, failure))
    else:
        findings['auth_log'].extend(line.strip() for line in out.splitlines() if line.strip())
findings['auth_log'] = findings['auth_log'][:50]
if event_failures:
    unavailable('auth_log', 'the Security event log could not be read without elevation (' + ' | '.join(event_failures) + ')')

try:
    for user in psutil.users():
        findings['users']['logged_in'].append({'name': user.name, 'terminal': getattr(user, 'terminal', None),
            'host': getattr(user, 'host', None), 'started': str(datetime.fromtimestamp(user.started))})
except Exception as exc:
    unavailable('users', 'logged-in user enumeration is unavailable: ' + type(exc).__name__ + ': ' + str(exc))

findings['unavailable'] = sorted(UNAVAILABLE_DETAIL)
if UNAVAILABLE_DETAIL:
    # One human-readable gap covers the whole unavailability set, so the report's
    # 5-gap render cap cannot hide one category behind another.
    findings['network']['scan_gaps'].append(
        'Windows evidence unavailable: ' + ' | '.join(
            category + ' (' + detail + ')' for category, detail in sorted(UNAVAILABLE_DETAIL.items())))
if findings['network']['scan_gaps']:
    findings['network']['scan_status'] = 'partial'
print(json.dumps(findings))
print('__AURORA_SECURITY_EXIT__=0')
'''


def _build_remote_command_windows():
    """
    The Windows SSH command: static text, one interpreter, no shell syntax.

    The program travels GZIP-COMPRESSED and then base64-encoded. Plain base64 of
    the 9,427-byte program produced a 12,624-character command, far beyond
    cmd.exe's 8,191-character command-line limit, so Windows truncated the
    command mid-base64 and the shell ran nothing at all. Compressed, the same
    program is a 4,520-character payload in a 4,594-character command, and
    decompressing it yields _REMOTE_SCRIPT_WINDOWS byte for byte.

    mtime=0 is required so the command is byte-deterministic across runs and a
    regression can pin it exactly; without it the gzip header would embed the
    build time. base64 and gzip are Python stdlib only, so the Windows host needs
    nothing beyond the interpreter it already runs.

    There is no `; exit "$rc"` here because the program prints its own trailer:
    the trailer is this program's success marker, so it does not depend on the
    SSH exit status, which a shell-quoted continuation would make unreliable.
    """
    payload = base64.b64encode(
        gzip.compress(_REMOTE_SCRIPT_WINDOWS.encode("utf-8"), 9, mtime=0)
    ).decode("ascii")
    return (
        "python -c \"import base64,gzip;exec(gzip.decompress(base64.b64decode('"
        + payload + "')))\""
    )


# Kept as a module-level name for callers/tests that referenced the old constant.
_REMOTE_PYTHON = _build_remote_command()


def collect_remote_linux(inst: dict, ssh_run_fn, security_config: dict | None = None) -> dict:
    """
    Gather structured Linux evidence from a remote instance via the caller's SSH runner.
    Empty, invalid, or nonzero remote responses are reported as failed scans.
    """
    findings = _base_findings(inst["name"], "remote")
    output = ssh_run_fn(inst, _build_remote_command())

    if output is None:
        _fail_scan(findings, "SSH unreachable", security_config)
        return findings

    response = str(output)
    exit_code = None
    if _EXIT_TRAILER in response:
        response, _, trailer = response.rpartition(_EXIT_TRAILER)
        exit_code = trailer.strip().splitlines()[0].strip() if trailer.strip() else ""
    if exit_code != "0":
        message = (
            "Remote security scanner exited nonzero"
            if exit_code
            else "Remote security scanner response is missing its exit status"
        )
        remote_data = _parse_remote_payload(response)
        if remote_data is None:
            _fail_scan(findings, message, security_config)
            return findings
        # A failed scan that still returned evidence keeps that evidence.
        for section, value in remote_data.items():
            findings[section] = value
        network = findings.get("network", {})
        _finalize_network(
            findings,
            network.pop("raw_observations", []),
            network.pop("docker_containers", []),
            network.get("docker_status", "unavailable"),
            [message] + list(network.get("scan_gaps", [])),
            security_config or {},
            "failed",
        )
        findings["error"] = message
        return findings

    try:
        remote_data = _parse_remote_payload(response)
        if remote_data is None:
            raise ValueError("scanner response is missing its network evidence")
    except Exception as exc:
        _fail_scan(
            findings, f"Invalid remote security response: {type(exc).__name__}: {exc}",
            security_config,
        )
        return findings

    for section, value in remote_data.items():
        findings[section] = value

    network = findings.get("network", {})
    _finalize_network(
        findings,
        network.pop("raw_observations", []),
        network.pop("docker_containers", []),
        network.get("docker_status", "unavailable"),
        network.get("scan_gaps", []),
        security_config or {},
        network.get("scan_status", "unknown"),
    )
    return findings


# Plain module-level alias, NOT a wrapper: callers and tests that still patch or
# call `collect_remote` reach the very same function object as
# `collect_remote_linux`.
collect_remote = collect_remote_linux


# ─── REMOTE FAILURE DIAGNOSTICS ────────────────────────────
# A remote interpreter that dies before printing its payload (a missing module, a
# syntax error, a command line cmd.exe truncated) leaves stdout empty, and stdout
# alone cannot say why. These patterns reduce that stderr to a short, inert
# fragment safe to show an operator: no key material, no token, no environment
# assignment, no absolute path, no username and no hostname ever reaches the
# report, and the fragment is capped so it cannot crowd out the evidence.
_REMOTE_DIAGNOSTIC_CAP = 240

_REMOTE_DIAGNOSTIC_RULES = (
    # Private key blocks, in full or truncated, are removed before anything else
    # can mistake the body for a path or a bare token.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
                re.DOTALL), "<key material removed>"),
    # Environment assignments: NAME=value with a credential-looking or long value.
    (re.compile(r"(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:key|token|secret|password|passwd|"
                r"credential|auth)[A-Za-z0-9_]*)\s*=\s*\S+"), r"\1=[redacted]"),
    (re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key|access[_-]?key)\b"
                r"\s*[:=]\s*\S+"), r"\1=[redacted]"),
    # Windows paths (drive-letter and UNC) and POSIX paths.
    (re.compile(r"[A-Za-z]:\\[^\s'\"]*"), "<path>"),
    (re.compile(r"\\\\[^\s'\"\\]+\\[^\s'\"]*"), "<path>"),
    (re.compile(r"(?:/[\w.-]+){2,}/?"), "<path>"),
    # Usernames in the shapes an SSH or Python error actually uses.
    (re.compile(r"(?i)\b(user|username|login|account)\b\s*[:=]\s*['\"]?[\w.\\/-]+"),
     r"\1=[redacted]"),
    (re.compile(r"(?i)\b(user|username|login|account)\b\s+['\"]?[\w.\\/-]+"),
     r"\1 [redacted]"),
    (re.compile(r"(?i)\bfor\s+user\b\s*['\"]?[\w.\\/-]+"), "for user [redacted]"),
    # Hostnames and addresses: IPv4 first, then IPv6, then dotted names.
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<host>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b"), "<host>"),
    (re.compile(r"\b[\w-]{2,}(?:\.[\w-]{2,})+(?::\d+)?\b"), "<host>"),
    # Anything left that is long and unbroken is an opaque blob (a token or an
    # encoded command), not something to echo into a chat message.
    (re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b"), "<blob removed>"),
)


def sanitize_remote_diagnostic(text, cap: int = _REMOTE_DIAGNOSTIC_CAP) -> str:
    """
    Reduce remote stderr (and a remote exit status) to a short inert fragment.

    Empty or non-string input returns "", so a caller can always append the
    result unconditionally and a silent remote stays silent. Every rule removes
    rather than quotes, the result is whitespace-collapsed and truncated to
    `cap` characters, and nothing here can raise a scan out of failed.
    """
    if not text:
        return ""
    fragment = " ".join(str(text).split())
    if not fragment:
        return ""
    for pattern, replacement in _REMOTE_DIAGNOSTIC_RULES:
        fragment = pattern.sub(replacement, fragment)
    return fragment[:cap].strip()


def _runner_outcome(ssh_run_fn, inst: dict, command: str) -> dict:
    """
    Run one SSH command and return its stdout plus any diagnostic extras.

    The runner may be the plain stdout-or-None runner the other callers use, or
    a detailed runner (monitor.ssh_run_detailed) that also carries stderr and the
    remote exit status. The shape is detected, not assumed, so a plain runner
    degrades to the pre-existing behaviour with no diagnostic at all rather than
    failing: `ssh_run_fn` itself is called exactly once either way, so this adds
    no SSH connection and no round trip.

    `reason` is a sanitized, capped fragment for the failure message, and is
    empty when the remote said nothing.
    """
    result = ssh_run_fn(inst, command)
    outcome = {"stdout": result, "stderr": "", "exit_status": None,
               "remote_nonzero": False, "reason": ""}
    # A detailed result is an object carrying stdout; a plain result IS stdout.
    if hasattr(result, "stdout"):
        outcome["stdout"] = result.stdout
        outcome["stderr"] = getattr(result, "stderr", "") or ""
        outcome["exit_status"] = getattr(result, "exit_status", None)
    exit_status = outcome["exit_status"]
    outcome["remote_nonzero"] = exit_status is not None and str(exit_status) != "0"

    diagnostic = sanitize_remote_diagnostic(outcome["stderr"])
    if outcome["remote_nonzero"]:
        # The status is folded in and the WHOLE reason is capped once, here, so no
        # prefix can push the fragment past the cap.
        status = sanitize_remote_diagnostic(exit_status, cap=16)
        diagnostic = f"remote exit status {status}: {diagnostic}" if diagnostic \
            else f"remote exit status {status}"
    outcome["reason"] = diagnostic[:_REMOTE_DIAGNOSTIC_CAP].strip()
    return outcome


def collect_remote_windows(inst: dict, ssh_run_fn, security_config: dict | None = None) -> dict:
    """
    Gather structured evidence from a remote Windows instance via SSH.

    The Windows program emits the same raw observation shape as the Linux one, so
    the classification, risk and legacy projections below are the unchanged
    central policy. Categories this collector cannot reach on Windows are
    reported as unavailable, which forces an incomplete posture rather than a
    clean one.

    `ssh_run_fn` may be either the plain stdout-or-None runner the other callers
    use or a detailed runner (monitor.ssh_run_detailed) that also carries stderr
    and the remote exit status. That extra evidence is diagnostic only: it never
    turns a failure into a pass and never enters the classification policy.

    Failure modes stay distinguishable, in this order: SSH loss, then NO OUTPUT
    at all, then a missing/nonzero trailer, then an unparsable payload. An empty
    response is reported in its own words because it is what a Windows host
    returns when the command line it was given never ran (for instance a command
    too long for cmd.exe) — a transport failure, not a protocol failure — and it
    must not be mistaken for a host that merely forgot its trailer.
    """
    findings = _base_findings(inst["name"], "remote")
    outcome = _runner_outcome(ssh_run_fn, inst, _build_remote_command_windows())

    if outcome["stdout"] is None:
        _fail_scan(findings, "SSH unreachable", security_config)
        return findings

    response = str(outcome["stdout"])

    # NO OUTPUT is its own failure, checked BEFORE the trailer: an empty
    # response has no exit status to be missing, and folding the two together
    # is what made a truncated command indistinguishable from a protocol bug.
    if not response.strip():
        message = "Remote security scanner produced no output"
        if outcome["reason"]:
            message += ": " + outcome["reason"]
        _fail_scan(findings, message, security_config)
        return findings

    exit_code = None
    if _EXIT_TRAILER in response:
        response, _, trailer = response.rpartition(_EXIT_TRAILER)
        exit_code = trailer.strip().splitlines()[0].strip() if trailer.strip() else ""
    # A remote exit status of its own is authoritative alongside the trailer: the
    # Windows program prints its trailer only after it has produced a payload, so
    # a nonzero status means the interpreter itself failed and the payload — if
    # any — cannot be trusted. It fails, and it fails even when the trailer says 0.
    remote_failed = outcome["remote_nonzero"]
    if exit_code != "0" or remote_failed:
        message = (
            "Remote security scanner exited nonzero"
            if exit_code or remote_failed
            else "Remote security scanner response is missing its exit status"
        )
        if outcome["reason"]:
            message += ": " + outcome["reason"]
        remote_data = _parse_remote_payload(response)
        if remote_data is None:
            _fail_scan(findings, message, security_config)
            return findings
        # A failed scan that still returned evidence keeps that evidence.
        for section, value in remote_data.items():
            findings[section] = value
        network = findings.get("network", {})
        _finalize_network(
            findings,
            network.pop("raw_observations", []),
            network.pop("docker_containers", []),
            network.get("docker_status", "not_applicable"),
            [message] + list(network.get("scan_gaps", [])),
            security_config or {},
            "failed",
        )
        findings["error"] = message
        return findings

    try:
        remote_data = _parse_remote_payload(response)
        if remote_data is None:
            raise ValueError("scanner response is missing its network evidence")
    except Exception as exc:
        _fail_scan(
            findings, f"Invalid remote security response: {type(exc).__name__}: {exc}",
            security_config,
        )
        return findings

    for section, value in remote_data.items():
        findings[section] = value

    network = findings.get("network", {})
    _finalize_network(
        findings,
        network.pop("raw_observations", []),
        network.pop("docker_containers", []),
        network.get("docker_status", "not_applicable"),
        network.get("scan_gaps", []),
        security_config or {},
        network.get("scan_status", "unknown"),
    )
    return findings


def _parse_remote_payload(response):
    """Return the remote payload dict, or None when it is not usable."""
    try:
        remote_data = json.loads(response)
    except Exception:
        return None
    if not isinstance(remote_data, dict) or not isinstance(remote_data.get("network"), dict):
        return None
    return remote_data


def _fail_scan(findings: dict, message: str, security_config: dict | None = None):
    """Record a failed scan without erasing any evidence already collected."""
    findings["error"] = message
    _finalize_network(
        findings, [], [], "unavailable", [message], security_config or {}, "failed"
    )


# ─── HELPERS ──────────────────────────────────────────────

def _base_findings(name: str, mode: str) -> dict:
    return {
        "instance":  name,
        "mode":      mode,
        "collected": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "processes": {
            "high_cpu":        [],
            "high_mem":        [],
            "suspicious_name": [],
            "suspicious_path": [],
            "zombies":         [],
        },
        "network": {
            "observations":      [],
            "category_counts":   {},
            "totals":            {},
            "risk":              {},
            "unexpected_listening": [],
            "external_connections":  [],
            "scan_status":       "unknown",
            "scan_gaps":         [],
            "docker_status":     "not_required",
        },
        "users":    {"logged_in": []},
        "files":    {"recently_modified_system": []},
        "services": {"failed": [], "new_units": []},
        "cron":     {"entries": []},
        "auth_log": [],
        "error":    None,
    }


# ─── NETWORK EVIDENCE + CENTRAL CLASSIFICATION POLICY ─────
# One policy, used by the local and the SSH-remote collectors. Nothing here
# trusts a port number, an address, a process basename, a container name, or an
# ephemeral port on its own: a classification is only "expected" when the
# operator configured the identity and the collected evidence matches it.

CLASSIFICATIONS = (
    "benign", "expected", "informational", "needs_review", "suspicious",
    "high_risk", "unknown",
)
DIRECTIONS = ("inbound", "outbound", "uncertain")
BIND_SCOPES = (
    "loopback-only", "private-interface", "all-interfaces", "public-interface",
    "unknown",
)
DEFAULT_OTEL_TARGET_PORT = 13133
BOT_HTTPS_PORT = 443
EPHEMERAL_PORT_MIN = 32768
_SCRIPT_INTERPRETERS = {"python", "python3", "python2", "perl", "ruby", "node", "php", "sh", "bash"}


def _unknown_owner(pid):
    return {
        "pid": pid, "ppid": None, "name": "unknown", "exe": "unknown",
        "cmdline": [], "user": "unknown", "parent_exe": "unknown",
    }


def _basename(path):
    if not path or path == "unknown":
        return ""
    return os.path.basename(str(path).rstrip("/")) or str(path)


def _is_loopback(ip):
    if not ip:
        return False
    try:
        return ipaddress.ip_address(str(ip).split("%")[0]).is_loopback
    except ValueError:
        return False


def _is_private(ip):
    """True for the host-local networks the legacy external list excluded."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return True
    if address.version == 6:
        return address.is_loopback or address.is_link_local or address in _ULA
    return any(address in network for network in _RFC1918)


def _is_public(ip):
    """True when the address is reached over the network rather than host-local."""
    if not ip:
        return False
    return not _is_private(ip) and not _is_loopback(ip)


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA = ipaddress.ip_network("fc00::/7")


def _ip_matches(ip, entries, port=None):
    """Match an address against operator-configured exact addresses or CIDRs."""
    if not ip or not entries:
        return None
    for entry in entries:
        entry = str(entry).strip()
        if not entry:
            continue
        expected_port = None
        if entry.count(":") == 1:
            entry, _, port_text = entry.partition(":")
            if port_text.isdigit():
                expected_port = int(port_text)
        try:
            if "/" in entry:
                matched = ipaddress.ip_address(str(ip).split("%")[0]) in ipaddress.ip_network(entry, strict=False)
            else:
                matched = str(ip).split("%")[0] == entry
        except ValueError:
            continue
        if matched and (expected_port is None or port == expected_port):
            return entry
    return None


def _bind_scope(ip):
    if ip is None or str(ip) in ("0.0.0.0", "::", "*", ""):
        return "all-interfaces"
    if _is_loopback(ip):
        return "loopback-only"
    if _is_private(ip):
        return "private-interface"
    if _is_public(ip):
        return "public-interface"
    return "unknown"


def _endpoint(ip, port):
    if ip is None and port is None:
        return "unknown"
    return f"{ip}:{port}" if port is not None else str(ip)


def _is_ephemeral_port(port):
    """Client sockets use an OS assigned high port; a low one is a deviation."""
    try:
        return int(port) >= EPHEMERAL_PORT_MIN
    except (TypeError, ValueError):
        return False


def _observation(raw, direction, bind_scope, container, classification,
                 confidence, reason, evidence):
    owner = raw.get("owner") or _unknown_owner(raw.get("pid"))
    return {
        "protocol":     raw.get("protocol") or "unknown",
        "state":        raw.get("state") or "UNKNOWN",
        "local_ip":     raw.get("local_ip"),
        "local_port":   raw.get("local_port"),
        "remote_ip":    raw.get("remote_ip"),
        "remote_port":  raw.get("remote_port"),
        "direction":    direction,
        "bind_scope":   bind_scope,
        "is_listener":  bool(raw.get("is_listener")),
        "pid":          raw.get("pid"),
        "process":      {
            "name":      owner.get("name") or "unknown",
            "exe":       owner.get("exe") or "unknown",
            "cmdline":   owner.get("cmdline") or [],
            "user":      owner.get("user") or "unknown",
            "parent_exe": owner.get("parent_exe") or "unknown",
        },
        "container":    container,
        "classification": classification,
        "confidence":   confidence,
        "reason":       reason,
        "evidence":     evidence,
    }


def _listener_matches(listener_ip, listener_port, ip, port):
    """A peer uses this listener when the port matches and the bind covers the address."""
    if listener_port is None or port is None or listener_port != port:
        return False
    if listener_ip in (None, "", "0.0.0.0", "::", "*"):
        return True
    return str(listener_ip) == str(ip)


def _assign_directions(raw_list):
    """Listener matching: a local listener is inbound when a peer uses it."""
    listeners = [
        (raw.get("local_ip"), raw.get("local_port"))
        for raw in raw_list if raw.get("is_listener")
    ]
    directions = []
    for raw in raw_list:
        if raw.get("is_listener") or raw.get("remote_ip") is None:
            directions.append("uncertain")   # refined once observed peers are matched
            continue
        if any(_listener_matches(*listener, raw.get("local_ip"), raw.get("local_port"))
               for listener in listeners):
            directions.append("inbound")
        else:
            directions.append("outbound")
    return directions


def _container_publications(containers, port):
    """Return the running-container publications that claim a host port."""
    matches = []
    if not containers or port is None:
        return matches
    for container in containers:
        if not container.get("running"):
            continue
        for key, bindings in (container.get("ports") or {}).items():
            if not key or "/" not in key:
                continue
            container_port, _, proto = key.partition("/")
            for binding in bindings or []:
                try:
                    host_port = int(binding.get("HostPort"))
                except (TypeError, ValueError):
                    continue
                if host_port != port:
                    continue
                if proto != "tcp":
                    continue
                try:
                    target_port = int(container_port)
                except ValueError:
                    continue
                matches.append({
                    "name":      container.get("name"),
                    "image":     container.get("image"),
                    "image_id":  container.get("image_id"),
                    "host_ip":   binding.get("HostIp") or "0.0.0.0",
                    "host_port": host_port,
                    "protocol":  "tcp",
                    "target_port": target_port,
                    "running":   True,
                })
    return matches


def _docker_owner_verified(owner):
    """True only for a socket actually held by the Docker userland proxy."""
    return _is_docker_proxy_process(owner)


def _is_docker_proxy_process(owner):
    owner = owner or {}
    return (_basename(owner.get("name")) == "docker-proxy"
            or _basename(owner.get("exe")) == "docker-proxy"
            or _basename(owner.get("parent_exe")) in ("dockerd", "docker"))


def _classify_otel_listener(raw, bind_scope, containers, docker_status, config, peers):
    target_port = config.get("otel_target_port") or DEFAULT_OTEL_TARGET_PORT
    port = raw.get("local_port")
    expected_name = config.get("otel_container_name")
    pinned_image = config.get("otel_image_id")

    if docker_status in ("unavailable", "error"):
        return None, None, (
            "Listener on port %s looks like a Docker publication, but container identity "
            "could not be verified (docker status: %s); treated as unverified" % (port, docker_status)
        )
    if port != target_port:
        return None, None, (
            "Listener on port %s is held by a Docker proxy but the configured collector "
            "target port is %s" % (port, target_port)
        )

    publications = _container_publications(containers, port)
    if len(publications) != 1:
        return None, None, (
            "Docker publication proof is %s for host port %s (exactly one running "
            "container publication is required)" % (
                "ambiguous" if len(publications) > 1 else "missing", port
            )
        )
    publication = publications[0]
    if publication.get("target_port") != target_port:
        return publication, None, (
            "Container %s publishes host port %s to container port %s, not the "
            "configured target port %s" % (
                publication.get("name"), port, publication.get("target_port"), target_port
            )
        )
    if expected_name and publication.get("name") != expected_name:
        return publication, None, (
            "Publishing container is named %r, not the configured collector %r" % (
                publication.get("name"), expected_name
            )
        )
    if not expected_name:
        return publication, None, (
            "Publishing container %s is verified, but no collector identity is "
            "configured (INSTANCE_<N>_SECURITY_OTEL_CONTAINER_NAME, and optionally "
            "INSTANCE_<N>_SECURITY_OTEL_IMAGE_ID), so the workload cannot be "
            "confirmed as the expected collector" % publication.get("name")
        )
    if pinned_image and pinned_image not in (
        publication.get("image_id") or "", publication.get("image") or ""
    ):
        return publication, None, (
            "Publishing container image %r does not match the pinned image %r" % (
                publication.get("image"), pinned_image
            )
        )
    return publication, None, None


def _classify_bot_client(raw, owner, config):
    bot_exe = config.get("bot_exe")
    bot_script = config.get("bot_script")
    bot_user = config.get("bot_user")
    destinations = config.get("bot_https_destinations") or []
    if not bot_exe or not bot_script:
        return None, None
    exe = owner.get("exe") or ""
    cmdline = [str(arg) for arg in (owner.get("cmdline") or [])]
    script_match = bot_script in cmdline
    exe_match = str(exe) == str(bot_exe)
    user = owner.get("user") or "unknown"
    user_match = (not bot_user) or str(user) == str(bot_user)
    if not (exe_match or script_match):
        return None, None          # unrelated process: judged by the other rules
    if not (exe_match and script_match and user_match):
        mismatched = []
        if not exe_match:
            mismatched.append("executable %s is not the configured %s" % (exe, bot_exe))
        if not script_match:
            mismatched.append("script argument %s is not the configured %s" % (
                next((arg for arg in cmdline[1:2]), "none"), bot_script))
        if not user_match:
            mismatched.append("owner user %s is not the configured %s" % (user, bot_user))
        return None, (
            "Process looks like the monitor bot but %s" % "; ".join(mismatched)
        )
    if raw.get("remote_port") != BOT_HTTPS_PORT:
        return None, (
            "Monitor bot process is connecting to port %s, not the configured "
            "HTTPS port %s" % (raw.get("remote_port"), BOT_HTTPS_PORT)
        )
    if not _is_ephemeral_port(raw.get("local_port")):
        return None, (
            "Monitor bot process is using local port %s, which is not an ephemeral "
            "client port as expected for an outbound client" % raw.get("local_port")
        )
    matched = _ip_matches(raw.get("remote_ip"), destinations, raw.get("remote_port"))
    if not matched:
        return None, (
            "Monitor bot process is connecting to %s, which is not one of this "
            "instance's configured HTTPS destinations" % _endpoint(
                raw.get("remote_ip"), raw.get("remote_port"))
        )
    return matched, None


def _classify_tailscale_client(raw, owner, config):
    tailscaled_exe = config.get("tailscaled_exe")
    tailscaled_user = config.get("tailscaled_user")
    destinations = config.get("tailscaled_https_destinations") or []
    name = _basename(owner.get("name"))
    exe = owner.get("exe") or "unknown"
    exe_base = _basename(exe)
    user = owner.get("user") or "unknown"
    looks_like_tailscale = "tailscale" in name.lower() or "tailscale" in exe_base.lower()
    if not tailscaled_exe:
        if looks_like_tailscale:
            return None, (
                "Process %s looks like the Tailscale client, but no "
                "INSTANCE_<N>_SECURITY_TAILSCALED_EXE is configured to verify it" % name
            )
        return None, None
    if str(exe) != str(tailscaled_exe):
        if looks_like_tailscale:
            return None, (
                "Process %s matches the Tailscale name but its executable %s is not "
                "the configured %s" % (name, exe, tailscaled_exe)
            )
        return None, None
    if tailscaled_user and str(user) != str(tailscaled_user):
        return None, (
            "Tailscale client runs as %s, not the configured %s" % (user, tailscaled_user)
        )
    if raw.get("remote_port") != BOT_HTTPS_PORT:
        return None, (
            "Tailscale client is connecting to port %s, not its configured "
            "HTTPS service port %s" % (raw.get("remote_port"), BOT_HTTPS_PORT)
        )
    if not _is_ephemeral_port(raw.get("local_port")):
        return None, (
            "Tailscale client is using local port %s, which is not an ephemeral "
            "client port as expected for an outbound client" % raw.get("local_port")
        )
    matched = _ip_matches(raw.get("remote_ip"), destinations, raw.get("remote_port"))
    if not matched:
        return None, (
            "Tailscale client is connecting to %s, which is not one of this "
            "instance's configured Tailscale destinations" % _endpoint(
                raw.get("remote_ip"), raw.get("remote_port"))
        )
    return matched, None


def _script_interpreter_owner(owner):
    """Detect a script run by an interpreter, used for the unknown-script case."""
    name = _basename(owner.get("name"))
    exe = _basename(owner.get("exe"))
    if name not in _SCRIPT_INTERPRETERS and exe not in _SCRIPT_INTERPRETERS:
        return None
    cmdline = [str(arg) for arg in (owner.get("cmdline") or [])]
    script = None
    for arg in cmdline[1:]:
        if arg.startswith("-"):
            continue
        script = arg
        break
    return script


def _is_known_service(owner):
    candidates = {_basename(owner.get("name")), _basename(owner.get("exe")),
                  _basename(owner.get("parent_exe"))}
    return bool(candidates & KNOWN_SERVICES)


def _classify_observation(raw, direction, bind_scope, containers, docker_status,
                          config, peers):
    """Return (observation, adverse_risk_hint) for one collected socket."""
    owner = raw.get("owner") or _unknown_owner(raw.get("pid"))
    port = raw.get("local_port")
    remote_port = raw.get("remote_port")
    remote_ip = raw.get("remote_ip")
    listener = bool(raw.get("is_listener"))
    exposure = bind_scope in ("all-interfaces", "public-interface")
    base_evidence = {
        "local": _endpoint(raw.get("local_ip"), port),
        "remote": _endpoint(remote_ip, remote_port),
        "state": raw.get("state"),
        "pid": raw.get("pid"),
        "owner_exe": owner.get("exe"),
        "owner_user": owner.get("user"),
        "peer_connections": len(peers),
    }
    identity = _is_known_service(owner) and owner.get("exe") not in (None, "", "unknown")

    if raw.get("protocol") == "unknown" or raw.get("state") in (None, "", "UNKNOWN"):
        obs = _observation(
            raw, direction, bind_scope, None, "unknown", "low",
            "Socket protocol or state could not be determined", base_evidence,
        )
        return obs, "unknown"

    # 1. Docker-published collector listener (A / E).
    if listener and _docker_owner_verified(owner):
        publication, _, failure = _classify_otel_listener(
            raw, bind_scope, containers, docker_status, config, peers
        )
        if failure:
            obs = _observation(
                raw, direction, bind_scope, publication, "needs_review", "low",
                failure, dict(base_evidence, docker_status=docker_status),
            )
            return obs, "review"
        reasons = [
            "socket is held by the Docker userland proxy and exactly one running "
            "container publishes host port %s to container port %s" % (
                port, publication.get("target_port"))
        ]
        if config.get("otel_container_name"):
            reasons.append("container name matches configured collector %r" %
                           config.get("otel_container_name"))
        if config.get("otel_image_id"):
            reasons.append("container image matches the pinned image")
        if peers:
            reasons.append("observed with %d peer connection(s)" % len(peers))
        if bind_scope != "loopback-only":
            obs = _observation(
                raw, direction, bind_scope, publication, "needs_review", "medium",
                "; ".join(reasons + [
                    "the host socket is bound to %s rather than loopback, so the "
                    "collector is reachable from the network" % bind_scope
                ]),
                dict(base_evidence, docker_status=docker_status),
            )
            return obs, "review"
        reasons.append("bound to loopback only, so it is not reachable from the network")
        obs = _observation(
            raw, direction, bind_scope, publication, "expected", "high",
            "; ".join(reasons), dict(base_evidence, docker_status=docker_status),
        )
        return obs, None

    # 2/3. Configured client services (C / D).
    if not listener and direction == "outbound":
        matched, failure = _classify_bot_client(raw, owner, config)
        if failure:
            obs = _observation(
                raw, direction, bind_scope, None, "needs_review", "low",
                failure, base_evidence,
            )
            return obs, "review"
        if matched:
            obs = _observation(
                raw, direction, bind_scope, None, "expected", "high",
                "Executable, script argument and owner user match the configured "
                "monitor bot and the destination matches configured entry %r; host "
                "process identity is not cryptographically attested" % matched,
                dict(base_evidence, matched_destination=matched),
            )
            return obs, None
        matched, failure = _classify_tailscale_client(raw, owner, config)
        if failure:
            obs = _observation(
                raw, direction, bind_scope, None, "needs_review", "low",
                failure, base_evidence,
            )
            return obs, "review"
        if matched:
            obs = _observation(
                raw, direction, bind_scope, None, "expected", "high",
                "Executable, owner user and destination match the configured "
                "Tailscale client and configured destination %r; host process "
                "identity is not cryptographically attested" % matched,
                dict(base_evidence, matched_destination=matched),
            )
            return obs, None

    # 4. Unknown script talking to a non-HTTPS service (F).
    if not listener and direction == "outbound" and remote_port not in (None, BOT_HTTPS_PORT):
        script = _script_interpreter_owner(owner)
        bot_script = config.get("bot_script")
        configured = bool(bot_script) and any(
            str(arg) == str(bot_script) for arg in (owner.get("cmdline") or [])
        )
        if script and not configured:
            obs = _observation(
                raw, direction, bind_scope, None, "suspicious", "medium",
                "Unrecognised script %s run by %s is connecting to an unexpected "
                "service port %s; the destination service is not a configured "
                "monitor service" % (script, _basename(owner.get("exe")) or
                                      _basename(owner.get("name")), remote_port),
                dict(base_evidence, script=script),
            )
            return obs, "suspicious"

    # 5. Listeners and matched inbound server-side connections (B / G).
    if listener or direction == "inbound":
        if identity:
            if not listener:
                # A peer that used a local listener is an accepted server-side
                # connection, not a listener; peers are not computed for it.
                reason = ("%s accepted inbound connection %s (state %s) on the local "
                          "address %s; it is peer traffic against that listener, "
                          "not a new listener" % (
                              _basename(owner.get("name")),
                              _endpoint(remote_ip, remote_port), raw.get("state"),
                              _endpoint(raw.get("local_ip"), port)))
            elif exposure:
                reason = ("%s owns this listener; it is bound to %s, so anyone who "
                          "can reach the host can reach it" % (
                              _basename(owner.get("name")), bind_scope))
            else:
                reason = ("%s owns this listener bound to %s; %d peer "
                          "connection(s) observed" % (
                              _basename(owner.get("name")), bind_scope, len(peers)))
            obs = _observation(
                raw, direction, bind_scope, None, "informational", "high",
                reason + "; no evidence of misuse, but confirm the exposure is intended",
                base_evidence,
            )
            return obs, "exposure" if exposure else None
        obs = _observation(
            raw, direction, bind_scope, None, "needs_review",
            "medium" if identity else "low",
            ("Listener owner identity could not be established, so this %s listener "
             "cannot be attributed to a known service" % (
                 "network reachable" if exposure else "loopback or private-interface"))
            if listener else
            ("Accepted inbound connection owner identity could not be established, "
             "so the peer of the local listener on %s cannot be attributed to a "
             "known service" % _endpoint(raw.get("local_ip"), port)),
            base_evidence,
        )
        return obs, "review" if exposure else "loopback-review"

    # 6. Everything else outbound stays unresolved rather than presumed benign.
    obs = _observation(
        raw, direction, bind_scope, None, "needs_review", "low",
        "Outbound connection to %s from %s is not matched to any configured "
        "service destination, so its purpose is unverified" % (
            _endpoint(remote_ip, remote_port), _basename(owner.get("exe")) or
            _basename(owner.get("name"))),
        base_evidence,
    )
    return obs, "review"


def _assess_network_risk(observations, scan_status, gaps, findings):
    counts = {name: 0 for name in CLASSIFICATIONS}
    for obs in observations:
        counts[obs["classification"]] = counts.get(obs["classification"], 0) + 1

    exposed = [
        obs for obs in observations
        if (obs.get("is_listener") or obs["direction"] == "inbound")
        and obs["classification"] in ("needs_review", "suspicious", "high_risk", "unknown")
        and obs["bind_scope"] in ("all-interfaces", "public-interface")
    ]
    unresolved_outbound = [
        obs for obs in observations
        if obs["direction"] == "outbound" and obs["classification"] in
        ("needs_review", "suspicious", "high_risk", "unknown")
    ]
    suspicious = [
        obs for obs in observations if obs["classification"] in ("suspicious", "high_risk")
    ]

    level = "negligible"
    reasons = []
    if counts["expected"] or counts["informational"] or counts["benign"]:
        reasons.append(
            "%d observation(s) matched a verified expected service and %d were "
            "attributed to a known service" % (
                counts["expected"], counts["informational"] + counts["benign"])
        )
    if exposed:
        level = "medium"
        reasons.append(
            "%d externally exposed or unresolved listener item(s) need review" % len(exposed)
        )
    if unresolved_outbound:
        level = "medium"
        reasons.append(
            "%d outbound connection(s) could not be matched to a configured "
            "service destination" % len(unresolved_outbound)
        )
    if suspicious:
        level = "medium"
        reasons.append(
            "%d observation(s) deviate from the configured environment" % len(suspicious)
        )

    processes = findings.get("processes", {})
    corroboration = []
    if processes.get("suspicious_name"):
        corroboration.append("suspicious process names")
    if processes.get("suspicious_path"):
        corroboration.append("processes running from temporary paths")
    if findings.get("services", {}).get("failed"):
        corroboration.append("failed system services")
    if findings.get("auth_log"):
        corroboration.append("authentication log entries")
    if any(obs["classification"] == "high_risk" for obs in observations):
        level = "high"
        reasons.append("a high risk observation was recorded")
    elif suspicious and corroboration:
        level = "high"
        reasons.append(
            "deviating network activity is corroborated by %s" % ", ".join(corroboration)
        )

    posture = "complete" if scan_status == "complete" else (
        "failed" if scan_status == "failed" else "incomplete"
    )
    if posture != "complete":
        if level in ("negligible", "low"):
            level = "medium"
        reasons.append(
            "evidence is %s (%s); the network posture cannot be cleared" % (
                posture, "; ".join(str(gap) for gap in gaps)[:200] or "scan status " + str(scan_status))
        )
    if findings.get("error"):
        if level in ("negligible", "low"):
            level = "medium"
        reasons.append("scanner reported an error: %s" % findings["error"])

    return {
        "level":    level,
        "posture":  posture,
        "reasons":  reasons,
        "corroboration": corroboration,
        "exposed_listener_items": len(exposed),
        "unresolved_outbound_items": len(unresolved_outbound),
    }


def _finalize_network(findings, raw_list, containers, docker_status, gaps,
                      config, scan_status="unknown"):
    """Classify every collected socket and rebuild the legacy projections."""
    raw_list = [item for item in (raw_list or []) if isinstance(item, dict)]
    gaps = [str(gap) for gap in (gaps or [])]
    directions = _assign_directions(raw_list)

    observations = []
    hints = []
    for index, raw in enumerate(raw_list):
        direction = directions[index]
        peers = [other for other, other_raw in enumerate(raw_list)
                 if other != index and other_raw.get("is_listener") is False
                 and directions[other] == "inbound"
                 and _listener_matches(raw.get("local_ip"), raw.get("local_port"),
                                       other_raw.get("local_ip"), other_raw.get("local_port"))
                 ] if raw.get("is_listener") else []
        if raw.get("is_listener") and peers:
            direction = "inbound"
        bind_scope = _bind_scope(raw.get("local_ip"))
        observation, hint = _classify_observation(
            raw, direction, bind_scope, containers, docker_status, config, peers
        )
        observations.append(observation)
        hints.append(hint)

    if scan_status in ("failed", "partial", "unknown"):
        # Identity or lookup failure keeps the evidence but lowers confidence.
        for observation in observations:
            observation["confidence"] = {
                "high": "medium", "medium": "low", "low": "low",
            }.get(observation["confidence"], "low")

    network = findings.setdefault("network", {})
    network["observations"] = observations
    network["category_counts"] = {
        name: sum(1 for obs in observations if obs["classification"] == name)
        for name in CLASSIFICATIONS
    }
    network["totals"] = {
        "observations": len(observations),
        "listeners":    sum(1 for obs in observations if obs["is_listener"]),
        "inbound":      sum(1 for obs in observations if obs["direction"] == "inbound"),
        "outbound":     sum(1 for obs in observations if obs["direction"] == "outbound"),
        "uncertain":    sum(1 for obs in observations if obs["direction"] == "uncertain"),
    }
    network["scan_status"] = scan_status
    network["scan_gaps"] = gaps
    network["docker_status"] = docker_status
    network["risk"] = _assess_network_risk(observations, scan_status, gaps, findings)
    network["adverse_hints"] = hints

    # Legacy compatible projections. They are views over the same evidence: no
    # owner is invented, inbound server-side sockets are never reported as
    # external outbound, and nothing is silently truncated.
    network["unexpected_listening"] = [
        {
            "port": obs["local_port"],
            "addr": _endpoint(obs["local_ip"], obs["local_port"]),
        }
        for obs in observations
        if obs.get("is_listener")
        and obs["classification"] not in ("expected", "informational", "benign")
        and obs["local_port"] is not None
    ]
    network["external_connections"] = [
        {
            "local":  _endpoint(obs["local_ip"], obs["local_port"]),
            "remote": _endpoint(obs["remote_ip"], obs["remote_port"]),
        }
        for obs in observations
        if obs["direction"] == "outbound" and _is_public(obs.get("remote_ip"))
    ]
    return network


def _is_private_ip(ip: str) -> bool:
    """Backwards-compatible helper: True for loopback/private/link-local addresses."""
    return _is_private(ip) or _is_loopback(ip)


def has_any_findings(f: dict) -> bool:
    """Return True if there is at least one signal that needs human attention."""
    if f.get("error"):
        return True
    p = f.get("processes", {})
    n = f.get("network", {})
    s = f.get("services", {})
    network_attention = any(
        n.get("observations")
        and obs.get("classification") in ("needs_review", "suspicious", "high_risk", "unknown")
        for obs in n.get("observations", [])
    ) or n.get("scan_status") not in (None, "complete") or bool(n.get("scan_gaps"))
    return bool(
        p.get("high_cpu")
        or p.get("high_mem")
        or p.get("suspicious_name")
        or p.get("suspicious_path")
        or p.get("zombies")
        or n.get("unexpected_listening")
        or n.get("external_connections")
        or s.get("failed")
        or f.get("auth_log")
        or network_attention
    )
