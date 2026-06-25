"""
security_scanner.py
───────────────────
Collects security-relevant signals from each EC2 instance using psutil (local)
or SSH (remote). Returns a structured dict of findings per instance.

Called by the scheduled 11 PM job and by the /security command.
"""

import json
import subprocess
import threading
from datetime import datetime

import psutil

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

def collect_local(inst_name: str) -> dict:
    """Gather security signals from the local machine using psutil + subprocess."""
    findings = _base_findings(inst_name, "local")

    with _lock:
        _scan_processes_local(findings)
        _scan_network_local(findings)
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

            # Zombie check
            if status == psutil.STATUS_ZOMBIE:
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


def _scan_network_local(f: dict):
    listening = []
    established = []
    suspicious_conns = []

    # Well-known safe ports — extend as needed
    safe_listening = {22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017}

    for conn in psutil.net_connections(kind="inet"):
        try:
            laddr = conn.laddr
            raddr = conn.raddr
            status = conn.status

            if status == "LISTEN":
                port = laddr.port if laddr else None
                if port and port not in safe_listening:
                    listening.append({"port": port, "addr": str(laddr)})

            elif status == "ESTABLISHED" and raddr:
                rip = raddr.ip
                # Flag non-RFC1918 outbound connections (public IPs)
                if not _is_private_ip(rip):
                    established.append({
                        "local":  str(laddr),
                        "remote": str(raddr),
                    })
        except Exception:
            continue

    f["network"]["unexpected_listening"] = listening
    f["network"]["external_connections"]  = established[:20]  # cap at 20


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
    """Pull last 50 auth log lines — failed SSH, sudo, new user events."""
    auth = _run_local(
        "grep -Ei 'failed|invalid|error|sudo|useradd|userdel|passwd' "
        "/var/log/auth.log 2>/dev/null | tail -50"
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

# Shared python3 inline script that runs on the remote host
_REMOTE_PYTHON = r"""python3 -c "
import psutil, json, subprocess, os, glob
from datetime import datetime

findings = {
    'processes': {'high_cpu': [], 'high_mem': [], 'suspicious_name': [], 'suspicious_path': [], 'zombies': []},
    'network':   {'unexpected_listening': [], 'external_connections': []},
    'users':     {'logged_in': []},
    'files':     {'recently_modified_system': []},
    'services':  {'failed': [], 'new_units': []},
    'cron':      {'entries': []},
    'auth_log':  [],
}

SUSP_NAMES = {'nc','netcat','ncat','nmap','masscan','socat','xmrig','cgminer','minerd','ethminer','msfconsole','hydra','sqlmap','john','hashcat'}
SUSP_PATHS = ['/tmp/','/dev/shm/','/var/tmp/','/run/shm/']
SAFE_PORTS  = {22,80,443,8080,8443,3306,5432,6379,27017}

def is_private(ip):
    parts = ip.split('.')
    if len(parts) != 4: return True
    try:
        a = int(parts[0]); b = int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127
    except: return True

def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ''

# Processes
for p in psutil.process_iter(['pid','name','exe','username','cpu_percent','memory_percent','status']):
    try:
        i = p.info
        name=i.get('name',''); exe=i.get('exe','') or ''; cpu=i.get('cpu_percent') or 0; mem=i.get('memory_percent') or 0; status=i.get('status',''); user=i.get('username','')
        if status == 'zombie': findings['processes']['zombies'].append({'pid':i['pid'],'name':name})
        if cpu >= 50: findings['processes']['high_cpu'].append({'pid':i['pid'],'name':name,'cpu':round(cpu,1),'user':user,'exe':exe})
        if mem >= 30: findings['processes']['high_mem'].append({'pid':i['pid'],'name':name,'mem':round(mem,1),'user':user,'exe':exe})
        if name.lower() in SUSP_NAMES: findings['processes']['suspicious_name'].append({'pid':i['pid'],'name':name,'exe':exe,'user':user})
        if exe and any(exe.startswith(s) for s in SUSP_PATHS): findings['processes']['suspicious_path'].append({'pid':i['pid'],'name':name,'exe':exe,'user':user})
    except: pass

# Network
for c in psutil.net_connections(kind='inet'):
    try:
        la=c.laddr; ra=c.raddr; st=c.status
        if st=='LISTEN' and la and la.port not in SAFE_PORTS: findings['network']['unexpected_listening'].append({'port':la.port,'addr':str(la)})
        elif st=='ESTABLISHED' and ra and not is_private(ra.ip): findings['network']['external_connections'].append({'local':str(la),'remote':str(ra)})
    except: pass
findings['network']['external_connections'] = findings['network']['external_connections'][:20]

# Users
for u in psutil.users():
    findings['users']['logged_in'].append({'name':u.name,'terminal':u.terminal,'host':u.host,'started':str(datetime.fromtimestamp(u.started))})

# Files
mod = run(\"find /etc /bin /sbin /usr/bin /usr/sbin -newer /tmp -type f -printf '%T+ %p\n' 2>/dev/null | sort -r | head -20\")
findings['files']['recently_modified_system'] = mod.splitlines() if mod else []

# Services
failed = run('systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | head -20')
findings['services']['failed'] = failed.splitlines() if failed else []

# Cron
cron = run('crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null; ls /var/spool/cron/crontabs/ 2>/dev/null')
findings['cron']['entries'] = cron.splitlines() if cron else []

# Auth log
auth = run(\"grep -Ei 'failed|invalid|error|sudo|useradd|userdel|passwd' /var/log/auth.log 2>/dev/null | tail -50\")
findings['auth_log'] = auth.splitlines() if auth else []

print(json.dumps(findings))
"
"""


def collect_remote(inst: dict, ssh_run_fn) -> dict:
    """
    Gather security signals from a remote instance via SSH.
    ssh_run_fn: the ssh_run(inst, cmd) function from main.py
    """
    findings = _base_findings(inst["name"], "remote")

    output = ssh_run_fn(inst, _REMOTE_PYTHON)
    if output is None:
        findings["error"] = "SSH unreachable"
        return findings

    try:
        remote_data = json.loads(output)
        # Merge remote_data into findings
        for section, value in remote_data.items():
            if section in findings:
                findings[section] = value
            else:
                findings[section] = value
    except json.JSONDecodeError as e:
        findings["error"] = f"JSON parse error: {e} | raw: {output[:200]}"

    return findings


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
            "unexpected_listening": [],
            "external_connections": [],
        },
        "users":    {"logged_in": []},
        "files":    {"recently_modified_system": []},
        "services": {"failed": [], "new_units": []},
        "cron":     {"entries": []},
        "auth_log": [],
        "error":    None,
    }


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is RFC1918, loopback, or link-local."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
        )
    except ValueError:
        return True


def has_any_findings(f: dict) -> bool:
    """Return True if there is at least one suspicious signal in the findings."""
    if f.get("error"):
        return True
    p = f.get("processes", {})
    n = f.get("network", {})
    s = f.get("services", {})
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
    )