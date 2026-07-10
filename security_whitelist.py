"""
security_whitelist.py
─────────────────────
Configuration file for whitelisting known-safe IPs, ports, and other security exceptions.
Edit this file to add your own trusted items.
"""

# ─── SAFE IPs ─────────────────────────────────────────────
# Add your known-safe external IP addresses here (your office, home, etc.)
# These IPs won't be flagged as suspicious in external connections
SAFE_EXTERNAL_IPS = {
    "121.58.203.121",  # Your SSH connection
    # Add more IPs as needed:
    # "203.0.113.5",   # Example: Office IP
    # "198.51.100.10", # Example: Home IP
}

# ─── SAFE PORTS ──────────────────────────────────────────
# Ports that are known to be safe for listening
SAFE_PORTS = {
    22,      # SSH
    53,      # DNS
    80,      # HTTP
    443,     # HTTPS
    5001,    # Custom application port
    3306,    # MySQL
    5432,    # PostgreSQL
    6379,    # Redis
    8080,    # HTTP alternate
    8443,    # HTTPS alternate
    27017,   # MongoDB
}

# ─── SAFE LOCALHOST ADDRESSES ───────────────────────────
# Localhost addresses that are safe (systemd-resolved, etc.)
SAFE_LOCALHOST_ADDRS = {
    "127.0.0.53",  # systemd-resolved
    "127.0.0.54",  # systemd-resolved
}

# ─── SAFE USERNAMES ──────────────────────────────────────
# Known administrator usernames
SAFE_ADMIN_USERS = {
    "ubuntu",    # Default Ubuntu user
    "admin",
    # Add your admin usernames here
}

# ─── SAFE SSH SOURCE IPs ─────────────────────────────────
# Known safe IPs for SSH connections (your workstation, office, etc.)
SAFE_SSH_SOURCES = {
    "121.58.203.121",  # Your current SSH IP
    # Add more trusted SSH source IPs here
}

# ─── KNOWN LEGITIMATE SERVICES ───────────────────────────
# Services/domains that legitimately make outbound HTTPS connections
# Examples: AWS services, package managers, Docker Hub, GitHub, etc.
LEGITIMATE_OUTBOUND_PATTERNS = {
    "package_updates",     # apt, yum, dnf
    "docker",              # Docker Hub
    "aws_services",        # AWS API calls
    "github",              # Git operations
    "cloudflare",          # CDN
    "letsencrypt",         # SSL certificate renewal
}

# ─── HTTPS OUTBOUND CONNECTION POLICY ────────────────────
# By default, don't flag HTTPS (443) outbound connections as highly suspicious
# unless there are OTHER red flags (suspicious processes, high volumes, etc.)
ALLOW_NORMAL_HTTPS_OUTBOUND = True

# Maximum number of concurrent HTTPS connections before flagging as suspicious
# Normal servers might have 5-20 connections for updates, APIs, etc.
MAX_NORMAL_HTTPS_CONNECTIONS = 30
