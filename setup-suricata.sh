#!/bin/bash

# This script automates the installation and configuration of Suricata in IPS mode on clean Ubuntu 24.04 machine

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Check if sudo is available
if ! command -v sudo &> /dev/null; then
    print_error "sudo is not installed or not available. Please install sudo first."
    exit 1
fi

print_status "Starting Suricata IPS setup on Ubuntu 24.04..."

# Step 1: System Update
print_status "Step 1/8: Updating system packages..."
sudo apt update && sudo apt upgrade -y
print_success "System update completed"

# Step 2: Installing Dependencies
print_status "Step 2/8: Installing dependencies..."
sudo apt install -y software-properties-common curl jq iptables-persistent libnetfilter-queue1 libnfnetlink0
print_success "Dependencies installed"

# Step 3: Kernel Configuration for Docker Bridge Traffic Filtering
print_status "Step 3/8: Configuring kernel for Docker bridge traffic filtering..."
sudo modprobe br_netfilter
echo "br_netfilter" | sudo tee /etc/modules-load.d/br_netfilter.conf
cat << EOF | sudo tee /etc/sysctl.d/99-bridge-nf.conf
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
EOF
sudo sysctl -p /etc/sysctl.d/99-bridge-nf.conf
print_success "Kernel configuration completed"

# Step 4: Installing Suricata from Official PPA Repository
print_status "Step 4/8: Installing Suricata from OISF PPA repository..."
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata
print_success "Suricata installed"

# Step 5: Creating and Adding Basic Rules
print_status "Step 5/8: Creating custom Suricata rules..."
sudo mkdir -p /etc/suricata/rules
cat << 'EOF' | sudo tee /etc/suricata/rules/local.rules
# Lab 1
# Block all ICMP packets — basic IPS test
drop icmp any any -> any any (msg:"[IPS] BLOCK ICMP"; sid:1000007; rev:1;)
# Log HTTP requests — basic IDS test
alert http any any -> any any (msg:"[IDS] HTTP Request Detected"; sid:100002; rev:1; flow:to_server; classtype:policy-violation;)

# Lab 2
# SYN scan (nmap -sS) — block
drop tcp any any -> any any (flags:S; msg:"[IPS] NMAP SYN Scan Blocked"; threshold: type both, track by_src, count 10, seconds 6; sid:1001001; rev:1;)
# XMAS scan (nmap -sX) — alert
alert tcp any any -> any any (flags:FPU; msg:"[IDS] NMAP XMAS Scan Detected"; threshold: type both, track by_src, count 5, seconds 6; sid:1001002; rev:1;)
# UDP scan (nmap -sU) — block
drop udp any any -> any any (msg:"[IPS] NMAP UDP Scan Blocked"; threshold: type both, track by_src, count 10, seconds 10; sid:1001003; rev:1;)
# OS fingerprinting (nmap -O) — alert
alert ip any any -> any any (msg:"[IDS] Possible OS Fingerprinting Attempt"; ipopts: any; threshold: type both, track by_src, count 5, seconds 20; sid:1001101; rev:1;)
# ACK scan (nmap -sA) — alert
alert tcp any any -> any any (flags:A; msg:"[IDS] NMAP ACK Scan Detected"; threshold: type both, track by_src, count 5, seconds 10; sid:1001004; rev:1;)
# FIN scan (nmap -sF) — alert
alert tcp any any -> any any (flags:F; msg:"[IDS] NMAP FIN Scan Detected"; threshold: type both, track by_src, count 3, seconds 10; sid:1001005; rev:1;)
# NULL scan (nmap -sN) — alert
alert tcp any any -> any any (flags:0; msg:"[IDS] NMAP NULL Scan Detected"; threshold: type both, track by_src, count 2, seconds 10; sid:1001006; rev:1;)

# Lab 3
# ActiveMQ (CVE-2023-46604) - detect OpenWire connections and ProcessBuilder
alert tcp any any -> any 61616 (msg:"[IDS] ActiveMQ OpenWire Connection"; flow:to_server,established; threshold: type limit, track by_src, count 1, seconds 300; sid:3000001; rev:1;)
drop tcp any any -> any 61616 (msg:"[IPS] ActiveMQ ProcessBuilder Exploit Blocked"; flow:to_server,established; content:"ProcessBuilder"; nocase; threshold: type limit, track by_src, count 1, seconds 60; sid:3000002; rev:1;)
drop tcp any any -> any 61616 (msg:"[IPS] ActiveMQ ClassPathXmlApplicationContext Blocked"; flow:to_server,established; content:"ClassPathXmlApplicationContext"; nocase; threshold: type limit, track by_src, count 1, seconds 60; sid:3000003; rev:1;)
# Redis - detect unauthorized access and dangerous operations
alert tcp any any -> any 6379 (msg:"[IDS] Redis Unauthorized Access"; flow:to_server,established; threshold: type limit, track by_src, count 1, seconds 300; sid:3000101; rev:1;)
drop tcp any any -> any 6379 (msg:"[IPS] Redis Config Manipulation Blocked"; flow:to_server,established; content:"config set dir"; nocase; threshold: type limit, track by_src, count 1, seconds 60; sid:3000102; rev:1;)
alert tcp any any -> any 6379 (msg:"[IDS] Redis SAVE Command Detected"; flow:to_server,established; content:"save"; nocase; sid:3000103; rev:1;)
alert tcp any any -> any 6379 (msg:"[IDS] Redis FLUSHALL Command Detected"; flow:to_server,established; content:"flushall"; nocase; sid:3000104; rev:1;)
# MinIO (CVE-2023-28432) - detect bootstrap verify exploitation
drop http any any -> any 9000 (msg:"[IPS] MinIO CVE-2023-28432 Exploitation Blocked"; flow:to_server,established; http_uri; content:"/minio/bootstrap/v1/verify"; http_method; content:"POST"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000201; rev:1;)
alert http any any -> any 9000 (msg:"[IDS] MinIO S3 API Operation Detected"; flow:to_server,established; http_header; content:"aws4_request"; sid:3000202; rev:1;)
# Samba (CVE-2017-7494) - detect SMB library uploads
alert smb any any -> any 445 (msg:"[IDS] SMB Shared Library Upload"; flow:to_server,established; smb_command:write; filename:".so"; sid:3000301; rev:1;)
drop smb any any -> any 445 (msg:"[IPS] SambaCry Library Upload Blocked"; flow:to_server,established; smb_command:write; filename:"libbindshell-samba.so"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000302; rev:1;)
alert tcp any any -> any 6699 (msg:"[IDS] SambaCry Bind Shell Connection"; flow:to_server; threshold: type limit, track by_src, count 1, seconds 60; sid:3000303; rev:1;)
# Jenkins (CVE-2024-23897) - detect file read exploitation
drop http any any -> any 8080 (msg:"[IPS] Jenkins File Read Exploitation Blocked"; flow:to_server,established; http_request_body; content:"@/"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000401; rev:1;)
alert http any any -> any 8080 (msg:"[IDS] Jenkins CLI JAR Download"; flow:to_server,established; http_uri; content:"jenkins-cli.jar"; sid:3000402; rev:1;)
alert http any any -> any 8080 (msg:"[IDS] Jenkins System File Access"; flow:to_server,established; http_request_body; pcre:"/@\/(etc|proc|var)/"; sid:3000403; rev:1;)
# Generic post-exploitation detection
alert tcp any any -> any any (msg:"[IDS] Reverse Shell Pattern /bin/sh Detected"; flow:established; content:"/bin/sh"; nocase; sid:3000501; rev:1;)
alert tcp any any -> any any (msg:"[IDS] Reverse Shell Pattern /bin/bash Detected"; flow:established; content:"/bin/bash"; nocase; sid:3000502; rev:1;)
alert tcp any any -> any 4444 (msg:"[IDS] Connection to Metasploit Port 4444"; flow:to_server; threshold: type limit, track by_dst, count 1, seconds 60; sid:3000503; rev:1;)
alert tcp any any -> any 4445 (msg:"[IDS] Connection to Metasploit Port 4445"; flow:to_server; threshold: type limit, track by_dst, count 1, seconds 60; sid:3000504; rev:1;)
# ==========================
# Lab 4: OWASP Top 10 — Juice Shop (HTTP)  [v2]
# Корректные буферы: http.uri / http.method / http.request_body
# ==========================

# --- A01: Broken Access Control (IDOR: /rest/basket/<id>) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] IDOR basket access attempt"; flow:to_server,established; http.uri; pcre:"/\\/rest\\/basket\\/\\d+(\\/)?$/"; classtype:web-application-attack; sid:4601001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] IDOR basket enumeration detected"; flow:to_server,established; http.uri; pcre:"/\\/rest\\/basket\\/\\d+(\\/)?$/"; threshold:type both, track by_src, count 3, seconds 10; classtype:web-application-attack; sid:4601002; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] IDOR basket enumeration blocked"; flow:to_server,established; http.uri; pcre:"/\\/rest\\/basket\\/\\d+(\\/)?$/"; threshold:type both, track by_src, count 5, seconds 10; sid:4601101; rev:1;)

# --- A02: Cryptographic Failures (backup, Poison Null Byte, coupons) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] FTP directory access"; flow:to_server,established; http.uri; content:"/ftp/"; classtype:policy-violation; sid:4602001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Backup file access attempt"; flow:to_server,established; http.uri; pcre:"/\\.bak(\\b|$)/i"; classtype:policy-violation; sid:4602002; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Poison Null Byte detected"; flow:to_server,established; http.uri; pcre:"/%00|%2500/i"; classtype:web-application-attack; sid:4602003; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Sensitive file access (coupons)"; flow:to_server,established; http.uri; content:"coupons"; nocase; classtype:policy-violation; sid:4602004; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Poison Null Byte blocked"; flow:to_server,established; http.uri; pcre:"/%00|%2500/i"; sid:4602101; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Backup file access blocked"; flow:to_server,established; http.uri; pcre:"/\\.bak(\\b|$)/i"; sid:4602102; rev:1;)

# --- A03: Injection (SQLi) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SQLi OR 1=1 detected"; flow:to_server,established; http.request_body; pcre:"/or\\s+1=1/i"; classtype:web-application-attack; sid:4603001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SQLi UNION SELECT detected"; flow:to_server,established; http.uri; pcre:"/union\\s+select/i"; classtype:web-application-attack; sid:4603002; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SQLi comment found"; flow:to_server,established; http.request_body; content:"--"; classtype:web-application-attack; sid:4603003; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] SQLi blocked on login"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; http.request_body; pcre:"/or\\s+1=1|union\\s+select/i"; sid:4603101; rev:1;)

# --- A04: Insecure Design (no rate limiting on login) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Login brute-force (>=5 in 10s)"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 5, seconds 10; classtype:attempted-recon; sid:4604001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Aggressive login brute-force (>=10 in 30s)"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 10, seconds 30; classtype:attempted-recon; sid:4604002; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Login brute-force blocked"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 5, seconds 10; sid:4604101; rev:1;)

# --- A05: Security Misconfiguration ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Metrics endpoint access"; flow:to_server,established; http.uri; content:"/metrics"; classtype:policy-violation; sid:4605001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Security Questions API access"; flow:to_server,established; http.uri; content:"/api/SecurityQuestions"; classtype:policy-violation; sid:4605002; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Score Board access"; flow:to_server,established; http.uri; content:"/score-board"; classtype:policy-violation; sid:4605003; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Metrics access blocked"; flow:to_server,established; http.uri; content:"/metrics"; sid:4605101; rev:1;)
drop  http !$HOME_NET any -> $HOME_NET 3000 (msg:"[IPS] External Score Board access blocked"; flow:to_server,established; http.uri; content:"/score-board"; sid:4605102; rev:1;)

# --- A06: Vulnerable/Outdated Components (fingerprinting) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Error page fingerprinting attempt"; flow:to_server,established; http.uri; pcre:"/\\.(txt|exe|dll|jsp)$/i"; classtype:attempted-recon; sid:4606001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Dependency config access"; flow:to_server,established; http.uri; pcre:"/(package\\.json|composer\\.json|requirements\\.txt)/i"; classtype:attempted-recon; sid:4606002; rev:1;)

# --- A07: Identification & Authentication Failures ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SQLi auth bypass"; flow:to_server,established; http.uri; content:"/rest/user/login"; http.request_body; pcre:"/or\\s+1=1/i"; classtype:web-application-attack; sid:4607001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Multiple failed login attempts"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 5, seconds 30; classtype:attempted-recon; sid:4607002; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Failed login threshold exceeded"; flow:to_server,established; http.uri; content:"/rest/user/login"; threshold:type both, track by_src, count 10, seconds 30; sid:4607101; rev:1;)

# --- A08: XSS ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] XSS script tag detected"; flow:to_server,established; http.uri; content:"<script"; nocase; classtype:web-application-attack; sid:4608001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] XSS event handler detected"; flow:to_server,established; http.uri; pcre:"/on(load|error|click)\\s*=/i"; classtype:web-application-attack; sid:4608002; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] XSS javascript: URI detected"; flow:to_server,established; http.uri; content:"javascript:"; nocase; classtype:web-application-attack; sid:4608003; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] XSS iframe injection detected"; flow:to_server,established; http.uri; content:"<iframe"; nocase; classtype:web-application-attack; sid:4608004; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] XSS img onerror detected"; flow:to_server,established; http.uri; content:"<img"; nocase; content:"onerror"; nocase; distance:50; classtype:web-application-attack; sid:4608005; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] XSS script blocked"; flow:to_server,established; http.uri; content:"<script"; nocase; sid:4608101; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] XSS javascript URI blocked"; flow:to_server,established; http.uri; content:"javascript:"; nocase; sid:4608102; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] XSS iframe blocked"; flow:to_server,established; http.uri; content:"<iframe"; nocase; sid:4608103; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] XSS event handler blocked"; flow:to_server,established; http.uri; pcre:"/on(load|error|click)\\s*=/i"; sid:4608104; rev:1;)

# --- A09: Logging & Monitoring Failures ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Log directory access"; flow:to_server,established; http.uri; content:"/support/logs"; classtype:policy-violation; sid:4609001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] Log file download"; flow:to_server,established; http.uri; pcre:"/support\\/logs\\/(access\\.log|audit\\.json)/"; classtype:policy-violation; sid:4609002; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] Log access blocked"; flow:to_server,established; http.uri; content:"/support/logs"; sid:4609101; rev:1;)

# --- A10: SSRF (profile image URL) ---
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SSRF AWS metadata attempt"; flow:to_server,established; http.request_body; content:"169.254.169.254"; classtype:web-application-attack; sid:4610001; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SSRF localhost targeting"; flow:to_server,established; http.request_body; pcre:"/(localhost|127\\.0\\.0\\.1)/i"; classtype:web-application-attack; sid:4610002; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SSRF internal IP targeting"; flow:to_server,established; http.request_body; pcre:"/(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)/"; classtype:web-application-attack; sid:4610003; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SSRF via profile image URL endpoint"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/profile/image/url"; classtype:policy-violation; sid:4610004; rev:1;)
alert http any any -> $HOME_NET 3000 (msg:"[IDS] SSRF file:// protocol attempt"; flow:to_server,established; http.request_body; content:"file://"; nocase; classtype:web-application-attack; sid:4610005; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] SSRF AWS metadata blocked"; flow:to_server,established; http.request_body; content:"169.254.169.254"; sid:4610101; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] SSRF localhost blocked"; flow:to_server,established; http.request_body; pcre:"/(localhost|127\\.0\\.0\\.1)/i"; sid:4610102; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] SSRF internal IP blocked"; flow:to_server,established; http.request_body; pcre:"/(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)/"; sid:4610103; rev:1;)
drop  http any any -> $HOME_NET 3000 (msg:"[IPS] SSRF file protocol blocked"; flow:to_server,established; http.request_body; content:"file://"; nocase; sid:4610104; rev:1;)

# ==========================
# END Lab 4 v2
EOF
print_success "Custom rules created (including Lab 3 & Lab 4)"

# Step 6: Basic suricata.yaml Configuration
print_status "Step 6/8: Configuring suricata.yaml..."
# Create backup of original configuration
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
print_warning "Original suricata.yaml backed up to suricata.yaml.bak"

cat << 'EOF' | sudo tee /etc/suricata/suricata.yaml
%YAML 1.1
---
runmodes:
- runmode: workers
# NFQUEUE for IPS
nfqueue:
  mode: accept
  repeat-mark: 1
  repeat-mask: 1
  bypass-mark: 2
  bypass-mask: 2
  queue-balance:
    - 0-3
# Rules
rule-files:
  - /etc/suricata/rules/local.rules
# EVE — main log
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - drop
        - http
        - dns
# Disable unnecessary features for simplicity
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
app-layer:
  protocols:
    http: enabled
    dns: enabled
    tls: enabled
# Logging
logging:
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        level: info
        filename: suricata.log
EOF
print_success "Suricata configuration completed"

# Step 7: Configuring iptables for Docker Traffic Interception
print_status "Step 7/8: Configuring iptables for Docker traffic interception..."
sudo iptables -D DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true
sudo iptables -I DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass
sudo netfilter-persistent save
print_success "iptables configuration completed"

# Step 8: Setting Permissions and Systemd Service
print_status "Step 8/8: Setting permissions and configuring systemd service..."
sudo setcap cap_net_admin,cap_net_raw+ep /usr/bin/suricata
sudo mkdir -p /etc/systemd/system/suricata.service.d
cat << 'EOF' | sudo tee /etc/systemd/system/suricata.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 1 --pidfile /run/suricata.pid
EOF
sudo systemctl daemon-reload
sudo systemctl enable suricata
sudo systemctl restart suricata

# Check if Suricata is running
if sudo systemctl is-active --quiet suricata; then
    print_success "Suricata service is running"
    sudo systemctl status suricata --no-pager
else
    print_error "Suricata service failed to start"
    sudo systemctl status suricata --no-pager
    exit 1
fi


# Final instructions
echo ""
print_success "🎉 Suricata IPS setup completed successfully!"
echo ""
print_status "Next steps:"
echo "1. Start Labs:"
echo "   docker compose up -d"
echo ""
echo "2. Install tools in attacker container:"
echo "   docker exec attacker apt update && docker exec attacker apt install -y curl iputils-ping nmap"
echo ""
echo "3. Test basic IPS/IDS functionality:"
echo "   docker exec attacker ping -c 4 172.16.90.10"
echo "   docker exec attacker curl -s http://172.16.90.10:8000"
echo ""
echo "4. Monitor Suricata logs:"
echo "   sudo tail -f /var/log/suricata/eve.json"
echo ""
echo "5. Access EveBox UI:"
echo "   http://localhost:5636"
echo ""
print_warning "Note: All Lab 3 protection rules are already installed and active!"
print_warning "Make sure Docker is installed and running before starting the lab environment."
