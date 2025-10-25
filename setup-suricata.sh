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
EOF
print_success "Custom rules created (including Lab 3 vulnerable services protection)"

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
echo "1. Start Lab 1 & 2 (basic environment):"
echo "   docker compose up -d"
echo ""
echo "2. Start Lab 3 (vulnerable services):"
echo "   docker compose -f docker-compose.lab3.yml up -d"
echo ""
echo "3. Install tools in attacker container:"
echo "   docker exec attacker apt update && docker exec attacker apt install -y curl iputils-ping nmap"
echo ""
echo "4. Test basic IPS/IDS functionality:"
echo "   docker exec attacker ping -c 4 172.16.90.10"
echo "   docker exec attacker curl -s http://172.16.90.10:8000"
echo ""
echo "5. Monitor Suricata logs:"
echo "   sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != \"flow\")'"
echo ""
echo "6. Access EveBox UI:"
echo "   http://localhost:5636"
echo ""
print_warning "Note: All Lab 3 protection rules are already installed and active!"
print_warning "Make sure Docker is installed and running before starting the lab environment."
