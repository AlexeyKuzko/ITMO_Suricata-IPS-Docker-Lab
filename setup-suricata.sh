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
# Block all ICMP packets — basic IPS test
drop icmp any any -> any any (msg:"[IPS] BLOCK ICMP"; sid:1000007; rev:1;)
# Log HTTP requests — basic IDS test
alert http any any -> any any (msg:"[IDS] HTTP Request Detected"; sid:100002; rev:1; flow:to_server; classtype:policy-violation;)
EOF
print_success "Custom rules created"

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

# Create docker-compose.yml file
print_status "Creating docker-compose.yml file..."
cat << 'EOF' > docker-compose.yml
version: '3.8'

services:
  victim:
    image: alpine:latest
    container_name: victim
    hostname: victim
    networks:
      suricata-lab:
        ipv4_address: 172.16.90.10
    command: sh -c "apk add --no-cache python3 && python3 -m http.server 8000"
    # Run a simple HTTP server on port 8000

  attacker:
    image: kalilinux/kali-rolling:latest
    container_name: attacker
    hostname: attacker
    networks:
      suricata-lab:
        ipv4_address: 172.16.90.20
    command: tail -f /dev/null
    # Container will run in background

networks:
  suricata-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.90.0/24
EOF
print_success "docker-compose.yml created"

# Final instructions
echo ""
print_success "🎉 Suricata IPS setup completed successfully!"
echo ""
print_status "Next steps:"
echo "1. Start the Docker lab environment:"
echo "   docker compose up -d"
echo ""
echo "2. Install utilities in the attacker container:"
echo "   docker exec attacker apt update && docker exec attacker apt install -y curl iputils-ping"
echo ""
echo "3. Test IPS mode (ICMP blocking):"
echo "   docker exec attacker ping -c 4 172.16.90.10"
echo ""
echo "4. Test IDS mode (HTTP logging):"
echo "   docker exec attacker curl -s http://172.16.90.10:8000"
echo ""
echo "5. Monitor Suricata logs:"
echo "   sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != \"flow\")'"
echo ""
print_warning "Note: Make sure Docker is installed and running before starting the lab environment."
