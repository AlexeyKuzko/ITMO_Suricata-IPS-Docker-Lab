# ITMO Network Security | Suricata IDS/IPS: Docker Lab
The project demonstrates the way to install and run Suricata in IPS mode on the Ubuntu host, provides a Docker lab environment with attacker/victim containers, adds EveBox for UI-driven analysis, and provide hands-on experience with both basic rules (ICMP block, HTTP alert) and advanced Nmap scan detection/blocking — all in one cohesive setup.

## Practical Part: Installing and Configuring Suricata in IPS Mode on Ubuntu 24.04

### 🛠️ Installation Steps

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

### 🐳 Docker Compose Lab Environment

Create a `docker-compose.yml` file with the following content:

```yaml
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
```

Start the lab environment: `docker compose up -d`

Install necessary utilities in containers:
```bash
docker exec attacker apt update && docker exec attacker apt install -y curl iputils-ping
```

### ✅ Testing Suricata Operation

1.  **Testing IPS Mode (ICMP Blocking)**
    Execute ping from `attacker` container to `victim` container:
    ```bash
    docker exec attacker ping -c 4 172.16.90.10
    ```
    *Expected result:* Packets should be lost (100% packet loss). The command won't receive a response as the rule with `drop` action blocks all ICMP traffic.

2.  **Testing IDS Mode (HTTP Logging)**
    Send HTTP request from `attacker` container to `victim` web server:
    ```bash
    docker exec attacker curl -s http://172.16.90.10:8000
    ```
    *Expected result:* The command should execute successfully and return directory listing, as the HTTP rule is configured only for alerting (`alert`), not blocking.

3.  **Analyzing Suricata Logs**
    To view events in real-time, use `jq` for convenient JSON log formatting of `eve.json`:
    ```bash
    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != "flow")'
    ```
    *Expected result:*
    -   When executing ping, events with `event_type: "drop"` and message `"[IPS] BLOCK ICMP"` should appear in the log.
    -   When executing curl, events with `event_type: "alert"` and message `"[IDS] HTTP Request Detected"` should appear in the log, as well as events with `event_type: "http"` containing HTTP request details.

### ⚠️ Bonus Task: IPS Limitations in Docker

Running Suricata in **IPS mode inside a Docker container** comes with serious challenges:

1.  **Network Architecture**: IPS mode requires traffic to pass *through* Suricata (inline mode). In Docker, this is difficult to organize, as by default traffic between containers in the same network goes directly through the bridge, bypassing other containers. A workaround is using `host` network mode or forwarding network interfaces to the container, which reduces isolation and security.
2.  **Traffic Capture Drivers**: For inline operation in Linux, Suricata typically uses the **NFQUEUE** mechanism (which iptables are configured for in this guide) or **AF_PACKET**. NFQUEUE configuration requires modifying iptables rules on the host, which can be difficult to manage from a container. AF_PACKET in IPS mode (with `copy-mode: ips` option) often requires direct work with physical or bridge interfaces, which is problematic inside a container without additional privileges and configurations.
3.  **Privileges and Capabilities**: A Suricata container in IPS mode requires elevated privileges (`NET_ADMIN`, `SYS_NICE`, `NET_RAW`) and access to host network namespaces, which contradicts containerization principles and minimal privileges.
4.  **Performance and Scalability**: Processing all traffic in a single container can become a bottleneck. In production environments, specialized network solutions (e.g., AWS Gateway Load Balancer with GENEVE) are often used for IPS scaling, which redirect traffic through a group of Suricata instances.

**Conclusion:** It's much simpler and more reliable to run Suricata in **IPS mode directly on the host** (as done in this lab work), where it has direct access to network interfaces and full control over the network stack. Inside Docker environments, it's more natural and simple to use Suricata in **IDS mode**, for example, in network interface monitoring mode or analyzing mirrored traffic (SPAN port).

## 📁 Repository Structure

```
ITMO_Suricata-IPS-Docker-Lab/
├── README.md                 # Unified lab guide (this file)
├── docker-compose.yml        # Attacker/Victim lab and optional EveBox service
└── setup-suricata.sh         # Host-side setup: Suricata, NFQUEUE, rules, restart
```

## 🔗 Useful Links

1.  [Official Suricata Documentation](https://docs.suricata.io) 
2.  [Suricata Community and Forum](https://forum.suricata.io) 
3.  [OISF Suricata Repository on GitHub](https://github.com/OISF/suricata)
4.  [Article on Building Scalable IDS/IPS with Suricata in AWS](https://www.tecracer.com/blog/2024/05/build-a-scalable-ids-and-ips-solution-using-suricata-and-aws-gateway-load-balancer.html) 


## Detecting and Blocking Nmap Scans with Suricata

### Theory (brief)
- **Port scanning** helps find open/closed ports and potential vulnerabilities.
- **nmap** scan types: SYN `-sS`, Connect `-sT`, UDP `-sU`, XMAS `-sX`, OS fingerprinting `-O`, etc.
- **Suricata** can detect/block scans via signature rules, operate in IPS mode (drop) or IDS (alert), and logs to `eve.json` for investigation.

### Environment
- Docker Compose includes `attacker` and `victim` containers used to generate traffic.
- Optionally, include `evebox` to view Suricata events at `http://localhost:5636`.
- `evebox` reads Suricata EVE logs from the host: `/var/log/suricata/eve.json` (mounted read-only).

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

### Generate test traffic (from attacker)
Install tools and run scans:

```bash
docker exec attacker apt update
docker exec attacker apt install -y nmap iputils-ping curl

# SYN scan
docker exec attacker nmap -sS 172.16.90.10

# XMAS scan
docker exec attacker nmap -sX 172.16.90.10

# UDP scan
docker exec attacker nmap -sU 172.16.90.10

# OS fingerprinting
docker exec attacker nmap -O 172.16.90.10
```

### Verify logs and EveBox
- Raw logs: `sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type != "flow")'`
- EveBox UI: open `http://localhost:5636` and filter by `event_type:alert` or `event_type:drop`.
- Expect `drop` events for blocked scans (e.g., SYN/UDP) and `alert` for detected-only techniques.

### Blocking strategy
- Use `drop` for noisy and clear patterns (SYN, UDP scans).
- Use `alert` for OS fingerprinting and rare techniques to review before enforcing.

### Reducing false positives
- Tune `threshold` values: increase `count`/`seconds` or scope by `src_ip`.
- Add IP-based exceptions for known scanners.

### Extra: quick jq stats by source IP
```bash
# Top sources by alerts/drops
jq -r 'select(.event_type=="alert" or .event_type=="drop") | .src_ip' /var/log/suricata/eve.json | sort | uniq -c | sort -nr | head

# Count by signature message
jq -r 'select(.event_type=="alert" or .event_type=="drop") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -nr | head
```