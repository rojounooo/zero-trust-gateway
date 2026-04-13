# Setup Guide – Zero Trust Gateway for Hospital Networks

This guide describes how to deploy the Zero Trust gateway from this repository.

Two deployment options are supported:

1. Raspberry Pi (ARM) gateway + laptop / separate webapp machine
2. Single host machine using two VirtualBox VMs (recommended)

---

## 1. Repository Layout

- gateway/arm/ – ARM (Raspberry Pi) gateway configuration
- gateway/vm/ – VM gateway configuration
- ingestion/ – FastAPI ingestion API
- detection/ – Detection engine and rules
- webapp/ – Protected FastAPI web application
- simulation/ – Traffic generation scripts
- logs/ – Monitoring and analysis scripts

---

## 2. Virtual Machine Setup

### Gateway VM
- 8GB RAM
- 4 CPU cores
- 25GB disk
- Adapter 1: Bridged
- Adapter 2: Internal Network (hospital-lan)

### Webapp VM
- 2GB RAM
- 2 CPU cores
- 25GB disk
- Adapter 1: Internal Network (hospital-lan)
- Adapter 2: Bridged (temporary)

---

## 3. Install Ubuntu Server

Install Ubuntu Server 24.04.4 LTS on both machines.

Enable OpenSSH during setup.

Check interfaces:

    ip a

---

## 4. Gateway Setup

Install dependencies:

    sudo apt update
    sudo apt install -y python3 python3-pip openssh-server iptables-persistent git curl

Configure Docker:

    ```bash
    sudo apt update && sudo apt install -y ca-certificates curl gnupg

    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    sudo usermod -aG docker $USER
    newgrp docker
    ```

Verify:

    ```bash
    docker --version
    docker compose version
    ```

Clone repo:

    git clone https://github.com/rojounooo/zero-trust-gateway.git

---

## 5. Log Setup

    mkdir -p ~/log
    touch ~/log/events.log
    touch ~/log/alerts.log
    touch ~/log/blocklist.txt
    touch ~/log/monitor.log

---

## 6. Networking (Gateway)

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

```yaml
network:
  version: 2
  ethernets:
    <bridged interface>:
      dhcp4: true
    <internal interface>:
      addresses: [10.0.0.1/24]
```

```bash
sudo netplan apply
ip addr show <internal interface>
```

---

## 7. Firewall and IP Routing

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

sudo iptables -t nat -A POSTROUTING -o <bridged interface> -j MASQUERADE
sudo iptables -A FORWARD -i <internal interface> -o <bridged interface> -j ACCEPT
sudo iptables -A FORWARD -i <bridged interface> -o <internal interface> -m state --state RELATED,ESTABLISHED -j ACCEPT

sudo netfilter-persistent save
```

---

## 8. Webapp Setup

Install dependencies:

    sudo apt update
    sudo apt install -y python3 python3-pip
    pip3 install -r webapp/requirements.txt

Networking:

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

```yaml
network:
  version: 2
  ethernets:
    <internal interface>:
      addresses: [10.0.0.2/24]
      routes:
        - to: default
          via: 10.0.0.1
      nameservers:
        addresses: [8.8.8.8]
    <bridged interface>:
      dhcp4: true # Remove bridged interface after webapp is accessible
```

---

## 9. Gateway Stack

VM:

    cd gateway/vm
    docker-compose up -d

ARM:

    cd gateway/arm/opa-arm
    docker build -t opa .
    cd ..
    docker-compose up -d

---

## 10. Systemd Services

The webapp, ingestion API, detector, and monitor all run as background systemd services so they start automatically on boot and restart on failure.

Replace `<your-user>` with your Linux username (e.g. `ubuntu` or `rojo`) and adjust the repo path if it differs from `/home/<your-user>/zero-trust-gateway`.

---

### 10.1 Webapp

Create the unit file:

```bash
sudo nano /etc/systemd/system/webapp.service
```

```ini
[Unit]
Description=Zero Trust Hospital Webapp
After=network.target

[Service]
User=<your-user>
WorkingDirectory=/home/<your-user>/zero-trust-gateway/webapp
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

### 10.2 Ingestion API

Create the unit file:

```bash
sudo nano /etc/systemd/system/ingestion.service
```

```ini
[Unit]
Description=Zero Trust Ingestion API
After=network.target

[Service]
User=<your-user>
WorkingDirectory=/home/<your-user>/zero-trust-gateway/ingestion
ExecStart=/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 12345
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

### 10.3 Detector

Create the unit file:

```bash
sudo nano /etc/systemd/system/detector.service
```

```ini
[Unit]
Description=Zero Trust Detector
After=network.target ingestion.service

[Service]
User=<your-user>
WorkingDirectory=/home/<your-user>/zero-trust-gateway/detection
ExecStart=/usr/bin/python3 detector.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

### 10.4 Monitor

Create the unit file:

```bash
sudo nano /etc/systemd/system/monitor.service
```

```ini
[Unit]
Description=Zero Trust Monitor
After=network.target detector.service

[Service]
User=<your-user>
WorkingDirectory=/home/<your-user>/zero-trust-gateway/logs
ExecStart=/usr/bin/python3 monitor.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

### 10.5 Enable and Start All Services

Run these commands after creating all four unit files:

```bash
sudo systemctl daemon-reload

sudo systemctl enable webapp ingestion detector monitor
sudo systemctl start webapp ingestion detector monitor
```

Check status:

```bash
sudo systemctl status webapp
sudo systemctl status ingestion
sudo systemctl status detector
sudo systemctl status monitor
```

View live logs for any service:

```bash
sudo journalctl -u webapp -f
sudo journalctl -u ingestion -f
sudo journalctl -u detector -f
sudo journalctl -u monitor -f
```

---

## 11. Ingestion (manual alternative)

    cd ingestion
    pip3 install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 12345

---

## 12. Detection (manual alternative)

    cd detection
    pip3 install -r requirements.txt
    python3 detector.py

---

## 13. Monitor (manual alternative)

    cd logs
    python3 monitor.py

---

## 14. Simulation

Run from separate machine:

    cd simulation
    pip install -r requirements.txt
    python main.py

---

## 15. Verification

Check connectivity:

    ping 10.0.0.2

Check logs:

    tail -f ~/log/events.log
    tail -f ~/log/alerts.log
    tail -f ~/log/monitor.log

---

## Notes

- Use `ip a` to confirm interface names
- Update IPs in config files
- Ensure services are running before starting simulation
- If using a virtual environment, replace `/usr/bin/python3` in unit files with the full path to the venv Python binary, e.g. `/home/<your-user>/zero-trust-gateway/venv/bin/python3`