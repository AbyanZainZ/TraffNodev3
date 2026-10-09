#!/usr/bin/env bash
# TraffNode V3: One-Line VPS Deployment Script (Ubuntu / Debian)
# Port: 8888 (Dashboard) | Ports: 10001-11000 (Relay Gateway)

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}==============================================================================${NC}"
echo -e "${CYAN}       TRAFFNODE V3 COCKPIT: HYBRID HARVESTER & PROXY GATEWAY INSTALLER       ${NC}"
echo -e "${CYAN}==============================================================================${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Harap jalankan script ini sebagai root (sudo bash deploy_vps.sh)${NC}"
  exit 1
fi

INSTALL_DIR="/opt/traffnode"
echo -e "${YELLOW}Menghentikan service lama jika sedang berjalan...${NC}"
systemctl stop traffnode 2>/dev/null || true
pkill -9 -f "app.py" 2>/dev/null || true
pkill -9 -f "cli start accept" 2>/dev/null || true
pkill -9 -f "wireproxy" 2>/dev/null || true
which fuser >/dev/null 2>&1 && fuser -k 10000:11000/tcp 2>/dev/null || true

echo -e "${GREEN}[1/6] Memperbarui sistem & menginstall dependensi...${NC}"
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git curl proxychains4 net-tools procps ufw psmisc
fuser -k 10000:11000/tcp 2>/dev/null || true

echo -e "${GREEN}[2/6] Menyiapkan binary resmi TraffMonetizer CLI (/usr/local/bin/cli)...${NC}"
TM_PATH="/usr/local/bin/cli"
TM_SYMLINK="/usr/local/bin/traffmonetizer"

if [ ! -f "$TM_PATH" ] && [ ! -f "$TM_SYMLINK" ]; then
    echo -e "${YELLOW}Mengunduh binary TraffMonetizer resmi dari Docker Hub...${NC}"
    curl -sL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz | tar -xz -C /usr/local/bin crane || true
    chmod +x /usr/local/bin/crane 2>/dev/null || true
    if [ -x "/usr/local/bin/crane" ]; then
        crane export traffmonetizer/cli_v2:latest - | tar -x -C / usr/local/bin/cli 2>/dev/null || true
    fi
    chmod +x "$TM_PATH" 2>/dev/null || true
    ln -sf "$TM_PATH" "$TM_SYMLINK" 2>/dev/null || true
fi

WP_PATH="/usr/local/bin/wireproxy"
if [ ! -f "$WP_PATH" ]; then
    echo -e "${YELLOW}Mengunduh binary wireproxy (Userspace WireGuard untuk Surfshark)...${NC}"
    curl -sL "https://github.com/windtf/wireproxy/releases/download/v1.1.3/wireproxy_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin wireproxy 2>/dev/null || true
    chmod +x "$WP_PATH" 2>/dev/null || true
fi

echo -e "${GREEN}[3/6] Menyiapkan direktori proyek di ${INSTALL_DIR}...${NC}"
if [ -f "app.py" ] && [ -d "static" ]; then
    CURRENT_DIR=$(pwd)
    if [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
        echo -e "${CYAN}Menyalin file dari ${CURRENT_DIR} ke ${INSTALL_DIR}...${NC}"
        mkdir -p "$INSTALL_DIR"
        cp -a . "$INSTALL_DIR/"
    fi
else
    REPO_URL="${1:-https://github.com/AbyanZainZ/TraffNodeV3.git}"
    echo -e "${YELLOW}Mengunduh source code dari ${REPO_URL}...${NC}"
    if [ -d "$INSTALL_DIR/.git" ]; then
        git -C "$INSTALL_DIR" pull
    else
        rm -rf "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

cd "$INSTALL_DIR"

echo -e "${GREEN}[4/6] Menyiapkan Python Virtual Environment...${NC}"
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

echo -e "${GREEN}[5/6] Tuning Kernel Limits & Konfigurasi Firewall Port 8888 + 10001-11000...${NC}"
ulimit -n 1048576 2>/dev/null || true
ulimit -u 655350 2>/dev/null || true
sysctl -w fs.file-max=2097152 2>/dev/null || true
sysctl -w kernel.pid_max=4194304 2>/dev/null || true
sysctl -w kernel.threads-max=4194304 2>/dev/null || true
sysctl -w vm.max_map_count=2621440 2>/dev/null || true

if [ -f /etc/systemd/system.conf ]; then
    grep -q "DefaultTasksMax" /etc/systemd/system.conf && sed -i 's/^#*DefaultTasksMax=.*/DefaultTasksMax=infinity/' /etc/systemd/system.conf || echo "DefaultTasksMax=infinity" >> /etc/systemd/system.conf
fi
systemctl daemon-reexec 2>/dev/null || true

TOTAL_SWAP=$(free -m | awk '/Swap:/ {print $2}')
if [ -z "$TOTAL_SWAP" ] || [ "$TOTAL_SWAP" -lt 1000 ]; then
    echo -e "${YELLOW}Membuat 4GB Swapfile agar server tidak kehabisan RAM...${NC}"
    if [ ! -f /swapfile ]; then
        fallocate -l 4G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=4096 2>/dev/null || true
        chmod 600 /swapfile
        mkswap /swapfile 2>/dev/null || true
        swapon /swapfile 2>/dev/null || true
        if ! grep -q "/swapfile" /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        sysctl vm.swappiness=25 2>/dev/null || true
    fi
fi

if [ -f "$INSTALL_DIR/config.json" ]; then
    sed -i 's/"dashboard_port": [0-9]*/"dashboard_port": 8888/' "$INSTALL_DIR/config.json"
fi

ufw allow 22/tcp comment "SSH" || true
ufw allow 80/tcp comment "HTTP" || true
ufw allow 8888/tcp comment "TraffNode V3 Dashboard" || true
ufw allow 10001:11000/tcp comment "TraffNode V3 Inbound Relay Ports" || true
ufw status | grep -q "Status: active" && ufw reload || true

echo -e "${GREEN}[6/6] Mendaftarkan Systemd Service (traffnode.service)...${NC}"
cat << 'EOF' > /etc/systemd/system/traffnode.service
[Unit]
Description=TraffNode V3 Hybrid Harvester and Proxy Gateway
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/traffnode
ExecStart=/opt/traffnode/venv/bin/python3 /opt/traffnode/app.py
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable traffnode
systemctl restart traffnode

SERVER_IP=$(curl -s -4 https://api.ipify.org || curl -s -4 https://ifconfig.me || echo "IP_VPS_ANDA")

echo ""
echo -e "${CYAN}==============================================================================${NC}"
echo -e "${GREEN}🎉 TRAFFNODE V3 COCKPIT BERHASIL DIINSTALL & DIAKTIFKAN DI VPS!${NC}"
echo -e "${CYAN}==============================================================================${NC}"
echo -e "Web Dashboard  : ${YELLOW}http://${SERVER_IP}:8888${NC}"
echo -e "Relay Ports    : ${CYAN}http://${SERVER_IP}:10001 s/d 11000 (Auth: gemini:gemini)${NC}"
echo -e "Status Service : ${GREEN}systemctl status traffnode${NC}"
echo -e "Log Service    : ${GREEN}journalctl -u traffnode -f${NC}"
echo -e "${CYAN}==============================================================================${NC}"
