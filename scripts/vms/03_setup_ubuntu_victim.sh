#!/usr/bin/env bash
# ==============================================================================
# Script: 03_setup_ubuntu_victim.sh
# Purpose: Configures Victim Host with Wazuh Agent, FIM, Cowrie, and Honey-Token
# Target VM: Ubuntu 64-bit (VMnet2: 10.0.0.20 / Gateway: 10.0.0.254)
# ==============================================================================

set -euo pipefail

WAZUH_MANAGER_IP="10.10.10.10"

echo "[+] Setting up Ubuntu Victim / Target Server..."

# Update and install dependencies
sudo apt-get update -y
sudo apt-get install -y curl apt-transport-https gnupg2 git python3-pip python3-virtualenv

# Install Wazuh Agent
echo "[+] Installing Wazuh Agent pointing to ${WAZUH_MANAGER_IP}..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update -y

WAZUH_MANAGER="${WAZUH_MANAGER_IP}" sudo apt-get install -y wazuh-agent

# Deploy FIM settings to /var/ossec/etc/ossec.conf
echo "[+] Configuring File Integrity Monitoring (FIM / Syscheck)..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [ -f "${REPO_ROOT}/wazuh/agent/ossec_agent_fim.xml" ]; then
    echo "[*] Please verify <syscheck> section in /var/ossec/etc/ossec.conf matches ossec_agent_fim.xml"
fi

# Deploy Honey-Token Decoy File
echo "[+] Deploying Adaptive Honey-Token (adaptive_honey_token.env)..."
cat << 'EOF' | sudo tee /var/www/adaptive_honey_token.env > /dev/null
# SYSTEM DEPLOYMENT CREDENTIALS - RESTRICTED
DB_HOST=10.0.0.50
DB_PORT=5432
DB_USER=soc_admin_backup
DB_PASS=V3ryS3cur3P@ssw0rd!2026
BACKUP_S3_KEY=AKIAIOSFODNN7EXAMPLE
BACKUP_S3_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

sudo chmod 644 /var/www/adaptive_honey_token.env

# Enable and start Wazuh Agent
echo "[+] Starting Wazuh Agent service..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent

echo "[✔] Ubuntu Target VM setup completed!"
