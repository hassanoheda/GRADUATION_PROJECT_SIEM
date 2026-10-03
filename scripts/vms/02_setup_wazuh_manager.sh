#!/usr/bin/env bash
# ==============================================================================
# Script: 02_setup_wazuh_manager.sh
# Purpose: Installs Wazuh Manager and deploys custom detection rules (XML)
# Target VM: Ubuntu Server (VMnet1: 10.10.10.10 / Gateway: 10.10.10.254)
# ==============================================================================

set -euo pipefail

echo "[+] Starting Wazuh Manager Setup..."

# Update packages
sudo apt-get update -y
sudo apt-get install -y curl apt-transport-https gnupg2

# Install Wazuh GPG key and repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update -y

# Install Wazuh Manager
sudo apt-get install -y wazuh-manager

# Copy custom rules and decoders
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "[+] Deploying custom Wazuh rules (local_rules.xml)..."
if [ -f "${REPO_ROOT}/wazuh/rules/local_rules.xml" ]; then
    sudo cp "${REPO_ROOT}/wazuh/rules/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
    sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
    sudo chmod 660 /var/ossec/etc/rules/local_rules.xml
fi

if [ -f "${REPO_ROOT}/wazuh/decoders/local_decoder.xml" ]; then
    sudo cp "${REPO_ROOT}/wazuh/decoders/local_decoder.xml" /var/ossec/etc/decoders/local_decoder.xml
    sudo chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml
    sudo chmod 660 /var/ossec/etc/decoders/local_decoder.xml
fi

# Enable and restart services
echo "[+] Starting and enabling Wazuh Manager..."
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl restart wazuh-manager

echo "[✔] Wazuh Manager setup completed successfully!"
sudo systemctl status wazuh-manager --no-pager
