#!/usr/bin/env bash
# ==============================================================================
# Script: 04_setup_ollama_tinyllama.sh
# Purpose: Installs Ollama LLM Runtime and downloads TinyLlama / LLaMA3 models
# Target: SOC Processing Host (or local developer machine)
# ==============================================================================

set -euo pipefail

echo "[+] Installing Ollama LLM Engine..."
curl -fsSL https://ollama.com/install.sh | sh

echo "[+] Starting Ollama service..."
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl start ollama || true

echo "[+] Pulling TinyLlama model for local inference..."
ollama pull tinyllama

echo "[+] Validating Ollama API endpoint on http://localhost:11434..."
curl -s http://localhost:11434/api/tags | grep -q "tinyllama" && echo "[✔] TinyLlama is ready for SOC Brain analysis!" || echo "[!] Model download verification pending."
