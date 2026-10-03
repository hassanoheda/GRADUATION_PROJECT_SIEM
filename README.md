# Proactive SIEM & SOC Pipeline

Proactive AI-driven SIEM system with deception integration, Wazuh rules, custom API, and automated analysis engine.

## Overview
This repository contains the full stack configuration and code for our AI-driven SOC:
- **SOC Dashboard**: A modern frontend application (`/frontend`) for monitoring and interacting with the system.
- **API Component**: Python backend (`api.py`) exposing endpoints for the dashboard and other integrations.
- **Wazuh Rules**: Custom Wazuh rules and decoders used to generate alerts.
- **Brain Engine**: `brain.py` (AI alert processing engine) - evaluates threats and triggers proactive deception and responses.

## Setup & Execution

### 1. API & Backend
- Ensure Python dependencies are installed.
- Run the API server: `python api.py`

### 2. Brain Engine (AI Processing)
- The core processing engine handles alerts and coordinates deception.
- Run the AI engine: `python brain.py`

### 3. Wazuh Configuration
- Copy the custom rules and decoders into your Wazuh manager.
- Restart the Wazuh manager to apply changes.

### 4. SOC Dashboard
- Navigate to the `frontend` directory.
- Install dependencies: `npm install`
- Start the development server: `npm run dev`
