@echo off
echo ==============================================================================
echo Starting AI-Driven SOC Pipeline System
echo ==============================================================================

echo [*] Initializing SQLite database...
python database\init_db.py

echo [*] Launching FastAPI Backend on http://localhost:8000...
start cmd /k "python -m uvicorn api:app --host 0.0.0.0 --port 8000 --reload"

echo [*] Launching React Interface on http://localhost:5173...
cd frontend
start cmd /k "npm run dev"
cd ..

echo [*] Launching Autonomous Brain Engine (brain.py)...
python brain.py

pause
