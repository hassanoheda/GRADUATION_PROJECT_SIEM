import sqlite3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
import os

app = FastAPI(title="SOC Pipeline API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = r"C:\Users\Lenovo\Desktop\soc_pipeline.db"

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "index_cdn.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>Error: index_cdn.html not found.</h3>"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/api/metrics/latest")
def get_latest_metrics():
    if not os.path.exists(DB_PATH):
        return {"total_alerts": 0, "isolated_vectors": 0, "active_decoys": 0, "ai_status": "OFFLINE"}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM system_metrics WHERE id = 1')
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return {"total_alerts": 0, "isolated_vectors": 0, "active_decoys": 0, "ai_status": "OFFLINE"}

@app.get("/api/metrics/history")
def get_metrics_history(limit: int = 24):
    if not os.path.exists(DB_PATH):
        return []
    
    conn = get_db_connection()
    cursor = conn.cursor()
    # Build real per-hour trend from actual incident records
    cursor.execute('''
        SELECT
            strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
            COUNT(*) AS total_alerts,
            SUM(CASE WHEN action NOT LIKE '%confined%' AND action NOT LIKE '%missing%' THEN 1 ELSE 0 END) AS isolated_vectors,
            0 AS active_decoys
        FROM incidents
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()

    # Return in chronological order for chart rendering
    return [dict(r) for r in reversed(rows)]

@app.get("/api/incidents")
def get_incidents(limit: int = 100):
    if not os.path.exists(DB_PATH):
        return []
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(r) for r in rows]

@app.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: int):
    if not os.path.exists(DB_PATH):
        return {}
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
    incident = cursor.fetchone()
    
    if not incident:
        conn.close()
        return {}
        
    result = dict(incident)
    
    cursor.execute('SELECT * FROM ai_reports WHERE incident_id = ?', (incident_id,))
    ai_report = cursor.fetchone()
    if ai_report:
        result['ai_report_details'] = dict(ai_report)
        
    conn.close()
    return result

@app.get("/api/threat-intel")
def get_threat_intel(limit: int = 50):
    if not os.path.exists(DB_PATH):
        return []
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM threat_intelligence ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/active-responses")
def get_active_responses():
    if not os.path.exists(DB_PATH):
        return {"blocked_ips": [], "honeypot_events": []}
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM blocked_ips ORDER BY timestamp DESC LIMIT 50')
    blocked = cursor.fetchall()
    
    cursor.execute('SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT 50')
    honeypot = cursor.fetchall()
    conn.close()
    
    return {
        "blocked_ips": [dict(r) for r in blocked],
        "honeypot_events": [dict(r) for r in honeypot]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
