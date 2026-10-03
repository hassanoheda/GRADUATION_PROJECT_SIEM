import sqlite3
import os
from datetime import datetime, timedelta

DB_NAME = "soc_pipeline.db"

def init_database(db_path=DB_NAME):
    print(f"[*] Initializing SQLite database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. System Metrics Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY,
            total_alerts INTEGER,
            isolated_vectors INTEGER,
            active_decoys INTEGER,
            ai_status TEXT
        )
    ''')

    # 2. Incidents Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_ip TEXT,
            category TEXT,
            event_count INTEGER,
            max_severity INTEGER,
            action TEXT,
            timestamp DATETIME,
            ai_report TEXT,
            vt_score INTEGER,
            country TEXT,
            net_owner TEXT,
            target_asset TEXT,
            target_user TEXT,
            target_port TEXT
        )
    ''')

    # 3. Honeypot Deception Traffic Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS honeypot_traffic (
            port INTEGER PRIMARY KEY,
            trapped_count INTEGER
        )
    ''')

    # Seed baseline metrics if empty
    cursor.execute('SELECT COUNT(*) FROM system_metrics')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO system_metrics (id, total_alerts, isolated_vectors, active_decoys, ai_status)
            VALUES (1, 14, 9, 3, "ACTIVE_AI_ONLINE")
        ''')

    conn.commit()
    conn.close()
    print("[✔] Database initialized successfully!")

if __name__ == "__main__":
    init_database()
