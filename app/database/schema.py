import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = "app/database/findings.db"

def get_db_connection():
    """Create a database connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create findings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        benchmark TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        level TEXT NOT NULL,
        cvss TEXT,
        title TEXT NOT NULL,
        failure TEXT NOT NULL,
        description TEXT,
        rationale TEXT,
        refs TEXT,
        first_seen DATE NOT NULL,
        due_date DATE NOT NULL,
        resolved_status BOOLEAN DEFAULT FALSE,
        closed_date DATE,
        UNIQUE(benchmark, finding_id, failure)
    )
    ''')
    
    # Create uploads tracking table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_date DATE NOT NULL,
        analysis_date DATE NOT NULL,
        filename TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

def insert_finding(conn, finding_data):
    """Insert a new finding into the database."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR REPLACE INTO findings (
        benchmark, finding_id, level, cvss, title, failure,
        description, rationale, refs, first_seen, due_date,
        resolved_status, closed_date
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', finding_data)
    conn.commit()

def mark_findings_resolved(conn, analysis_date, exclude_keys):
    """Mark findings as resolved if they're not in the current upload."""
    cursor = conn.cursor()
    placeholders = ','.join(['?' for _ in exclude_keys])
    cursor.execute(f'''
    UPDATE findings
    SET resolved_status = TRUE,
        closed_date = ?
    WHERE resolved_status = FALSE
    AND (benchmark || '|' || finding_id || '|' || failure) NOT IN ({placeholders})
    ''', [analysis_date] + list(exclude_keys))
    conn.commit()

def get_active_findings(conn):
    """Get all active (unresolved) findings."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM findings
    WHERE resolved_status = FALSE
    ORDER BY due_date ASC
    ''')
    return cursor.fetchall()

def get_findings_by_status(conn, resolved_status=False):
    """Get findings by their resolved status."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT * FROM findings
    WHERE resolved_status = ?
    ORDER BY due_date ASC
    ''', (resolved_status,))
    return cursor.fetchall()

# Initialize the database when the module is imported
init_db() 