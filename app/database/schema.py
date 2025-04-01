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
    
    # Create benchmark table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS benchmark (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        benchmark TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        level TEXT,
        cvss REAL,
        title TEXT,
        description TEXT,
        rationale TEXT,
        refs TEXT,
        UNIQUE(benchmark, finding_id)
    )
    ''')
    
    # Create findings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        benchmark_id INTEGER NOT NULL,
        failure TEXT NOT NULL,
        FOREIGN KEY (benchmark_id) REFERENCES benchmark(id),
        UNIQUE(benchmark_id, failure)
    )
    ''')
    
    # Create scans table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_date DATE NOT NULL UNIQUE
    )
    ''')
    
    # Create remediations table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        benchmark_id INTEGER NOT NULL,
        first_seen_scan INTEGER NOT NULL,
        resolved_in_scan INTEGER,
        state TEXT NOT NULL CHECK (state IN ('open', 'resolved')),
        due_date DATE NOT NULL,
        FOREIGN KEY (benchmark_id) REFERENCES benchmark(id),
        FOREIGN KEY (first_seen_scan) REFERENCES scans(id),
        FOREIGN KEY (resolved_in_scan) REFERENCES scans(id)
    )
    ''')
    
    # Create remediation_findings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS remediation_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        remediation_id INTEGER NOT NULL,
        finding_id INTEGER NOT NULL,
        FOREIGN KEY (remediation_id) REFERENCES remediations(id),
        FOREIGN KEY (finding_id) REFERENCES findings(id),
        UNIQUE (remediation_id, finding_id)
    )
    ''')
    
    # Create issues table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        benchmark_id INTEGER NOT NULL,
        due_date DATE NOT NULL,
        created_at TIMESTAMP NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
        resolved_at TIMESTAMP,
        FOREIGN KEY (benchmark_id) REFERENCES benchmark(id)
    )
    ''')
    
    # Create issue_remediations table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS issue_remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER NOT NULL,
        remediation_id INTEGER NOT NULL,
        FOREIGN KEY (issue_id) REFERENCES issues(id),
        FOREIGN KEY (remediation_id) REFERENCES remediations(id),
        UNIQUE (issue_id, remediation_id)
    )
    ''')
    
    conn.commit()
    conn.close()

def get_or_create_benchmark(conn, benchmark_data):
    """Get existing benchmark or create a new one."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR IGNORE INTO benchmark (
        benchmark, finding_id, level, cvss, title,
        description, rationale, refs
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', benchmark_data)
    
    cursor.execute('''
    SELECT id FROM benchmark
    WHERE benchmark = ? AND finding_id = ?
    ''', (benchmark_data[0], benchmark_data[1]))
    
    return cursor.fetchone()['id']

def get_or_create_scan(conn, scan_date):
    """Get existing scan or create a new one."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR IGNORE INTO scans (scan_date)
    VALUES (?)
    ''', (scan_date,))
    
    cursor.execute('''
    SELECT id FROM scans
    WHERE scan_date = ?
    ''', (scan_date,))
    
    return cursor.fetchone()['id']

def insert_finding(conn, benchmark_id, failure):
    """Insert a new finding into the database."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR IGNORE INTO findings (benchmark_id, failure)
    VALUES (?, ?)
    ''', (benchmark_id, failure))
    
    cursor.execute('''
    SELECT id FROM findings
    WHERE benchmark_id = ? AND failure = ?
    ''', (benchmark_id, failure))
    
    return cursor.fetchone()['id']

def create_remediation(conn, benchmark_id, scan_id, due_date):
    """Create a new remediation."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO remediations (
        benchmark_id, first_seen_scan, state, due_date
    ) VALUES (?, ?, 'open', ?)
    ''', (benchmark_id, scan_id, due_date))
    
    return cursor.lastrowid

def link_finding_to_remediation(conn, remediation_id, finding_id):
    """Link a finding to a remediation."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT OR IGNORE INTO remediation_findings (remediation_id, finding_id)
    VALUES (?, ?)
    ''', (remediation_id, finding_id))

def check_if_scan_exists(conn, scan_date):
    """Check if a scan exists for a given date."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT id FROM scans WHERE scan_date = ?
    ''', (scan_date,))
    return cursor.fetchone() is not None


def get_active_issues(conn):
    """Get all active issues."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        b.description,
        b.rationale,
        b.refs,
        i.due_date,
        i.created_at,
        i.resolved_at,
        i.status,
        COUNT(ir.remediation_id) as remediation_count
    FROM issues i
    JOIN issue_remediations ir ON i.id = ir.issue_id
    JOIN benchmark b ON i.benchmark_id = b.id
    WHERE i.status = 'open'
    GROUP BY i.id
    ''')
    
    # Convert rows to dictionaries with column names
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def mark_remediations_resolved_if_not_in_list(conn, scan_id, active_remediation_ids):
    """Mark remediations as resolved if they're not in the current scan."""
    
    print(f"Marking all but {len(active_remediation_ids)} still-active remediations as resolved")
    
    if not active_remediation_ids:
        # No active remediations - update all open remediations to resolved
        cursor = conn.cursor()
        cursor.execute('''
        UPDATE remediations
        SET state = 'resolved'
        WHERE state = 'open'
        ''')
    else:
        cursor = conn.cursor()
        placeholders = ','.join(['?' for _ in active_remediation_ids])
        cursor.execute(f'''
        UPDATE remediations
        SET state = 'resolved',
            resolved_in_scan = ?
        WHERE state = 'open'
        AND id NOT IN ({placeholders})
        ''', [scan_id, *active_remediation_ids])

    conn.commit()


def mark_issues_as_resolved_if_no_open_remediations(conn, resolved_date):
    """Mark issues as resolved if they no longer have any open remediations."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT i.id
    FROM issues i
    WHERE i.status = 'open'
    AND NOT EXISTS (
        SELECT 1
        FROM remediations r
        JOIN issue_remediations ir ON r.id = ir.remediation_id
        WHERE r.state = 'open'
        AND ir.issue_id = i.id
    )
    ''', ())
    
    issue_ids = [row[0] for row in cursor.fetchall()]
    print(f"Marking {len(issue_ids)} issues as resolved ({issue_ids})")
    placeholders = ','.join(['?' for _ in issue_ids])

    if issue_ids:
        cursor.execute(f'''
        UPDATE issues
        SET status = 'resolved', resolved_at = ?
        WHERE id IN ({placeholders})
        ''', (resolved_date, *issue_ids))

    conn.commit()


def create_issue_for_remediations(conn, remediation_ids, benchmark_id, created_at, due_date):
    """Create a new issue for a remediation if one doesn't exist."""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO issues (benchmark_id, due_date, created_at, status)
    VALUES (?, ?, ?, 'open')
    ''', (benchmark_id, due_date, created_at))
    
    issue_id = cursor.lastrowid
    
    for remediation_id in remediation_ids:
        cursor.execute('''
        INSERT INTO issue_remediations (issue_id, remediation_id)
        VALUES (?, ?)
        ''', (issue_id, remediation_id))
    
    conn.commit()

# Initialize the database when the module is imported
init_db() 