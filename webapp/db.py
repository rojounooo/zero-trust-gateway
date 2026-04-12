import sqlite3
from contextlib import contextmanager
from datetime import datetime

DB_PATH = "hospital.db"

# ── Connection ────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    """Context manager — opens a connection, yields cursor, commits and closes."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    finally:
        conn.close()

# ── Audit log ─────────────────────────────────────────────────────────────────

def create_audit_log_table():
    """Create audit_log table on first run if it doesn't exist."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                username  TEXT    NOT NULL,
                role      TEXT    NOT NULL,
                action    TEXT    NOT NULL,
                resource  TEXT    NOT NULL,
                result    TEXT    NOT NULL DEFAULT 'SUCCESS'
            )
        """)

def add_audit_log(username: str, role: str, action: str, resource: str, result: str = "SUCCESS"):
    """Insert a new audit log entry."""
    with get_db() as db:
        db.execute(
            "INSERT INTO audit_log (timestamp, username, role, action, resource, result) VALUES (?,?,?,?,?,?)",
            (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), username, role, action, resource, result)
        )

def get_audit_logs(limit: int = 100) -> list:
    """Return the most recent audit log entries, newest first."""
    with get_db() as db:
        return db.execute(
            "SELECT timestamp, username, role, action, resource, result FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()

# ── Internal helpers ──────────────────────────────────────────────────────────

def _update(table: str, where_col: str, where_val, **fields):
    """Generic UPDATE helper used by patient and contact update functions."""
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_db() as db:
        db.execute(f"UPDATE {table} SET {set_clause} WHERE {where_col} = ?", (*fields.values(), where_val))

# ── Patient queries ───────────────────────────────────────────────────────────

def get_patient(name: str = "") -> list:
    """Search patients by name (partial match). Returns empty list if no name given."""
    if not name:
        return []
    with get_db() as db:
        return db.execute(
            "SELECT * FROM patient_demographics WHERE name LIKE ?", (f"%{name}%",)
        ).fetchall()

def get_patient_nhs_number(name: str = ""):
    """Return the NHS number row for the first patient matching name."""
    if not name:
        return None
    with get_db() as db:
        return db.execute(
            "SELECT nhs_number FROM patient_demographics WHERE name LIKE ?", (f"%{name}%",)
        ).fetchone()

def get_patient_by_nhs(nhs_number: str):
    """Return a single patient record by NHS number."""
    with get_db() as db:
        return db.execute(
            "SELECT * FROM patient_demographics WHERE nhs_number = ?", (nhs_number,)
        ).fetchone()

def update_patient(nhs_number: str, **fields):
    """Update patient demographic fields."""
    _update("patient_demographics", "nhs_number", nhs_number, **fields)

# ── Emergency contact queries ─────────────────────────────────────────────────

def get_emergency_contact(nhs_number) -> list:
    """Return all emergency contacts for a patient."""
    if not nhs_number:
        return []
    with get_db() as db:
        return db.execute(
            "SELECT * FROM emergency_contacts WHERE nhs_number = ?", (nhs_number,)
        ).fetchall()

def get_emergency_contact_single(nhs_number: str):
    """Return a single emergency contact by NHS number."""
    with get_db() as db:
        return db.execute(
            "SELECT * FROM emergency_contacts WHERE nhs_number = ?", (nhs_number,)
        ).fetchone()

def update_emergency_contact(nhs_number: str, **fields):
    """Update emergency contact fields."""
    _update("emergency_contacts", "nhs_number", nhs_number, **fields)

# ── Medical record queries ────────────────────────────────────────────────────

_MEDICAL_SELECT = """
    SELECT mh.nhs_number,
           ct.condition_treatment_id as id,
           ct.condition_name         as condition,
           ct.treatment_description  as treatment
    FROM   medical_history mh
    JOIN   conditions_treatments ct ON mh.condition_treatment_id = ct.condition_treatment_id
"""

def get_medical_records(nhs_number) -> list:
    """Return all medical records for a patient."""
    if not nhs_number:
        return []
    with get_db() as db:
        return db.execute(_MEDICAL_SELECT + "WHERE mh.nhs_number = ?", (nhs_number,)).fetchall()

def get_medical_record_single(record_id: int, nhs_number: str):
    """Return a single medical record by ID and NHS number."""
    with get_db() as db:
        return db.execute(
            _MEDICAL_SELECT + "WHERE ct.condition_treatment_id = ? AND mh.nhs_number = ?",
            (record_id, nhs_number)
        ).fetchone()

def update_medical_record(record_id: int, nhs_number: str, **fields):
    """Update a condition/treatment record."""
    mapping = {"condition": "condition_name", "treatment": "treatment_description"}
    updates = {mapping[k]: v for k, v in fields.items() if k in mapping}
    if updates:
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        with get_db() as db:
            db.execute(
                f"UPDATE conditions_treatments SET {set_clause} WHERE condition_treatment_id = ?",
                (*updates.values(), record_id)
            )

def add_medical_record(nhs_number: str, condition: str, treatment: str):
    """Add a new condition/treatment and link it to a patient."""
    with get_db() as db:
        db.execute(
            "INSERT OR IGNORE INTO conditions_treatments (condition_name, treatment_description) VALUES (?,?)",
            (condition, treatment)
        )
        result = db.execute(
            "SELECT condition_treatment_id FROM conditions_treatments WHERE condition_name = ? AND treatment_description = ?",
            (condition, treatment)
        ).fetchone()
        if result:
            db.execute(
                "INSERT OR IGNORE INTO medical_history (nhs_number, condition_treatment_id) VALUES (?,?)",
                (nhs_number, result[0])
            )

def delete_medical_record(record_id: int, nhs_number: str):
    """Remove a medical record link from a patient's history."""
    with get_db() as db:
        db.execute(
            "DELETE FROM medical_history WHERE condition_treatment_id = ? AND nhs_number = ?",
            (record_id, nhs_number)
        )