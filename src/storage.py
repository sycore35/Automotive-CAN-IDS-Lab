"""
Automotive-CAN-IDS-Lab — SQLite Event Store & Incident Exporter.
Zero external database dependencies.
"""
import sqlite3
import json
import time
import os
from typing import Dict, Any, List, Optional
from src.can_frame import CANFrame
from src.can_ids import CANAlert


class CANStorage:
    """Local SQLite repository for CAN traffic, IDS security alerts, and audit trails."""

    def __init__(self, db_path: str = "data/can_events.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS can_frames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    arbitration_id INTEGER,
                    hex_id TEXT,
                    dlc INTEGER,
                    data_hex TEXT,
                    bus_load_pct REAL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ids_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    rule_id TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    arbitration_id INTEGER,
                    hex_id TEXT,
                    message_name TEXT,
                    observed_value TEXT,
                    expected_threshold TEXT,
                    evidence TEXT,
                    mitigation TEXT,
                    raw_frame_hex TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    action TEXT,
                    details TEXT
                )
            """)
            conn.commit()

    def save_frame(self, frame: CANFrame, bus_load: float = 0.0) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO can_frames (timestamp, arbitration_id, hex_id, dlc, data_hex, bus_load_pct) VALUES (?, ?, ?, ?, ?, ?)",
                (frame.timestamp, frame.arbitration_id, frame.hex_id, frame.dlc, frame.hex_data, bus_load)
            )

    def save_batch(self, frames: List[CANFrame], alerts: List[CANAlert], bus_load: float = 0.0, keep: int = 20000) -> None:
        """One transaction per simulation tick (the per-row path is far too slow at ~1k frames/s)."""
        conn = self._get_conn()
        try:
            with conn:
                conn.executemany(
                    "INSERT INTO can_frames (timestamp, arbitration_id, hex_id, dlc, data_hex, bus_load_pct) VALUES (?, ?, ?, ?, ?, ?)",
                    [(f.timestamp, f.arbitration_id, f.hex_id, f.dlc, f.hex_data, bus_load) for f in frames])
                conn.executemany(
                    """INSERT INTO ids_alerts (timestamp, rule_id, rule_name, severity, arbitration_id, hex_id,
                       message_name, observed_value, expected_threshold, evidence, mitigation, raw_frame_hex)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    [(a.timestamp, a.rule_id, a.rule_name, a.severity, a.arbitration_id, a.hex_id, a.message_name,
                      str(a.observed_value), str(a.expected_threshold), a.evidence, a.mitigation, a.raw_frame_hex)
                     for a in alerts])
                self._since_prune = getattr(self, "_since_prune", 0) + len(frames)
                if self._since_prune > keep:
                    self._since_prune = 0
                    conn.execute("DELETE FROM can_frames WHERE id < (SELECT MAX(id) FROM can_frames) - ?", (keep,))
        finally:
            conn.close()

    def save_alert(self, alert: CANAlert) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO ids_alerts (
                    timestamp, rule_id, rule_name, severity, arbitration_id, hex_id,
                    message_name, observed_value, expected_threshold, evidence, mitigation, raw_frame_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.timestamp, alert.rule_id, alert.rule_name, alert.severity,
                    alert.arbitration_id, alert.hex_id, alert.message_name,
                    str(alert.observed_value), str(alert.expected_threshold),
                    alert.evidence, alert.mitigation, alert.raw_frame_hex
                )
            )

    def log_audit(self, action: str, details: Dict[str, Any]) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
                (time.time(), action, json.dumps(details))
            )

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ids_alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def get_recent_frames(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM can_frames ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def export_incident_bundle(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            alerts = [dict(r) for r in conn.execute("SELECT * FROM ids_alerts ORDER BY id DESC LIMIT 500").fetchall()]
            frames = [dict(r) for r in conn.execute("SELECT * FROM can_frames ORDER BY id DESC LIMIT 500").fetchall()]
            audit = [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()]
            return {
                "bundle_type": "AUTOMOTIVE_CAN_INCIDENT_BUNDLE",
                "export_time": time.time(),
                "alert_count": len(alerts),
                "frame_sample_count": len(frames),
                "alerts": alerts,
                "frames": frames,
                "audit": audit
            }

    def clear_all(self) -> None:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM ids_alerts")
            conn.execute("DELETE FROM can_frames")
            conn.execute("DELETE FROM audit_log")
            conn.commit()
