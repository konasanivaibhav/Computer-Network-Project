"""
db_manager.py
=============
SQLite Persistence Manager for Device Bayesian Trust States and Audit Logging.
"""

from contextlib import contextmanager
import sqlite3
import os
import time
from typing import Iterator, Dict, Any, List, Optional
import logging
from src.trust.trust_engine import DeviceTrustState

logger = logging.getLogger(__name__)


class TrustDBManager:
    """
    Manages SQLite storage for device trust profiles and historical telemetry events.
    """

    def __init__(self, db_path: str = "data/threat_db.sqlite"):
        """Initialize SQLite database connection and verify table schemas."""
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_tables()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """
        Open a connection with Row factory, commit on success and always close it.

        `with sqlite3.connect(...)` only commits; it leaves the file open, which on
        Windows locks the database file until the process exits.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_tables(self) -> None:
        """Create device_trust and trust_audit_log tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_trust (
                    device_id TEXT PRIMARY KEY,
                    alpha REAL NOT NULL,
                    beta REAL NOT NULL,
                    score REAL NOT NULL,
                    variance REAL NOT NULL,
                    category TEXT NOT NULL,
                    last_updated REAL NOT NULL,
                    total_flows INTEGER NOT NULL,
                    total_violations INTEGER NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS trust_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    attack_confidence REAL NOT NULL,
                    action_taken TEXT NOT NULL,
                    previous_score REAL NOT NULL,
                    new_score REAL NOT NULL
                )
            """)
            conn.commit()
            logger.info("Initialized Trust DB tables at %s", self.db_path)

    def save_device_state(self, state: DeviceTrustState) -> None:
        """Persist or update device trust state."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO device_trust (
                    device_id, alpha, beta, score, variance, category, last_updated, total_flows, total_violations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    alpha=excluded.alpha,
                    beta=excluded.beta,
                    score=excluded.score,
                    variance=excluded.variance,
                    category=excluded.category,
                    last_updated=excluded.last_updated,
                    total_flows=excluded.total_flows,
                    total_violations=excluded.total_violations
            """, (
                state.device_id,
                state.alpha,
                state.beta,
                state.score,
                state.variance,
                state.category,
                state.last_updated,
                state.total_flows,
                state.total_violations,
            ))
            conn.commit()

    def load_device_state(self, device_id: str) -> Optional[DeviceTrustState]:
        """Load device trust state from DB or return None if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_trust WHERE device_id = ?", (device_id,))
            row = cursor.fetchone()
            if row:
                return DeviceTrustState(
                    device_id=row["device_id"],
                    alpha=float(row["alpha"]),
                    beta=float(row["beta"]),
                    last_updated=float(row["last_updated"]),
                    total_flows=int(row["total_flows"]),
                    total_violations=int(row["total_violations"]),
                )
            return None

    def log_audit_event(
        self,
        device_id: str,
        attack_confidence: float,
        action_taken: str,
        previous_score: float,
        new_score: float,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record an audit trail event for mitigation decision and trust change."""
        ts = timestamp if timestamp is not None else time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO trust_audit_log (
                    device_id, timestamp, attack_confidence, action_taken, previous_score, new_score
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, ts, attack_confidence, action_taken, previous_score, new_score))
            conn.commit()

    def get_all_devices(self) -> List[DeviceTrustState]:
        """Fetch all stored device trust states."""
        devices = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM device_trust")
            for row in cursor.fetchall():
                devices.append(DeviceTrustState(
                    device_id=row["device_id"],
                    alpha=float(row["alpha"]),
                    beta=float(row["beta"]),
                    last_updated=float(row["last_updated"]),
                    total_flows=int(row["total_flows"]),
                    total_violations=int(row["total_violations"]),
                ))
        return devices
