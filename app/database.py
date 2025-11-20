"""SQLite persistence layer for OS Log Analyzer."""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional


class DatabaseManager:
    """Thread-safe helper for working with the security database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    threat_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    description TEXT,
                    source_ip TEXT,
                    target_system TEXT,
                    event_count INTEGER,
                    action_taken TEXT,
                    log_reference TEXT,
                    metadata TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    action TEXT DEFAULT 'alert',
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    identifier TEXT NOT NULL,
                    type TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    active INTEGER DEFAULT 1,
                    metadata TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT DEFAULT 'system',
                    action TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER,
                    summary TEXT,
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    notes TEXT,
                    FOREIGN KEY(alert_id) REFERENCES alerts(id)
                )
                """
            )

    # Alert operations -----------------------------------------------------
    def record_alert(
        self,
        threat: Dict[str, Any],
        action_taken: Optional[str] = None,
        log_reference: Optional[Dict[str, Any]] = None,
    ) -> int:
        payload = {
            "created_at": datetime.utcnow().isoformat(),
            "threat_type": threat.get("threat_type"),
            "severity": threat.get("severity"),
            "confidence": threat.get("confidence"),
            "description": threat.get("description"),
            "source_ip": threat.get("source_ip"),
            "target_system": threat.get("target_system"),
            "event_count": threat.get("event_count", 1),
            "action_taken": action_taken,
            "log_reference": json.dumps(log_reference) if log_reference else None,
        }
        metadata: Dict[str, Any] = {}
        raw_evidence = threat.get("raw_evidence")
        if raw_evidence:
            metadata["evidence"] = raw_evidence
        reason = threat.get("reason")
        if reason:
            metadata["reason"] = reason
        payload["metadata"] = json.dumps(metadata) if metadata else None
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts (
                    created_at, threat_type, severity, confidence, description,
                    source_ip, target_system, event_count, action_taken,
                    log_reference, metadata
                ) VALUES (:created_at, :threat_type, :severity, :confidence, :description,
                          :source_ip, :target_system, :event_count, :action_taken,
                          :log_reference, :metadata)
                """,
                payload,
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if lastrowid is not None else 0

    def fetch_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # Rule operations ------------------------------------------------------
    def upsert_rule(self, rule: Dict[str, Any]) -> int:
        timestamp = datetime.utcnow().isoformat()
        payload = {
            "name": rule["name"],
            "pattern": rule["pattern"],
            "severity": rule.get("severity", "medium"),
            "action": rule.get("action", "alert"),
            "enabled": 1 if rule.get("enabled", True) else 0,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO rules (name, pattern, severity, action, enabled, created_at, updated_at)
                VALUES (:name, :pattern, :severity, :action, :enabled, :created_at, :updated_at)
                """,
                payload,
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if lastrowid is not None else 0

    def update_rule(self, rule_id: int, updates: Dict[str, Any]) -> None:
        updates = updates.copy()
        updates["updated_at"] = datetime.utcnow().isoformat()
        sets = []
        params: Dict[str, Any] = {"id": rule_id}
        for key in ["name", "pattern", "severity", "action", "enabled", "updated_at"]:
            if key in updates:
                sets.append(f"{key} = :{key}")
                params[key] = int(updates[key]) if key == "enabled" else updates[key]
        if not sets:
            return
        with self._lock, self._connection() as conn:
            conn.execute(
                f"UPDATE rules SET {', '.join(sets)} WHERE id = :id",
                params,
            )

    def delete_rule(self, rule_id: int) -> None:
        with self._lock, self._connection() as conn:
            conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))

    def fetch_rules(self, include_disabled: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT * FROM rules"
        params: tuple = ()
        if not include_disabled:
            query += " WHERE enabled = 1"
        query += " ORDER BY datetime(created_at) DESC"
        with self._lock, self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # Blacklist operations -------------------------------------------------
    def add_blacklist_entry(
        self,
        identifier: str,
        entry_type: str,
        reason: Optional[str] = None,
        expires_at: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        payload = {
            "identifier": identifier,
            "type": entry_type,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at,
            "active": 1,
            "metadata": json.dumps(metadata) if metadata else None,
        }
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO blacklist (identifier, type, reason, created_at, expires_at, active, metadata)
                VALUES (:identifier, :type, :reason, :created_at, :expires_at, :active, :metadata)
                """,
                payload,
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if lastrowid is not None else 0

    def deactivate_blacklist_entry(self, entry_id: int) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE blacklist SET active = 0 WHERE id = ?",
                (entry_id,),
            )

    def remove_blacklist_identifier(self, identifier: str) -> None:
        with self._lock, self._connection() as conn:
            conn.execute(
                "UPDATE blacklist SET active = 0 WHERE identifier = ?",
                (identifier,),
            )

    def fetch_blacklist(self, active_only: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT * FROM blacklist"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY datetime(created_at) DESC"
        with self._lock, self._connection() as conn:
            rows = conn.execute(query).fetchall()
        return [dict(row) for row in rows]

    # Audit operations -----------------------------------------------------
    def record_audit(self, action: str, details: Dict[str, Any], actor: str = "system") -> int:
        payload = {
            "created_at": datetime.utcnow().isoformat(),
            "actor": actor,
            "action": action,
            "details": json.dumps(details) if details else None,
        }
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_logs (created_at, actor, action, details)
                VALUES (:created_at, :actor, :action, :details)
                """,
                payload,
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if lastrowid is not None else 0

    def fetch_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # Incident operations --------------------------------------------------
    def create_incident(
        self,
        alert_id: Optional[int],
        summary: str,
        status: str = "open",
        notes: Optional[str] = None,
    ) -> int:
        payload = {
            "alert_id": alert_id,
            "summary": summary,
            "status": status,
            "created_at": datetime.utcnow().isoformat(),
            "resolved_at": None,
            "notes": notes,
        }
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO incidents (alert_id, summary, status, created_at, resolved_at, notes)
                VALUES (:alert_id, :summary, :status, :created_at, :resolved_at, :notes)
                """,
                payload,
            )
            lastrowid = cursor.lastrowid
            return int(lastrowid) if lastrowid is not None else 0

    def update_incident(self, incident_id: int, updates: Dict[str, Any]) -> None:
        updates = updates.copy()
        if updates.get("status") in {"resolved", "closed"}:
            updates.setdefault("resolved_at", datetime.utcnow().isoformat())
        sets = []
        params: Dict[str, Any] = {"id": incident_id}
        for key, value in updates.items():
            sets.append(f"{key} = :{key}")
            params[key] = value
        if not sets:
            return
        with self._lock, self._connection() as conn:
            conn.execute(
                f"UPDATE incidents SET {', '.join(sets)} WHERE id = :id",
                params,
            )

    def fetch_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY datetime(created_at) DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]
