#!/usr/bin/env python3
"""Autonomous OS Log Analyzer Flask backend."""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Pattern, Tuple

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_sock import Sock
from simple_websocket import ConnectionClosed

# Ensure project root is importable before bringing in internal modules
APP_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(APP_DIR)
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

try:
    import pandas as pd
except ImportError:  # pragma: no cover - optional dependency
    pd = None

from app.config import config
from app.database import DatabaseManager
from app.event_dispatcher import EventDispatcher
from app.process_control import ProcessController
from app.response_engine import ResponseEngine
from unified_analyzer import (
    MLAnomaly,
    LogEntry,
    ThreatIndicator,
    UnifiedLogAnalyzer,
    quick_analysis,
)


def _resolve_path(path_value: str, fallback_dir: str) -> str:
    return path_value if os.path.isabs(path_value) else os.path.join(fallback_dir, path_value)


DATABASE_PATH = _resolve_path(config.database_path, ROOT_DIR)
QUARANTINE_DIR = _resolve_path(config.quarantine_dir, ROOT_DIR)
EXPORTS_DIR = os.path.join(ROOT_DIR, "exports")
UPLOAD_DIR = _resolve_path(config.upload_folder, ROOT_DIR)

os.makedirs(EXPORTS_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = config.secret_key
app.config["CORS_ORIGINS"] = config.cors_origins
app.config["LOG_UPDATE_INTERVAL"] = config.log_update_interval
app.config["MAX_LOGS_DISPLAY"] = config.max_logs_display
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app_start_time = datetime.now()

CORS(app, origins=config.cors_origins)
sock = Sock(app)

db_manager = DatabaseManager(DATABASE_PATH)
event_dispatcher = EventDispatcher()
process_controller = ProcessController(db_manager, QUARANTINE_DIR)
response_engine = ResponseEngine(db_manager, process_controller, event_dispatcher)

unified_analyzer: Optional[UnifiedLogAnalyzer] = None
monitoring_active = False
monitoring_thread: Optional[threading.Thread] = None
metrics_thread: Optional[threading.Thread] = None
blacklist_thread: Optional[threading.Thread] = None
heartbeat_thread: Optional[threading.Thread] = None
shutdown_event = threading.Event()
state_lock = threading.RLock()

real_time_state: Dict[str, Any] = {
    "logs": [],
    "threats": [],
    "anomalies": [],
    "metrics": {},
    "processes": [],
    "blacklist": db_manager.fetch_blacklist(),
    "rules": db_manager.fetch_rules(),
    "incidents": [],
    "alerts": [],
    "log_total": 0,
}

MIN_LOGS_PER_BURST = 15
HEARTBEAT_INTERVAL = 10
replay_cursor = 0

compiled_rules_lock = threading.Lock()
compiled_rules: Dict[int, Pattern[str]] = {}


def _current_log_total() -> int:
    if unified_analyzer and getattr(unified_analyzer, "logs", None) is not None:
        try:
            return len(unified_analyzer.logs)
        except Exception:  # pragma: no cover - defensive guard
            pass
    return int(real_time_state.get("log_total", len(real_time_state["logs"])))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _limit_list(items: List[Any], limit: int) -> List[Any]:
    if limit <= 0:
        return items
    return items[-limit:]


def _calculate_time_ago(ts: datetime | str | None) -> str:
    try:
        if ts is None:
            return "Unknown"
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        now = datetime.now(ts.tzinfo) if ts.tzinfo else datetime.now()
        diff = now - ts
        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())}s ago"
        if diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)}m ago"
        if diff.total_seconds() < 86400:
            return f"{int(diff.total_seconds() / 3600)}h ago"
        return f"{int(diff.total_seconds() / 86400)}d ago"
    except Exception:
        return "Unknown"


def _severity_color(level: str) -> str:
    mapping = {
        "CRITICAL": "#dc3545",
        "ERROR": "#fd7e14",
        "WARNING": "#ffc107",
        "INFO": "#17a2b8",
        "DEBUG": "#6c757d",
        "VERBOSE": "#6f42c1",
    }
    return mapping.get(level.upper(), "#17a2b8")


def _log_icon(log_type: str) -> str:
    icons = {
        "system": "⚙",
        "application": "📱",
        "security": "🔒",
        "setup": "⚡",
        "network": "🌐",
        "service": "🔧",
    }
    return icons.get(log_type.lower(), "📄")


def _log_to_dict(log: LogEntry) -> Dict[str, Any]:
    log_id = f"{log.timestamp.isoformat()}-{log.event_id}-{log.source}"
    is_recent = (datetime.now() - log.timestamp).total_seconds() <= 30
    return {
        "id": log_id,
        "timestamp": log.timestamp.isoformat(),
        "formatted_timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "time_ago": _calculate_time_ago(log.timestamp),
        "os_type": log.os_type,
        "log_type": log.log_type,
        "source": log.source,
        "event_id": log.event_id,
        "level": log.level,
        "message": log.message,
        "full_message": log.message,
        "raw_data": log.raw_data,
        "severity_color": _severity_color(log.level),
        "type_icon": _log_icon(log.log_type),
        "is_recent": is_recent,
    }


def _update_compiled_rules(rules: List[Dict[str, Any]]) -> None:
    with compiled_rules_lock:
        compiled_rules.clear()
        for rule in rules:
            rule_id_value = rule.get("id")
            try:
                rule_id = int(rule_id_value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            pattern = rule.get("pattern")
            enabled = rule.get("enabled", 1)
            if not pattern or not enabled:
                continue
            try:
                compiled_rules[rule_id] = re.compile(str(pattern), re.IGNORECASE)
            except re.error:
                continue


def _apply_detection_rules(log_dict: Dict[str, Any]) -> None:
    message = (log_dict.get("full_message") or log_dict.get("message") or "")
    raw_data = log_dict.get("raw_data") or ""
    search_space = f"{message}\n{raw_data}"
    if not search_space.strip():
        return

    with state_lock:
        active_rules = [rule for rule in real_time_state["rules"] if rule.get("enabled", 1)]

    if not active_rules:
        return

    with compiled_rules_lock:
        patterns_snapshot = {rule_id: pattern for rule_id, pattern in compiled_rules.items()}

    triggered_rules: List[Dict[str, Any]] = []
    for rule in active_rules:
        rule_id_value = rule.get("id")
        try:
            rule_id = int(rule_id_value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        pattern = patterns_snapshot.get(rule_id)
        if pattern is None:
            continue
        try:
            if not pattern.search(search_space):
                continue
        except re.error:
            continue

        triggered_rules.append(rule)
        rule_name = rule.get("name") or f"Rule {rule_id}"
        action = (rule.get("action") or "alert").lower()
        severity = (rule.get("severity") or "medium").lower()
        if action == "block" and severity not in {"high", "critical"}:
            severity = "high"

        threat_payload = {
            "id": f"rule-{rule_id}-{log_dict.get('id')}",
            "timestamp": datetime.now().isoformat(),
            "threat_type": f"Rule Match: {rule_name}",
            "severity": severity,
            "confidence": 0.9 if action == "block" else 0.75,
            "description": f"Detection rule '{rule_name}' matched log entry",
            "rule_id": rule_id,
            "rule_action": action,
            "rule_pattern": rule.get("pattern"),
            "log_reference": log_dict,
            "source": log_dict.get("source"),
        }

        with state_lock:
            real_time_state["threats"].append(threat_payload)
            real_time_state["threats"] = _limit_list(real_time_state["threats"], 500)

        event_dispatcher.publish("threat.detected", threat_payload)
        response_engine.handle_threat(threat_payload, log_dict)

    if triggered_rules:
        event_dispatcher.publish(
            "rules.triggered",
            {
                "timestamp": datetime.now().isoformat(),
                "rules": [rule.get("id") for rule in triggered_rules],
                "log": log_dict,
            },
        )


_update_compiled_rules(real_time_state["rules"])


def _ensure_minimum_real_logs(new_logs: List[LogEntry], minimum: int = MIN_LOGS_PER_BURST) -> List[Tuple[LogEntry, bool]]:
    enriched: List[Tuple[LogEntry, bool]] = [(log, False) for log in new_logs]
    if len(enriched) >= minimum:
        return enriched

    if not unified_analyzer or not unified_analyzer.logs:
        return enriched

    global replay_cursor
    backlog = unified_analyzer.logs
    needed = minimum - len(enriched)
    if not backlog:
        return enriched

    for _ in range(needed):
        entry = backlog[replay_cursor % len(backlog)]
        replay_cursor += 1
        enriched.append((entry, True))

    return enriched


def _threat_to_dict(threat: ThreatIndicator, log_dict: Dict[str, Any]) -> Dict[str, Any]:
    first_seen = threat.first_seen or log_dict.get("timestamp")
    last_seen = threat.last_seen or first_seen
    if isinstance(first_seen, datetime):
        first_seen_str = first_seen.isoformat()
    elif isinstance(first_seen, str):
        first_seen_str = first_seen
    elif first_seen is None:
        first_seen_str = log_dict.get("timestamp")
    else:
        first_seen_str = str(first_seen)

    if isinstance(last_seen, datetime):
        last_seen_str = last_seen.isoformat()
    elif isinstance(last_seen, str):
        last_seen_str = last_seen
    elif last_seen is None:
        last_seen_str = first_seen_str
    else:
        last_seen_str = str(last_seen)
    return {
        "id": f"threat_{len(real_time_state['threats']) + 1}_{int(time.time())}",
        "threat_type": threat.threat_type,
        "severity": threat.severity,
        "confidence": threat.confidence,
        "description": threat.description,
        "source_ip": threat.source_ip,
        "event_count": threat.event_count,
        "first_seen": first_seen_str,
        "last_seen": last_seen_str,
        "reason": threat.reason,
        "raw_evidence": threat.raw_evidence,
        "log_reference": log_dict,
    }


def _anomaly_to_dict(anomaly: MLAnomaly) -> Dict[str, Any]:
    return {
        "timestamp": anomaly.timestamp.isoformat(),
        "anomaly_score": anomaly.anomaly_score,
        "description": anomaly.description,
        "detection_method": anomaly.detection_method,
        "log_entry": anomaly.log_entry,
    }


def _snapshot() -> Dict[str, Any]:
    with state_lock:
        return {
            "timestamp": datetime.now().isoformat(),
            "monitoring_active": monitoring_active,
            "logs": real_time_state["logs"][-200:],
            "threats": real_time_state["threats"][-100:],
            "anomalies": real_time_state["anomalies"][-100:],
            "metrics": real_time_state["metrics"],
            "processes": real_time_state["processes"][:50],
            "blacklist": real_time_state["blacklist"],
            "rules": real_time_state["rules"],
            "incidents": real_time_state["incidents"][-50:],
            "total_logs": _current_log_total(),
        }


# ---------------------------------------------------------------------------
# Background services
# ---------------------------------------------------------------------------


def initialize_services() -> bool:
    global unified_analyzer
    try:
        unified_analyzer = UnifiedLogAnalyzer()
        unified_analyzer.display_logs = False
        return True
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error initializing analyzer: {exc}")
        return False


def ensure_background_threads() -> None:
    global metrics_thread, blacklist_thread, heartbeat_thread
    if metrics_thread is None or not metrics_thread.is_alive():
        metrics_thread = threading.Thread(target=_metrics_loop, daemon=True)
        metrics_thread.start()
    if blacklist_thread is None or not blacklist_thread.is_alive():
        blacklist_thread = threading.Thread(target=_blacklist_loop, daemon=True)
        blacklist_thread.start()
    if heartbeat_thread is None or not heartbeat_thread.is_alive():
        heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
        heartbeat_thread.start()


def start_monitoring() -> bool:
    global monitoring_active, monitoring_thread
    if unified_analyzer is None:
        return False
    if monitoring_active:
        return True
    monitoring_active = True
    monitoring_thread = threading.Thread(target=_monitor_logs_loop, daemon=True)
    monitoring_thread.start()
    return True


def stop_monitoring() -> bool:
    global monitoring_active
    if not monitoring_active:
        return False
    monitoring_active = False
    if unified_analyzer:
        unified_analyzer.stop()
    return True


def _monitor_logs_loop() -> None:
    assert unified_analyzer is not None
    while monitoring_active and not shutdown_event.is_set():
        try:
            if unified_analyzer.os_type == "windows":
                new_logs = unified_analyzer.collect_windows_logs()
            elif unified_analyzer.os_type == "linux":
                new_logs = unified_analyzer.collect_linux_logs()
            else:
                new_logs = []

            processed_logs = _ensure_minimum_real_logs(new_logs)
            with state_lock:
                existing_ids = {entry["id"] for entry in real_time_state["logs"]}

            for log, replayed in processed_logs:
                log_dict = _log_to_dict(log)
                log_dict["received_at"] = datetime.now().isoformat()
                original_id = log_dict["id"]
                if replayed:
                    replay_suffix = int(time.time() * 1000)
                    log_dict["replayed"] = True
                    log_dict["original_id"] = original_id
                    log_dict["id"] = f"{original_id}-replay-{replay_suffix}"
                with state_lock:
                    if log_dict["id"] not in existing_ids:
                        real_time_state["logs"].append(log_dict)
                        real_time_state["logs"] = _limit_list(real_time_state["logs"], config.max_logs_display)
                        if not replayed:
                            real_time_state["log_total"] = _current_log_total()
                        existing_ids.add(log_dict["id"])
                    current_total = _current_log_total()
                payload = dict(log_dict)
                payload["collection_total"] = current_total
                event_dispatcher.publish("log.new", payload)

                if replayed:
                    continue

                _apply_detection_rules(log_dict)

                threats = unified_analyzer.detect_threats(log)
                for threat in threats:
                    threat_dict = _threat_to_dict(threat, log_dict)
                    with state_lock:
                        real_time_state["threats"].append(threat_dict)
                        real_time_state["threats"] = _limit_list(real_time_state["threats"], 500)
                    event_dispatcher.publish("threat.detected", threat_dict)
                    response_summary = response_engine.handle_threat(threat_dict, log_dict)
                    with state_lock:
                        real_time_state["incidents"].append(response_summary)
                        real_time_state["alerts"].append({"threat": threat_dict, "response": response_summary})

            with state_lock:
                real_time_state["log_total"] = _current_log_total()

            if len(unified_analyzer.logs) >= 10:
                recent_logs = unified_analyzer.logs[-30:]
                new_anomalies = unified_analyzer.detect_ml_anomalies(recent_logs)
                if new_anomalies:
                    anomaly_dicts = [_anomaly_to_dict(anomaly) for anomaly in new_anomalies]
                    with state_lock:
                        real_time_state["anomalies"].extend(anomaly_dicts)
                        real_time_state["anomalies"] = _limit_list(real_time_state["anomalies"], 500)
                    for anomaly in anomaly_dicts:
                        event_dispatcher.publish("anomaly.detected", anomaly)

            time.sleep(max(1, config.log_update_interval))
        except Exception as exc:  # pylint: disable=broad-except
            event_dispatcher.publish("monitoring.error", {"message": str(exc)})
            time.sleep(5)


def _metrics_loop() -> None:
    while not shutdown_event.is_set():
        metrics = process_controller.collect_system_metrics()
        processes = process_controller.list_processes(limit=200)
        with state_lock:
            blacklist_snapshot = list(real_time_state["blacklist"])
        with state_lock:
            real_time_state["metrics"] = metrics
            real_time_state["processes"] = processes
        event_dispatcher.publish("system.metrics", metrics)

        if blacklist_snapshot:
            results = process_controller.enforce_blacklist(blacklist_snapshot)
            if results:
                timestamp = datetime.now().isoformat()
                event_dispatcher.publish(
                    "blacklist.enforced",
                    {"results": results, "timestamp": timestamp, "count": len(results)},
                )
                refreshed_processes = process_controller.list_processes(limit=200)
                audit_entries = db_manager.fetch_audit_logs(limit=200)
                with state_lock:
                    real_time_state["processes"] = refreshed_processes
                    real_time_state["audit_logs"] = audit_entries

        time.sleep(max(2, config.metrics_poll_interval))


def _blacklist_loop() -> None:
    while not shutdown_event.is_set():
        entries = db_manager.fetch_blacklist()
        if entries:
            results = process_controller.enforce_blacklist(entries)
            if results:
                event_dispatcher.publish("blacklist.enforced", {"results": results})
        time.sleep(max(5, config.blacklist_enforcement_interval))


def _heartbeat_loop() -> None:
    while not shutdown_event.is_set():
        event_dispatcher.publish(
            "monitoring.heartbeat",
            {"timestamp": datetime.now().isoformat(), "subscribers": event_dispatcher.subscriber_count()},
        )
        time.sleep(HEARTBEAT_INTERVAL)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index() -> Any:
    return jsonify(
        {
            "message": "OS Log Analyzer API",
            "version": "3.0",
            "websocket": "/api/ws/stream",
            "health": "/api/health",
        }
    )


@app.route("/api/system/status")
def system_status() -> Any:
    uptime = (datetime.now() - app_start_time).total_seconds()
    with state_lock:
        logs_count = _current_log_total()
        threat_count = len(real_time_state["threats"])
        anomaly_count = len(real_time_state["anomalies"])
        metrics = real_time_state["metrics"]
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "monitoring_active": monitoring_active,
            "uptime_seconds": uptime,
            "os_type": unified_analyzer.os_type if unified_analyzer else os.name,
            "logs_collected": logs_count,
            "threats_detected": threat_count,
            "anomalies_found": anomaly_count,
            "metrics": metrics,
            "services": {
                "unified_analyzer": unified_analyzer is not None,
                "monitoring_thread": monitoring_thread.is_alive() if monitoring_thread else False,
                "metrics_thread": metrics_thread.is_alive() if metrics_thread else False,
                "blacklist_thread": blacklist_thread.is_alive() if blacklist_thread else False,
            },
        }
    )


@app.route("/api/system/metrics")
def system_metrics() -> Any:
    with state_lock:
        metrics = real_time_state["metrics"]
        processes = real_time_state["processes"][:100]
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "metrics": metrics,
            "processes": processes,
        }
    )


@app.route("/api/logs/live")
def logs_live() -> Any:
    limit = request.args.get("limit", 100, type=int)
    with state_lock:
        logs = real_time_state["logs"][-max(1, min(limit, 1000)) :]
        total = _current_log_total()
        for entry in logs:
            entry.setdefault("received_at", entry.get("timestamp"))
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "total": total,
            "returned": len(logs),
            "logs": logs,
            "monitoring_active": monitoring_active,
        }
    )


@app.route("/api/threats/active")
def threats_active() -> Any:
    with state_lock:
        threats = real_time_state["threats"][-200:]
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "active_threats": len(threats),
            "threats": threats,
        }
    )


@app.route("/api/threats/analyze", methods=["POST"])
def threats_analyze() -> Any:
    data = request.get_json() or {}
    logs = data.get("logs", [])
    if unified_analyzer is None:
        return jsonify({"error": "Analyzer not initialized"}), 500
    results: List[Dict[str, Any]] = []
    for log in logs:
        try:
            entry = LogEntry(
                timestamp=datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")),
                os_type=log.get("os_type", "unknown"),
                log_type=log.get("log_type", "unknown"),
                source=log.get("source", "unknown"),
                event_id=log.get("event_id", ""),
                level=log.get("level", "INFO"),
                message=log.get("message", ""),
                raw_data=log.get("raw_data", ""),
            )
        except Exception as exc:  # pylint: disable=broad-except
            results.append({"error": str(exc), "log": log})
            continue
        for threat in unified_analyzer.detect_threats(entry):
            threat_dict = _threat_to_dict(threat, log)
            results.append(threat_dict)
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "analyzed_logs": len(logs),
            "threats_found": len(results),
            "results": results,
        }
    )


@app.route("/api/ml/anomalies")
def ml_anomalies() -> Any:
    with state_lock:
        anomalies = real_time_state["anomalies"][-200:]
    return jsonify(
        {
            "timestamp": datetime.now().isoformat(),
            "anomalies": anomalies,
            "total_logs_analyzed": len(unified_analyzer.logs) if unified_analyzer else 0,
        }
    )


@app.route("/api/processes")
def list_processes() -> Any:
    limit = request.args.get("limit", 200, type=int)
    processes = process_controller.list_processes(limit=max(10, min(limit, 500)))
    return jsonify({"timestamp": datetime.now().isoformat(), "processes": processes})


@app.route("/api/process-groups/action", methods=["POST"])
def process_group_action() -> Any:
    payload = request.get_json() or {}
    action = payload.get("action")
    reason = payload.get("reason")
    identifier = payload.get("identifier")
    identifier_type = payload.get("identifier_type", "process")
    raw_pids = payload.get("pids", [])
    metadata = payload.get("metadata")

    if action not in {"kill", "quarantine", "blacklist"}:
        return jsonify({"error": "Unsupported action"}), 400
    if not isinstance(raw_pids, list) or not raw_pids:
        return jsonify({"error": "pids list is required"}), 400

    normalized_pids: List[int] = []
    for pid in raw_pids:
        try:
            normalized_pids.append(int(pid))
        except (TypeError, ValueError):
            continue
    if not normalized_pids:
        return jsonify({"error": "No valid process identifiers provided"}), 400

    result: Dict[str, Any]
    blacklist_entry_id: Optional[int] = None

    if action == "kill":
        result = process_controller.terminate_process_group(normalized_pids, reason=reason)
    elif action == "quarantine":
        result = process_controller.quarantine_process_group(normalized_pids, reason=reason)
    else:
        if not identifier:
            return jsonify({"error": "identifier is required for blacklist action"}), 400
        blacklist_entry_id = db_manager.add_blacklist_entry(
            identifier=identifier,
            entry_type=identifier_type,
            reason=reason or "manual block",
            metadata=metadata,
        )
        with state_lock:
            real_time_state["blacklist"] = db_manager.fetch_blacklist()
        result = process_controller.terminate_process_group(normalized_pids, reason="blacklist")
        result["blacklist_entry_id"] = blacklist_entry_id
        result["identifier"] = identifier
        result["identifier_type"] = identifier_type

    response_payload = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "identifier": identifier,
        "identifier_type": identifier_type,
        "pids": normalized_pids,
        "reason": reason,
        "result": result,
    }

    event_dispatcher.publish("process.action", response_payload)
    event_dispatcher.publish("process_group.action", response_payload)
    if action == "blacklist" and blacklist_entry_id is not None:
        event_dispatcher.publish("blacklist.added", {"entry_id": blacklist_entry_id, "identifier": identifier})

    return jsonify(response_payload)


@app.route("/api/processes/<int:pid>/action", methods=["POST"])
def process_action(pid: int) -> Any:
    payload = request.get_json() or {}
    action = payload.get("action")
    reason = payload.get("reason")
    if action not in {"kill", "quarantine", "blacklist"}:
        return jsonify({"error": "Unsupported action"}), 400
    if action == "kill":
        result = process_controller.terminate_process(pid, reason=reason)
    elif action == "quarantine":
        result = process_controller.quarantine_process(pid, reason=reason)
    else:
        hash_value = process_controller.process_hash(pid)
        if hash_value:
            db_manager.add_blacklist_entry(hash_value, "hash", reason or "manual")
        result = process_controller.terminate_process(pid, reason="blacklist")
    event_dispatcher.publish("process.action", {"pid": pid, "action": action, "result": result})
    return jsonify({"timestamp": datetime.now().isoformat(), "result": result})


@app.route("/api/blacklist", methods=["GET", "POST"])
def blacklist() -> Any:
    if request.method == "GET":
        entries = db_manager.fetch_blacklist()
        return jsonify({"timestamp": datetime.now().isoformat(), "blacklist": entries})
    payload = request.get_json() or {}
    identifier = payload.get("identifier")
    entry_type = payload.get("type", "process")
    if not identifier:
        return jsonify({"error": "identifier is required"}), 400
    entry_id = db_manager.add_blacklist_entry(
        identifier=identifier,
        entry_type=entry_type,
        reason=payload.get("reason"),
        expires_at=payload.get("expires_at"),
        metadata=payload.get("metadata"),
    )
    with state_lock:
        real_time_state["blacklist"] = db_manager.fetch_blacklist()
    event_dispatcher.publish("blacklist.added", {"entry_id": entry_id, "identifier": identifier})
    return jsonify({"entry_id": entry_id, "status": "added"}), 201


@app.route("/api/blacklist/<path:identifier>", methods=["DELETE"])
def blacklist_remove(identifier: str) -> Any:
    db_manager.remove_blacklist_identifier(identifier)
    with state_lock:
        real_time_state["blacklist"] = db_manager.fetch_blacklist()
    event_dispatcher.publish("blacklist.removed", {"identifier": identifier})
    return jsonify({"status": "removed"})


@app.route("/api/blacklist/enforce", methods=["POST"])
def blacklist_enforce() -> Any:
    entries = db_manager.fetch_blacklist()
    results = process_controller.enforce_blacklist(entries)
    payload = {
        "timestamp": datetime.now().isoformat(),
        "results": results,
        "count": len(results),
    }
    event_dispatcher.publish("blacklist.enforced", payload)
    return jsonify(payload)


@app.route("/api/rules", methods=["GET", "POST"])
def rules() -> Any:
    if request.method == "GET":
        ruleset = db_manager.fetch_rules()
        return jsonify({"rules": ruleset})
    payload = request.get_json() or {}
    if not payload.get("name") or not payload.get("pattern"):
        return jsonify({"error": "name and pattern are required"}), 400
    rule_id = db_manager.upsert_rule(payload)
    with state_lock:
        real_time_state["rules"] = db_manager.fetch_rules()
    _update_compiled_rules(real_time_state["rules"])
    event_dispatcher.publish("rule.created", {"rule_id": rule_id})
    return jsonify({"rule_id": rule_id, "status": "created"}), 201


@app.route("/api/rules/<int:rule_id>", methods=["PATCH", "DELETE"])
def rule_detail(rule_id: int) -> Any:
    if request.method == "PATCH":
        payload = request.get_json() or {}
        db_manager.update_rule(rule_id, payload)
        with state_lock:
            real_time_state["rules"] = db_manager.fetch_rules()
        _update_compiled_rules(real_time_state["rules"])
        event_dispatcher.publish("rule.updated", {"rule_id": rule_id})
        return jsonify({"status": "updated"})
    db_manager.delete_rule(rule_id)
    with state_lock:
        real_time_state["rules"] = db_manager.fetch_rules()
    _update_compiled_rules(real_time_state["rules"])
    event_dispatcher.publish("rule.deleted", {"rule_id": rule_id})
    return jsonify({"status": "deleted"})


@app.route("/api/incidents", methods=["GET"])
def incidents() -> Any:
    incidents_list = db_manager.fetch_incidents()
    return jsonify({"incidents": incidents_list})


@app.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
def update_incident(incident_id: int) -> Any:
    payload = request.get_json() or {}
    db_manager.update_incident(incident_id, payload)
    event_dispatcher.publish("incident.updated", {"incident_id": incident_id, "payload": payload})
    return jsonify({"status": "updated"})


@app.route("/api/audit/logs")
def audit_logs() -> Any:
    logs = db_manager.fetch_audit_logs(limit=200)
    return jsonify({"audit_logs": logs})


@app.route("/api/export/logs/<format>")
def export_logs(format: str) -> Any:
    if unified_analyzer is None or not unified_analyzer.logs:
        return jsonify({"error": "No logs available"}), 400
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if format == "json":
        filename = f"logs_{timestamp}.json"
        filepath = os.path.join(EXPORTS_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as handle:
            json.dump([_log_to_dict(log) for log in unified_analyzer.logs], handle, indent=2)
        return send_from_directory(EXPORTS_DIR, filename, as_attachment=True)
    if format == "csv":
        filename = f"logs_{timestamp}.csv"
        filepath = os.path.join(EXPORTS_DIR, filename)
        with open(filepath, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Timestamp", "OS", "Type", "Source", "Event", "Level", "Message"])
            for log in unified_analyzer.logs:
                writer.writerow(
                    [
                        log.timestamp.isoformat(),
                        log.os_type,
                        log.log_type,
                        log.source,
                        log.event_id,
                        log.level,
                        log.message[:500],
                    ]
                )
        return send_from_directory(EXPORTS_DIR, filename, as_attachment=True)
    if format == "xlsx":
        if pd is None:
            return jsonify({"error": "pandas is required for xlsx export"}), 400
        filename = unified_analyzer.export_to_excel(directory=EXPORTS_DIR)
        return send_from_directory(EXPORTS_DIR, filename, as_attachment=True)
    return jsonify({"error": "Unsupported format"}), 400


@app.route("/api/monitoring/start", methods=["POST"])
def monitoring_start() -> Any:
    if unified_analyzer is None:
        return jsonify({"error": "Analyzer unavailable"}), 500
    started = start_monitoring()
    event_dispatcher.publish("monitoring.state", {"active": started})
    return jsonify({"status": "active" if started else "already"})


@app.route("/api/monitoring/stop", methods=["POST"])
def monitoring_stop() -> Any:
    stopped = stop_monitoring()
    event_dispatcher.publish("monitoring.state", {"active": not stopped})
    return jsonify({"status": "inactive" if stopped else "already"})


@app.route("/api/analysis/comprehensive", methods=["POST"])
def analysis_comprehensive() -> Any:
    if unified_analyzer is None:
        return jsonify({"error": "Analyzer unavailable"}), 500
    summary = unified_analyzer.get_summary()
    return jsonify({"timestamp": datetime.now().isoformat(), "analysis_results": summary})


@app.route("/api/analysis/quick", methods=["POST"])
def analysis_quick() -> Any:
    payload = request.get_json() or {}
    duration = int(payload.get("duration", 30))
    result = quick_analysis(duration)
    return jsonify({"timestamp": datetime.now().isoformat(), "duration": duration, "results": result})


@app.route("/api/health")
def health() -> Any:
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime": (datetime.now() - app_start_time).total_seconds(),
            "monitoring_active": monitoring_active,
            "logs_collected": len(unified_analyzer.logs) if unified_analyzer else 0,
            "threats_detected": len(unified_analyzer.threats) if unified_analyzer else 0,
        }
    )


@app.errorhandler(404)
def not_found(_: Exception) -> Any:  # pylint: disable=unused-argument
    return (
        jsonify(
            {
                "error": "Endpoint not found",
                "available": [
                    "/api/health",
                    "/api/system/status",
                    "/api/logs/live",
                    "/api/threats/active",
                    "/api/system/metrics",
                ],
            }
        ),
        404,
    )


@app.errorhandler(500)
def internal_error(_: Exception) -> Any:  # pylint: disable=unused-argument
    return (
        jsonify(
            {
                "error": "Internal server error",
                "timestamp": datetime.now().isoformat(),
            }
        ),
        500,
    )


# ---------------------------------------------------------------------------
# WebSocket streaming
# ---------------------------------------------------------------------------


@sock.route("/api/ws/stream")
def ws_stream(ws):  # type: ignore[override]
    subscription = event_dispatcher.subscribe()
    try:
        ws.send(json.dumps({"type": "snapshot", "payload": _snapshot()}))
        while True:
            event = subscription.get()
            ws.send(json.dumps(event))
    except ConnectionClosed:
        pass
    finally:
        event_dispatcher.unsubscribe(subscription)


# ---------------------------------------------------------------------------
# Application startup
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("Starting OS Log Analyzer backend...")
    if initialize_services():
        ensure_background_threads()
        start_monitoring()
    else:
        print("Failed to initialize analyzer; running in limited mode")
    ensure_background_threads()
    app.run(host="0.0.0.0", port=5000, debug=config.debug, use_reloader=False)