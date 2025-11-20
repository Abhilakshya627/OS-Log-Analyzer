"""Autonomous response actions for detected threats."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set

from app.database import DatabaseManager
from app.event_dispatcher import EventDispatcher
from app.process_control import ProcessController

SEVERITY_AUTO_ACTION = {"high", "critical"}
PROCESS_NAME_REGEX = re.compile(r"([\\w\\-]+(?:\.exe|\.bin|\.sh|\.py)?)", re.IGNORECASE)


class ResponseEngine:
    """Executes automated countermeasures and records outcomes."""

    def __init__(
        self,
        db: DatabaseManager,
        processes: ProcessController,
        dispatcher: EventDispatcher,
    ) -> None:
        self._db = db
        self._processes = processes
        self._dispatcher = dispatcher

    # ------------------------------------------------------------------
    def handle_threat(self, threat: Dict[str, object], log_entry: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        actions_taken: List[Dict[str, object]] = []

        severity = str(threat.get("severity") or "").lower()
        message = ""
        source = ""
        if isinstance(log_entry, dict):
            raw_message = log_entry.get("message")
            if isinstance(raw_message, str):
                message = raw_message
            elif raw_message is not None:
                message = str(raw_message)

            raw_source = log_entry.get("source")
            if isinstance(raw_source, str):
                source = raw_source
            elif raw_source is not None:
                source = str(raw_source)

        rule_action = str(threat.get("rule_action") or "").lower()

        auto_action_required = severity in SEVERITY_AUTO_ACTION or rule_action == "block"

        if auto_action_required:
            suspected_processes = self._extract_process_names(str(message))
            if source:
                suspected_processes.add(str(source))
            for process_name in suspected_processes:
                if not process_name:
                    continue
                terminate_results = self._processes.terminate_by_name(process_name, reason="auto_response")
                for result in terminate_results:
                    if result.get("status") == "terminated":
                        actions_taken.append({"type": "terminate", "target": process_name, "result": result})
                        self._db.add_blacklist_entry(
                            identifier=process_name,
                            entry_type="process",
                            reason=f"Auto-response for threat {threat.get('threat_type')}",
                        )

            # Attempt IP block if available
            source_ip = threat.get("source_ip")
            if isinstance(source_ip, str) and source_ip:
                block_result = self._block_ip(source_ip)
                actions_taken.append({"type": "block_ip", "target": source_ip, "result": block_result})

            if rule_action == "block" and not suspected_processes and log_entry:
                identifier = (log_entry.get("source") or log_entry.get("log_type") or "rule_block") if isinstance(log_entry, dict) else "rule_block"
                try:
                    self._db.add_blacklist_entry(
                        identifier=str(identifier),
                        entry_type="process",
                        reason=f"Rule enforced block for {threat.get('rule_id', 'unknown')}",
                    )
                except Exception:
                    pass

        # Record alert + actions
        action_labels = [str(action.get("type")) for action in actions_taken if action.get("type")]
        action_taken = "; ".join(action_labels) if action_labels else None
        alert_id = self._db.record_alert(
            threat=threat,
            action_taken=action_taken,
            log_reference=log_entry,
        )
        incident_id = self._db.create_incident(
            alert_id=alert_id,
            summary=f"Threat detected: {threat.get('threat_type')} ({severity})",
            status="open",
        )
        self._db.record_audit(
            action="auto_response",
            details={
                "alert_id": alert_id,
                "incident_id": incident_id,
                "threat": threat,
                "actions": actions_taken,
            },
        )
        # Notify dashboards
        self._dispatcher.publish(
            "threat.response",
            {
                "alert_id": alert_id,
                "incident_id": incident_id,
                "threat": threat,
                "actions": actions_taken,
            },
        )
        return {"alert_id": alert_id, "incident_id": incident_id, "actions": actions_taken}

    # ------------------------------------------------------------------
    def _extract_process_names(self, message: str) -> Set[str]:
        matches = PROCESS_NAME_REGEX.findall(message or "")
        return {match for match in matches if match}

    # ------------------------------------------------------------------
    def _block_ip(self, ip_address: str) -> Dict[str, object]:
        if os.name == "nt":
            command = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=OSLogAnalyzer_{ip_address}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
            ]
        else:
            command = ["sh", "-c", f"sudo iptables -A INPUT -s {ip_address} -j DROP"]

        response: Dict[str, object]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            success = result.returncode == 0
            response = {
                "status": "blocked" if success else "failed",
                "returncode": int(result.returncode),
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except Exception as exc:  # pylint: disable=broad-except
            response = {"status": "error", "error": str(exc)}

        self._db.record_audit(
            action="block_ip",
            details={"ip": ip_address, "result": response},
        )
        return response
