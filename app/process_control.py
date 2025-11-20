"""Process management helpers for autonomous response capabilities."""

from __future__ import annotations

from collections import Counter
import hashlib
import os
import shutil
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, cast

import psutil

from app.database import DatabaseManager


class ProcessController:
    """Encapsulates process inspection and response operations."""

    def __init__(self, db: DatabaseManager, quarantine_dir: str) -> None:
        self._db = db
        self._quarantine_dir = quarantine_dir
        os.makedirs(self._quarantine_dir, exist_ok=True)

    # ------------------------------------------------------------------
    def list_processes(self, limit: int = 200) -> List[Dict[str, object]]:
        """Return aggregated process information grouped by executable/name."""

        groups: Dict[str, Dict[str, Any]] = {}
        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "username",
                "cpu_percent",
                "memory_percent",
                "exe",
                "create_time",
                "cmdline",
            ]
        ):
            try:
                info = proc.info
                name = info.get("name") or f"PID {proc.pid}"
                exe = info.get("exe")
                key = (exe or name).lower()
                group = groups.get(key)
                if group is None:
                    display_name = os.path.basename(exe) if exe else name
                    group = {
                        "app_id": key,
                        "name": name,
                        "display_name": display_name,
                        "exe": exe,
                        "identifier": exe or name,
                        "identifier_type": "path" if exe else "process",
                        "usernames": set(),
                        "pids": [],
                        "cpu": 0.0,
                        "memory": 0.0,
                        "instances": 0,
                        "first_start": None,
                        "recent_start": None,
                        "command_lines": [],
                    }
                    groups[key] = group

                cpu_value = float(info.get("cpu_percent") or 0.0)
                mem_value = float(info.get("memory_percent") or 0.0)
                create_time = info.get("create_time")
                cmdline = info.get("cmdline") or []

                group["cpu"] = float(group.get("cpu", 0.0)) + cpu_value
                group["memory"] = float(group.get("memory", 0.0)) + mem_value
                group["instances"] = int(group.get("instances", 0)) + 1
                pids = cast(List[int], group["pids"])
                pid_value = info.get("pid")
                if pid_value is not None:
                    pids.append(int(pid_value))
                username = info.get("username") or "Unknown"
                usernames = cast(Set[str], group["usernames"])
                usernames.add(username)
                if create_time:
                    create_time = float(create_time)
                    first_start = cast(Optional[float], group.get("first_start"))
                    recent_start = cast(Optional[float], group.get("recent_start"))
                    if first_start is None or create_time < first_start:
                        group["first_start"] = create_time
                    if recent_start is None or create_time > recent_start:
                        group["recent_start"] = create_time
                if cmdline:
                    rendered = " ".join(cmdline)
                    command_lines = cast(List[str], group["command_lines"])
                    if rendered and rendered not in command_lines:
                        command_lines.append(rendered)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        aggregated: List[Dict[str, object]] = []
        for group in groups.values():
            first_start = cast(Optional[float], group.get("first_start"))
            usernames = cast(Set[str], group["usernames"])
            command_lines = cast(List[str], group["command_lines"])
            aggregated.append(
                {
                    "app_id": group["app_id"],
                    "name": group["name"],
                    "display_name": group["display_name"],
                    "identifier": group["identifier"],
                    "identifier_type": group["identifier_type"],
                    "exe": group["exe"],
                    "pids": sorted(pid for pid in cast(List[int], group["pids"]) if pid is not None),
                    "instances": int(group.get("instances", 0)),
                    "cpu": round(float(group.get("cpu", 0.0)), 2),
                    "memory": round(float(group.get("memory", 0.0)), 2),
                    "usernames": sorted(usernames),
                    "command_lines": command_lines[:5],
                    "create_time": datetime.fromtimestamp(first_start).isoformat() if first_start else None,
                }
            )

        aggregated.sort(key=lambda item: (item.get("cpu", 0.0), item.get("memory", 0.0)), reverse=True)
        return aggregated[:limit]

    # ------------------------------------------------------------------
    def terminate_process(self, pid: int, reason: Optional[str] = None) -> Dict[str, str]:
        try:
            process = psutil.Process(pid)
            process.terminate()
            _, alive = psutil.wait_procs([process], timeout=3)
            if alive:
                # Force kill if still running
                for proc in alive:
                    proc.kill()
            self._db.record_audit(
                action="terminate_process",
                details={"pid": pid, "reason": reason, "status": "terminated"},
            )
            return {"status": "terminated", "pid": str(pid)}
        except psutil.NoSuchProcess:
            return {"status": "not_found", "pid": str(pid)}
        except psutil.AccessDenied:
            self._db.record_audit(
                action="terminate_process_denied",
                details={"pid": pid, "reason": reason or "", "status": "access_denied"},
            )
            return {"status": "access_denied", "pid": str(pid)}
        except Exception as exc:  # pylint: disable=broad-except
            self._db.record_audit(
                action="terminate_process_error",
                details={"pid": pid, "reason": reason or "", "error": str(exc)},
            )
            return {"status": "error", "pid": str(pid), "error": str(exc)}

    # ------------------------------------------------------------------
    def quarantine_process(self, pid: int, reason: Optional[str] = None) -> Dict[str, str]:
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
            if not exe_path or not os.path.exists(exe_path):
                return {"status": "missing_exe", "pid": str(pid)}

            # Stop process before moving binary
            self.terminate_process(pid, reason="quarantine_pre" if reason else None)

            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            filename = os.path.basename(exe_path)
            target_path = os.path.join(self._quarantine_dir, f"{timestamp}_{filename}")
            try:
                shutil.move(exe_path, target_path)
            except Exception as move_exc:  # pylint: disable=broad-except
                return {"status": "move_failed", "pid": str(pid), "error": str(move_exc)}

            entry_id = self._db.add_blacklist_entry(
                identifier=os.path.normcase(target_path),
                entry_type="path",
                reason=reason or "quarantined",
                metadata={"original_path": exe_path},
            )
            self._db.record_audit(
                action="quarantine_process",
                details={"pid": pid, "from": exe_path, "to": target_path, "entry_id": entry_id},
            )
            return {"status": "quarantined", "pid": str(pid), "path": target_path}
        except psutil.NoSuchProcess:
            return {"status": "not_found", "pid": str(pid)}
        except psutil.AccessDenied:
            return {"status": "access_denied", "pid": str(pid)}

    # ------------------------------------------------------------------
    def terminate_by_name(self, name: str, reason: Optional[str] = None) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc_name = proc.info.get("name")
                if proc_name and proc_name.lower() == name.lower():
                    results.append(self.terminate_process(proc.info["pid"], reason=reason))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    # ------------------------------------------------------------------
    def terminate_process_group(self, pids: Iterable[int], reason: Optional[str] = None) -> Dict[str, object]:
        results = [self.terminate_process(pid, reason=reason) for pid in self._normalize_pids(pids)]
        return self._summarize_results(results)

    # ------------------------------------------------------------------
    def quarantine_process_group(self, pids: Iterable[int], reason: Optional[str] = None) -> Dict[str, object]:
        results = [self.quarantine_process(pid, reason=reason) for pid in self._normalize_pids(pids)]
        return self._summarize_results(results)

    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_pids(pids: Iterable[int]) -> List[int]:
        normalized: List[int] = []
        for pid in pids:
            try:
                value = int(pid)
            except (TypeError, ValueError):
                continue
            if value not in normalized:
                normalized.append(value)
        return normalized

    # ------------------------------------------------------------------
    @staticmethod
    def _summarize_results(results: Iterable[Dict[str, str]]) -> Dict[str, object]:
        summary_counter = Counter()
        for result in results:
            status = result.get("status", "unknown")
            summary_counter[status] += 1
        return {
            "results": results,
            "summary": dict(summary_counter),
        }

    # ------------------------------------------------------------------
    def process_hash(self, pid: int) -> Optional[str]:
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
            if not exe_path or not os.path.exists(exe_path):
                return None
            hasher = hashlib.sha256()
            with open(exe_path, "rb") as binary:
                for chunk in iter(lambda: binary.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            return None

    # ------------------------------------------------------------------
    def enforce_blacklist(self, blacklist_entries: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        normalized_entries = [
            {
                **entry,
                "identifier": os.path.normcase(entry.get("identifier", "")),
                "type": entry.get("type", "process"),
            }
            for entry in blacklist_entries
        ]
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                proc_name = proc.info.get("name", "")
                proc_path = os.path.normcase(proc.info.get("exe", "")) if proc.info.get("exe") else ""
                for entry in normalized_entries:
                    identifier = entry.get("identifier", "")
                    entry_type = entry.get("type", "process")
                    if not identifier:
                        continue
                    if entry_type == "process" and proc_name.lower() == identifier.lower():
                        results.append(self.terminate_process(proc.pid, reason="blacklist"))
                        break
                    if entry_type == "path" and proc_path and proc_path == identifier:
                        results.append(self.terminate_process(proc.pid, reason="blacklist"))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    # ------------------------------------------------------------------
    def collect_system_metrics(self) -> Dict[str, object]:
        try:
            cpu = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/") if os.name != "nt" else psutil.disk_usage(psutil.Process().cwd())
            net = psutil.net_io_counters()
            return {
                "cpu_percent": round(cpu, 2),
                "memory_percent": round(memory.percent, 2),
                "memory_used": memory.used,
                "memory_total": memory.total,
                "disk_percent": round(disk.percent, 2),
                "disk_used": disk.used,
                "disk_total": disk.total,
                "bytes_sent": getattr(net, "bytes_sent", 0),
                "bytes_recv": getattr(net, "bytes_recv", 0),
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"error": str(exc)}
