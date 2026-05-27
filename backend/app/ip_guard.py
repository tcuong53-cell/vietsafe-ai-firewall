from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field
from fastapi import Request, HTTPException, status

BLACKLIST_FILE = Path(__file__).parent.parent.parent / "ip_blacklist.json"


@dataclass
class IPRecord:
    blocked_at: float = 0
    reason: str = ""
    violations: int = 0
    last_violation: float = 0


class IPGuard:
    def __init__(self):
        self._blacklist: dict[str, IPRecord] = {}
        self._violations: dict[str, list[float]] = defaultdict(list)
        self._load_blacklist()

    def _load_blacklist(self):
        if BLACKLIST_FILE.exists():
            try:
                data = json.loads(BLACKLIST_FILE.read_text(encoding="utf-8"))
                for ip, info in data.items():
                    self._blacklist[ip] = IPRecord(**info)
            except Exception:
                pass

    def _save_blacklist(self):
        data = {}
        for ip, record in self._blacklist.items():
            data[ip] = {"blocked_at": record.blocked_at, "reason": record.reason, "violations": record.violations, "last_violation": record.last_violation}
        BLACKLIST_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def is_blocked(self, ip: str) -> tuple[bool, str]:
        record = self._blacklist.get(ip)
        if record and record.blocked_at > 0:
            return True, record.reason
        return False, ""

    def block_ip(self, ip: str, reason: str = "Manual block"):
        self._blacklist[ip] = IPRecord(blocked_at=time.time(), reason=reason)
        self._save_blacklist()

    def unblock_ip(self, ip: str):
        self._blacklist.pop(ip, None)
        self._save_blacklist()

    def record_violation(self, ip: str, threshold: int = 10, window_seconds: int = 300):
        now = time.monotonic()
        timestamps = self._violations[ip]
        timestamps.append(now)
        # Prune old violations
        self._violations[ip] = [t for t in timestamps if now - t <= window_seconds]
        if len(self._violations[ip]) >= threshold:
            self.block_ip(ip, f"Auto-blocked: {len(self._violations[ip])} violations in {window_seconds}s")

    def list_blocked(self) -> list[dict]:
        result = []
        for ip, record in self._blacklist.items():
            if record.blocked_at > 0:
                result.append({"ip": ip, "reason": record.reason, "blocked_at": record.blocked_at, "violations": record.violations})
        return result


ip_guard = IPGuard()
