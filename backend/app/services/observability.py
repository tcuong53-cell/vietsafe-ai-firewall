from __future__ import annotations

import logging
from typing import Any

from ..config import Settings


logger = logging.getLogger(__name__)


class ObservabilityClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = bool(settings.langfuse_public_key and settings.langfuse_secret_key)
        self._client: Any = None
        if not self.enabled:
            return
        try:
            from langfuse import Langfuse  # type: ignore

            self._client = Langfuse(
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
                host=settings.langfuse_host,
            )
        except Exception as exc:
            self.enabled = False
            logger.warning("Langfuse unavailable: %s", exc)

    def trace_inspection(self, payload: dict[str, Any]) -> None:
        if not self.enabled or self._client is None:
            return
        try:
            trace = self._client.trace(
                name="ai_firewall_inspection",
                user_id=payload.get("user_id"),
                metadata={
                    "tenant_id": payload.get("tenant_id"),
                    "risk": payload.get("risk"),
                    "action": payload.get("action"),
                    "model": payload.get("model"),
                    "latency_ms": payload.get("latency_ms"),
                },
            )
            trace.score(name="risk", value=payload.get("risk", 0) / 100)
        except Exception as exc:
            logger.warning("Langfuse trace failed: %s", exc)
