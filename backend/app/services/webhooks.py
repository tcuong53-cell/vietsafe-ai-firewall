from __future__ import annotations

import logging
from typing import Any

import httpx

from ..config import Settings


logger = logging.getLogger(__name__)


async def send_siem_webhook(url: str | None, payload: dict[str, Any], settings: Settings) -> None:
    if not url:
        return
    async with httpx.AsyncClient(timeout=settings.webhook_timeout_seconds) as client:
        try:
            await client.post(url, json=payload)
        except httpx.HTTPError as exc:
            logger.warning("SIEM webhook delivery failed: %s", exc)
