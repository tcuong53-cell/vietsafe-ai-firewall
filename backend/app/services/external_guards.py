from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging

import httpx

from ..config import Settings
from .detection import Finding


logger = logging.getLogger(__name__)


@dataclass
class ExternalGuardResult:
    findings: list[Finding]
    metadata: dict[str, Any]


class OpenAIModerationGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def scan(self, text: str) -> ExternalGuardResult:
        if not self.settings.openai_api_key:
            return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "missing_openai_api_key"})

        payload = {"model": self.settings.openai_moderation_model, "input": text}
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                f"{self.settings.openai_base_url.rstrip('/')}/v1/moderations",
                headers={"Authorization": f"Bearer {self.settings.openai_api_key}"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        result = (data.get("results") or [{}])[0]
        flagged = bool(result.get("flagged"))
        scores = result.get("category_scores") or {}
        max_score = max(scores.values(), default=0)
        findings = []
        if flagged or max_score >= 0.6:
            top_categories = sorted(scores.items(), key=lambda item: item[1], reverse=True)[:3]
            evidence = ", ".join(f"{name}={score:.2f}" for name, score in top_categories)
            findings.append(
                Finding(
                    type="toxicity",
                    label="OpenAI Moderation",
                    severity="high" if flagged else "medium",
                    score=26 if flagged else 16,
                    evidence=f"Moderation flagged content: {evidence}",
                    action="block" if flagged else "warn",
                    source="openai_moderation",
                )
            )
        return ExternalGuardResult(findings=findings, metadata={"enabled": True, "raw": data})


class PresidioGuard:
    def __init__(self) -> None:
        self.available = False
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore

            self._analyzer = AnalyzerEngine()
            self.available = True
        except Exception:
            self._analyzer = None

    async def scan(self, text: str) -> ExternalGuardResult:
        if not self.available or self._analyzer is None:
            return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "presidio_not_installed"})

        results = self._analyzer.analyze(text=text, language="en")
        findings = [
            Finding(
                type="pii",
                label=f"Presidio {item.entity_type}",
                severity="high" if item.score >= 0.75 else "medium",
                score=14 if item.score >= 0.75 else 8,
                evidence=f"Presidio found {item.entity_type} with confidence {item.score:.2f}",
                action="mask",
                source="presidio",
            )
            for item in results
            if item.score >= 0.5
        ]
        return ExternalGuardResult(findings=findings, metadata={"enabled": True, "count": len(results)})


class LlamaGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def scan(self, text: str) -> ExternalGuardResult:
        prompt = (
            "Task: Check if the following user message is unsafe. "
            "Return only 'safe' or 'unsafe' and a short category.\n\n"
            f"Message:\n{text}"
        )
        payload = {"model": self.settings.llama_guard_model, "prompt": prompt, "stream": False}
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            try:
                response = await client.post(f"{self.settings.ollama_base_url.rstrip('/')}/api/generate", json=payload)
                response.raise_for_status()
            except httpx.HTTPError:
                return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "llama_guard_unavailable"})
            data = response.json()

        verdict = (data.get("response") or "").strip().lower()
        findings = []
        if verdict.startswith("unsafe"):
            findings.append(
                Finding(
                    type="toxicity",
                    label="Llama Guard",
                    severity="high",
                    score=22,
                    evidence=verdict[:220],
                    action="block",
                    source="llama_guard",
                )
            )
        return ExternalGuardResult(findings=findings, metadata={"enabled": True, "verdict": verdict})


class LLMGuardPackageGuard:
    async def scan(self, text: str) -> ExternalGuardResult:
        try:
            from llm_guard.input_scanners import PromptInjection, Secrets, Toxicity  # type: ignore
        except Exception:
            return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "llm_guard_not_installed"})

        scanners = [PromptInjection(), Secrets(), Toxicity()]
        findings: list[Finding] = []
        metadata: dict[str, Any] = {"enabled": True, "scanners": []}
        for scanner in scanners:
            sanitized, is_valid, risk_score = scanner.scan(text)
            scanner_name = scanner.__class__.__name__
            metadata["scanners"].append({"name": scanner_name, "valid": is_valid, "risk": risk_score})
            if is_valid:
                continue
            findings.append(
                Finding(
                    type="prompt_injection" if scanner_name.lower().startswith("prompt") else "toxicity",
                    label=f"LLM Guard {scanner_name}",
                    severity="high" if risk_score >= 0.7 else "medium",
                    score=24 if risk_score >= 0.7 else 14,
                    evidence=f"{scanner_name} risk={risk_score:.2f}",
                    action="block" if risk_score >= 0.7 else "warn",
                    source="llm_guard",
                )
            )
            if sanitized != text and scanner_name == "Secrets":
                findings[-1].type = "pii"
                findings[-1].action = "mask"
        return ExternalGuardResult(findings=findings, metadata=metadata)


class DetoxifyGuard:
    async def scan(self, text: str) -> ExternalGuardResult:
        try:
            from detoxify import Detoxify  # type: ignore
        except Exception:
            return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "detoxify_not_installed"})

        scores = Detoxify("multilingual").predict(text)
        top_name, top_score = max(scores.items(), key=lambda item: float(item[1]))
        if float(top_score) < 0.55:
            return ExternalGuardResult(findings=[], metadata={"enabled": True, "scores": scores})
        return ExternalGuardResult(
            findings=[
                Finding(
                    type="toxicity",
                    label="Detoxify multilingual",
                    severity="high" if float(top_score) >= 0.8 else "medium",
                    score=24 if float(top_score) >= 0.8 else 14,
                    evidence=f"{top_name}={float(top_score):.2f}",
                    action="block" if float(top_score) >= 0.8 else "warn",
                    source="detoxify",
                )
            ],
            metadata={"enabled": True, "scores": scores},
        )


class PerspectiveGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def scan(self, text: str) -> ExternalGuardResult:
        if not self.settings.perspective_api_key:
            return ExternalGuardResult(findings=[], metadata={"enabled": False, "reason": "missing_perspective_api_key"})

        payload = {
            "comment": {"text": text},
            "languages": ["vi", "en"],
            "requestedAttributes": {
                "TOXICITY": {},
                "INSULT": {},
                "THREAT": {},
                "IDENTITY_ATTACK": {},
                "PROFANITY": {},
            },
        }
        url = (
            "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"
            f"?key={self.settings.perspective_api_key}"
        )
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        scores = {
            name: value.get("summaryScore", {}).get("value", 0)
            for name, value in (data.get("attributeScores") or {}).items()
        }
        top_name, top_score = max(scores.items(), key=lambda item: float(item[1]), default=("TOXICITY", 0))
        findings = []
        if float(top_score) >= 0.55:
            findings.append(
                Finding(
                    type="toxicity",
                    label="Perspective API",
                    severity="high" if float(top_score) >= 0.8 else "medium",
                    score=24 if float(top_score) >= 0.8 else 14,
                    evidence=f"{top_name}={float(top_score):.2f}",
                    action="block" if float(top_score) >= 0.8 else "warn",
                    source="perspective",
                )
            )
        return ExternalGuardResult(findings=findings, metadata={"enabled": True, "scores": scores})


class VietnameseNLPGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def scan(self, text: str) -> ExternalGuardResult:
        from .vietnamese_nlp import vietnamese_entity_findings

        entities = vietnamese_entity_findings(text, self.settings.vietnamese_nlp_backend)
        findings = [
            Finding(
                type="pii",
                label="Vietnamese NLP entity",
                severity="low",
                score=5,
                evidence=item["evidence"],
                action="review",
                source="vietnamese_nlp",
            )
            for item in entities
        ]
        return ExternalGuardResult(findings=findings, metadata={"enabled": True, "entities": entities})


async def run_external_guards(text: str, settings: Settings, options: Any) -> list[Finding]:
    findings: list[Finding] = []
    if getattr(options, "use_openai_moderation", False):
        try:
            findings.extend((await OpenAIModerationGuard(settings).scan(text)).findings)
        except Exception as exc:
            logger.warning("OpenAI moderation guard failed: %s", exc)
    if getattr(options, "use_presidio", False):
        try:
            findings.extend((await PresidioGuard().scan(text)).findings)
        except Exception as exc:
            logger.warning("Presidio guard failed: %s", exc)
    if getattr(options, "use_llama_guard", False):
        try:
            findings.extend((await LlamaGuard(settings).scan(text)).findings)
        except Exception as exc:
            logger.warning("Llama Guard failed: %s", exc)
    if getattr(options, "use_llm_guard", False):
        try:
            findings.extend((await LLMGuardPackageGuard().scan(text)).findings)
        except Exception as exc:
            logger.warning("LLM Guard package failed: %s", exc)
    if getattr(options, "use_detoxify", False):
        try:
            findings.extend((await DetoxifyGuard().scan(text)).findings)
        except Exception as exc:
            logger.warning("Detoxify guard failed: %s", exc)
    if getattr(options, "use_perspective", False):
        try:
            findings.extend((await PerspectiveGuard(settings).scan(text)).findings)
        except Exception as exc:
            logger.warning("Perspective guard failed: %s", exc)
    if getattr(options, "use_vietnamese_nlp", False):
        try:
            findings.extend((await VietnameseNLPGuard(settings).scan(text)).findings)
        except Exception as exc:
            logger.warning("Vietnamese NLP guard failed: %s", exc)
    return findings
