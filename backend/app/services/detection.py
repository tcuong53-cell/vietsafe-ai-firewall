from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any

from .policy import POLICY_CATALOG, enabled_rule_ids, thresholds


@dataclass
class Finding:
    type: str
    label: str
    severity: str
    score: int
    evidence: str
    action: str
    ruleId: str | None = None
    source: str = "local"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PIIMatch:
    kind: str
    value: str
    masked: str


def normalize_text(text: str) -> str:
    stripped = "".join(
        char for char in unicodedata.normalize("NFD", text) if unicodedata.category(char) != "Mn"
    )
    return stripped.replace("đ", "d").replace("Đ", "D").lower().strip()


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def unique_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.type, finding.evidence, finding.ruleId, finding.source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def mask_value(kind: str, value: str) -> str:
    if kind == "email" and "@" in value:
        name, domain = value.split("@", 1)
        return f"{name[:2]}{'*' * max(3, len(name) - 2)}@{domain}"

    digits = re.sub(r"\D", "", value)
    if len(digits) <= 4:
        return "*" * len(value)

    keep = set(digits[-2:])
    remaining = len(digits)
    output: list[str] = []
    for char in value:
        if not char.isdigit():
            output.append(char)
            continue
        remaining -= 1
        if remaining < 2 and char in keep:
            output.append(char)
        else:
            output.append("*")
    return "".join(output)


def detect_prompt_injection(text: str) -> list[Finding]:
    normalized = normalize_text(text)
    detectors = (
        (r"(bo qua|ignore|quen).{0,28}(luat|chi dan|system|developer|instruction)", 26, "high", "Yeu cau bo qua chi dan he thong"),
        (r"(show|reveal|hien|in ra).{0,32}(system prompt|developer message|luat an|prompt he thong)", 28, "high", "Co lay system prompt hoac chi dan an"),
        (r"(jailbreak|dan|do anything now|khong con gioi han)", 24, "high", "Tin hieu jailbreak pho bien"),
        (r"(hay|please).{0,24}(gia vo|dong vai|roleplay).{0,48}(khong bi rang buoc|bo policy|khong tuan thu)", 20, "medium", "Roleplay de ne policy"),
        (r"(base64|ma hoa|encode|decode).{0,40}(lenh|payload|prompt|policy)", 16, "medium", "Co dau hieu che giau lenh"),
    )
    findings = []
    for pattern, score, severity, evidence in detectors:
        if re.search(pattern, normalized, re.I):
            findings.append(
                Finding(
                    type="prompt_injection",
                    label="Prompt Injection",
                    severity=severity,
                    score=score,
                    evidence=evidence,
                    action="block_or_sandbox",
                )
            )
    return findings


def detect_pii(text: str) -> tuple[list[Finding], list[PIIMatch]]:
    detectors = (
        ("email", "Email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), 10, None),
        ("phone", "So dien thoai", re.compile(r"(?:\+?84|0)(?:3|5|7|8|9)[0-9][ .-]?[0-9]{3}[ .-]?[0-9]{3,4}\b"), 12, None),
        ("national_id", "CCCD/CMND", re.compile(r"\b(?:\d[ -]?){9,12}\b"), 16, re.compile(r"(cccd|cmnd|can cuoc|chung minh)", re.I)),
        ("bank_account", "Tai khoan ngan hang", re.compile(r"\b(?:\d[ -]?){8,16}\b"), 16, re.compile(r"(stk|so tai khoan|ngan hang|account number)", re.I)),
        ("contract", "Ma hop dong", re.compile(r"\b(?:HD|POL|BH)[-_]?[0-9A-Z]{5,12}\b", re.I), 12, None),
    )

    findings: list[Finding] = []
    matches: list[PIIMatch] = []
    normalized = normalize_text(text)
    for kind, label, pattern, score, context in detectors:
        for match in pattern.finditer(text):
            if context:
                start = max(0, match.start() - 55)
                end = min(len(text), match.end() + 55)
                window = normalize_text(text[start:end])
                if not context.search(window):
                    continue
            masked = mask_value(kind, match.group(0))
            matches.append(PIIMatch(kind=kind, value=match.group(0), masked=masked))
            findings.append(
                Finding(
                    type="pii",
                    label=label,
                    severity="high" if score >= 16 else "medium",
                    score=score,
                    evidence=f"Phat hien {label}: {masked}",
                    action="mask",
                )
            )

    if "customer" in normalized and "database" in normalized:
        findings.append(
            Finding(
                type="pii",
                label="Data leak intent",
                severity="high",
                score=16,
                evidence="Prompt co y dinh truy cap database khach hang.",
                action="block",
            )
        )

    return unique_findings(findings), matches


def detect_toxicity(text: str) -> list[Finding]:
    normalized = normalize_text(text)
    detectors = (
        (r"(giet|tan cong|danh bom|tu sat)", 24, "high", "Noi dung bao luc hoac tu hai"),
        (r"(ngu|dien|cam mieng|rac ruoi)", 11, "medium", "Ngon ngu xuc pham hoac quay roi"),
        (r"(spam|gui hang loat|quet danh ba|mua data)", 16, "medium", "Tin hieu spam hoac lam dung"),
    )
    return [
        Finding(
            type="toxicity",
            label="Toxicity / Abuse",
            severity=severity,
            score=score,
            evidence=evidence,
            action="block" if severity == "high" else "warn",
        )
        for pattern, score, severity, evidence in detectors
        if re.search(pattern, normalized, re.I)
    ]


def detect_policy_violations(text: str, tenant_policy: dict | None) -> list[Finding]:
    normalized = normalize_text(text)
    active_rules = enabled_rule_ids(tenant_policy)
    findings: list[Finding] = []
    for rule in POLICY_CATALOG:
        if rule.id not in active_rules:
            continue
        if rule.max_length and len(text) > rule.max_length:
            findings.append(
                Finding(
                    type="policy",
                    label=rule.name,
                    severity="medium",
                    score=rule.weight,
                    evidence=f"Prompt dai {len(text)} ky tu, vuot gioi han {rule.max_length}.",
                    action="warn",
                    ruleId=rule.id,
                )
            )
        for pattern in rule.patterns:
            if not pattern.search(normalized):
                continue
            findings.append(
                Finding(
                    type="policy",
                    label=rule.name,
                    severity="critical" if rule.weight >= 30 else "high" if rule.weight >= 20 else "medium",
                    score=rule.weight,
                    evidence=rule.description,
                    action="block" if rule.weight >= 30 else "warn",
                    ruleId=rule.id,
                )
            )
    return unique_findings(findings)


def sanitize_text(text: str, pii_matches: list[PIIMatch], should_mask: bool) -> str:
    if not should_mask:
        return text
    sanitized = text
    for match in pii_matches:
        sanitized = sanitized.replace(match.value, match.masked)
    return sanitized


def score_findings(findings: list[Finding]) -> dict[str, Any]:
    categories = {
        "prompt_injection": 0,
        "pii": 0,
        "toxicity": 0,
        "policy": 0,
        "output_guard": 0,
    }
    for finding in findings:
        categories[finding.type] = categories.get(finding.type, 0) + finding.score

    weighted_score = (
        min(categories.get("prompt_injection", 0), 42)
        + min(categories.get("pii", 0), 28)
        + min(categories.get("toxicity", 0), 28)
        + min(categories.get("policy", 0), 42)
        + min(categories.get("output_guard", 0), 30)
    )
    critical_boost = 12 if any(f.severity == "critical" for f in findings) else 0
    return {"risk": clamp(weighted_score + critical_boost, 0, 100), "categories": categories}


def decide_action(risk: int, findings: list[Finding], tenant_policy: dict | None, block_high_risk: bool) -> dict[str, str]:
    values = thresholds(tenant_policy)
    if (block_high_risk and risk >= values["block"]) or any(f.severity == "critical" for f in findings):
        return {"action": "block", "label": "Blocked", "className": "danger"}
    if risk >= values["warn"]:
        return {"action": "warn", "label": "Warning", "className": "warn"}
    return {"action": "allow", "label": "Allowed", "className": "safe"}
