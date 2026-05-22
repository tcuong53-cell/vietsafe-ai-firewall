from __future__ import annotations

import re
from dataclasses import dataclass

from .detection import Finding, detect_pii, detect_policy_violations, sanitize_text, score_findings, unique_findings


@dataclass
class OutputGuardResult:
    findings: list[Finding]
    risk: int
    safe_response: str
    status: str
    pii_masked: int


def detect_hallucination(response: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"nguyen trai sinh nam 1500", response, re.I):
        findings.append(
            Finding(
                type="output_guard",
                label="Hallucination Checker",
                severity="high",
                score=24,
                evidence="Claim mau sai: Nguyen Trai khong sinh nam 1500.",
                action="regenerate_or_warn",
            )
        )
    if re.search(r"(chac chan dung|khong the sai|bao dam chinh xac)", response, re.I):
        findings.append(
            Finding(
                type="output_guard",
                label="Overconfidence",
                severity="medium",
                score=12,
                evidence="Phan hoi dung ngon ngu chac chan qua muc.",
                action="rewrite",
            )
        )
    return findings


def run_output_guard(raw_response: str, tenant_policy: dict | None, mask_pii: bool, auto_rewrite: bool) -> OutputGuardResult:
    pii_findings, pii_matches = detect_pii(raw_response)
    policy_findings = [
        Finding(
            type="output_guard",
            label=f"Output Policy: {finding.label}",
            severity=finding.severity,
            score=min(finding.score + 4, 30),
            evidence=finding.evidence,
            action=finding.action,
            ruleId=finding.ruleId,
            source=finding.source,
        )
        for finding in detect_policy_violations(raw_response, tenant_policy)
    ]
    output_findings = [
        Finding(
            type="output_guard" if finding.type == "pii" else finding.type,
            label=finding.label,
            severity=finding.severity,
            score=finding.score,
            evidence=finding.evidence,
            action=finding.action,
            ruleId=finding.ruleId,
            source=finding.source,
        )
        for finding in pii_findings
    ]
    output_findings.extend(policy_findings)
    output_findings.extend(detect_hallucination(raw_response))
    output_findings = unique_findings(output_findings)

    score = score_findings(output_findings)
    risk = score["risk"]
    safe_response = sanitize_text(raw_response, pii_matches, mask_pii)
    status = "danger" if risk >= 70 else "warn" if risk >= 35 else "safe"

    if output_findings and auto_rewrite:
        reasons = "\n".join(f"- {finding.label}: {finding.evidence}" for finding in output_findings)
        safe_response = (
            "Phan hoi da duoc Output Guard rewrite.\n\n"
            "Ly do:\n"
            f"{reasons}\n\n"
            "Phien ban an toan: Toi co the cung cap thong tin chung, giai thich quy trinh "
            "va khuyen nghi kiem tra dieu khoan/ho so chinh thuc. Khong cam ket ket qua "
            "tuyet doi, khong tiet lo du lieu ca nhan va khong thay the chuyen gia phu trach."
        )
    elif risk >= 70:
        safe_response = "Output bi chan vi phat hien rui ro cao trong phan hoi AI."

    return OutputGuardResult(
        findings=output_findings,
        risk=risk,
        safe_response=safe_response,
        status=status,
        pii_masked=len(pii_matches),
    )
