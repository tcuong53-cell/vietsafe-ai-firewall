from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from ..config import Settings
from ..models import APIKey, AuditLog, Tenant
from ..schemas import InspectRequest, InspectResponse
from .adapters import MockAdapter, get_adapter
from .detection import (
    Finding,
    decide_action,
    detect_pii,
    detect_policy_violations,
    detect_prompt_injection,
    detect_toxicity,
    sanitize_text,
    score_findings,
    unique_findings,
)
from .external_guards import run_external_guards
from .output_guard import run_output_guard
from .observability import ObservabilityClient
from .webhooks import send_siem_webhook


def load_policy(tenant: Tenant) -> dict[str, Any]:
    try:
        return json.loads(tenant.policy_json)
    except json.JSONDecodeError:
        return {}


def summarize_reasons(findings: list[Finding]) -> str:
    if not findings:
        return "safe"
    labels = []
    for finding in findings:
        if finding.label not in labels:
            labels.append(finding.label)
    return ", ".join(labels[:3])


async def inspect_gateway(
    request: InspectRequest,
    tenant: Tenant,
    api_key: APIKey,
    db: Session,
    settings: Settings,
    request_ip: str | None = None,
) -> InspectResponse:
    started = time.perf_counter()
    now = datetime.utcnow()
    tenant_policy = load_policy(tenant)

    local_input_findings = unique_findings(
        [
            *detect_prompt_injection(request.prompt),
            *detect_pii(request.prompt)[0],
            *detect_toxicity(request.prompt),
            *detect_policy_violations(request.prompt, tenant_policy),
        ]
    )
    external_findings = await run_external_guards(request.prompt, settings, request.options)
    input_findings = unique_findings([*local_input_findings, *external_findings])
    pii_findings, pii_matches = detect_pii(request.prompt)
    sanitized = sanitize_text(request.prompt, pii_matches, request.options.mask_pii)
    input_score = score_findings(input_findings)
    input_decision = decide_action(
        input_score["risk"],
        input_findings,
        tenant_policy,
        request.options.block_high_risk,
    )

    adapter = get_adapter(request.adapter, settings)
    raw_prompt = sanitized
    if input_decision["action"] == "block":
        raw_response = "Request bi chan truoc AI Core vi risk vuot nguong policy."
    else:
        try:
            raw_response = await adapter.generate(raw_prompt, request.role)
        except Exception as exc:
            adapter = MockAdapter(name=f"{adapter.name}-fallback")
            raw_response = (
                await adapter.generate(raw_prompt, request.role)
                + f"\n\n[Provider fallback: {type(exc).__name__}]"
            )

    output = run_output_guard(
        raw_response,
        tenant_policy,
        mask_pii=request.options.mask_pii,
        auto_rewrite=request.options.auto_rewrite,
    )
    all_findings = unique_findings([*input_findings, *output.findings])
    total_score = score_findings(all_findings)
    final_decision = (
        {"action": "block", "label": "Blocked", "className": "danger"}
        if output.status == "danger"
        else decide_action(total_score["risk"], all_findings, tenant_policy, request.options.block_high_risk)
    )
    latency_ms = round((time.perf_counter() - started) * 1000, 2)

    audit = AuditLog(
        tenant_id=tenant.id,
        api_key_id=api_key.id,
        user_id=request.user_id,
        role=request.role,
        model=adapter.name,
        prompt_hash=hashlib.sha256(request.prompt.encode("utf-8")).hexdigest(),
        sanitized_prompt=sanitized,
        raw_response=raw_response,
        safe_response=output.safe_response,
        risk=total_score["risk"],
        action=final_decision["action"],
        latency_ms=latency_ms,
        reasons_json=json.dumps([finding.label for finding in all_findings], ensure_ascii=False),
        findings_json=json.dumps([finding.to_dict() for finding in all_findings], ensure_ascii=False),
        request_ip=request_ip,
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)

    webhook_payload = {
        "audit_id": audit.id,
        "tenant_id": tenant.id,
        "risk": audit.risk,
        "action": audit.action,
        "reasons": summarize_reasons(all_findings),
        "created_at": now.isoformat(),
    }
    send_on = (tenant_policy.get("webhooks") or {}).get("send_on") or ["block"]
    if audit.action in send_on:
        await send_siem_webhook(tenant.siem_webhook_url, webhook_payload, settings)

    ObservabilityClient(settings).trace_inspection(
        {
            "tenant_id": tenant.id,
            "user_id": request.user_id,
            "model": adapter.name,
            "risk": audit.risk,
            "action": audit.action,
            "latency_ms": latency_ms,
            "audit_id": audit.id,
        }
    )

    return InspectResponse(
        timestamp=now,
        role=request.role,
        model=adapter.name,
        inputFindings=[finding.to_dict() for finding in input_findings],
        outputFindings=[finding.to_dict() for finding in output.findings],
        allFindings=[finding.to_dict() for finding in all_findings],
        sanitized=sanitized,
        raw=raw_response,
        safeResponse=output.safe_response,
        risk=total_score["risk"],
        categories=total_score["categories"],
        decision=final_decision,
        piiMasked=len(pii_matches) + output.pii_masked,
        latencyMs=latency_ms,
        auditId=audit.id,
        gatewayMode="backend",
    )
