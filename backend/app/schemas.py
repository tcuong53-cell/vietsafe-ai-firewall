from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Action = Literal["allow", "warn", "block"]
Severity = Literal["low", "medium", "high", "critical"]


class RuntimeOptions(BaseModel):
    mask_pii: bool = True
    block_high_risk: bool = True
    auto_rewrite: bool = True
    use_openai_moderation: bool = False
    use_presidio: bool = False
    use_llama_guard: bool = False
    use_llm_guard: bool = False
    use_detoxify: bool = False
    use_perspective: bool = False
    use_vietnamese_nlp: bool = True


class InspectRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    role: str = "insurance"
    adapter: str = "mock"
    user_id: str | None = None
    options: RuntimeOptions = Field(default_factory=RuntimeOptions)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    action: Action
    label: str
    className: str


class Finding(BaseModel):
    type: str
    label: str
    severity: Severity
    score: int
    evidence: str
    action: str
    ruleId: str | None = None
    source: str = "local"


class InspectResponse(BaseModel):
    timestamp: datetime
    role: str
    model: str
    inputFindings: list[Finding]
    outputFindings: list[Finding]
    allFindings: list[Finding]
    sanitized: str
    raw: str
    safeResponse: str
    risk: int
    categories: dict[str, int]
    decision: Decision
    piiMasked: int
    latencyMs: float
    auditId: str | None = None
    gatewayMode: str = "backend"


class AuditLogItem(BaseModel):
    id: str
    time: datetime
    model: str
    risk: int
    action: Action
    reason: str
    role: str
    latencyMs: float


class TenantPolicy(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    enabled_rules: list[str] = Field(default_factory=list)
    thresholds: dict[str, int] = Field(default_factory=lambda: {"warn": 35, "block": 70})
    webhooks: dict[str, Any] = Field(default_factory=dict)


class TenantPolicyUpdate(BaseModel):
    policy: TenantPolicy
    siem_webhook_url: str | None = None


class APIKeyCreate(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=lambda: ["inspect", "logs:read"])


class APIKeyCreated(BaseModel):
    id: str
    name: str
    api_key: str
    prefix: str
