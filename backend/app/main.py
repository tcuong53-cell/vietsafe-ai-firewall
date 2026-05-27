from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import Base, SessionLocal, engine, get_db
from .models import APIKey, AuditLog
from .ip_guard import ip_guard
from .rate_limit import rate_limited_principal
from .schemas import APIKeyCreate, APIKeyCreated, AuditLogItem, InspectRequest, InspectResponse, TenantPolicyUpdate
from .security import Principal, create_api_key_secret, hash_api_key, require_scope
from .seed import seed_database
from .services.inspection import inspect_gateway, load_policy, summarize_reasons


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.2.0")


@app.middleware("http")
async def ip_guard_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    blocked, reason = ip_guard.is_blocked(client_ip)
    if blocked:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"detail": f"IP blocked: {reason}"})
    response = await call_next(request)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8765", "http://localhost:8765", "http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db, settings)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "environment": settings.environment}


@app.post(f"{settings.api_prefix}/inspect", response_model=InspectResponse)
async def inspect(
    payload: InspectRequest,
    request: Request,
    principal: Principal = Depends(rate_limited_principal),
    db: Session = Depends(get_db),
    active_settings: Settings = Depends(get_settings),
) -> InspectResponse:
    return await inspect_gateway(
        request=payload,
        tenant=principal.tenant,
        api_key=principal.api_key,
        db=db,
        settings=active_settings,
        request_ip=request.client.host if request.client else None,
    )


@app.get(f"{settings.api_prefix}/audit-logs", response_model=list[AuditLogItem])
def list_audit_logs(
    limit: int = 50,
    principal: Principal = Depends(require_scope("logs:read")),
    db: Session = Depends(get_db),
) -> list[AuditLogItem]:
    limit = min(max(limit, 1), 200)
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.tenant_id == principal.tenant.id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    ).all()
    items: list[AuditLogItem] = []
    for row in rows:
        try:
            findings = json.loads(row.findings_json)
            reason = summarize_reasons([]) if not findings else ", ".join(dict.fromkeys(f["label"] for f in findings).keys())
        except Exception:
            reason = "unavailable"
        items.append(
            AuditLogItem(
                id=row.id,
                time=row.created_at,
                model=row.model,
                risk=row.risk,
                action=row.action,
                reason=reason,
                role=row.role,
                latencyMs=row.latency_ms,
            )
        )
    return items


@app.get(f"{settings.api_prefix}/policies/current")
def get_policy(principal: Principal = Depends(require_scope("policy:read"))) -> dict:
    return {
        "tenant_id": principal.tenant.id,
        "name": principal.tenant.name,
        "policy": load_policy(principal.tenant),
        "siem_webhook_url": principal.tenant.siem_webhook_url,
    }


@app.put(f"{settings.api_prefix}/policies/current")
def update_policy(
    payload: TenantPolicyUpdate,
    principal: Principal = Depends(require_scope("policy:write")),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    principal.tenant.policy_json = payload.policy.model_dump_json()
    principal.tenant.siem_webhook_url = payload.siem_webhook_url
    db.add(principal.tenant)
    db.commit()
    return {"status": "updated"}


@app.post(f"{settings.api_prefix}/api-keys", response_model=APIKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(
    payload: APIKeyCreate,
    principal: Principal = Depends(require_scope("api_keys:write")),
    db: Session = Depends(get_db),
    active_settings: Settings = Depends(get_settings),
) -> APIKeyCreated:
    raw_key = create_api_key_secret()
    api_key = APIKey(
        tenant_id=principal.tenant.id,
        name=payload.name,
        key_hash=hash_api_key(raw_key, active_settings),
        prefix=raw_key[:8],
        scopes_json=json.dumps(payload.scopes),
        active=True,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    return APIKeyCreated(id=api_key.id, name=api_key.name, api_key=raw_key, prefix=api_key.prefix)


@app.get(f"{settings.api_prefix}/metrics")
def metrics(
    principal: Principal = Depends(require_scope("logs:read")),
    db: Session = Depends(get_db),
) -> dict[str, int | float]:
    total = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == principal.tenant.id)) or 0
    blocked = (
        db.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == principal.tenant.id, AuditLog.action == "block")
        )
        or 0
    )
    avg_risk = db.scalar(select(func.avg(AuditLog.risk)).where(AuditLog.tenant_id == principal.tenant.id)) or 0
    return {"total": total, "blocked": blocked, "average_risk": round(float(avg_risk), 2)}


@app.get(f"{settings.api_prefix}/blocked-ips")
def list_blocked_ips(principal: Principal = Depends(require_scope("policy:read"))):
    return ip_guard.list_blocked()


@app.post(f"{settings.api_prefix}/blocked-ips")
def manage_blocked_ip(
    payload: dict,
    principal: Principal = Depends(require_scope("policy:write")),
):
    action = payload.get("action", "block")
    ip = payload.get("ip", "")
    if not ip:
        raise HTTPException(status_code=400, detail="IP required")
    if action == "unblock":
        ip_guard.unblock_ip(ip)
        return {"status": "unblocked", "ip": ip}
    ip_guard.block_ip(ip, payload.get("reason", "Manual block via API"))
    return {"status": "blocked", "ip": ip}


ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"
INDEX_FILE = ROOT_DIR / "index.html"

if SRC_DIR.exists():
    app.mount("/src", StaticFiles(directory=SRC_DIR), name="src")


@app.get("/")
def index() -> FileResponse:
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(INDEX_FILE)


@app.get("/index.html")
def index_html() -> FileResponse:
    return index()
