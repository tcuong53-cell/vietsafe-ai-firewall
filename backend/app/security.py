import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import get_db
from .models import APIKey, Tenant


def hash_api_key(raw_key: str, settings: Settings | None = None) -> str:
    active_settings = settings or get_settings()
    return hashlib.sha256(f"{active_settings.api_key_salt}:{raw_key}".encode("utf-8")).hexdigest()


def create_api_key_secret() -> str:
    return f"vsk_{secrets.token_urlsafe(32)}"


@dataclass
class Principal:
    tenant: Tenant
    api_key: APIKey


def get_principal(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key")

    key_hash = hash_api_key(x_api_key, settings)
    api_key = db.scalar(select(APIKey).where(APIKey.key_hash == key_hash, APIKey.active.is_(True)))
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    tenant = db.get(Tenant, api_key.tenant_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tenant disabled")

    api_key.last_used_at = datetime.utcnow()
    db.add(api_key)
    db.commit()
    return Principal(tenant=tenant, api_key=api_key)


def require_scope(scope: str):
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        import json

        scopes = json.loads(principal.api_key.scopes_json)
        if scope not in scopes and "*" not in scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing scope: {scope}")
        return principal

    return dependency
