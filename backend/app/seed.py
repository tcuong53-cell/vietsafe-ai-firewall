import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .models import APIKey, Tenant
from .security import hash_api_key
from .services.policy import default_tenant_policy


def seed_database(db: Session, settings: Settings) -> None:
    tenant = db.get(Tenant, settings.bootstrap_tenant_id)
    if not tenant:
        tenant = Tenant(
            id=settings.bootstrap_tenant_id,
            name=settings.bootstrap_tenant_name,
            policy_json=json.dumps(default_tenant_policy(), ensure_ascii=False),
        )
        db.add(tenant)

    key_hash = hash_api_key(settings.bootstrap_api_key, settings)
    api_key = db.scalar(select(APIKey).where(APIKey.key_hash == key_hash))
    if not api_key:
        api_key = APIKey(
            tenant_id=tenant.id,
            name="Local development key",
            key_hash=key_hash,
            prefix=settings.bootstrap_api_key[:8],
            scopes_json=json.dumps(["*"]),
            active=True,
        )
        db.add(api_key)

    db.commit()
