from __future__ import annotations

from dataclasses import dataclass
from typing import Pattern
import re


@dataclass(frozen=True)
class PolicyRule:
    id: str
    name: str
    description: str
    category: str
    weight: int
    patterns: tuple[Pattern[str], ...] = ()
    max_length: int | None = None


POLICY_CATALOG: tuple[PolicyRule, ...] = (
    PolicyRule(
        id="no_customer_data_export",
        name="Chan xuat du lieu khach hang",
        description="Khong cho phep truy van, dump hoac liet ke ho so khach hang.",
        category="data_leak",
        weight=34,
        patterns=(
            re.compile(r"(toan bo|dump|export|trich xuat).{0,32}(database|khach hang|ho so|hop dong)", re.I),
            re.compile(r"(danh sach|toan bo).{0,32}(khach hang|hop dong)", re.I),
        ),
    ),
    PolicyRule(
        id="no_guaranteed_profit",
        name="Khong hua loi nhuan hoac boi thuong chac chan",
        description="Ngan AI cam ket ket qua tai chinh, phap ly hoac quyen loi bao hiem tuyet doi.",
        category="regulated_advice",
        weight=20,
        patterns=(
            re.compile(r"(cam ket|chac chan|bao dam).{0,32}(lai|loi nhuan|hoan von|boi thuong)", re.I),
            re.compile(r"(100%|mot tram phan tram).{0,32}(boi thuong|lai|thang)", re.I),
        ),
    ),
    PolicyRule(
        id="no_medical_diagnosis",
        name="Khong chan doan y khoa",
        description="Chi cung cap thong tin chung, khong thay the bac si hoac ho so benh an.",
        category="medical",
        weight=18,
        patterns=(
            re.compile(r"(chan doan|ket luan).{0,32}(benh|ung thu|tram cam|tim mach)", re.I),
            re.compile(r"(ke toa|uong thuoc|lieu dung).{0,32}(ngay|bao nhieu|chinh xac)", re.I),
        ),
    ),
    PolicyRule(
        id="no_legal_advice",
        name="Khong tu van phap ly chac chan",
        description="Tranh chi dan phap ly tuyet doi hoac huong dan ne quy dinh.",
        category="legal",
        weight=18,
        patterns=(
            re.compile(r"(lach luat|qua mat|gia ho so|hop thuc hoa)", re.I),
            re.compile(r"(chac chan thang kien|khong can luat su)", re.I),
        ),
    ),
    PolicyRule(
        id="max_prompt_length",
        name="Gioi han do dai prompt",
        description="Canh bao prompt qua dai, co kha nang nhoi lenh hoac spam.",
        category="abuse",
        weight=14,
        max_length=1300,
    ),
)


def default_tenant_policy() -> dict:
    return {
        "allow": ["product_info", "premium_calculation", "claim_process", "coverage_explanation"],
        "deny": ["guaranteed_compensation", "fake_claim", "medical_diagnosis", "customer_data_export"],
        "enabled_rules": [rule.id for rule in POLICY_CATALOG],
        "thresholds": {"warn": 35, "block": 70},
        "webhooks": {"send_on": ["block", "warn"]},
    }


def enabled_rule_ids(policy: dict | None) -> set[str]:
    if not policy:
        return {rule.id for rule in POLICY_CATALOG}
    return set(policy.get("enabled_rules") or [rule.id for rule in POLICY_CATALOG])


def thresholds(policy: dict | None) -> dict[str, int]:
    values = (policy or {}).get("thresholds") or {}
    return {"warn": int(values.get("warn", 35)), "block": int(values.get("block", 70))}
