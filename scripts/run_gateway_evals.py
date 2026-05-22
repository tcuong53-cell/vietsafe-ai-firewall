from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "evals" / "firewall_cases.jsonl"


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def post_json(url: str, api_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def evaluate_case(case: dict[str, Any], result: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    action = result.get("decision", {}).get("action")
    if action not in case.get("expect_action", []):
        failures.append(f"action={action} expected one of {case.get('expect_action')}")

    risk = int(result.get("risk", 0))
    if "min_risk" in case and risk < int(case["min_risk"]):
        failures.append(f"risk={risk} below min_risk={case['min_risk']}")
    if "max_risk" in case and risk > int(case["max_risk"]):
        failures.append(f"risk={risk} above max_risk={case['max_risk']}")

    pii_masked = int(result.get("piiMasked", 0))
    if "min_pii_masked" in case and pii_masked < int(case["min_pii_masked"]):
        failures.append(f"piiMasked={pii_masked} below min_pii_masked={case['min_pii_masked']}")

    labels = {finding.get("label") for finding in result.get("allFindings", [])}
    for label in case.get("must_find", []):
        if label not in labels:
            failures.append(f"missing finding label {label!r}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VietSafe AI Firewall eval cases against a running gateway.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Gateway base URL")
    parser.add_argument("--api-key", default="dev_demo_key", help="Gateway API key")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES, help="JSONL eval cases")
    args = parser.parse_args()

    cases = load_cases(args.cases)
    failures = 0
    for case in cases:
        payload = {
            "prompt": case["prompt"],
            "role": case.get("role", "insurance"),
            "adapter": case.get("adapter", "mock"),
            "options": {
                "mask_pii": True,
                "block_high_risk": True,
                "auto_rewrite": True,
                "use_vietnamese_nlp": False,
            },
        }
        try:
            result = post_json(f"{args.base_url.rstrip('/')}/api/v1/inspect", args.api_key, payload)
        except urllib.error.URLError as exc:
            print(f"ERROR {case['id']}: {exc}")
            return 2

        case_failures = evaluate_case(case, result)
        if case_failures:
            failures += 1
            print(f"FAIL {case['id']}: {'; '.join(case_failures)}")
        else:
            action = result.get("decision", {}).get("action")
            print(f"PASS {case['id']}: action={action} risk={result.get('risk')}")

    print(f"\n{len(cases) - failures}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
