from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VietnameseNLPResult:
    backend: str
    normalized: str
    tokens: list[str]
    entities: list[dict[str, str]]


def _fallback_tokenize(text: str) -> list[str]:
    return [token for token in text.replace("\n", " ").split(" ") if token]


def analyze_vietnamese(text: str, backend: str = "auto") -> VietnameseNLPResult:
    selected = backend.lower()
    if selected in {"auto", "underthesea"}:
        try:
            from underthesea import ner, word_tokenize  # type: ignore

            tokens = word_tokenize(text)
            entities = [
                {"token": item[0], "pos": item[1], "chunk": item[2], "ner": item[3]}
                for item in ner(text)
                if len(item) >= 4 and item[3] != "O"
            ]
            return VietnameseNLPResult(
                backend="underthesea",
                normalized=text,
                tokens=tokens if isinstance(tokens, list) else str(tokens).split(),
                entities=entities,
            )
        except Exception:
            if selected == "underthesea":
                return VietnameseNLPResult("fallback", text, _fallback_tokenize(text), [])

    if selected in {"auto", "pyvi"}:
        try:
            from pyvi import ViTokenizer  # type: ignore

            segmented = ViTokenizer.tokenize(text)
            return VietnameseNLPResult("pyvi", segmented, segmented.split(), [])
        except Exception:
            pass

    return VietnameseNLPResult("fallback", text, _fallback_tokenize(text), [])


def vietnamese_entity_findings(text: str, backend: str = "auto") -> list[dict[str, str]]:
    analysis = analyze_vietnamese(text, backend)
    findings: list[dict[str, str]] = []
    for entity in analysis.entities:
        ner_label = entity.get("ner", "")
        if "PER" in ner_label:
            findings.append({"type": "person", "evidence": f"Vietnamese NER detected person: {entity.get('token')}"})
        elif "LOC" in ner_label:
            findings.append({"type": "location", "evidence": f"Vietnamese NER detected location: {entity.get('token')}"})
        elif "ORG" in ner_label:
            findings.append({"type": "organization", "evidence": f"Vietnamese NER detected organization: {entity.get('token')}"})
    return findings
