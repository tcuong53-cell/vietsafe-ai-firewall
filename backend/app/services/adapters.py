from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from ..config import Settings


class AIAdapter(Protocol):
    name: str

    async def generate(self, prompt: str, role: str) -> str:
        ...


ROLE_CONTEXT = {
    "insurance": "You are assisting an insurance agent. Avoid guarantees and avoid exposing customer data.",
    "banking": "You are assisting a banking support team. Avoid investment guarantees and data leaks.",
    "education": "You are assisting an educator. Avoid exam cheating and student data leaks.",
    "general": "You are assisting a business team. Keep answers safe, grounded, and policy aware.",
}


@dataclass
class MockAdapter:
    name: str = "mock"

    async def generate(self, prompt: str, role: str) -> str:
        normalized = prompt.lower()
        if "request bi chan" in normalized or "blocked" in normalized:
            return "Request bi chan truoc AI Core vi risk vuot nguong policy."
        if "nguyen trai" in normalized and "1500" in normalized:
            return "Nguyen Trai sinh nam 1500 va la mot nha tho thoi Le so. Thong tin nay chac chan dung."
        if "khach hang" in normalized and ("hd" in normalized or "bh" in normalized or "hop dong" in normalized):
            return "Theo ho so noi bo, khach hang Nguyen Van A co hop dong BH-928177 voi quyen loi dieu tri noi tru 200 trieu dong."
        if "cam ket" in normalized or "100%" in normalized:
            return "Ban co the noi voi khach hang rang cong ty chac chan boi thuong 100% neu ho mua goi nay hom nay."

        intro = {
            "insurance": "Toi co the ho tro giai thich quyen loi bao hiem theo dieu khoan hop dong va quy trinh yeu cau boi thuong.",
            "banking": "Toi co the ho tro thong tin san pham ngan hang, quy trinh bao cao gian lan va bao ve tai khoan.",
            "education": "Toi co the ho tro giai thich bai hoc, rubric va phan hoi hoc tap.",
            "general": "Toi co the ho tro thong tin chung va chuan hoa cau tra loi truoc khi gui nguoi dung.",
        }.get(role, ROLE_CONTEXT["general"])
        return (
            f"{intro}\n\n"
            "Khuyen nghi tra loi: neu ro day la thong tin tham khao, khong cam ket ket qua tuyet doi, "
            "khong thu thap them du lieu ca nhan neu khong can thiet, va chuyen sang nhan vien phu trach "
            "khi co tinh huong phuc tap."
        )


@dataclass
class OpenAIAdapter:
    settings: Settings
    name: str = "openai"

    async def generate(self, prompt: str, role: str) -> str:
        if not self.settings.openai_api_key or not self.settings.openai_model:
            return await MockAdapter(name="openai-mock").generate(prompt, role)

        payload = {
            "model": self.settings.openai_model,
            "input": [
                {"role": "system", "content": ROLE_CONTEXT.get(role, ROLE_CONTEXT["general"])},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                f"{self.settings.openai_base_url.rstrip('/')}/v1/responses",
                headers={"Authorization": f"Bearer {self.settings.openai_api_key}"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            if data.get("output_text"):
                return data["output_text"]
            chunks: list[str] = []
            for item in data.get("output", []):
                for content in item.get("content", []):
                    if content.get("type") in {"output_text", "text"} and content.get("text"):
                        chunks.append(content["text"])
            return "\n".join(chunks).strip() or "[OpenAI returned an empty response]"


@dataclass
class ClaudeAdapter:
    settings: Settings
    name: str = "claude"

    async def generate(self, prompt: str, role: str) -> str:
        if not self.settings.anthropic_api_key or not self.settings.anthropic_model:
            return await MockAdapter(name="claude-mock").generate(prompt, role)

        payload = {
            "model": self.settings.anthropic_model,
            "max_tokens": 700,
            "system": ROLE_CONTEXT.get(role, ROLE_CONTEXT["general"]),
            "messages": [{"role": "user", "content": prompt}],
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return "\n".join(
                part.get("text", "") for part in data.get("content", []) if part.get("type") == "text"
            ).strip()


@dataclass
class GeminiAdapter:
    settings: Settings
    name: str = "gemini"

    async def generate(self, prompt: str, role: str) -> str:
        if not self.settings.gemini_api_key or not self.settings.gemini_model:
            return await MockAdapter(name="gemini-mock").generate(prompt, role)

        payload = {
            "systemInstruction": {"parts": [{"text": ROLE_CONTEXT.get(role, ROLE_CONTEXT["general"])}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        }
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.settings.gemini_model}:generateContent?key={self.settings.gemini_api_key}"
        )
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
            return "\n".join(part.get("text", "") for part in parts).strip()


@dataclass
class OllamaAdapter:
    settings: Settings
    name: str = "ollama"

    async def generate(self, prompt: str, role: str) -> str:
        payload = {
            "model": self.settings.ollama_model,
            "prompt": f"{ROLE_CONTEXT.get(role, ROLE_CONTEXT['general'])}\n\nUser: {prompt}",
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            try:
                response = await client.post(f"{self.settings.ollama_base_url.rstrip('/')}/api/generate", json=payload)
                response.raise_for_status()
            except httpx.HTTPError:
                return await MockAdapter(name="ollama-mock").generate(prompt, role)
            data = response.json()
            return data.get("response", "").strip() or "[Ollama returned an empty response]"


@dataclass
class LiteLLMAdapter:
    settings: Settings
    name: str = "litellm"

    async def generate(self, prompt: str, role: str) -> str:
        if not self.settings.litellm_base_url:
            return await MockAdapter(name="litellm-mock").generate(prompt, role)

        headers = {"Content-Type": "application/json"}
        if self.settings.litellm_api_key:
            headers["Authorization"] = f"Bearer {self.settings.litellm_api_key}"
        payload = {
            "model": self.settings.litellm_model,
            "messages": [
                {"role": "system", "content": ROLE_CONTEXT.get(role, ROLE_CONTEXT["general"])},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            try:
                response = await client.post(
                    f"{self.settings.litellm_base_url.rstrip('/')}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
            except httpx.HTTPError:
                return await MockAdapter(name="litellm-mock").generate(prompt, role)
            data = response.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()


def get_adapter(name: str, settings: Settings) -> AIAdapter:
    normalized = name.lower()
    if normalized in {"openai", "openaiadapter"}:
        return OpenAIAdapter(settings=settings)
    if normalized in {"claude", "anthropic", "claudeadapter"}:
        return ClaudeAdapter(settings=settings)
    if normalized in {"gemini", "geminiadapter"}:
        return GeminiAdapter(settings=settings)
    if normalized in {"ollama", "local", "localmodeladapter"}:
        return OllamaAdapter(settings=settings)
    if normalized in {"litellm", "litellmadapter", "proxy"}:
        return LiteLLMAdapter(settings=settings)
    return MockAdapter()
