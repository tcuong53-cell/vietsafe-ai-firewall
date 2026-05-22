# GitHub Learnings Applied To VietSafe AI Firewall

Tai lieu nay tom tat nhung pattern da hoc tu cac repo nguon va cach dua vao roadmap/codebase hien tai.

## 1. Gateway va provider routing

Nguon:

- [BerriAI/litellm](https://github.com/BerriAI/litellm): AI Gateway goi 100+ LLM providers bang OpenAI-compatible format, kem virtual keys, spend tracking, guardrails, load balancing va logging.
- [undertheseanlp/underthesea](https://github.com/undertheseanlp/underthesea): multi-provider agent, auto-detect provider tu env, uu tien dependency nhe.

Ap dung:

- `backend/app/services/adapters.py` co adapter registry cho `mock`, `openai`, `claude`, `gemini`, `ollama`, `litellm`.
- LiteLLM duoc xem la provider gateway upstream. VietSafe co the chay nhu security gateway nam truoc LiteLLM hoac goi LiteLLM nhu model router phia sau.

## 2. Scanner pipeline va data protection

Nguon:

- [microsoft/presidio](https://github.com/microsoft/presidio): PII detection/anonymization co recognizer tuy bien, regex, NER, checksum va external models.
- [protectai/llm-guard](https://github.com/protectai/llm-guard): security toolkit cho LLM interactions, gom sanitization, prompt injection, harmful language, data leakage.
- [unitaryai/detoxify](https://github.com/unitaryai/detoxify): toxic comment classification tren Jigsaw datasets, co multilingual model.
- [conversationai/perspectiveapi](https://github.com/conversationai/perspectiveapi): toxicity scoring API cho conversation moderation.

Ap dung:

- `backend/app/services/external_guards.py` gom optional guards: OpenAI Moderation, Presidio, Llama Guard, LLM Guard, Detoxify, Perspective API.
- Tat ca guard deu fail-open co log warning neu thieu package/API key, de local demo khong bi vo.
- Local regex detector van la baseline bat buoc cho Vietnamese insurance compliance.

## 3. Programmable guardrails

Nguon:

- [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails): input/output guards gom validators co the ket hop, detect/quantify/mitigate risk va validate structured output.
- [NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails): phan chia rails thanh input, dialog, retrieval, execution, output; config folder gom `config.yml`, `actions.py`, rails definitions.
- [meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama): Llama Guard, Prompt Guard, Code Shield, CyberSec Evals, purple-team mindset.

Ap dung:

- Kien truc hien tai da tach `Input Guard -> AI Adapter -> Output Guard`.
- Roadmap tiep theo nen them `Retrieval Guard` va `Execution Guard` truoc khi ho tro RAG/tools.
- Policy Engine nen tien toi YAML/JSON DSL theo tenant thay vi hard-coded regex.

## 4. Observability, evals, datasets

Nguon:

- [langfuse/langfuse](https://github.com/langfuse/langfuse): observability, prompt management, evals, datasets, playground.
- [openai/evals](https://github.com/openai/evals): eval framework va registry benchmark cho LLM systems.
- [openai/openai-cookbook](https://github.com/openai/openai-cookbook): examples/guides dung OpenAI API theo task thuc te.

Ap dung:

- `backend/app/services/observability.py` them optional Langfuse tracing.
- `evals/firewall_cases.jsonl` va `scripts/run_gateway_evals.py` tao regression evals cho firewall decisions.
- Moi rule moi nen co eval case: safe, warn, block, false positive, output rewrite.

## 5. Vietnamese NLP layer

Nguon:

- [undertheseanlp/underthesea](https://github.com/undertheseanlp/underthesea): Vietnamese NLP va agent toolkit.
- [vncorenlp/VnCoreNLP](https://github.com/vncorenlp/VnCoreNLP): Vietnamese word segmentation, POS tagging, NER, dependency parsing.
- [trungtv/pyvi](https://github.com/trungtv/pyvi): tokenization, POS tagging, accents remove/add.
- [VinAIResearch/PhoBERT](https://github.com/VinAIResearch/PhoBERT): Vietnamese pretrained models; raw text can need word segmentation before downstream use.

Ap dung:

- `backend/app/services/vietnamese_nlp.py` co optional Underthesea/PyVi/fallback analyzer.
- Vietnamese NLP nen dung de giam false positive cua regex, phat hien PERSON/ORG/LOC quanh PII, va lam tien xu ly cho PhoBERT-classifier sau nay.

## Production Roadmap Cap Nhat

1. Provider gateway: them LiteLLM proxy mode, cost tracking, quota theo tenant.
2. Scanner registry: chuan hoa scanner interface, moi scanner tra `finding`, `risk`, `latency`, `source`.
3. Policy DSL: YAML/JSON rails theo tenant, co versioning va approval workflow.
4. Observability: Langfuse/OpenTelemetry trace cho tung buoc input guard, adapter, output guard.
5. Eval discipline: moi release chay `scripts/run_gateway_evals.py`; them dataset tieng Viet cho bao hiem/ngan hang/giao duc.
6. Vietnamese AI: PhoBERT-based classifier cho toxicity/compliance tieng Viet, Underthesea/VnCoreNLP cho entity context.
7. Enterprise controls: Redis rate limit, webhook retry queue, SIEM schema, audit retention, tenant-specific encryption.
