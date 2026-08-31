"""
llm/llm_client.py
Thin wrapper around LLM APIs for AI Kavach.

Supports:
  - google  (Gemini via google-generativeai SDK)  [DEFAULT]
  - openai  (GPT-4o or similar)
  - ollama  (local models via HTTP API)

Tracks call count and token usage per session.
Enforces a per-finding call budget.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    provider: str = "google"          # google | openai | ollama
    # Google
    google_api_key: str = ""
    google_triage_model: str = "gemini-3.6-flash"    # fast, cheap — for triage
    google_reasoning_model: str = "gemini-3.6-flash"   # capable, active free tier
    # OpenAI
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_triage_model: str = "llama3.1:8b"
    ollama_reasoning_model: str = "qwen2.5-coder:14b"
    # Budget
    max_calls_per_finding: int = 8    # hard cap
    request_timeout_secs: int = 120


@dataclass
class LLMUsage:
    call_count: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_latency_secs: float = 0.0
    calls_log: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Unified LLM client with call tracking.

    Usage:
        client = LLMClient.from_env()
        response = client.call(prompt, mode="triage")    # uses fast model
        response = client.call(prompt, mode="reasoning") # uses capable model
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.cfg = config or LLMConfig()
        self.usage = LLMUsage()
        self._client = None
        self._init_client()

    @classmethod
    def from_env(cls) -> "LLMClient":
        """Create client from environment variables."""
        cfg = LLMConfig(
            provider=os.getenv("KAVACH_LLM_PROVIDER", "google"),
            google_api_key=os.getenv("GOOGLE_API_KEY", ""),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )
        return cls(cfg)

    def reset_usage(self) -> None:
        """Reset usage counters (call at the start of each finding)."""
        self.usage = LLMUsage()

    def call(self, prompt: str, mode: str = "reasoning", system: str = "") -> str:
        """
        Call the LLM.

        Args:
            prompt: The user prompt.
            mode: "triage" (fast model) or "reasoning" (powerful model).
            system: Optional system message.

        Returns:
            The LLM's text response.

        Raises:
            RuntimeError: If the call budget is exceeded.
        """
        if self.usage.call_count >= self.cfg.max_calls_per_finding:
            raise RuntimeError(
                f"LLM call budget exceeded ({self.cfg.max_calls_per_finding} calls/finding)"
            )

        log.info("[llm] Call #%d | mode=%s | provider=%s",
                 self.usage.call_count + 1, mode, self.cfg.provider)

        start = time.time()
        try:
            if self.cfg.provider == "google":
                response_text = self._call_google(prompt, mode, system)
            elif self.cfg.provider == "openai":
                response_text = self._call_openai(prompt, mode, system)
            elif self.cfg.provider == "ollama":
                response_text = self._call_ollama(prompt, mode, system)
            else:
                raise ValueError(f"Unknown LLM provider: {self.cfg.provider}")
        except Exception as e:
            log.error("[llm] Call failed: %s", e)
            raise

        latency = time.time() - start
        self.usage.call_count += 1
        self.usage.total_latency_secs += latency
        self.usage.calls_log.append({
            "call_num": self.usage.call_count,
            "mode": mode,
            "latency_secs": round(latency, 2),
            "response_len": len(response_text),
        })
        log.info("[llm] Response received in %.2fs (len=%d)", latency, len(response_text))
        return response_text

    # ------------------------------------------------------------------
    # Provider implementations
    # ------------------------------------------------------------------

    def _init_client(self) -> None:
        """Initialize the underlying SDK client."""
        if self.cfg.provider == "google":
            try:
                import google.generativeai as genai
                api_key = self.cfg.google_api_key or os.getenv("GOOGLE_API_KEY", "")
                if not api_key:
                    log.warning("[llm] GOOGLE_API_KEY not set — LLM calls will fail")
                genai.configure(api_key=api_key)
                self._genai = genai
            except ImportError:
                log.error("[llm] google-generativeai not installed. Run: pip install google-generativeai")
        elif self.cfg.provider == "openai":
            try:
                from openai import OpenAI
                self._openai_client = OpenAI(api_key=self.cfg.openai_api_key)
            except ImportError:
                log.error("[llm] openai not installed. Run: pip install openai")

    def _call_google(self, prompt: str, mode: str, system: str) -> str:
        import google.generativeai as genai
        api_key = self.cfg.google_api_key or os.getenv("GOOGLE_API_KEY", "")
        if api_key:
            genai.configure(api_key=api_key)
        model_name = (
            self.cfg.google_triage_model if mode == "triage"
            else self.cfg.google_reasoning_model
        )
        model = genai.GenerativeModel(
            model_name,
            system_instruction=system or "You are an expert C/C++ software engineer and code maintenance assistant helping developers remediate memory safety bugs."
        )
        response = model.generate_content(prompt)
        return response.text

    def _call_openai(self, prompt: str, mode: str, system: str) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        else:
            messages.append({"role": "system", "content": "You are an expert security researcher and patch engineer."})
        messages.append({"role": "user", "content": prompt})
        response = self._openai_client.chat.completions.create(
            model=self.cfg.openai_model,
            messages=messages,
            timeout=self.cfg.request_timeout_secs,
        )
        return response.choices[0].message.content

    def _call_ollama(self, prompt: str, mode: str, system: str) -> str:
        import requests
        model_name = (
            self.cfg.ollama_triage_model if mode == "triage"
            else self.cfg.ollama_reasoning_model
        )
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system or "You are an expert security researcher and patch engineer."},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
        }
        r = requests.post(
            f"{self.cfg.ollama_base_url}/api/chat",
            json=payload,
            timeout=self.cfg.request_timeout_secs
        )
        r.raise_for_status()
        return r.json()["message"]["content"]
