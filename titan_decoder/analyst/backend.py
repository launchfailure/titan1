"""Model backends for the Local AI Analyst.

The first (and only) real backend speaks the OpenAI-compatible
chat-completions protocol used by llama.cpp's server and similar local
runtimes. Endpoints are restricted to loopback by default — talking to a
non-local model host must be an explicit operator decision, never a
default. Requests are bounded by a timeout and a token cap, and use
temperature 0 for reproducibility.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

MAX_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class BackendResult:
    text: str
    model: str
    backend: str


class AnalystBackend(ABC):
    """One model backend: takes a system+user prompt, returns text."""

    @abstractmethod
    def generate(self, *, system: str, prompt: str) -> BackendResult: ...


class LocalOpenAIBackend(AnalystBackend):
    """OpenAI-compatible local HTTP backend (llama.cpp server et al.)."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8080/v1/chat/completions",
        model: str = "local-model",
        *,
        timeout_seconds: float = 60.0,
        max_tokens: int = 800,
        temperature: float = 0.0,
        allow_non_loopback: bool = False,
    ):
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("endpoint must use HTTP or HTTPS")
        if not allow_non_loopback and parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError(
                "non-loopback AI endpoint is disabled by default "
                "(pass --allow-remote-endpoint to opt in explicitly)"
            )
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.endpoint = endpoint
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.temperature = temperature

    def generate(self, *, system: str, prompt: str) -> BackendResult:
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "stream": False,
            }
        ).encode("utf-8")
        request = Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("local model response exceeded the size bound")
        data = json.loads(raw.decode("utf-8"))
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("local model returned no choices")
        text = str((choices[0].get("message") or {}).get("content") or "").strip()
        if not text:
            raise RuntimeError("local model returned empty content")
        return BackendResult(text, self.model, "local-openai")


class ScriptedBackend(AnalystBackend):
    """Test backend returning a fixed answer."""

    def __init__(self, text: str):
        self.text = text

    def generate(self, *, system: str, prompt: str) -> BackendResult:
        return BackendResult(self.text, "scripted", "scripted")
