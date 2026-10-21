"""Optional server-side AI provider integrations."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


class ProviderError(Exception):
    """A provider failed without exposing provider response details to callers."""


class ProviderTimeout(ProviderError):
    """The provider did not respond before the configured timeout."""


class ChatProvider(Protocol):
    name: str

    def complete(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class ProviderSetup:
    provider: ChatProvider | None
    status: str
    model: str | None = None


class OpenAICompatibleProvider:
    name = "openai-compatible"

    def __init__(self, api_key: str, model: str, base_url: str | None, timeout_seconds: float) -> None:
        try:
            from openai import APIConnectionError, APITimeoutError, OpenAI
        except ImportError as exc:
            raise RuntimeError("optional OpenAI SDK is not installed") from exc
        self._timeout_error = APITimeoutError
        self._connection_error = APIConnectionError
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url or None,
            timeout=timeout_seconds,
            max_retries=0,
        )
        self.model = model

    def complete(self, prompt: str) -> str:
        try:
            result = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
        except self._timeout_error as exc:
            raise ProviderTimeout from exc
        except self._connection_error as exc:
            raise ProviderError from exc
        except Exception as exc:
            # Keep provider status/body/key details out of application responses and logs.
            raise ProviderError from exc
        content = result.choices[0].message.content if result.choices else None
        if not isinstance(content, str):
            raise ProviderError("provider returned no text")
        return content


def configure_provider() -> ProviderSetup:
    provider_name = os.getenv("AI_PROVIDER", "none").strip().lower()
    if provider_name in {"", "none", "disabled"}:
        return ProviderSetup(None, "disabled")
    if provider_name not in {"openai", "openai-compatible"}:
        return ProviderSetup(None, "unsupported_provider")
    api_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "").strip()
    if not api_key or not model:
        return ProviderSetup(None, "missing_credentials_or_model")
    try:
        timeout = float(os.getenv("AI_PROVIDER_TIMEOUT_SECONDS", "20"))
        if not 1 <= timeout <= 120:
            return ProviderSetup(None, "invalid_configuration")
        provider = OpenAICompatibleProvider(
            api_key=api_key,
            model=model,
            base_url=os.getenv("OPENAI_BASE_URL", "").strip() or None,
            timeout_seconds=timeout,
        )
    except RuntimeError:
        return ProviderSetup(None, "sdk_not_installed")
    except Exception:
        return ProviderSetup(None, "invalid_configuration")
    return ProviderSetup(provider, "ready", model)
