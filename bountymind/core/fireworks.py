from __future__ import annotations

from langchain_openai import ChatOpenAI
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .config import ModelConfig, app_config


@retry(
    retry=retry_if_exception_type(Exception),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3),
    reraise=True,
)
def get_model(alias: str, temperature: float = 0.1) -> ChatOpenAI:
    """Return a ChatOpenAI client pointed at Fireworks AI for the given model alias.

    Aliases are defined in core/config.py ModelConfig._MAP (single source of truth).
    Retries up to 3 times with exponential back-off on any exception.
    """
    model_id = ModelConfig.get(alias)
    return ChatOpenAI(
        model=model_id,
        openai_api_key=app_config.FIREWORKS_API_KEY,
        openai_api_base=app_config.FIREWORKS_BASE_URL,
        temperature=temperature,
        max_tokens=4096,
        streaming=True,
    )
