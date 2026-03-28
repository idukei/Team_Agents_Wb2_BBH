from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import ClassVar


class _ModelConfig:
    _MAP: ClassVar[dict[str, str]] = {
        "MODEL_COMMANDER":   "accounts/fireworks/models/deepseek-r1",
        "MODEL_THINKER":     "accounts/fireworks/models/deepseek-r1",
        "MODEL_RESEARCH":    "accounts/fireworks/models/mixtral-8x22b-instruct",
        "MODEL_RECON":       "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "MODEL_AGENT_STD":   "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "MODEL_AGENT_CODE":  "accounts/fireworks/models/qwen2p5-coder-32b-instruct",
        "MODEL_SYNTHESIZER": "accounts/fireworks/models/deepseek-v3",
    }

    @classmethod
    def get(cls, alias: str) -> str:
        if alias not in cls._MAP:
            raise ValueError(f"Unknown model alias: {alias}")
        return cls._MAP[alias]

    @classmethod
    def all_aliases(cls) -> list[str]:
        return list(cls._MAP.keys())


ModelConfig = _ModelConfig()


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    FIREWORKS_API_KEY: str = ""
    FIREWORKS_BASE_URL: str = "https://api.fireworks.ai/inference/v1"
    LANGSMITH_API_KEY: str = ""
    LANGSMITH_PROJECT: str = "bountymind-dev"
    LANGCHAIN_TRACING_V2: bool = False
    APP_ENV: str = "development"
    POSTGRES_URL: str = ""
    CONFIDENCE_THRESHOLD: float = 0.85
    MAX_AGENT_ITERATIONS: int = 25
    TAVILY_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    SHODAN_API_KEY: str = ""


app_config = AppConfig()
