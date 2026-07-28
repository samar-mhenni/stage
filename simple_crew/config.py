import fcntl
import os
from pathlib import Path

from crewai import LLM
from dotenv import load_dotenv
from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(PROJECT_ROOT / ".env.local", override=True)


class Settings(BaseModel):
    llm_provider: str = os.getenv("LLM_PROVIDER", "openrouter")
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_base_url: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    openrouter_model: str = os.getenv("QWEN_MODEL", "qwen/qwen3.5-flash-02-23")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_api_key_secondary: str = os.getenv("GROQ_API_KEY_SECONDARY", "")
    groq_api_key_tertiary: str = os.getenv("GROQ_API_KEY_TERTIARY", "")
    groq_base_url: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    groq_model: str = os.getenv("GROQ_MODEL", "qwen/qwen3-32b")
    llm_max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2400"))
    chroma_path: Path = PROJECT_ROOT / os.getenv("CHROMADB_PATH", "./chroma_db")
    max_agent_context_chars: int = int(os.getenv("MAX_AGENT_CONTEXT_CHARS", "10000"))
    max_tool_output_chars: int = int(os.getenv("MAX_TOOL_OUTPUT_CHARS", "50000"))
    max_database_results: int = int(os.getenv("MAX_DATABASE_RESULTS", "5"))
    max_history_items: int = int(os.getenv("MAX_HISTORY_ITEMS", "5"))
    email_alerts_enabled: bool = os.getenv("EMAIL_ALERTS_ENABLED", "").lower() in {"1", "true", "yes"}
    alert_email_to: str = os.getenv("ALERT_EMAIL_TO", "samar.mhenni.work@gmail.com")
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_starttls: bool = os.getenv("SMTP_STARTTLS", "true").lower() in {"1", "true", "yes"}
    wazuh_ingest_token: str = os.getenv("WAZUH_INGEST_TOKEN", "")
    wazuh_bruteforce_threshold: int = int(os.getenv("WAZUH_BRUTEFORCE_THRESHOLD", "5"))
    wazuh_bruteforce_window_seconds: int = int(os.getenv("WAZUH_BRUTEFORCE_WINDOW_SECONDS", "30"))
    wazuh_alert_cooldown_seconds: int = int(os.getenv("WAZUH_ALERT_COOLDOWN_SECONDS", "300"))
    wazuh_level10_grace_seconds: float = float(os.getenv("WAZUH_LEVEL10_GRACE_SECONDS", "2"))
    remediation_enabled: bool = os.getenv("REMEDIATION_ENABLED", "true").lower() in {"1", "true", "yes"}
    remediation_ssh_host: str = os.getenv("REMEDIATION_SSH_HOST", "63.184.123.234")
    remediation_ssh_user: str = os.getenv("REMEDIATION_SSH_USER", "ubuntu")
    remediation_ssh_key: Path = Path(os.getenv(
        "REMEDIATION_SSH_KEY", "/home/samar/.ssh/samar-ec2.pem"
    ))
    remediation_block_seconds: int = int(os.getenv("REMEDIATION_BLOCK_SECONDS", "1800"))
    remediation_trusted_ips: str = os.getenv("REMEDIATION_TRUSTED_IPS", "")


settings = Settings()
KEY_CURSOR_PATH = Path(__file__).resolve().parent / "outputs" / ".groq_key_cursor"


def _next_groq_api_key() -> str:
    keys = list(dict.fromkeys(key for key in (
        settings.groq_api_key,
        settings.groq_api_key_secondary,
        settings.groq_api_key_tertiary,
    ) if key))
    if not keys:
        return ""
    KEY_CURSOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    with KEY_CURSOR_PATH.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            cursor = int(handle.read().strip() or "0")
        except ValueError:
            cursor = 0
        selected = keys[cursor % len(keys)]
        handle.seek(0)
        handle.truncate()
        handle.write(str((cursor + 1) % len(keys)))
        handle.flush()
        fcntl.flock(handle, fcntl.LOCK_UN)
    return selected


def get_llm(max_tokens_override: int | None = None) -> LLM:
    max_tokens = max_tokens_override or min(max(settings.llm_max_tokens, 2400), 2400)
    if settings.llm_provider.lower() == "groq":
        return LLM(
            model=settings.groq_model,
            provider="openai",
            api_key=_next_groq_api_key(),
            base_url=settings.groq_base_url,
            temperature=0.1,
            max_tokens=max_tokens,
            reasoning_effort="low",
        )
    return LLM(
        model=f"openrouter/{settings.openrouter_model}",
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0.1,
        max_tokens=max_tokens,
        reasoning_effort="low",
    )
