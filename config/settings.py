import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    """Centralized environment variable management."""
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_BASE_URL: str = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    QWEN_MODEL: str = os.getenv("QWEN_MODEL", "qwen/qwen3.5-flash-02-23")
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "900"))
    CHROMADB_PATH: str = os.getenv("CHROMADB_PATH", "./chroma_db")
    
    # Global settings
    DEBUG_MODE: bool = os.getenv("DEBUG_MODE", "False").lower() == "true"

settings = Settings()
