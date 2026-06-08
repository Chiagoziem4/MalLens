"""
MalLens Configuration Settings
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    APP_NAME: str = "MalLens"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Malware Behavior Analyzer"
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./mallens.db"
    )

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # File Storage
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./uploads")
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS: list = [
        ".exe", ".dll", ".sys", ".bin", ".elf", ".so",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh",
        ".zip", ".rar", ".7z", ".jar", ".apk",
        ".msi", ".scr", ".pif", ".com", ".hta",
        ".py", ".rb", ".php", ".html", ".htm",
        ".macho", ".dylib"
    ]

    # Analysis
    ANALYSIS_TIMEOUT: int = 300  # 5 minutes
    MAX_CONCURRENT_ANALYSES: int = 5

    # Threat Intelligence APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")

    # AI Report Generation
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    AI_MODEL: str = "gpt-4.1-mini"

    # YARA Rules
    YARA_RULES_DIR: str = os.getenv("YARA_RULES_DIR", "./yara_rules")

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "mallens-dev-secret-key-change-in-production")
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:5173", "*"]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Ensure upload directory exists
Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.YARA_RULES_DIR).mkdir(parents=True, exist_ok=True)
