from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOGSENTINEL_")

    host: str = "127.0.0.1"
    port: int = 8000
    db_path: Path = BASE_DIR / "data" / "logsentinel.db"
    upload_dir: Path = BASE_DIR / "data" / "uploads"
    rules_dir: Path = BASE_DIR / "rules"
    policy_path: Path = BASE_DIR / "rules" / "privacy_policy.yaml"
    attack_mapping_path: Path = BASE_DIR / "rules" / "attack_mapping.json"
    max_upload_mb: int = 700
    chunk_lines: int = 5120
    allowed_extensions: frozenset = frozenset({".log", ".txt", ".json", ".csv", ".xml"})
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    jwt_secret: str = "logsentinel-dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440
    default_admin_password: str = "changeme"
    # Alert notifications (optional). Leave empty to disable a channel.
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    # M5 Item 8: opt-in at-rest AES-GCM encryption of message/raw columns.
    encrypt_at_rest: bool = False
    db_key: str = ""


settings = Settings()
settings.upload_dir.mkdir(parents=True, exist_ok=True)
settings.db_path.parent.mkdir(parents=True, exist_ok=True)
