"""Configuration — paths, defaults, environment overrides.

Override any setting with an env var like BTSPY_DB_PATH=/tmp/foo.db.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BTSPY_", env_file=".env", extra="ignore")

    data_dir: Path = Path.home() / ".bt-spy"
    db_filename: str = "bt-spy.db"
    firmware_cache_dir_name: str = "firmware-cache"

    rest_host: str = "127.0.0.1"
    rest_port: int = 8765

    mcp_transport: str = "stdio"  # "stdio" or "sse"
    mcp_sse_port: int = 8766

    sniffer_extcap_path: str | None = None  # auto-detected if None
    sniffer_baudrate: int = 1000000

    log_level: str = "INFO"

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def firmware_cache_dir(self) -> Path:
        return self.data_dir / self.firmware_cache_dir_name

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.firmware_cache_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
