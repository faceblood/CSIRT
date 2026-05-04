from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _repo_root() -> Path:
    # backend/app/config.py -> backend/app -> backend -> CSIRT
    return Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CSIRT_", env_file=".env", extra="ignore")

    repo_root: Path = _repo_root()
    data_dir: Path = Path(__file__).resolve().parent.parent / "data"
    exercises_dir_name: str = "exercises"

    fortisiem_ip: str = "10.255.9.3"
    fortisiem_port: int = 514

    history_limit: int = 500


settings = Settings()
