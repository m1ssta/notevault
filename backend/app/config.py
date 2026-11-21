import os
from dataclasses import dataclass


@dataclass
class Settings:
    database_url: str = "sqlite://"
    jwt_secret: str = ""
    token_ttl_minutes: int = 15
    login_rate_per_min: int = 5      # SR-7
    api_rate_per_min: int = 100      # SR-7
    lock_threshold: int = 10         # CR-1
    lock_minutes: int = 15           # CR-1
    max_body_bytes: int = 1_000_000  # SR-5
    static_dir: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        secret = os.environ.get("NOTEVAULT_JWT_SECRET", "")
        # Secure by default: refuse to start without a strong secret, no built-in default.
        if len(secret) < 32:
            raise RuntimeError("NOTEVAULT_JWT_SECRET must be set and at least 32 characters long")
        return cls(
            database_url=os.environ["DATABASE_URL"],
            jwt_secret=secret,
            static_dir=os.environ.get("NOTEVAULT_STATIC_DIR", ""),
        )
