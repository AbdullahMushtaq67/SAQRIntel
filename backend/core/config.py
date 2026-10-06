"""
SAQRIntel global settings.

Values here are defaults; the Settings page and scan requests can override
rate limits, thread counts, and nmap port ranges at runtime.
"""

from pathlib import Path
from pydantic_settings import BaseSettings

# Project root: SAQRIntel/ (two levels above this file: core/ -> backend/ -> root)
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
WORDLISTS_DIR = ROOT_DIR / "wordlists"
REPORTS_DIR = ROOT_DIR / "reports"
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "saqrintel.db"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SAQRIntel/1.0"
)


class Settings(BaseSettings):
    """Application settings with sensible Kali-oriented defaults."""

    app_name: str = "SAQRIntel"
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = f"sqlite:///{DB_PATH}"

    # HTTP client defaults
    http_timeout: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT

    # Rate limiting (requests per second across outbound HTTP)
    rate_limit_rps: float = 5.0

    # Concurrency for DNS brute-force / fuzzing
    thread_count: int = 20

    # Nmap defaults — top 100 is fast; full 1-65535 warned in UI
    nmap_ports: str = "--top-ports 100"
    nmap_timing: str = "T3"

    # Wordlists
    subdomain_wordlist: str = str(WORDLISTS_DIR / "subdomains_small.txt")
    fuzzer_wordlist: str = str(WORDLISTS_DIR / "fuzzer_paths_small.txt")

    # Web crawler
    crawl_max_depth: int = 2
    crawl_max_pages: int = 50

    class Config:
        env_prefix = "SAQRINTEL_"


settings = Settings()


def ensure_directories() -> None:
    """Create runtime directories if they do not exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
