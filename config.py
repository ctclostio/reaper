"""Scan configuration."""

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScanConfig:
    target_url: str
    allowed_scope: list[str] = field(default_factory=list)
    max_requests: int = 500
    request_timeout: int = 10
    output_dir: str = "./reports"
    model: str = "claude-sonnet-4-5-20250929"

    def __post_init__(self):
        # Default scope to target domain
        if not self.allowed_scope:
            parsed = urlparse(self.target_url)
            self.allowed_scope = [f"{parsed.scheme}://{parsed.netloc}"]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the allowed scope."""
        for prefix in self.allowed_scope:
            if url.startswith(prefix):
                return True
        return False
