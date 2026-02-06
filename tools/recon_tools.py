"""Recon tools — payload loading and discovery helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any


PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"


async def load_payloads(inputs: dict, *, config, state) -> dict:
    """Load a curated payload list by category."""
    category = inputs["category"]
    payload_file = PAYLOAD_DIR / f"{category}.txt"

    if not payload_file.exists():
        available = [f.stem for f in PAYLOAD_DIR.glob("*.txt")]
        return {"error": f"Unknown category: {category}. Available: {available}"}

    payloads = [
        line.strip()
        for line in payload_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return {"category": category, "count": len(payloads), "payloads": payloads}
