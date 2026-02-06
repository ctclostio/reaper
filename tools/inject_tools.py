"""Injection tools — finding recording."""

from __future__ import annotations

from typing import Any
from ..models import Finding, Severity


async def record_finding(inputs: dict, *, config, state) -> dict:
    """Record a confirmed vulnerability finding."""
    finding = Finding(
        title=inputs["title"],
        severity=Severity(inputs["severity"]),
        owasp_category=inputs["owasp_category"],
        url=inputs["url"],
        evidence=inputs["evidence"],
        reproduction_steps=inputs["reproduction_steps"],
        remediation=inputs["remediation"],
    )
    state.findings.append(finding)
    return {
        "status": "recorded",
        "finding_number": len(state.findings),
        "title": finding.title,
        "severity": finding.severity.value,
    }
