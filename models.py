"""Data models for Reaper scan state and findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class FormField:
    name: str
    field_type: str  # text, password, hidden, etc.
    value: str = ""


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    content_type: str = ""


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: Severity
    owasp_category: str
    url: str
    evidence: str
    reproduction_steps: str
    remediation: str


@dataclass
class ScanState:
    target: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, dict[str, str]] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    request_count: int = 0

    def to_summary(self) -> dict:
        """Serialize state for passing between phases."""
        return {
            "target": self.target,
            "endpoints_discovered": len(self.endpoints),
            "endpoints": [
                {"url": e.url, "method": e.method, "params": e.params,
                 "status_code": e.status_code, "content_type": e.content_type}
                for e in self.endpoints
            ],
            "forms": [
                {"page_url": f.page_url, "action": f.action, "method": f.method,
                 "fields": [{"name": ff.name, "type": ff.field_type, "value": ff.value}
                            for ff in f.fields]}
                for f in self.forms
            ],
            "technologies": self.technologies,
            "cookies": self.cookies,
            "findings_so_far": [
                {"title": f.title, "severity": f.severity.value,
                 "owasp_category": f.owasp_category, "url": f.url}
                for f in self.findings
            ],
            "request_count": self.request_count,
        }
