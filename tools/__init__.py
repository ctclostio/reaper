"""Tool registry — maps tool names to handlers and generates JSON schemas for the AI agent."""

from __future__ import annotations

import json
from typing import Any, Callable, Awaitable

from .http_tools import (
    http_request,
    crawl_page,
    test_payload,
    fuzz_parameter,
)
from .analysis_tools import (
    check_headers,
    check_cookies,
    check_tls,
    check_cors,
    check_methods,
)
from .recon_tools import load_payloads
from .inject_tools import record_finding

# Each entry: (handler, description, input_schema)
TOOL_REGISTRY: dict[str, tuple[Callable[..., Awaitable[Any]], str, dict]] = {
    "http_request": (
        http_request,
        "Make an HTTP request (GET/POST/PUT/DELETE) to a URL. Returns status code, headers, and truncated body.",
        {
            "type": "object",
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"], "description": "HTTP method"},
                "url": {"type": "string", "description": "Full URL to request"},
                "headers": {"type": "object", "description": "Optional request headers", "additionalProperties": {"type": "string"}},
                "body": {"type": "string", "description": "Optional request body (for POST/PUT/PATCH)"},
                "content_type": {"type": "string", "description": "Content-Type header value (default: application/x-www-form-urlencoded)"},
            },
            "required": ["method", "url"],
        },
    ),
    "crawl_page": (
        crawl_page,
        "Fetch a page and extract all links, forms, scripts, meta tags, and comments. Returns structured data about the page.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to crawl"},
            },
            "required": ["url"],
        },
    ),
    "check_headers": (
        check_headers,
        "Analyze HTTP response headers for security issues (missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check headers for"},
            },
            "required": ["url"],
        },
    ),
    "check_cookies": (
        check_cookies,
        "Analyze cookies set by a URL for security flags (Secure, HttpOnly, SameSite, expiration).",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check cookies for"},
            },
            "required": ["url"],
        },
    ),
    "check_tls": (
        check_tls,
        "Check TLS/SSL configuration for a host (protocol version, certificate details).",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to check TLS for"},
            },
            "required": ["url"],
        },
    ),
    "check_cors": (
        check_cors,
        "Test CORS configuration by sending requests with various Origin headers to detect misconfigurations.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test CORS on"},
            },
            "required": ["url"],
        },
    ),
    "check_methods": (
        check_methods,
        "Test which HTTP methods are allowed on an endpoint (OPTIONS, PUT, DELETE, TRACE, etc.).",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to test methods on"},
            },
            "required": ["url"],
        },
    ),
    "test_payload": (
        test_payload,
        "Send a specific payload to a parameter or form field. Returns the full response for analysis. Use this to test individual injection payloads.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH"], "description": "HTTP method"},
                "param_name": {"type": "string", "description": "Parameter or field name to inject into"},
                "payload": {"type": "string", "description": "The payload string to inject"},
                "param_location": {"type": "string", "enum": ["query", "body", "header", "cookie"], "description": "Where to inject (default: query for GET, body for POST)"},
                "content_type": {"type": "string", "description": "Content-Type for body params (default: application/x-www-form-urlencoded)"},
                "extra_params": {"type": "object", "description": "Additional parameters to include in the request", "additionalProperties": {"type": "string"}},
            },
            "required": ["url", "method", "param_name", "payload"],
        },
    ),
    "fuzz_parameter": (
        fuzz_parameter,
        "Send multiple payloads to a parameter and return which ones produced interesting responses (errors, reflections, status changes, time differences). Efficient batch testing.",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH"]},
                "param_name": {"type": "string", "description": "Parameter name to fuzz"},
                "payloads": {"type": "array", "items": {"type": "string"}, "description": "List of payloads to test"},
                "param_location": {"type": "string", "enum": ["query", "body"], "description": "Where the parameter goes"},
                "extra_params": {"type": "object", "description": "Additional parameters to include", "additionalProperties": {"type": "string"}},
                "baseline_value": {"type": "string", "description": "Normal/expected value for comparison"},
            },
            "required": ["url", "method", "param_name", "payloads"],
        },
    ),
    "load_payloads": (
        load_payloads,
        "Load a curated payload list by category. Returns an array of payload strings.",
        {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": ["sqli", "xss", "ssti", "traversal", "ssrf"], "description": "Payload category to load"},
            },
            "required": ["category"],
        },
    ),
    "record_finding": (
        record_finding,
        "Record a confirmed vulnerability finding. Use this when you have proof that a vulnerability is exploitable.",
        {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short title for the finding"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "owasp_category": {"type": "string", "description": "OWASP Top 10 category (e.g. A03 - Injection)"},
                "url": {"type": "string", "description": "Affected URL"},
                "evidence": {"type": "string", "description": "Proof the vulnerability exists (response data, behavior observed)"},
                "reproduction_steps": {"type": "string", "description": "Step-by-step or curl command to reproduce"},
                "remediation": {"type": "string", "description": "Recommended fix"},
            },
            "required": ["title", "severity", "owasp_category", "url", "evidence", "reproduction_steps", "remediation"],
        },
    ),
}

# Phase-to-tool mapping
PHASE_TOOLS = {
    "recon": [
        "http_request", "crawl_page", "check_headers", "check_cookies",
        "check_tls", "check_cors", "check_methods",
    ],
    "analysis": [
        "http_request", "crawl_page", "check_headers", "check_cookies",
        "check_tls", "check_cors", "check_methods", "load_payloads",
    ],
    "exploitation": list(TOOL_REGISTRY.keys()),
    "reporting": ["record_finding"],
}


def get_tool_schemas(phase: str) -> list[dict]:
    """Get tool definitions for a phase."""
    tool_names = PHASE_TOOLS.get(phase, list(TOOL_REGISTRY.keys()))
    schemas = []
    for name in tool_names:
        if name not in TOOL_REGISTRY:
            continue
        _, description, input_schema = TOOL_REGISTRY[name]
        schemas.append({
            "name": name,
            "description": description,
            "input_schema": input_schema,
        })
    return schemas


async def dispatch(name: str, inputs: dict, config, state) -> dict:
    """Dispatch a tool call and return the result."""
    if name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {name}"}
    handler, _, _ = TOOL_REGISTRY[name]
    try:
        return await handler(inputs, config=config, state=state)
    except Exception as e:
        return {"error": f"Tool {name} failed: {str(e)}"}
