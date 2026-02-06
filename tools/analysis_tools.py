"""Analysis tools — header, cookie, TLS, CORS, and HTTP method checks."""

from __future__ import annotations

import ssl
import socket
from urllib.parse import urlparse
from typing import Any

from .http_tools import _make_request


async def check_headers(inputs: dict, *, config, state) -> dict:
    """Analyze response headers for security issues."""
    result = await _make_request("GET", inputs["url"], config=config, state=state)
    if "error" in result:
        return result

    headers = result["headers"]
    issues = []
    info = []

    security_headers = {
        "strict-transport-security": "HSTS not set — vulnerable to protocol downgrade attacks",
        "content-security-policy": "CSP not set — vulnerable to XSS and data injection",
        "x-frame-options": "X-Frame-Options not set — vulnerable to clickjacking",
        "x-content-type-options": "X-Content-Type-Options not set — vulnerable to MIME sniffing",
        "referrer-policy": "Referrer-Policy not set — may leak sensitive URLs",
        "permissions-policy": "Permissions-Policy not set — browser features unrestricted",
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, issue_msg in security_headers.items():
        if header not in headers_lower:
            issues.append({"header": header, "issue": issue_msg, "severity": "MEDIUM"})
        else:
            info.append({"header": header, "value": headers_lower[header]})

    # Check for information disclosure
    disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    for h in disclosure_headers:
        if h in headers_lower:
            issues.append({
                "header": h,
                "issue": f"Information disclosure: {h}: {headers_lower[h]}",
                "severity": "LOW",
                "value": headers_lower[h],
            })

    # Store in scan state
    state.headers[inputs["url"]] = dict(headers)

    return {
        "url": inputs["url"],
        "issues": issues,
        "present_security_headers": info,
        "all_headers": dict(headers),
    }


async def check_cookies(inputs: dict, *, config, state) -> dict:
    """Analyze cookies for security flags."""
    result = await _make_request("GET", inputs["url"], config=config, state=state)
    if "error" in result:
        return result

    headers = result["headers"]
    cookie_headers = []

    # Collect all Set-Cookie headers
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_headers.append(value)

    if not cookie_headers:
        return {"url": inputs["url"], "cookies": [], "message": "No cookies set by this URL"}

    analyzed = []
    for cookie_str in cookie_headers:
        parts = cookie_str.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=")[0].strip() if "=" in name_value else name_value

        flags = cookie_str.lower()
        cookie_info = {
            "name": name,
            "raw": cookie_str,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": "none",
            "issues": [],
        }

        if "samesite=strict" in flags:
            cookie_info["samesite"] = "strict"
        elif "samesite=lax" in flags:
            cookie_info["samesite"] = "lax"
        elif "samesite=none" in flags:
            cookie_info["samesite"] = "none"

        if not cookie_info["secure"]:
            cookie_info["issues"].append("Missing Secure flag — cookie sent over HTTP")
        if not cookie_info["httponly"]:
            cookie_info["issues"].append("Missing HttpOnly flag — accessible via JavaScript")
        if cookie_info["samesite"] == "none":
            cookie_info["issues"].append("SameSite=None or missing — vulnerable to CSRF")

        analyzed.append(cookie_info)

    # Store in state
    state.cookies.extend(analyzed)

    return {"url": inputs["url"], "cookies": analyzed}


async def check_tls(inputs: dict, *, config, state) -> dict:
    """Check TLS configuration for a host."""
    parsed = urlparse(inputs["url"])
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {
            "url": inputs["url"],
            "issue": "Not using HTTPS — all traffic is unencrypted",
            "severity": "HIGH",
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=config.request_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                issues = []
                if protocol in ("TLSv1", "TLSv1.1"):
                    issues.append(f"Outdated TLS version: {protocol}")

                return {
                    "url": inputs["url"],
                    "protocol": protocol,
                    "cipher": ssock.cipher(),
                    "cert_subject": dict(x[0] for x in cert.get("subject", [])),
                    "cert_issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "cert_expires": cert.get("notAfter", ""),
                    "cert_san": [
                        e[1] for e in cert.get("subjectAltName", [])
                    ],
                    "issues": issues,
                }
    except ssl.SSLCertVerificationError as e:
        return {"url": inputs["url"], "issue": f"SSL certificate error: {e}", "severity": "HIGH"}
    except Exception as e:
        return {"url": inputs["url"], "error": f"TLS check failed: {e}"}


async def check_cors(inputs: dict, *, config, state) -> dict:
    """Test CORS configuration with various Origin headers."""
    url = inputs["url"]
    test_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]
    # Also test reflecting the target's own domain with a subdomain twist
    parsed = urlparse(url)
    test_origins.append(f"https://evil.{parsed.hostname}")

    results = []
    for origin in test_origins:
        resp = await _make_request(
            "GET", url, config=config, state=state,
            headers={"Origin": origin},
        )
        if "error" in resp:
            continue

        acao = resp["headers"].get("access-control-allow-origin", "")
        acac = resp["headers"].get("access-control-allow-credentials", "")

        if acao:
            issue = None
            if acao == "*":
                issue = "Wildcard ACAO — any origin can read responses"
            elif acao == origin:
                issue = f"Origin '{origin}' is reflected — possible CORS misconfiguration"
                if acac.lower() == "true":
                    issue += " WITH credentials (critical)"

            results.append({
                "origin_tested": origin,
                "acao": acao,
                "acac": acac,
                "issue": issue,
            })

    return {"url": url, "cors_tests": results}


async def check_methods(inputs: dict, *, config, state) -> dict:
    """Test which HTTP methods are allowed on an endpoint."""
    url = inputs["url"]

    # First try OPTIONS
    options_resp = await _make_request("OPTIONS", url, config=config, state=state)
    allowed_from_options = ""
    if "error" not in options_resp:
        allowed_from_options = options_resp["headers"].get("allow", "")

    # Test potentially dangerous methods
    dangerous = ["PUT", "DELETE", "TRACE", "PATCH"]
    method_results = {}
    for method in dangerous:
        resp = await _make_request(method, url, config=config, state=state)
        if "error" not in resp:
            method_results[method] = resp["status_code"]

    issues = []
    if "TRACE" in method_results and method_results["TRACE"] == 200:
        issues.append("TRACE method enabled — vulnerable to Cross-Site Tracing (XST)")
    if "PUT" in method_results and method_results["PUT"] not in (404, 405, 403, 401):
        issues.append(f"PUT method returned {method_results['PUT']} — may allow file upload")
    if "DELETE" in method_results and method_results["DELETE"] not in (404, 405, 403, 401):
        issues.append(f"DELETE method returned {method_results['DELETE']} — may allow resource deletion")

    return {
        "url": url,
        "allowed_header": allowed_from_options,
        "method_responses": method_results,
        "issues": issues,
    }
