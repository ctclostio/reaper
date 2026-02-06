"""Core HTTP tools — all requests flow through _make_request for scope enforcement."""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, urljoin
from typing import Any

import httpx
from bs4 import BeautifulSoup


MAX_BODY_LENGTH = 5000


async def _make_request(
    method: str,
    url: str,
    *,
    config,
    state,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    content_type: str | None = None,
    timeout: int | None = None,
) -> dict:
    """Single chokepoint for all HTTP requests. Enforces scope and limits."""
    if not config.is_in_scope(url):
        return {"error": f"URL out of scope: {url}"}

    if state.request_count >= config.max_requests:
        return {"error": f"Request limit reached ({config.max_requests})"}

    state.request_count += 1
    req_headers = headers or {}
    if content_type:
        req_headers["Content-Type"] = content_type

    # Default User-Agent
    req_headers.setdefault("User-Agent", "Reaper/1.0 (Security Scanner)")

    try:
        async with httpx.AsyncClient(
            verify=False,  # Accept self-signed certs for testing
            follow_redirects=True,
            timeout=timeout or config.request_timeout,
        ) as client:
            resp = await client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                content=body.encode() if body else None,
            )
            body_text = resp.text[:MAX_BODY_LENGTH]
            truncated = len(resp.text) > MAX_BODY_LENGTH

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": body_text,
                "body_truncated": truncated,
                "body_length": len(resp.text),
                "url": str(resp.url),
                "request_number": state.request_count,
            }
    except httpx.TimeoutException:
        return {"error": f"Request timed out after {config.request_timeout}s", "url": url}
    except httpx.ConnectError as e:
        return {"error": f"Connection failed: {e}", "url": url}
    except Exception as e:
        return {"error": f"Request failed: {e}", "url": url}


async def http_request(inputs: dict, *, config, state) -> dict:
    """Make a generic HTTP request."""
    return await _make_request(
        method=inputs["method"],
        url=inputs["url"],
        config=config,
        state=state,
        headers=inputs.get("headers"),
        body=inputs.get("body"),
        content_type=inputs.get("content_type"),
    )


async def crawl_page(inputs: dict, *, config, state) -> dict:
    """Fetch a page and extract links, forms, scripts, meta tags, comments."""
    result = await _make_request("GET", inputs["url"], config=config, state=state)
    if "error" in result:
        return result

    soup = BeautifulSoup(result["body"], "html.parser")
    base_url = result["url"]

    # Extract links
    links = set()
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        if config.is_in_scope(href):
            links.add(href)

    # Extract forms
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action", ""))
        method = form.get("method", "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            fields.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append({"action": action, "method": method, "fields": fields})

    # Extract script sources
    scripts = []
    for s in soup.find_all("script", src=True):
        scripts.append(urljoin(base_url, s["src"]))

    # Extract meta tags
    meta = []
    for m in soup.find_all("meta"):
        meta.append({k: v for k, v in m.attrs.items()})

    # Extract HTML comments
    from bs4 import Comment
    comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment))]

    # Extract title
    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    return {
        "url": base_url,
        "status_code": result["status_code"],
        "title": title,
        "links": sorted(links)[:100],  # Cap at 100 links
        "forms": forms,
        "scripts": scripts,
        "meta_tags": meta,
        "comments": comments[:20],  # Cap comments
        "content_type": result["headers"].get("content-type", ""),
    }


async def test_payload(inputs: dict, *, config, state) -> dict:
    """Send a payload to a specific parameter."""
    url = inputs["url"]
    method = inputs["method"]
    param_name = inputs["param_name"]
    payload = inputs["payload"]
    location = inputs.get("param_location", "query" if method == "GET" else "body")
    content_type = inputs.get("content_type", "application/x-www-form-urlencoded")
    extra_params = inputs.get("extra_params", {})

    if location == "query":
        separator = "&" if "?" in url else "?"
        params = {param_name: payload, **extra_params}
        full_url = url.split("?")[0] + "?" + urlencode(params)
        return await _make_request(method, full_url, config=config, state=state)

    elif location == "body":
        params = {param_name: payload, **extra_params}
        body = urlencode(params)
        return await _make_request(
            method, url, config=config, state=state,
            body=body, content_type=content_type,
        )

    elif location == "header":
        headers = {param_name: payload}
        return await _make_request(method, url, config=config, state=state, headers=headers)

    elif location == "cookie":
        headers = {"Cookie": f"{param_name}={payload}"}
        return await _make_request(method, url, config=config, state=state, headers=headers)

    return {"error": f"Unknown param_location: {location}"}


async def fuzz_parameter(inputs: dict, *, config, state) -> dict:
    """Send multiple payloads and report interesting responses."""
    url = inputs["url"]
    method = inputs["method"]
    param_name = inputs["param_name"]
    payloads = inputs["payloads"]
    location = inputs.get("param_location", "query" if method == "GET" else "body")
    extra_params = inputs.get("extra_params", {})
    baseline_value = inputs.get("baseline_value", "test123")

    # Get baseline response first
    baseline_result = await test_payload(
        {"url": url, "method": method, "param_name": param_name,
         "payload": baseline_value, "param_location": location,
         "extra_params": extra_params},
        config=config, state=state,
    )
    baseline_status = baseline_result.get("status_code", 0)
    baseline_length = baseline_result.get("body_length", 0)

    interesting = []
    for payload in payloads[:30]:  # Cap at 30 payloads per fuzz
        result = await test_payload(
            {"url": url, "method": method, "param_name": param_name,
             "payload": payload, "param_location": location,
             "extra_params": extra_params},
            config=config, state=state,
        )
        if "error" in result:
            if "Request limit" in result["error"]:
                break
            continue

        # Determine if response is "interesting"
        is_interesting = False
        reasons = []

        if result["status_code"] != baseline_status:
            is_interesting = True
            reasons.append(f"status changed: {baseline_status} → {result['status_code']}")

        body_len = result.get("body_length", 0)
        if abs(body_len - baseline_length) > max(100, baseline_length * 0.2):
            is_interesting = True
            reasons.append(f"body length changed: {baseline_length} → {body_len}")

        body = result.get("body", "")
        # Check for payload reflection
        if payload in body:
            is_interesting = True
            reasons.append("payload reflected in response")

        # Check for error signatures
        error_sigs = ["sql", "syntax", "error", "exception", "traceback",
                      "warning", "mysql", "postgresql", "sqlite", "oracle",
                      "microsoft", "odbc", "stack trace"]
        body_lower = body.lower()
        for sig in error_sigs:
            if sig in body_lower and sig not in baseline_result.get("body", "").lower():
                is_interesting = True
                reasons.append(f"new error signature: '{sig}'")
                break

        if is_interesting:
            interesting.append({
                "payload": payload,
                "status_code": result["status_code"],
                "body_length": body_len,
                "reasons": reasons,
                "body_preview": body[:500],
            })

    return {
        "baseline_status": baseline_status,
        "baseline_body_length": baseline_length,
        "payloads_tested": min(len(payloads), 30),
        "interesting_responses": interesting,
        "requests_remaining": config.max_requests - state.request_count,
    }
