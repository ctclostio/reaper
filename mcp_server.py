"""Reaper MCP Server — exposes pentesting tools via Model Context Protocol."""

import asyncio
import json
import sys
import os
import ssl
import socket
from urllib.parse import urljoin, urlencode, urlparse
from pathlib import Path

import urllib.request
import urllib.error
from bs4 import BeautifulSoup, Comment
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Config from environment ──────────────────────────────────
TARGET_URL = os.environ.get("REAPER_TARGET", "")
SCOPE = os.environ.get("REAPER_SCOPE", TARGET_URL)
MAX_REQUESTS = int(os.environ.get("REAPER_MAX_REQUESTS", "500"))
REQUEST_TIMEOUT = int(os.environ.get("REAPER_TIMEOUT", "10"))
MAX_BODY = 5000

# State file for cross-process state sharing
STATE_FILE = os.environ.get("REAPER_STATE_FILE", "")

request_count = 0


def load_state():
    global request_count
    if STATE_FILE and Path(STATE_FILE).exists():
        data = json.loads(Path(STATE_FILE).read_text())
        request_count = data.get("request_count", 0)


def save_state():
    if STATE_FILE:
        existing = {}
        if Path(STATE_FILE).exists():
            existing = json.loads(Path(STATE_FILE).read_text())
        existing["request_count"] = request_count
        Path(STATE_FILE).write_text(json.dumps(existing))


def is_in_scope(url: str) -> bool:
    scope_prefixes = [s.strip() for s in SCOPE.split(",") if s.strip()]
    return any(url.startswith(p) for p in scope_prefixes)


_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def _sync_request(method, url, req_headers, body_bytes):
    """Sync HTTP request using urllib — httpx has connectivity issues on Windows/WSL."""
    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method.upper())
    try:
        resp = urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=_ssl_ctx)
        status_code = resp.status
        resp_headers = dict(resp.headers)
        body_raw = resp.read()
        body_text = body_raw.decode("utf-8", errors="replace")
        final_url = resp.url or url
    except urllib.error.HTTPError as e:
        status_code = e.code
        resp_headers = dict(e.headers)
        body_raw = e.read()
        body_text = body_raw.decode("utf-8", errors="replace")
        final_url = url
    return {
        "status_code": status_code,
        "headers": resp_headers,
        "body": body_text[:MAX_BODY],
        "body_truncated": len(body_text) > MAX_BODY,
        "body_length": len(body_text),
        "url": final_url,
    }


async def _make_request(method, url, *, headers=None, body=None, content_type=None):
    global request_count
    if not is_in_scope(url):
        return {"error": f"URL out of scope: {url}"}
    if request_count >= MAX_REQUESTS:
        return {"error": f"Request limit reached ({MAX_REQUESTS})"}
    request_count += 1
    save_state()
    req_headers = headers or {}
    if content_type:
        req_headers["Content-Type"] = content_type
    req_headers.setdefault("User-Agent", "Reaper/1.0 (Security Scanner)")
    try:
        body_bytes = body.encode() if body else None
        result = await asyncio.to_thread(_sync_request, method, url, req_headers, body_bytes)
        result["request_number"] = request_count
        result["requests_remaining"] = MAX_REQUESTS - request_count
        return result
    except urllib.error.URLError as e:
        return {"error": f"Connection error: {e.reason}", "url": url}
    except TimeoutError:
        return {"error": f"Timeout after {REQUEST_TIMEOUT}s", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


# ── MCP Server Setup ─────────────────────────────────────────
server = Server("reaper")


@server.list_tools()
async def list_tools():
    return [
        Tool(name="http_request", description="Make an HTTP request (GET/POST/PUT/DELETE). Returns status, headers, truncated body.",
             inputSchema={"type": "object", "properties": {"method": {"type": "string", "enum": ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"]}, "url": {"type": "string"}, "headers": {"type": "string", "description": "JSON string of headers dict"}, "body": {"type": "string"}, "content_type": {"type": "string"}}, "required": ["method", "url"]}),
        Tool(name="crawl_page", description="Fetch a page and extract all links, forms, scripts, meta tags, comments.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="check_headers", description="Analyze response headers for security issues (CSP, HSTS, X-Frame-Options, etc.)",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="check_cookies", description="Analyze cookies for Secure, HttpOnly, SameSite flags.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="check_cors", description="Test CORS configuration with various Origin headers.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="check_methods", description="Test which HTTP methods (PUT, DELETE, TRACE) are allowed.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="check_tls", description="Check TLS/SSL configuration (protocol, cert details).",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="test_payload", description="Inject a payload into a specific parameter. Returns full response for analysis.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}, "param_name": {"type": "string"}, "payload": {"type": "string"}, "param_location": {"type": "string", "enum": ["query","body","header","cookie"]}, "extra_params": {"type": "string", "description": "JSON object of additional params"}}, "required": ["url","method","param_name","payload"]}),
        Tool(name="fuzz_parameter", description="Send multiple payloads to a parameter. Returns which caused interesting responses.",
             inputSchema={"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string"}, "param_name": {"type": "string"}, "payloads": {"type": "string", "description": "JSON array of payload strings"}, "param_location": {"type": "string"}, "baseline_value": {"type": "string"}}, "required": ["url","method","param_name","payloads"]}),
        Tool(name="load_payloads", description="Load curated payload list by category (sqli, xss, ssti, traversal, ssrf).",
             inputSchema={"type": "object", "properties": {"category": {"type": "string", "enum": ["sqli","xss","ssti","traversal","ssrf"]}}, "required": ["category"]}),
        Tool(name="record_finding", description="Record a confirmed vulnerability. Only use when you have PROOF of exploitation.",
             inputSchema={"type": "object", "properties": {"title": {"type": "string"}, "severity": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}, "owasp_category": {"type": "string"}, "url": {"type": "string"}, "evidence": {"type": "string"}, "reproduction_steps": {"type": "string"}, "remediation": {"type": "string"}}, "required": ["title","severity","owasp_category","url","evidence","reproduction_steps","remediation"]}),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    load_state()
    result = await _dispatch(name, arguments)
    return [TextContent(type="text", text=json.dumps(result, default=str))]


async def _dispatch(name: str, args: dict):
    if name == "http_request":
        hdrs = json.loads(args.get("headers", "{}")) if args.get("headers") else None
        return await _make_request(args["method"], args["url"], headers=hdrs, body=args.get("body"), content_type=args.get("content_type"))

    elif name == "crawl_page":
        result = await _make_request("GET", args["url"])
        if "error" in result:
            return result
        soup = BeautifulSoup(result["body"], "html.parser")
        base_url = result["url"]
        links = sorted({urljoin(base_url, a["href"]) for a in soup.find_all("a", href=True) if is_in_scope(urljoin(base_url, a["href"]))})[:100]
        forms = []
        for form in soup.find_all("form"):
            fields = [{"name": i.get("name",""), "type": i.get("type","text"), "value": i.get("value","")} for i in form.find_all(["input","textarea","select"])]
            forms.append({"action": urljoin(base_url, form.get("action","")), "method": form.get("method","GET").upper(), "fields": fields})
        scripts = [urljoin(base_url, s["src"]) for s in soup.find_all("script", src=True)]
        meta = [{k:v for k,v in m.attrs.items()} for m in soup.find_all("meta")]
        comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment))][:20]
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        return {"url": base_url, "status_code": result["status_code"], "title": title, "links": links, "forms": forms, "scripts": scripts, "meta_tags": meta, "comments": comments}

    elif name == "check_headers":
        result = await _make_request("GET", args["url"])
        if "error" in result:
            return result
        h = {k.lower(): v for k, v in result["headers"].items()}
        issues = []
        for hdr, msg in {"strict-transport-security":"HSTS not set","content-security-policy":"CSP not set","x-frame-options":"X-Frame-Options not set","x-content-type-options":"X-Content-Type-Options not set"}.items():
            if hdr not in h:
                issues.append({"header": hdr, "issue": msg})
        for hdr in ["server","x-powered-by"]:
            if hdr in h:
                issues.append({"header": hdr, "issue": f"Info disclosure: {h[hdr]}"})
        return {"url": args["url"], "issues": issues, "all_headers": result["headers"]}

    elif name == "check_cookies":
        result = await _make_request("GET", args["url"])
        if "error" in result:
            return result
        cookies = []
        for k, v in result["headers"].items():
            if k.lower() == "set-cookie":
                fl = v.lower()
                issues = []
                if "secure" not in fl: issues.append("Missing Secure")
                if "httponly" not in fl: issues.append("Missing HttpOnly")
                if "samesite" not in fl or "samesite=none" in fl: issues.append("SameSite issue")
                cookies.append({"name": v.split("=")[0].strip(), "issues": issues})
        return {"url": args["url"], "cookies": cookies}

    elif name == "check_cors":
        url = args["url"]
        results = []
        for origin in ["https://evil.com", "null", f"https://evil.{urlparse(url).hostname}"]:
            resp = await _make_request("GET", url, headers={"Origin": origin})
            if "error" not in resp:
                acao = resp["headers"].get("access-control-allow-origin","")
                if acao:
                    issue = "Wildcard" if acao == "*" else f"Reflected: {origin}" if acao == origin else None
                    results.append({"origin": origin, "acao": acao, "issue": issue})
        return {"url": url, "cors_tests": results}

    elif name == "check_methods":
        url = args["url"]
        results = {}
        for m in ["OPTIONS","PUT","DELETE","TRACE","PATCH"]:
            r = await _make_request(m, url)
            if "error" not in r:
                results[m] = r["status_code"]
        issues = []
        if results.get("TRACE") == 200: issues.append("TRACE enabled")
        return {"url": url, "methods": results, "issues": issues}

    elif name == "check_tls":
        parsed = urlparse(args["url"])
        if parsed.scheme != "https":
            return {"issue": "Not using HTTPS", "severity": "HIGH"}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {"protocol": ssock.version(), "cipher": ssock.cipher(), "expires": cert.get("notAfter","")}
        except Exception as e:
            return {"error": str(e)}

    elif name == "test_payload":
        url, method = args["url"], args["method"]
        loc = args.get("param_location") or ("query" if method.upper() == "GET" else "body")
        extras = json.loads(args.get("extra_params","{}")) if args.get("extra_params") else {}
        if loc == "query":
            full_url = url.split("?")[0] + "?" + urlencode({args["param_name"]: args["payload"], **extras})
            return await _make_request(method, full_url)
        elif loc == "body":
            return await _make_request(method, url, body=urlencode({args["param_name"]: args["payload"], **extras}), content_type="application/x-www-form-urlencoded")
        elif loc == "header":
            return await _make_request(method, url, headers={args["param_name"]: args["payload"]})
        elif loc == "cookie":
            return await _make_request(method, url, headers={"Cookie": f"{args['param_name']}={args['payload']}"})
        return {"error": f"Unknown location: {loc}"}

    elif name == "fuzz_parameter":
        payloads = json.loads(args["payloads"])
        loc = args.get("param_location") or ("query" if args["method"].upper() == "GET" else "body")
        bl = await _dispatch("test_payload", {"url": args["url"], "method": args["method"], "param_name": args["param_name"], "payload": args.get("baseline_value","test123"), "param_location": loc})
        bl_status, bl_len = bl.get("status_code",0), bl.get("body_length",0)
        interesting = []
        for p in payloads[:30]:
            r = await _dispatch("test_payload", {"url": args["url"], "method": args["method"], "param_name": args["param_name"], "payload": p, "param_location": loc})
            if "error" in r:
                if "Request limit" in r.get("error",""):
                    break
                continue
            reasons = []
            if r.get("status_code") != bl_status: reasons.append(f"status:{bl_status}->{r['status_code']}")
            if abs(r.get("body_length",0) - bl_len) > max(100, bl_len*0.2): reasons.append(f"length:{bl_len}->{r['body_length']}")
            body = r.get("body","")
            if p in body: reasons.append("reflected")
            for sig in ["sql","syntax","error","exception","traceback","mysql","postgresql","sqlite"]:
                if sig in body.lower() and sig not in bl.get("body","").lower():
                    reasons.append(f"error:'{sig}'")
                    break
            if reasons:
                interesting.append({"payload": p, "status": r.get("status_code"), "reasons": reasons, "preview": body[:300]})
        return {"baseline_status": bl_status, "tested": min(len(payloads),30), "interesting": interesting, "requests_remaining": MAX_REQUESTS - request_count}

    elif name == "load_payloads":
        pf = Path(__file__).parent / "payloads" / f"{args['category']}.txt"
        if not pf.exists():
            avail = [f.stem for f in (Path(__file__).parent / "payloads").glob("*.txt")]
            return {"error": f"Unknown: {args['category']}. Available: {avail}"}
        payloads = [l.strip() for l in pf.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
        return {"category": args["category"], "count": len(payloads), "payloads": payloads}

    elif name == "record_finding":
        # Append finding to state file
        findings_file = Path(STATE_FILE).parent / "findings.json" if STATE_FILE else Path("findings.json")
        existing = json.loads(findings_file.read_text()) if findings_file.exists() else []
        existing.append({"title": args["title"], "severity": args["severity"], "owasp_category": args["owasp_category"], "url": args["url"], "evidence": args["evidence"], "reproduction_steps": args["reproduction_steps"], "remediation": args["remediation"]})
        findings_file.write_text(json.dumps(existing, indent=2))
        return {"status": "recorded", "finding_number": len(existing), "title": args["title"]}

    return {"error": f"Unknown tool: {name}"}


async def main():
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
