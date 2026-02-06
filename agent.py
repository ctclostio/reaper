"""Core agent — drives the AI CLI with Reaper MCP server for each phase."""

from __future__ import annotations

import json
import subprocess
import time
import tempfile
import os
from pathlib import Path

from .config import ScanConfig
from .models import ScanState, Finding, Severity
from .prompts import (
    RECON_PROMPT,
    ANALYSIS_PROMPT,
    EXPLOITATION_PROMPT,
    REPORTING_PROMPT,
)


PHASE_TOOLS = {
    "recon": ["http_request", "crawl_page", "check_headers", "check_cookies", "check_tls", "check_cors", "check_methods"],
    "analysis": ["http_request", "crawl_page", "check_headers", "check_cookies", "check_tls", "check_cors", "check_methods", "load_payloads"],
    "exploitation": ["http_request", "crawl_page", "check_headers", "check_cookies", "check_tls", "check_cors", "check_methods", "test_payload", "fuzz_parameter", "load_payloads", "record_finding"],
    "reporting": ["record_finding"],
}


def build_phase_input(phase: str, state: ScanState) -> str:
    summary = json.dumps(state.to_summary(), indent=2)
    if phase == "recon":
        return f"Begin reconnaissance on the target.\n\nTarget: {state.target}\nRequests used so far: {state.request_count}"
    elif phase == "analysis":
        return f"Analyze the recon data and plan the exploitation strategy.\n\nRecon Data:\n{summary}"
    elif phase == "exploitation":
        return f"Execute attacks against identified vulnerabilities.\n\nCurrent State:\n{summary}"
    elif phase == "reporting":
        return f"Review and finalize all findings.\n\nCurrent State:\n{summary}"
    return summary


def run_phase(phase: str, system_prompt: str, config: ScanConfig, state: ScanState, work_dir: str) -> ScanState:
    """Run a phase by invoking the AI CLI with the Reaper MCP server."""
    print(f"\n{'='*60}")
    print(f"  PHASE: {phase.upper()}")
    print(f"{'='*60}")

    # Write MCP config
    mcp_config = {
        "mcpServers": {
            "reaper": {
                "command": "python",
                "args": [str(Path(__file__).parent / "mcp_server.py")],
                "env": {
                    "REAPER_TARGET": config.target_url,
                    "REAPER_SCOPE": ",".join(config.allowed_scope),
                    "REAPER_MAX_REQUESTS": str(config.max_requests),
                    "REAPER_TIMEOUT": str(config.request_timeout),
                    "REAPER_STATE_FILE": str(Path(work_dir) / "state.json"),
                },
            }
        }
    }
    mcp_config_path = Path(work_dir) / "mcp_config.json"
    mcp_config_path.write_text(json.dumps(mcp_config))

    # Save current state for the MCP server to read
    state_path = Path(work_dir) / "state.json"
    state_data = {"request_count": state.request_count}
    state_path.write_text(json.dumps(state_data))

    # Build allowed tools list
    phase_tools = PHASE_TOOLS.get(phase, [])
    allowed = [f"mcp__reaper__{t}" for t in phase_tools]

    # Build the prompt
    prompt = build_phase_input(phase, state)
    full_prompt = f"{prompt}"

    # Run AI CLI
    cmd = [
        "claude",
        "-p", full_prompt,
        "--system-prompt", system_prompt,
        "--model", config.model,
        "--mcp-config", str(mcp_config_path),
        "--allowed-tools", ",".join(allowed),
        "--permission-mode", "bypassPermissions",
        "--output-format", "json",
        "--no-session-persistence",
        "--tools", "",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout per phase
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            print(f"  [CLI error] exit code {result.returncode}")
            if result.stderr:
                print(f"  stderr: {result.stderr[:500]}")

        if result.stdout:
            try:
                output = json.loads(result.stdout)
                # Print AI response
                response_text = output.get("result", "")
                if response_text:
                    for line in response_text[:500].split("\n")[:10]:
                        print(f"  {line}")
                # Print stats
                cost = output.get("total_cost_usd", 0)
                turns = output.get("num_turns", 0)
                print(f"  [turns: {turns}, cost: ${cost:.4f}]")
            except json.JSONDecodeError:
                print(f"  {result.stdout[:500]}")

    except subprocess.TimeoutExpired:
        print(f"  [Phase timed out after 600s]")
    except Exception as e:
        print(f"  [Error: {e}]")

    # Read back state from MCP server
    if state_path.exists():
        updated = json.loads(state_path.read_text())
        state.request_count = updated.get("request_count", state.request_count)

    # Read findings
    findings_path = Path(work_dir) / "findings.json"
    if findings_path.exists():
        findings_data = json.loads(findings_path.read_text())
        # Only add new findings
        existing_titles = {f.title for f in state.findings}
        for f in findings_data:
            if f["title"] not in existing_titles:
                state.findings.append(Finding(
                    title=f["title"],
                    severity=Severity(f["severity"]),
                    owasp_category=f["owasp_category"],
                    url=f["url"],
                    evidence=f["evidence"],
                    reproduction_steps=f["reproduction_steps"],
                    remediation=f["remediation"],
                ))

    print(f"  Phase {phase} complete. Requests: {state.request_count}, Findings: {len(state.findings)}")
    return state


def run_scan(config: ScanConfig) -> ScanState:
    """Run the full 4-phase pentest."""
    state = ScanState(target=config.target_url)

    # Create working directory
    work_dir = tempfile.mkdtemp(prefix="reaper_")

    start = time.time()
    print(f"\nReaper Security Scan")
    print(f"Target: {config.target_url}")
    print(f"Scope: {config.allowed_scope}")
    print(f"Max requests: {config.max_requests}")
    print(f"Model: {config.model}")
    print(f"Working dir: {work_dir}")

    phases = [
        ("recon", RECON_PROMPT),
        ("analysis", ANALYSIS_PROMPT),
        ("exploitation", EXPLOITATION_PROMPT),
        ("reporting", REPORTING_PROMPT),
    ]

    for phase_name, prompt in phases:
        if state.request_count >= config.max_requests:
            print(f"\n  Skipping {phase_name} - request limit reached")
            continue
        state = run_phase(phase_name, prompt, config, state, work_dir)

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  Duration: {elapsed:.0f}s")
    print(f"  Requests made: {state.request_count}")
    print(f"  Findings: {len(state.findings)}")
    print(f"{'='*60}")

    return state
