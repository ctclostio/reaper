"""Reaper CLI entry point."""

import argparse
import asyncio
import time
import sys
import os

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from .auth import verify_cli_installed
from .config import ScanConfig
from .agent import run_scan
from .reporter import generate_report


BANNER = """
  REAPER
  AI-Powered Black-Box Penetration Testing
"""


def main():
    parser = argparse.ArgumentParser(
        description="Reaper - AI-powered black-box pentesting tool",
    )
    parser.add_argument("target", help="Target URL to test (e.g. https://example.com)")
    parser.add_argument("--scope", nargs="*", help="Allowed URL prefixes (default: target domain)")
    parser.add_argument("--max-requests", type=int, default=500, help="Maximum HTTP requests (default: 500)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", default="./reports", help="Output directory for reports (default: ./reports)")
    parser.add_argument("--model", default="claude-sonnet-4-5-20250929", help="AI model to use")

    args = parser.parse_args()

    print(BANNER)

    # Build config
    config = ScanConfig(
        target_url=args.target,
        allowed_scope=args.scope or [],
        max_requests=args.max_requests,
        request_timeout=args.timeout,
        output_dir=args.output,
        model=args.model,
    )

    # Verify AI CLI is installed
    print("[*] Verifying AI CLI...")
    try:
        verify_cli_installed()
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)
    print("[+] AI CLI found")

    # Disclaimer
    print()
    print("[!] IMPORTANT: Only scan applications you own or have authorization to test.")
    print(f"[!] Target: {config.target_url}")
    print(f"[!] Scope: {config.allowed_scope}")
    print()

    confirm = input("Proceed with scan? [y/N] ").strip().lower()
    if confirm != "y":
        print("Scan cancelled.")
        sys.exit(0)

    # Run scan
    start_time = time.time()
    state = run_scan(config)
    duration = time.time() - start_time

    # Generate report
    print("\n[*] Generating report...")
    report_path = generate_report(state, duration, config.output_dir)
    print(f"[+] Report saved to: {report_path}")

    # Summary
    print(f"\n[+] Scan complete!")
    print(f"    Findings: {len(state.findings)}")
    print(f"    Requests: {state.request_count}")
    print(f"    Duration: {duration:.0f}s")

    if state.findings:
        print("\n    Findings Summary:")
        for f in state.findings:
            print(f"    [{f.severity.value}] {f.title}")


if __name__ == "__main__":
    main()
