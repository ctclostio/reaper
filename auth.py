"""Authentication — verifies the AI CLI backend is available."""

import shutil


def verify_cli_installed():
    """Verify the AI CLI is available on PATH."""
    if not shutil.which("claude"):
        raise FileNotFoundError(
            "AI CLI not found. Install it with: npm install -g @anthropic-ai/claude-code\n"
            "Then log in with: claude login"
        )
    return True
