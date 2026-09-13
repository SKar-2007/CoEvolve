#!/usr/bin/env python3
"""Prompt diff utility for comparing prompt versions."""

from __future__ import annotations

import difflib
import sys
from pathlib import Path


def diff_prompts(version_a: str, version_b: str, prompts_dir: Path | None = None) -> str:
    """Compare two prompt versions and return unified diff output."""
    if prompts_dir is None:
        prompts_dir = Path(__file__).parent.parent

    file_a = prompts_dir / "history" / f"{version_a}.md"
    file_b = prompts_dir / "history" / f"{version_b}.md"

    if not file_a.exists():
        return f"Error: {file_a} not found"
    if not file_b.exists():
        return f"Error: {file_b} not found"

    lines_a = file_a.read_text().splitlines(keepends=True)
    lines_b = file_b.read_text().splitlines(keepends=True)

    diff = difflib.unified_diff(
        lines_a,
        lines_b,
        fromfile=f"prompts/history/{version_a}.md",
        tofile=f"prompts/history/{version_b}.md",
        lineterm="",
    )

    return "".join(diff)


def diff_current_vs_version(version: str, prompts_dir: Path | None = None) -> str:
    """Compare current prompts against a specific version."""
    if prompts_dir is None:
        prompts_dir = Path(__file__).parent.parent

    current_dir = prompts_dir / "current"
    history_file = prompts_dir / "history" / f"{version}.md"

    if not history_file.exists():
        return f"Error: {history_file} not found"

    current_content = "\n\n".join(
        f"# {f.stem.upper()}\n\n{f.read_text()}"
        for f in sorted(current_dir.glob("*.md"))
    )
    history_content = history_file.read_text()

    lines_current = current_content.splitlines(keepends=True)
    lines_history = history_content.splitlines(keepends=True)

    diff = difflib.unified_diff(
        lines_history,
        lines_current,
        fromfile=f"prompts/history/{version}.md",
        tofile="prompts/current/",
        lineterm="",
    )

    return "".join(diff)


def main() -> None:
    """CLI entry point for prompt diff utility."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python diff.py <version_a> <version_b>  # Compare two versions")
        print("  python diff.py <version>                 # Compare current vs version")
        print("\nExamples:")
        print("  python diff.py v1_2026-09-12 v1_2026-09-13")
        print("  python diff.py v1_2026-09-12")
        sys.exit(1)

    prompts_dir = Path(__file__).parent.parent

    if len(sys.argv) == 2:
        version = sys.argv[1]
        result = diff_current_vs_version(version, prompts_dir)
    elif len(sys.argv) == 3:
        version_a = sys.argv[1]
        version_b = sys.argv[2]
        result = diff_prompts(version_a, version_b, prompts_dir)
    else:
        print("Error: Too many arguments")
        sys.exit(1)

    if result:
        print(result)
    else:
        print("No differences found.")


if __name__ == "__main__":
    main()
