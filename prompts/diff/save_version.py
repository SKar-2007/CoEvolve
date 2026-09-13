#!/usr/bin/env python3
"""Save a new version of prompts to history."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path


def save_version(description: str = "", prompts_dir: Path | None = None) -> str:
    """Save current prompts as a new version in history."""
    if prompts_dir is None:
        prompts_dir = Path(__file__).parent.parent

    current_dir = prompts_dir / "current"
    history_dir = prompts_dir / "history"

    if not current_dir.exists():
        return "Error: prompts/current/ directory not found"

    # Get next version number
    existing_versions = list(history_dir.glob("v*.md"))
    next_version = len(existing_versions) + 1

    # Create version filename with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d")
    version_name = f"v{next_version}_{timestamp}"
    output_file = history_dir / f"{version_name}.md"

    # Combine all current prompts
    sections = []
    for f in sorted(current_dir.glob("*.md")):
        content = f.read_text()
        sections.append(f"# {f.stem.upper()} (v{next_version})\n\n{content}")

    combined = "\n\n---\n\n".join(sections)

    # Add header
    header = f"# Prompt Version {version_name}\n\n"
    if description:
        header += f"## Description\n{description}\n\n"
    header += f"## Date\n{datetime.now().isoformat()}\n\n"
    header += "---\n\n"

    output_file.write_text(header + combined)

    # Update README
    _update_readme(history_dir, version_name, description, timestamp)

    return f"Saved version {version_name} to {output_file}"


def _update_readme(history_dir: Path, version_name: str, description: str, date: str) -> None:
    """Update the history README with the new version entry."""
    readme = history_dir / "README.md"

    if readme.exists():
        content = readme.read_text()
        # Add new entry before the last line
        new_entry = f"| {version_name} | {date} | {description or 'No description'} |"
        lines = content.split("\n")
        # Find the last table row and insert after it
        for i, line in enumerate(lines):
            if line.startswith("| v"):
                last_row = i
        lines.insert(last_row + 1, new_entry)
        readme.write_text("\n".join(lines))


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) > 1:
        description = " ".join(sys.argv[1:])
    else:
        description = input("Enter version description (optional): ").strip()

    prompts_dir = Path(__file__).parent.parent
    result = save_version(description, prompts_dir)
    print(result)


if __name__ == "__main__":
    main()
