"""Shared task-formatting helpers for developer agents."""

from __future__ import annotations

from typing import Any


def format_task(task: dict[str, Any]) -> str:
    """Format a task dict into a user prompt (single canonical implementation)."""
    lines = [f"TASK: {task.get('task_description', '')}"]
    context_files = task.get("context_files", [])
    if context_files:
        file_strs = []
        for f in context_files:
            if isinstance(f, str):
                file_strs.append(f)
            elif isinstance(f, dict):
                path = f.get("path", "unknown")
                snippet = f.get("snippet", "")
                file_strs.append(f"{path}: {snippet}" if snippet else path)
            else:
                # ContextFile pydantic model or similar
                file_strs.append(getattr(f, "path", str(f)))
        lines.append(f"CONTEXT FILES: {', '.join(file_strs)}")
    if task.get("acceptance_criteria"):
        lines.append(f"ACCEPTANCE CRITERIA: {task['acceptance_criteria']}")
    return "\n".join(lines)
