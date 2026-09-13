"""Tests for ReActDeveloperAgent parsing and shared formatting."""

from __future__ import annotations

from packages.agents.developer.executor import DeveloperAgent
from packages.agents.developer.formatting import format_task
from packages.agents.developer.tools import ReActDeveloperAgent


class TestFormatTask:
    def test_consistent(self):
        task = {
            "task_description": "fix sqli",
            "context_files": [{"path": "a.py", "snippet": "x"}],
            "acceptance_criteria": "pass",
        }
        assert DeveloperAgent._format_task(task) == format_task(task)
        assert ReActDeveloperAgent._format_task(task) == format_task(task)

    def test_empty(self):
        assert "TASK:" in format_task({})


class TestParseToolCall:
    def test_valid(self):
        text = 'Thought: x\nAction: read_file\nAction Input: {"path": "a.py"}'
        call = ReActDeveloperAgent._parse_tool_call(text)
        assert call is not None
        assert call.tool_name == "read_file"
        assert call.arguments == {"path": "a.py"}

    def test_none(self):
        assert ReActDeveloperAgent._parse_tool_call("no action here") is None

    def test_extract_patch(self):
        text = "Thought: done\nFinal Answer:\n--- a/x\n+++ b/x"
        assert "--- a/x" in ReActDeveloperAgent._extract_patch(text)
