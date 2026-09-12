"""Developer Agent with ReAct tool-use framework.

Implements a multi-step agent that can read files, write code, run tests,
and interact with the codebase via a tool-use loop inside a sandboxed container.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..llm import LLMClient, ModelConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


class Tool(Protocol):
    """Protocol for a tool the developer agent can invoke."""

    name: str
    description: str

    def execute(self, **kwargs: Any) -> str: ...


@dataclass
class ToolResult:
    """Result of a single tool invocation."""

    tool_name: str
    output: str
    success: bool = True
    error: str = ""


@dataclass
class ToolCall:
    """A parsed tool call from the LLM response."""

    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""


# ---------------------------------------------------------------------------
# Built-in tools
# ---------------------------------------------------------------------------


class ReadFileTool:
    """Read a file from the workspace."""

    name = "read_file"
    description = "Read the contents of a file. Args: path (str)"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def execute(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "")
        if not path:
            return "ERROR: path is required"
        target = self.workspace / path
        if not target.exists():
            return f"ERROR: file not found: {path}"
        try:
            content = target.read_text(errors="replace")
            return f"--- {path} ---\n{content}"
        except Exception as exc:
            return f"ERROR reading {path}: {exc}"


class WriteFileTool:
    """Write content to a file in the workspace."""

    name = "write_file"
    description = "Write content to a file. Args: path (str), content (str)"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def execute(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "")
        content = kwargs.get("content", "")
        if not path:
            return "ERROR: path is required"
        target = self.workspace / path
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            return f"Wrote {len(content)} bytes to {path}"
        except Exception as exc:
            return f"ERROR writing {path}: {exc}"


class RunShellTool:
    """Run a shell command in the workspace (sandboxed)."""

    name = "run_shell"
    description = "Run a shell command. Args: command (str), timeout (int, optional, default 30)"

    BLOCKED = frozenset({"rm -rf /", "mkfs", "dd if=", "> /dev/sda"})

    def __init__(self, workspace: Path, timeout: int = 30) -> None:
        self.workspace = workspace
        self.timeout = timeout

    def execute(self, **kwargs: Any) -> str:
        command = kwargs.get("command", "")
        if not command:
            return "ERROR: command is required"
        if any(b in command for b in self.BLOCKED):
            return f"ERROR: blocked dangerous command: {command}"
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=min(kwargs.get("timeout", self.timeout), 60),
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]\n{result.stderr}"
            if result.returncode != 0:
                output += f"\n[exit code: {result.returncode}]"
            return output or "(no output)"
        except subprocess.TimeoutExpired:
            return f"ERROR: command timed out after {self.timeout}s"
        except Exception as exc:
            return f"ERROR: {exc}"


class SearchCodeTool:
    """Search for patterns in the workspace codebase."""

    name = "search_code"
    description = "Search for a regex pattern in files. Args: pattern (str), include (str, optional file glob)"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def execute(self, **kwargs: Any) -> str:
        pattern = kwargs.get("pattern", "")
        include = kwargs.get("include", "*.py")
        if not pattern:
            return "ERROR: pattern is required"
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        matches: list[str] = []
        for path in self.workspace.rglob(include):
            if ".venv" in path.parts or "__pycache__" in path.parts:
                continue
            try:
                for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                    if regex.search(line):
                        rel = path.relative_to(self.workspace)
                        matches.append(f"{rel}:{i}: {line.strip()}")
            except Exception:
                continue
            if len(matches) >= 50:
                matches.append("... (truncated at 50 matches)")
                break
        return "\n".join(matches) if matches else "No matches found"


class RunTestsTool:
    """Run pytest in the workspace."""

    name = "run_tests"
    description = "Run pytest. Args: path (str, optional, default 'tests')"

    def __init__(self, workspace: Path, timeout: int = 60) -> None:
        self.workspace = workspace
        self.timeout = timeout

    def execute(self, **kwargs: Any) -> str:
        test_path = kwargs.get("path", "tests")
        cmd = f"python -m pytest {test_path} -x -q --tb=short 2>&1"
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            output = result.stdout
            if result.returncode == 0:
                return f"PASSED\n{output}"
            return f"FAILED (exit {result.returncode})\n{output}"
        except subprocess.TimeoutExpired:
            return f"ERROR: tests timed out after {self.timeout}s"
        except Exception as exc:
            return f"ERROR: {exc}"


class GitDiffTool:
    """Show git diff in the workspace."""

    name = "git_diff"
    description = "Show the current git diff. No args."

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def execute(self, **kwargs: Any) -> str:
        try:
            result = subprocess.run(
                "git diff",
                shell=True,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout or "(no changes)"
        except Exception as exc:
            return f"ERROR: {exc}"


class GitCommitTool:
    """Create a git commit in the workspace."""

    name = "git_commit"
    description = "Stage all changes and commit. Args: message (str)"

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def execute(self, **kwargs: Any) -> str:
        message = kwargs.get("message", "auto-commit")
        try:
            subprocess.run(
                "git add -A", shell=True, cwd=str(self.workspace), check=True, timeout=10
            )
            result = subprocess.run(
                f"git commit -m {json.dumps(message)}",
                shell=True,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout or "Committed (no output)"
        except Exception as exc:
            return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


def build_default_tools(workspace: Path) -> dict[str, Any]:
    """Return the default set of tools for the developer agent."""
    return {
        "read_file": ReadFileTool(workspace),
        "write_file": WriteFileTool(workspace),
        "run_shell": RunShellTool(workspace),
        "search_code": SearchCodeTool(workspace),
        "run_tests": RunTestsTool(workspace),
        "git_diff": GitDiffTool(workspace),
        "git_commit": GitCommitTool(workspace),
    }


# ---------------------------------------------------------------------------
# ReAct Developer Agent
# ---------------------------------------------------------------------------

TOOL_USE_SYSTEM_PROMPT = """\
You are an expert software engineer with access to tools for interacting with a codebase.

You operate in a ReAct loop: think step-by-step, use tools to explore and modify code,
then verify your changes.

AVAILABLE TOOLS (call via JSON):
{tool_descriptions}

RESPONSE FORMAT — use EXACTLY this structure for each step:

Thought: <your reasoning about what to do next>
Action: <tool_name>
Action Input: {{"arg1": "value1", ...}}

After all steps, respond with your final patch as a unified diff:

Final Answer:
--- a/file.py
+++ b/file.py
@@ -1,5 +1,5 @@
 ... unified diff lines ...

IMPORTANT:
- Always read relevant files before making changes.
- Run tests after making changes to verify correctness.
- Keep changes minimal and focused on the task.
- Follow existing code conventions.
- Never expose secrets or hardcode credentials.
"""

FINAL_ANSWER_MARKER = "Final Answer:"


class ReActDeveloperAgent:
    """Developer agent with tool-use capabilities.

    Executes engineering tasks by iteratively reading code, making changes,
    and verifying correctness through a ReAct (Reason + Act) loop.
    """

    MAX_STEPS = 12

    def __init__(
        self,
        client: LLMClient,
        base_prompt: str | None = None,
        config: ModelConfig | None = None,
        tools: dict[str, Any] | None = None,
        workspace: Path | None = None,
        max_steps: int = 12,
    ) -> None:
        self.client = client
        self.base_prompt = base_prompt or TOOL_USE_SYSTEM_PROMPT
        self.temperature = (config or ModelConfig()).temperature
        self.workspace = workspace or Path("/tmp/coevolve_workspace")
        self.tools = tools or build_default_tools(self.workspace)
        self.max_steps = max_steps

    def build_system_prompt(self, rules: list[str] | None = None) -> str:
        """Compose the system prompt with tool descriptions and evolved rules."""
        tool_descs = "\n".join(f"- {name}: {tool.description}" for name, tool in self.tools.items())
        prompt = self.base_prompt.format(tool_descriptions=tool_descs)
        if rules:
            prompt += "\n\nEVOLVED SECURITY RULES (must be followed):\n"
            prompt += "\n".join(f"- {r}" for r in rules)
        return prompt

    def execute(self, task: dict[str, Any], rules: list[str] | None = None) -> str:
        """Run the ReAct loop and return the final patch text."""
        system = self.build_system_prompt(rules)
        user = self._format_task(task)

        messages: list[dict[str, str]] = [{"role": "user", "content": user}]
        tool_calls_made: list[ToolCall] = []

        for _step in range(self.max_steps):
            response = self.client.generate(
                system=system,
                user=json.dumps(messages),
                temperature=self.temperature,
            )
            text = response.text

            # Check for final answer
            if FINAL_ANSWER_MARKER in text:
                return self._extract_patch(text)

            # Parse tool call
            tool_call = self._parse_tool_call(text)
            if tool_call is None:
                # LLM didn't produce a valid tool call — treat as final answer
                return self._extract_patch(text)

            # Execute tool
            result = self._execute_tool(tool_call)
            tool_calls_made.append(tool_call)

            # Feed result back
            messages.append({"role": "assistant", "content": text})
            messages.append(
                {
                    "role": "user",
                    "content": f"Tool Result ({tool_call.tool_name}):\n{result.output}",
                }
            )

        # Exhausted max steps — return best effort
        logger.warning("Developer agent exhausted %d steps", self.max_steps)
        return ""

    def _execute_tool(self, call: ToolCall) -> ToolResult:
        """Execute a single tool call."""
        tool = self.tools.get(call.tool_name)
        if tool is None:
            return ToolResult(
                tool_name=call.tool_name,
                output=f"ERROR: unknown tool '{call.tool_name}'",
                success=False,
                error=f"unknown tool: {call.tool_name}",
            )
        try:
            output = tool.execute(**call.arguments)
            return ToolResult(tool_name=call.tool_name, output=output)
        except Exception as exc:
            return ToolResult(
                tool_name=call.tool_name,
                output=f"ERROR: {exc}",
                success=False,
                error=str(exc),
            )

    @staticmethod
    def _parse_tool_call(text: str) -> ToolCall | None:
        """Extract a tool call from the LLM response."""
        action_match = re.search(r"Action:\s*(\w+)", text)
        input_match = re.search(r"Action Input:\s*(\{.*?\})", text, re.DOTALL)
        if not action_match:
            return None
        tool_name = action_match.group(1)
        arguments: dict[str, Any] = {}
        if input_match:
            import contextlib

            with contextlib.suppress(json.JSONDecodeError):
                arguments = json.loads(input_match.group(1))
        return ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            call_id=uuid.uuid4().hex[:8],
        )

    @staticmethod
    def _extract_patch(text: str) -> str:
        """Extract the unified diff from the final answer."""
        if FINAL_ANSWER_MARKER in text:
            return text.split(FINAL_ANSWER_MARKER, 1)[1].strip()
        return text.strip()

    @staticmethod
    def _format_task(task: dict[str, Any]) -> str:
        """Format a task dict into a user prompt."""
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
                    file_strs.append(getattr(f, "path", str(f)))
            lines.append(f"CONTEXT FILES: {', '.join(file_strs)}")
        if task.get("acceptance_criteria"):
            lines.append(f"ACCEPTANCE CRITERIA: {task['acceptance_criteria']}")
        return "\n".join(lines)
