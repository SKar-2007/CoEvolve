"""Hybrid Judge Engine.

Implements the dual-condition evaluation from blueprint.md §3.1:

    J = 1  iff  SAST(C_k, v_k) matches  AND  DynamicReplay(C_k, v_k) succeeds
    J = 0  otherwise
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .dast.executor import ExploitExecutor
from .sast.scanner import SASTResult, SemgrepScanner


@dataclass
class JudgeVerdict:
    j: int  # 0 = secure, 1 = exploitable
    episode_k: int | None = None
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    structure: str = ""  # short description of the evaluated artifact
    sast: SASTResult = field(default_factory=SASTResult)
    dast: dict = field(default_factory=dict)
    error: str = ""

    @property
    def exploitable(self) -> bool:
        return self.j == 1

    def as_dict(self) -> dict:
        return {
            "j": self.j,
            "trace_id": self.trace_id,
            "episode_k": self.episode_k,
            "structure": self.structure,
            "sast": self.sast.as_dict(),
            "dast": self.dast,
            "error": self.error,
        }


class HybridJudge:
    """Evaluates a developer patch for a confirmed exploitable vulnerability."""

    def __init__(
        self,
        scanner: SemgrepScanner | None = None,
        executor: ExploitExecutor | None = None,
    ):
        self.scanner = scanner or SemgrepScanner()
        self.executor = executor or ExploitExecutor()

    def evaluate(
        self,
        patch_text: str,
        vulnerability_class: str,
        episode_k: int | None = None,
        workspace_dir: Path | None = None,
    ) -> JudgeVerdict:
        """Run both stages and return the verdict.

        Stage 1 (SAST): semantic pattern matching on the patch.
        Stage 2 (DAST): dynamic payload replay against the sandboxed app.
        """
        verdict = JudgeVerdict(j=0, episode_k=episode_k, structure=patch_text[:200])

        # Stage 1: static analysis
        if workspace_dir and workspace_dir.exists():
            sast = self.scanner.scan_directory(workspace_dir)
        else:
            sast = self.scanner.scan_patch(patch_text)

        verdict.sast = sast
        if not sast.matched:
            verdict.structure = f"{verdict.structure} [SAST clean]"
            return verdict

        # Stage 2: dynamic verification — confirms exploitability, kills FPs
        try:
            dast = self.executor.execute(class_id=vulnerability_class)
            verdict.dast = dast.as_dict()
            if dast.success:
                verdict.j = 1
                verdict.structure = f"{verdict.structure} [exploitable]"
            else:
                verdict.structure = f"{verdict.structure} [SAST hit but not exploitable]"
        except Exception as exc:  # dynamic replay failure
            verdict.error = f"dynamic replay failed: {exc}"
            verdict.structure = f"{verdict.structure} [dynamic equivocal]"

        return verdict
