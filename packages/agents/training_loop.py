"""Training Loop Controller — the co-evolutionary orchestrator.

Wires Attacker -> Developer -> Judge -> Distiller -> RegressionGuard -> Elo -> PromptStore
into a single episode loop.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .attacker.generator import AttackerAgent, GeneratedTask
from .developer.executor import DeveloperAgent
from .developer.tools import ReActDeveloperAgent
from .distiller.pipeline import DistilledRule, DistillerAgent
from .llm import LLMClient, LLMResponse
from .regression_guard.guard import HistoricalArchive, RegressionGuard

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step reporter protocol — pluggable UI for agent progress
# ---------------------------------------------------------------------------


class StepReporter(Protocol):
    """Protocol for receiving step-by-step agent progress notifications."""

    def on_step_start(self, agent: str, description: str) -> None: ...
    def on_step_end(self, agent: str, description: str, duration_s: float) -> None: ...
    def on_llm_call(self, agent: str, system: str, user: str, response: LLMResponse) -> None: ...
    def on_sast_result(self, matched: bool, findings: list[str]) -> None: ...
    def on_dast_result(self, success: bool, details: str) -> None: ...
    def on_elo_update(self, attacker_before: float, developer_before: float, attacker_after: float, developer_after: float) -> None: ...
    def on_rule_distilled(self, rule_text: str, accepted: bool) -> None: ...
    def on_regressions(self, tested: int, regressed: int) -> None: ...
    def on_error(self, agent: str, error: str) -> None: ...
    def on_episode_start(self, episode_id: str, config: Any) -> None: ...
    def on_episode_end(self, trace: Any) -> None: ...

# Lazy telemetry import — graceful if prometheus_client not installed
_telemetry_available = False
try:
    from ..telemetry.exporters.metrics import (
        record_episode,
        set_rule_count,
        update_elo,
    )

    _telemetry_available = True
except ImportError:  # pragma: no cover
    pass


def _safe_record_episode(
    outcome: int, vuln_class: str | None = None, duration_s: float = 0
) -> None:
    if _telemetry_available:
        record_episode(outcome, vuln_class, duration_s)  # type: ignore[misc]


def _safe_update_elo(attacker: float, developer: float) -> None:
    if _telemetry_available:
        update_elo(attacker, developer)  # type: ignore[misc]


def _safe_set_rule_count(count: int) -> None:
    if _telemetry_available:
        set_rule_count(count)  # type: ignore[misc]


@dataclass
class EpisodeConfig:
    """Configuration for a single co-evolutionary episode."""

    vulnerability_class: str = "SQLi"
    language: str = "python"
    context_hint: str = ""
    max_retries: int = 3


@dataclass
class EpisodeTrace:
    """Full trace of a single episode — all intermediate artifacts."""

    episode_id: str
    task: GeneratedTask | None = None
    patch_text: str = ""
    judge_outcome: int = 0  # 0=secure, 1=exploitable
    judge_verdict: dict[str, Any] = field(default_factory=dict)
    distilled_rule: DistilledRule | None = None
    regression_passed: bool = True
    elo_before: dict[str, float] = field(default_factory=dict)
    elo_after: dict[str, float] = field(default_factory=dict)
    difficulty_tier: int = 1
    prompt_version: int = 0
    duration_s: float = 0.0
    error: str = ""


class TrainingLoop:
    """Orchestrates the full co-evolutionary training cycle.

    Each call to ``run_episode`` executes one round of:
        Attacker -> Developer -> Judge -> Elo Update -> (Distiller -> RegressionGuard)
    """

    def __init__(
        self,
        llm: LLMClient,
        *,
        judge: Any = None,
        elo_calculator: Any = None,
        prompt_store: Any = None,
        archive: HistoricalArchive | None = None,
        prompt_version: int = 0,
        use_react: bool = False,
        workspace_dir: str | Path = "/tmp/coevolve_workspace",
        reporter: StepReporter | None = None,
    ) -> None:
        self.llm = llm
        self.reporter = reporter

        # Wrap LLM with reporting callback if a reporter is provided
        if reporter is not None:
            from .llm import ReportingLLMClient
            reporting_llm = ReportingLLMClient(llm, callback=self._make_llm_callback())
            self.attacker = AttackerAgent(reporting_llm)
        else:
            self.attacker = AttackerAgent(llm)

        if use_react:
            workspace = Path(workspace_dir)
            workspace.mkdir(parents=True, exist_ok=True)
            if reporter is not None:
                self.developer: Any = ReActDeveloperAgent(reporting_llm, workspace=workspace)
            else:
                self.developer = ReActDeveloperAgent(llm, workspace=workspace)
            logger.info("Using ReAct Developer Agent (tool-use enabled)")
        else:
            if reporter is not None:
                self.developer = DeveloperAgent(reporting_llm)
            else:
                self.developer = DeveloperAgent(llm)

        if reporter is not None:
            self.distiller = DistillerAgent(reporting_llm)
        else:
            self.distiller = DistillerAgent(llm)

        # Pluggable dependencies — import lazily to avoid circular imports
        if judge is not None:
            self.judge = judge
        else:
            from ..judge.engine import HybridJudge

            self.judge = HybridJudge()

        if elo_calculator is not None:
            self.elo = elo_calculator
        else:
            from ..elo.calculator import EloCalculator

            self.elo = EloCalculator()

        if prompt_store is not None:
            self.prompt_store = prompt_store
        else:
            from ..evolution.store import PromptStore

            self.prompt_store = PromptStore()

        self.archive = archive or HistoricalArchive()
        self.prompt_version = prompt_version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _notify(self, method: str, *args: Any, **kwargs: Any) -> None:
        """Call a reporter method if the reporter exists."""
        if self.reporter is not None:
            getattr(self.reporter, method)(*args, **kwargs)

    def _make_llm_callback(self) -> Any:
        """Create a callback that notifies the reporter of LLM calls."""
        reporter = self.reporter

        def _callback(system: str, user: str, response: Any) -> None:
            # Infer agent from the system prompt content
            agent = "developer"
            lower = system.lower()
            if "red-team" in lower or "attacker" in lower:
                agent = "attacker"
            elif "failure trace" in lower or "distill" in lower:
                agent = "distiller"
            reporter.on_llm_call(agent, system, user, response)

        return _callback

    def run_episode(
        self,
        config: EpisodeConfig,
        *,
        current_ratings: tuple[float, float] = (1500.0, 1500.0),
        workspace_dir: str = "/tmp/coevolve_workspace",
    ) -> EpisodeTrace:
        """Execute one full co-evolutionary episode.

        Returns an ``EpisodeTrace`` with all intermediate artifacts.
        """
        t0 = time.time()
        episode_id = uuid.uuid4().hex[:12]
        trace = EpisodeTrace(episode_id=episode_id)

        self._notify("on_episode_start", episode_id, config)

        try:
            # 0. Resolve difficulty tier from Elo ratings
            from ..elo.difficulty import mapping_for

            mapping = mapping_for(current_ratings[0], current_ratings[1])
            trace.difficulty_tier = mapping.tier
            trace.elo_before = {
                "attacker": current_ratings[0],
                "developer": current_ratings[1],
            }

            # 1. Attacker generates a task
            logger.info("[episode=%s] Attacker generating task (tier=%d)", episode_id, mapping.tier)
            self._notify("on_step_start", "attacker", f"generating adversarial task (tier {mapping.tier}/10)...")
            s = time.time()
            task = self.attacker.generate(
                vulnerability_class=config.vulnerability_class,
                difficulty_tier=mapping.tier,
                episode_k=self.prompt_version,
                context_hint=config.context_hint,
                language=config.language,
            )
            self._notify("on_step_end", "attacker", f"task generated — {task.task_description[:60]}", time.time() - s)
            trace.task = task

            # 2. Developer generates a patch
            logger.info("[episode=%s] Developer generating patch", episode_id)
            current_rules = self.prompt_store.rules()
            self._notify("on_step_start", "developer", f"reading code & building patch ({len(current_rules)} rules active)...")
            s = time.time()
            patch_text = self.developer.execute(
                task=task.as_dict(),
                rules=[r.rule_text for r in current_rules],
            )
            self._notify("on_step_end", "developer", f"patch built ({len(patch_text)} chars)", time.time() - s)
            trace.patch_text = patch_text

            # 3. Judge evaluates the patch (SAST + DAST)
            logger.info("[episode=%s] Judge evaluating patch", episode_id)
            self._notify("on_step_start", "judge", "running SAST + DAST verification...")
            s = time.time()
            workspace_path = Path(workspace_dir)
            verdict = self.judge.evaluate(
                patch_text=patch_text,
                vulnerability_class=config.vulnerability_class,
                episode_k=self.prompt_version,
                workspace_dir=workspace_path,
            )
            trace.judge_outcome = verdict.j
            trace.judge_verdict = verdict.as_dict()

            outcome_text = "VULNERABLE" if verdict.j == 1 else "SECURE"
            self._notify("on_step_end", "judge", f"outcome: {outcome_text}", time.time() - s)
            self._notify("on_sast_result", verdict.sast.matched, [f.message for f in verdict.sast.findings])

            # 4. Update Elo ratings
            new_ratings = self.elo.update_pair(
                attacker=current_ratings[0],
                developer=current_ratings[1],
                j=verdict.j,
            )
            trace.elo_after = {"attacker": new_ratings.attacker, "developer": new_ratings.developer}

            self._notify(
                "on_elo_update",
                current_ratings[0], current_ratings[1],
                new_ratings.attacker, new_ratings.developer,
            )

            # Emit telemetry for Elo update
            _safe_update_elo(new_ratings.attacker, new_ratings.developer)

            # 5. If exploitable (developer lost), distill a rule and check regression
            if verdict.j == 1:
                logger.info("[episode=%s] Vulnerability found — distilling rule", episode_id)
                self._notify("on_step_start", "distiller", "distilling failure into defensive rule...")
                s = time.time()
                rule = self.distiller.distill(
                    trace=verdict.as_dict(),
                    trace_id=verdict.trace_id,
                )
                trace.distilled_rule = rule
                self._notify("on_step_end", "distiller", f"rule: {rule.rule_text[:60]}...", time.time() - s)

                if rule.is_valid:
                    # Check regression before accepting
                    self._notify("on_step_start", "regression", "checking rule against historical tasks...")
                    s = time.time()
                    guard = RegressionGuard(
                        archive=self.archive,
                        evaluate=self._make_evaluator(config),
                        max_retries=config.max_retries,
                    )
                    approved, report = guard.approve(
                        rule=rule,
                        all_rules=[r.rule_text for r in self.prompt_store.rules()],
                    )
                    trace.regression_passed = approved
                    self._notify("on_regressions", report.get("tested", 0), report.get("regressions", 0))
                    self._notify("on_step_end", "regression", f"{'passed' if approved else 'failed'} ({report.get('tested', 0)} tasks)", time.time() - s)

                    if approved:
                        self.prompt_store.add_rule(rule)
                        self.prompt_version += 1
                        trace.prompt_version = self.prompt_version
                        _safe_set_rule_count(len(self.prompt_store.rules()))
                        self._notify("on_rule_distilled", rule.rule_text, True)
                        logger.info(
                            "[episode=%s] Rule accepted: %s", episode_id, rule.rule_text[:80]
                        )
                    else:
                        self._notify("on_rule_distilled", rule.rule_text, False)
                        logger.info("[episode=%s] Rule rejected (regression detected)", episode_id)
            else:
                self._notify("on_rule_distilled", "", False)
                logger.info("[episode=%s] Developer secure — no rule needed", episode_id)

            # Record task in archive for future regression checks
            self.archive.add(
                task=task.as_dict() if task else {},
                outcome=verdict.j,
                prompt_version=self.prompt_version,
            )

        except Exception as exc:
            trace.error = str(exc)
            self._notify("on_error", "loop", str(exc))
            logger.exception("[episode=%s] Episode failed: %s", episode_id, exc)

        trace.duration_s = time.time() - t0

        self._notify("on_episode_end", trace)

        # Emit telemetry for episode completion
        _safe_record_episode(
            outcome=trace.judge_outcome,
            vuln_class=config.vulnerability_class if trace.judge_outcome == 1 else None,
            duration_s=trace.duration_s,
        )

        return trace

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_evaluator(self, config: EpisodeConfig):
        """Return a callable that evaluates (task, rules) -> outcome for the RegressionGuard."""

        def evaluate(task: dict, rules: list[str]) -> int:
            # Minimal evaluation: re-run developer + judge on the same task
            try:
                patch = self.developer.execute(task=task, rules=rules)
                verdict = self.judge.evaluate(
                    patch_text=patch,
                    vulnerability_class=config.vulnerability_class,
                    episode_k=self.prompt_version,
                )
                return verdict.j
            except Exception:
                return 1  # assume vulnerable on error

        return evaluate
