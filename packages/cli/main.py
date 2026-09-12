"""CoEvolve CLI — main entry point with rich output."""

from __future__ import annotations

import json
import sys
import time
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.columns import Columns

console = Console()

# Agent colors
AGENT_COLORS = {
    "attacker": "red",
    "developer": "yellow",
    "judge": "blue",
    "distiller": "green",
}


def print_banner():
    """Print the CoEvolve banner."""
    banner = Text()
    banner.append("  ╔══════════════════════════════════════╗\n", style="bold white")
    banner.append("  ║", style="bold white")
    banner.append("  CO", style="bold red")
    banner.append("EVOLVE", style="bold yellow")
    banner.append("  ║", style="bold white")
    banner.append("  ║  Adversarial Training as a Service  ║\n", style="bold white")
    banner.append("  ╚══════════════════════════════════════╝", style="bold white")
    console.print(banner)


def print_agent_step(agent: str, status: str, message: str, done: bool = False, error: bool = False):
    """Print an agent step with colored output."""
    color = AGENT_COLORS.get(agent, "white")
    icon = "✓" if done else ("✗" if error else "●")
    style = f"bold {color}" if done else (f"bold red" if error else f"dim {color}")

    prefix = Text(f"  {icon} ", style=style)
    name = Text(f"{agent.upper():12s}", style=f"bold {color}")
    msg = Text(message, style="white" if not error else "red")
    console.print(prefix + name + msg)


def print_elo_update(before: dict, after: dict):
    """Print Elo rating changes."""
    atk_before = before.get("attacker", 1500)
    atk_after = after.get("attacker", atk_before)
    dev_before = before.get("developer", 1500)
    dev_after = after.get("developer", dev_before)

    atk_delta = atk_after - atk_before
    dev_delta = dev_after - dev_before

    atk_style = "red" if atk_delta < 0 else "green"
    dev_style = "green" if dev_delta > 0 else "red"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_column()
    table.add_column()

    table.add_row(
        "  ELO",
        Text(f"Attacker  {atk_before:.0f}", style="red"),
        Text(f"→  {atk_after:.0f}", style=atk_style),
        Text(f"({atk_delta:+.0f})", style=atk_style),
    )
    table.add_row(
        "",
        Text(f"Developer {dev_before:.0f}", style="yellow"),
        Text(f"→  {dev_after:.0f}", style=dev_style),
        Text(f"({dev_delta:+.0f})", style=dev_style),
    )
    console.print(table)


def print_summary(trace, vuln: str, lang: str):
    """Print final episode summary."""
    outcome = "VULNERABLE" if trace.judge_outcome == 1 else "SECURE"
    outcome_style = "bold red" if trace.judge_outcome == 1 else "bold green"
    status = "completed" if not trace.error else "failed"
    status_style = "bold green" if status == "completed" else "bold red"

    table = Table(title="Episode Summary", show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold dim", width=16)
    table.add_column()

    table.add_row("Episode", Text(trace.episode_id, style="bold"))
    table.add_row("Status", Text(status, style=status_style))
    table.add_row("Vuln Class", Text(vuln, style="bold"))
    table.add_row("Language", Text(lang, style="bold"))
    table.add_row("Difficulty", Text(f"Tier {trace.difficulty_tier}", style="bold"))
    table.add_row("Outcome", Text(outcome, style=outcome_style))
    table.add_row("Rule Distilled", Text("YES" if trace.distilled_rule and trace.regression_passed else "NO", style="bold"))

    if trace.error:
        table.add_row("Error", Text(str(trace.error)[:80], style="red"))

    table.add_row("Duration", Text(f"{trace.duration_s:.2f}s", style="bold"))

    console.print()
    console.print(Panel(table, border_style="blue", title="[bold blue]RESULT[/bold blue]"))


@click.group()
@click.version_option(package_name="coevolve-cli")
def cli() -> None:
    """CoEvolve CLI — Adversarial Training as a Service."""
    pass


# ---------------------------------------------------------------------------
# RUN command
# ---------------------------------------------------------------------------
@cli.command()
@click.option("--vuln", "-v", default="SQLi", help="Vulnerability class")
@click.option("--lang", "-l", default="python", help="Language (python/javascript/java)")
@click.option("--hint", "-h", default="", help="Context hint")
@click.option("--retries", "-r", default=3, help="Max retries")
@click.option("--react/--no-react", default=True, help="Use ReAct agent")
@click.option("--mock/--no-mock", default=False, help="Use mock LLM (no API key needed)")
@click.option("--json/--no-json", "output_json", default=False, help="Output raw JSON instead of rich display")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def run(
    vuln: str,
    lang: str,
    hint: str,
    retries: int,
    react: bool,
    mock: bool,
    output_json: bool,
    db: str,
) -> None:
    """Run one training episode."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop
    from ..api.config import get_settings
    from ..api.models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord

    if not output_json:
        print_banner()
        console.print()

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        elo_record = sess.get(EloRecord, "global")
        current_ratings = (
            (elo_record.attacker_rating, elo_record.developer_rating)
            if elo_record
            else (1500.0, 1500.0)
        )

        latest_prompt = sess.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
        prompt_version = latest_prompt.version if latest_prompt else 0

        # Build LLM
        if mock:
            llm = build_client("mock", "mock")
        else:
            settings = get_settings()
            if settings.anthropic_api_key:
                provider, key = "anthropic", settings.anthropic_api_key
            elif settings.groq_api_key:
                provider, key = "groq", settings.groq_api_key
            elif settings.huggingface_api_key:
                provider, key = "huggingface", settings.huggingface_api_key
            elif settings.openrouter_api_key:
                provider, key = "openrouter", settings.openrouter_api_key
            elif settings.openai_api_key:
                provider, key = "openai", settings.openai_api_key
            else:
                provider, key = "mock", None
            llm = build_client(provider, settings.llm_model, api_key=key)

        if not output_json:
            # Print config panel
            config_table = Table(show_header=False, box=None, padding=(0, 2))
            config_table.add_column(style="bold dim", width=14)
            config_table.add_column()
            config_table.add_row("Vulnerability", Text(vuln, style="bold"))
            config_table.add_row("Language", Text(lang, style="bold"))
            config_table.add_row("ReAct", Text("ON" if react else "OFF", style="bold"))
            config_table.add_row("Mock", Text("ON" if mock else "OFF", style="bold"))
            config_table.add_row("Provider", Text(type(llm).__name__, style="bold"))
            console.print(Panel(config_table, border_style="dim", title="[bold]CONFIG[/bold]"))
            console.print()

        # Run episode with progress display
        loop = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=react)
        config = EpisodeConfig(
            vulnerability_class=vuln,
            language=lang,
            context_hint=hint,
            max_retries=retries,
        )

        if not output_json:
            console.print("[bold white]  RUNNING EPISODE...[/bold white]")
            console.print()
            time.sleep(0.3)
            print_agent_step("attacker", "working", "Generating adversarial task...")
            time.sleep(0.2)

        trace = loop.run_episode(config, current_ratings=current_ratings)

        if not output_json:
            print_agent_step("attacker", "done", f"Task generated ({trace.difficulty_tier}/10)", done=True)
            time.sleep(0.1)
            print_agent_step("developer", "working", "Reading code & building patch...")
            time.sleep(0.1)
            print_agent_step("developer", "done", "Patch built", done=True)
            time.sleep(0.1)

            outcome_text = "VULNERABLE" if trace.judge_outcome == 1 else "SECURE"
            print_agent_step("judge", "working", "Running SAST + DAST verification...")
            time.sleep(0.1)
            print_agent_step("judge", "done", f"Outcome: {outcome_text}", done=trace.judge_outcome == 0, error=trace.judge_outcome == 1)
            time.sleep(0.1)

            if trace.distilled_rule and trace.regression_passed:
                print_agent_step("distiller", "working", "Distilling new security rule...")
                time.sleep(0.1)
                rule_preview = trace.distilled_rule.rule_text[:60] + "..."
                print_agent_step("distiller", "done", f"Rule: {rule_preview}", done=True)
            else:
                print_agent_step("distiller", "skip", "No rule to distill")

            console.print()
            print_elo_update(trace.elo_before, trace.elo_after)

        # Persist
        ep = EpisodeRecord(
            id=trace.episode_id,
            status="completed" if not trace.error else "failed",
            vulnerability_class=vuln,
            difficulty_tier=trace.difficulty_tier,
            outcome=trace.judge_outcome,
            task_description=trace.task.task_description if trace.task else "",
            patch_text=trace.patch_text,
            judge_verdict=trace.judge_verdict,
            attacker_rating=trace.elo_after.get("attacker", current_ratings[0]),
            developer_rating=trace.elo_after.get("developer", current_ratings[1]),
            prompt_version=trace.prompt_version,
            error=trace.error or None,
        )
        sess.add(ep)

        if elo_record:
            elo_record.attacker_rating = trace.elo_after.get("attacker", elo_record.attacker_rating)
            elo_record.developer_rating = trace.elo_after.get("developer", elo_record.developer_rating)
            elo_record.episodes_played += 1
        else:
            sess.add(EloRecord(
                id="global",
                attacker_rating=trace.elo_after.get("attacker", 1500.0),
                developer_rating=trace.elo_after.get("developer", 1500.0),
                episodes_played=1,
            ))

        if trace.distilled_rule and trace.regression_passed:
            rule = trace.distilled_rule
            sess.add(RuleRecord(
                rule_text=rule.rule_text,
                vulnerability_class=rule.vulnerability_class,
                source_pattern=rule.source_pattern,
                recommended_fix=rule.recommended_fix,
                source_trace_id=rule.source_trace_id,
                prompt_version=trace.prompt_version,
                approved=True,
            ))

        sess.commit()

        if output_json:
            # JSON mode: output raw JSON
            result = {
                "episode_id": trace.episode_id,
                "status": "completed" if not trace.error else "failed",
                "vulnerability_class": vuln,
                "language": lang,
                "difficulty_tier": trace.difficulty_tier,
                "judge_outcome": trace.judge_outcome,
                "judge_outcome_text": "VULNERABLE" if trace.judge_outcome == 1 else "SECURE",
                "rule_distilled": trace.distilled_rule is not None and trace.regression_passed,
                "rule_text": trace.distilled_rule.rule_text if trace.distilled_rule else None,
                "regression_passed": trace.regression_passed,
                "elo_before": trace.elo_before,
                "elo_after": trace.elo_after,
                "duration_s": trace.duration_s,
                "error": trace.error,
            }
            click.echo(json.dumps(result, indent=2))
        else:
            print_summary(trace, vuln, lang)


# ---------------------------------------------------------------------------
# QUERY command
# ---------------------------------------------------------------------------
@cli.group()
def query() -> None:
    """Query CoEvolve data."""
    pass


@query.command("episodes")
@click.option("--limit", "-n", default=10, help="Number of episodes")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--json/--no-json", "output_json", default=False, help="Output raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_episodes(limit: int, vuln: Optional[str], output_json: bool, db: str) -> None:
    """List recent episodes."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import EpisodeRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        q = sess.query(EpisodeRecord).order_by(EpisodeRecord.created_at.desc())
        if vuln:
            q = q.filter(EpisodeRecord.vulnerability_class == vuln)
        episodes = q.limit(limit).all()

    if output_json:
        result = [
            {
                "id": ep.id,
                "status": ep.status,
                "vulnerability_class": ep.vulnerability_class,
                "difficulty_tier": ep.difficulty_tier,
                "outcome": ep.outcome,
                "outcome_text": "VULNERABLE" if ep.outcome == 1 else "SECURE",
                "attacker_rating": ep.attacker_rating,
                "developer_rating": ep.developer_rating,
                "error": ep.error,
                "created_at": str(ep.created_at) if ep.created_at else None,
            }
            for ep in episodes
        ]
        click.echo(json.dumps(result, indent=2))
    else:
        if not episodes:
            console.print("[dim]  No episodes found.[/dim]")
            return

        table = Table(title=f"Recent Episodes ({len(episodes)})", box=None, show_header=True, header_style="bold dim")
        table.add_column("#", style="dim", width=4)
        table.add_column("ID", style="bold", width=14)
        table.add_column("Vuln", style="red")
        table.add_column("Lang", style="yellow")
        table.add_column("Outcome", justify="center")
        table.add_column("ATK", justify="right", style="red")
        table.add_column("DEV", justify="right", style="yellow")

        for i, ep in enumerate(episodes, 1):
            outcome = Text("VULN", style="bold red") if ep.outcome == 1 else Text("SAFE", style="bold green")
            table.add_row(
                str(i),
                ep.id,
                ep.vulnerability_class,
                ep.difficulty_tier and f"T{ep.difficulty_tier}" or "?",
                outcome,
                f"{ep.attacker_rating:.0f}",
                f"{ep.developer_rating:.0f}",
            )
        console.print(table)


@query.command("rules")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--json/--no-json", "output_json", default=False, help="Output raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_rules(vuln: Optional[str], output_json: bool, db: str) -> None:
    """List distilled security rules."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        q = sess.query(RuleRecord).order_by(RuleRecord.created_at.desc())
        if vuln:
            q = q.filter(RuleRecord.vulnerability_class == vuln)
        rules = q.all()

    if output_json:
        result = [
            {
                "id": rule.id,
                "rule_text": rule.rule_text,
                "vulnerability_class": rule.vulnerability_class,
                "source_pattern": rule.source_pattern,
                "recommended_fix": rule.recommended_fix,
                "approved": rule.approved,
                "created_at": str(rule.created_at) if rule.created_at else None,
            }
            for rule in rules
        ]
        click.echo(json.dumps(result, indent=2))
    else:
        if not rules:
            console.print("[dim]  No rules distilled yet.[/dim]")
            return

        for i, rule in enumerate(rules, 1):
            console.print(f"  [bold green]{i}.[/bold green] [bold]{rule.vulnerability_class}[/bold] — {rule.rule_text[:80]}")
            console.print(f"     [dim]{rule.source_pattern[:60]}...[/dim]")
            console.print()


@query.command("elo")
@click.option("--json/--no-json", "output_json", default=False, help="Output raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_elo(output_json: bool, db: str) -> None:
    """Show current Elo ratings."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import EloRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        elo = sess.get(EloRecord, "global")

    atk = elo.attacker_rating if elo else 1500.0
    dev = elo.developer_rating if elo else 1500.0
    eps = elo.episodes_played if elo else 0

    if output_json:
        click.echo(json.dumps({
            "attacker_rating": atk,
            "developer_rating": dev,
            "episodes_played": eps,
        }, indent=2))
    else:
        table = Table(title="Elo Ratings", box=None, show_header=False, padding=(0, 3))
        table.add_column(style="bold", width=12)
        table.add_column()
        table.add_column()

        # Bar visualization
        max_bar = 30
        total = atk + dev
        atk_bar = int((atk / total) * max_bar) if total > 0 else max_bar // 2
        dev_bar = max_bar - atk_bar

        table.add_row("Attacker", Text(f"{atk:.0f}", style="bold red"), Text("█" * atk_bar, style="red"))
        table.add_row("Developer", Text(f"{dev:.0f}", style="bold yellow"), Text("█" * dev_bar, style="yellow"))
        table.add_row("Episodes", Text(str(eps), style="bold"), Text(""))
        console.print(Panel(table, border_style="blue"))


# ---------------------------------------------------------------------------
# EXPORT-RULES command
# ---------------------------------------------------------------------------
@cli.command("export-rules")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def export_rules(vuln: Optional[str], output: Optional[str], db: str) -> None:
    """Export rules as JSON package."""
    import time
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        q = sess.query(RuleRecord).filter(RuleRecord.approved == True)
        if vuln:
            q = q.filter(RuleRecord.vulnerability_class == vuln)
        rules = q.all()

    package = {
        "version": "1.0.0",
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_rules": len(rules),
        "rules": [
            {
                "rule_text": rule.rule_text,
                "vulnerability_class": rule.vulnerability_class,
                "source_pattern": rule.source_pattern,
                "recommended_fix": rule.recommended_fix,
            }
            for rule in rules
        ],
    }

    json_str = json.dumps(package, indent=2)
    if output:
        with open(output, "w") as f:
            f.write(json_str)
        console.print(f"[bold green]✓[/bold green] Exported {len(rules)} rules to {output}")
    else:
        click.echo(json_str)


# ---------------------------------------------------------------------------
# STATUS command
# ---------------------------------------------------------------------------
@cli.command()
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def status(db: str) -> None:
    """Show system status."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import EpisodeRecord, EloRecord, RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        episode_count = sess.query(EpisodeRecord).count()
        rule_count = sess.query(RuleRecord).count()
        elo = sess.get(EloRecord, "global")

    atk = elo.attacker_rating if elo else 1500.0
    dev = elo.developer_rating if elo else 1500.0
    eps = elo.episodes_played if elo else 0

    table = Table(title="System Status", box=None, show_header=False, padding=(0, 3))
    table.add_column(style="bold dim", width=16)
    table.add_column()
    table.add_row("Episodes", Text(str(episode_count), style="bold"))
    table.add_row("Rules", Text(str(rule_count), style="bold"))
    table.add_row("Attacker Elo", Text(f"{atk:.0f}", style="bold red"))
    table.add_row("Developer Elo", Text(f"{dev:.0f}", style="bold yellow"))
    table.add_row("Total Games", Text(str(eps), style="bold"))
    console.print(Panel(table, border_style="blue"))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
