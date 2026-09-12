"""CoEvolve CLI — clean, minimal terminal interface."""

from __future__ import annotations

import json
import sys
import time
from typing import Optional

import click
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

console = Console()

# ── Colors ──
C = {
    "red": "#E63946",
    "yellow": "#FFD166",
    "green": "#06D6A0",
    "blue": "#118AB2",
    "dim": "#6C757D",
    "white": "#F8F9FA",
    "bold": "#FFFFFF",
}


def banner():
    t = Text()
    t.append("  co", style="bold red")
    t.append("evolve", style="bold yellow")
    t.append("  │  Adversarial Training as a Service", style="dim")
    console.print(t)
    console.print()


def step(agent: str, msg: str, icon: str = "·", color: str = "dim"):
    """Print a single agent step — minimal, clean."""
    tag = Text(f"  {icon} ", style=color)
    name = Text(f"{agent:12s}", style=f"bold {color}")
    body = Text(msg, style="white")
    console.print(tag + name + body)


def header(title: str):
    console.print(f"\n[bold]{title}[/bold]")
    console.print("─" * 50)


def elo_bar(before: dict, after: dict):
    atk_b, atk_a = before.get("attacker", 1500), after.get("attacker", 1500)
    dev_b, dev_a = before.get("developer", 1500), after.get("developer", 1500)
    atk_d, dev_d = atk_a - atk_b, dev_a - dev_b

    def sign(v):
        return f"+{v:.0f}" if v >= 0 else f"{v:.0f}"

    def col(v):
        return "green" if v > 0 else ("red" if v < 0 else "dim")

    console.print()
    console.print(
        Text("    ATK  ", style="bold red")
        + Text(f"{atk_b:.0f}", style="red")
        + Text(" → ", style="dim")
        + Text(f"{atk_a:.0f}", style=f"bold {col(atk_d)}")
        + Text(f"  ({sign(atk_d)})", style=col(atk_d))
    )
    console.print(
        Text("    DEV  ", style="bold yellow")
        + Text(f"{dev_b:.0f}", style="yellow")
        + Text(" → ", style="dim")
        + Text(f"{dev_a:.0f}", style=f"bold {col(dev_d)}")
        + Text(f"  ({sign(dev_d)})", style=col(dev_d))
    )


def summary_box(trace, vuln: str, lang: str):
    outcome = "VULNERABLE" if trace.judge_outcome == 1 else "SECURE"
    o_color = "red" if trace.judge_outcome == 1 else "green"

    lines = [
        ("Episode", trace.episode_id, "bold"),
        ("Status", "completed" if not trace.error else "failed", "green" if not trace.error else "red"),
        ("Vuln", vuln, "bold"),
        ("Lang", lang, "bold"),
        ("Tier", str(trace.difficulty_tier), "bold"),
        ("Outcome", outcome, f"bold {o_color}"),
        ("Rule", "yes" if trace.distilled_rule and trace.regression_passed else "no", "bold"),
        ("Time", f"{trace.duration_s:.2f}s", "dim"),
    ]

    table = Table(show_header=False, box=None, padding=(0, 3), expand=False)
    table.add_column(style="bold dim", width=10)
    table.add_column()
    for label, val, style in lines:
        table.add_row(label, Text(val, style=style))

    console.print()
    console.print(Panel(table, border_style="dim", title="[bold]result[/bold]", title_align="left"))


@click.group()
@click.version_option(package_name="coevolve-cli")
def cli():
    """CoEvolve CLI — Adversarial Training as a Service."""
    pass


# ─── RUN ────────────────────────────────────────────────────────────
@cli.command()
@click.option("--vuln", "-v", default="SQLi", help="Vulnerability class")
@click.option("--lang", "-l", default="python", help="Language (python/javascript/java)")
@click.option("--hint", "-h", default="", help="Context hint")
@click.option("--retries", "-r", default=3, help="Max retries")
@click.option("--react/--no-react", default=True, help="Use ReAct agent")
@click.option("--mock/--no-mock", default=False, help="Use mock LLM (no API key)")
@click.option("--json/--no-json", "output_json", default=False, help="Raw JSON output")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def run(vuln, lang, hint, retries, react, mock, output_json, db):
    """Run one training episode."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop
    from ..api.config import get_settings
    from ..api.models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        elo_rec = sess.get(EloRecord, "global")
        elo = (elo_rec.attacker_rating, elo_rec.developer_rating) if elo_rec else (1500.0, 1500.0)
        prompt_rec = sess.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
        pv = prompt_rec.version if prompt_rec else 0

        if mock:
            llm = build_client("mock", "mock")
        else:
            s = get_settings()
            if s.anthropic_api_key:
                prov, key = "anthropic", s.anthropic_api_key
            elif s.groq_api_key:
                prov, key = "groq", s.groq_api_key
            elif s.huggingface_api_key:
                prov, key = "huggingface", s.huggingface_api_key
            elif s.openrouter_api_key:
                prov, key = "openrouter", s.openrouter_api_key
            elif s.openai_api_key:
                prov, key = "openai", s.openai_api_key
            else:
                prov, key = "mock", None
            llm = build_client(prov, s.llm_model, api_key=key)

        loop = TrainingLoop(llm=llm, prompt_version=pv, use_react=react)
        config = EpisodeConfig(vulnerability_class=vuln, language=lang, context_hint=hint, max_retries=retries)

        if not output_json:
            banner()
            provider_name = type(llm).__name__.replace("Client", "")
            console.print(
                Text("  ") + Text(vuln, style="bold red")
                + Text(" · ", style="dim") + Text(lang, style="bold yellow")
                + Text(" · ", style="dim") + Text(provider_name, style="bold blue")
                + Text(" · ", style="dim") + Text("mock" if mock else "live", style="bold green" if mock else "bold")
            )
            console.print()

        # ── Run ──
        if not output_json:
            step("attacker", "generating adversarial task...", "◎", "red")

        t0 = time.time()
        trace = loop.run_episode(config, current_ratings=elo)

        if not output_json:
            dur = time.time() - t0
            o = "VULNERABLE" if trace.judge_outcome == 1 else "SECURE"
            o_c = "red" if trace.judge_outcome == 1 else "green"
            step("attacker", f"task generated  [{trace.difficulty_tier}/10]", "●", "red")
            step("developer", "reading code & building patch...", "◎", "yellow")
            step("developer", "patch built", "●", "yellow")
            step("judge", "running SAST + DAST verification...", "◎", "blue")
            step("judge", f"outcome: {o}", "●", o_c)

            if trace.distilled_rule and trace.regression_passed:
                rule_preview = trace.distilled_rule.rule_text[:55] + "..."
                step("distiller", f"new rule: {rule_preview}", "●", "green")
            else:
                step("distiller", "no rule to distill", "·", "dim")

            elo_bar(trace.elo_before, trace.elo_after)

        # ── Persist ──
        ep = EpisodeRecord(
            id=trace.episode_id,
            status="completed" if not trace.error else "failed",
            vulnerability_class=vuln,
            difficulty_tier=trace.difficulty_tier,
            outcome=trace.judge_outcome,
            task_description=trace.task.task_description if trace.task else "",
            patch_text=trace.patch_text,
            judge_verdict=trace.judge_verdict,
            attacker_rating=trace.elo_after.get("attacker", elo[0]),
            developer_rating=trace.elo_after.get("developer", elo[1]),
            prompt_version=trace.prompt_version,
            error=trace.error or None,
        )
        sess.add(ep)
        if elo_rec:
            elo_rec.attacker_rating = trace.elo_after.get("attacker", elo_rec.attacker_rating)
            elo_rec.developer_rating = trace.elo_after.get("developer", elo_rec.developer_rating)
            elo_rec.episodes_played += 1
        else:
            sess.add(EloRecord(
                id="global",
                attacker_rating=trace.elo_after.get("attacker", 1500.0),
                developer_rating=trace.elo_after.get("developer", 1500.0),
                episodes_played=1,
            ))
        if trace.distilled_rule and trace.regression_passed:
            r = trace.distilled_rule
            sess.add(RuleRecord(
                rule_text=r.rule_text, vulnerability_class=r.vulnerability_class,
                source_pattern=r.source_pattern, recommended_fix=r.recommended_fix,
                source_trace_id=r.source_trace_id, prompt_version=trace.prompt_version, approved=True,
            ))
        sess.commit()

        if output_json:
            click.echo(json.dumps({
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
            }, indent=2))
        else:
            summary_box(trace, vuln, lang)


# ─── QUERY ──────────────────────────────────────────────────────────
@cli.group()
def query():
    """Query CoEvolve data."""
    pass


@query.command("episodes")
@click.option("--limit", "-n", default=10, help="Number of episodes")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--json/--no-json", "output_json", default=False, help="Raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_episodes(limit, vuln, output_json, db):
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
        click.echo(json.dumps([{
            "id": ep.id, "status": ep.status, "vulnerability_class": ep.vulnerability_class,
            "difficulty_tier": ep.difficulty_tier, "outcome": ep.outcome,
            "outcome_text": "VULNERABLE" if ep.outcome == 1 else "SECURE",
            "attacker_rating": ep.attacker_rating, "developer_rating": ep.developer_rating,
            "error": ep.error, "created_at": str(ep.created_at) if ep.created_at else None,
        } for ep in episodes], indent=2))
        return

    if not episodes:
        console.print("[dim]  no episodes[/dim]")
        return

    banner()
    for i, ep in enumerate(episodes, 1):
        o = "VULN" if ep.outcome == 1 else "SAFE"
        oc = "red" if ep.outcome == 1 else "green"
        atk_d = ep.attacker_rating
        dev_d = ep.developer_rating
        console.print(
            Text(f"  {i:2d}. ", style="dim")
            + Text(f"{ep.id}", style="bold")
            + Text("  ", style="dim")
            + Text(f"{ep.vulnerability_class:16s}", style="red")
            + Text(f"T{ep.difficulty_tier}  ", style="dim")
            + Text(f"{o:4s}", style=f"bold {oc}")
            + Text(f"  ATK {atk_d:.0f}  DEV {dev_d:.0f}", style="dim")
        )
    console.print()


@query.command("rules")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--json/--no-json", "output_json", default=False, help="Raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_rules(vuln, output_json, db):
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
        click.echo(json.dumps([{
            "id": r.id, "rule_text": r.rule_text, "vulnerability_class": r.vulnerability_class,
            "source_pattern": r.source_pattern, "recommended_fix": r.recommended_fix,
            "approved": r.approved, "created_at": str(r.created_at) if r.created_at else None,
        } for r in rules], indent=2))
        return

    if not rules:
        console.print("[dim]  no rules distilled yet[/dim]")
        return

    banner()
    for i, r in enumerate(rules, 1):
        console.print(Text(f"  {i}. ", style="bold") + Text(f"{r.vulnerability_class}", style="red") + Text(f"  {r.rule_text[:70]}", style="white"))
        console.print(Text(f"     {r.source_pattern[:60]}...", style="dim"))
    console.print()


@query.command("elo")
@click.option("--json/--no-json", "output_json", default=False, help="Raw JSON")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_elo(output_json, db):
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
        click.echo(json.dumps({"attacker_rating": atk, "developer_rating": dev, "episodes_played": eps}, indent=2))
        return

    banner()
    max_w = 40
    total = atk + dev
    atk_w = int((atk / total) * max_w) if total > 0 else max_w // 2
    dev_w = max_w - atk_w

    console.print(
        Text("  ATK  ", style="bold red")
        + Text(f"{atk:.0f}  ", style="red")
        + Text("█" * atk_w, style="red")
    )
    console.print(
        Text("  DEV  ", style="bold yellow")
        + Text(f"{dev:.0f}  ", style="yellow")
        + Text("█" * dev_w, style="yellow")
    )
    console.print(Text(f"\n  {eps} episodes played", style="dim"))
    console.print()


# ─── EXPORT ─────────────────────────────────────────────────────────
@cli.command("export-rules")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--output", "-o", default=None, help="Output file")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def export_rules(vuln, output, db):
    """Export rules as JSON."""
    import time as _time
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

    pkg = {
        "version": "1.0.0",
        "exported_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        "total_rules": len(rules),
        "rules": [{"rule_text": r.rule_text, "vulnerability_class": r.vulnerability_class,
                   "source_pattern": r.source_pattern, "recommended_fix": r.recommended_fix} for r in rules],
    }
    js = json.dumps(pkg, indent=2)
    if output:
        with open(output, "w") as f:
            f.write(js)
        console.print(f"[green]  exported {len(rules)} rules → {output}[/green]")
    else:
        click.echo(js)


# ─── STATUS ─────────────────────────────────────────────────────────
@cli.command()
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def status(db):
    """Show system status."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from ..api.models import EpisodeRecord, EloRecord, RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as sess:
        eps = sess.query(EpisodeRecord).count()
        rules = sess.query(RuleRecord).count()
        elo = sess.get(EloRecord, "global")

    atk = elo.attacker_rating if elo else 1500.0
    dev = elo.developer_rating if elo else 1500.0
    n = elo.episodes_played if elo else 0

    banner()
    console.print(
        Text("  episodes  ", style="dim") + Text(str(eps), style="bold")
        + Text("  │  ", style="dim") + Text("rules  ", style="dim") + Text(str(rules), style="bold")
        + Text("  │  ", style="dim") + Text("ATK ", style="red") + Text(f"{atk:.0f}", style="bold red")
        + Text("  DEV ", style="yellow") + Text(f"{dev:.0f}", style="bold yellow")
    )
    console.print()


def main():
    cli()


if __name__ == "__main__":
    main()
