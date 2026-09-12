"""CoEvolve CLI — main entry point."""

from __future__ import annotations

import json
import sys
from typing import Optional

import click


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
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def run(
    vuln: str,
    lang: str,
    hint: str,
    retries: int,
    react: bool,
    db: str,
) -> None:
    """Run one training episode and output JSON."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker

    from ..agents.llm import build_client
    from ..agents.training_loop import EpisodeConfig, TrainingLoop
    from ..api.config import get_settings
    from ..api.models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        # Get current Elo
        elo_record = sess.get(EloRecord, "global")
        current_ratings = (
            (elo_record.attacker_rating, elo_record.developer_rating)
            if elo_record
            else (1500.0, 1500.0)
        )

        # Get prompt version
        latest_prompt = sess.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
        prompt_version = latest_prompt.version if latest_prompt else 0

        # Build LLM
        settings = get_settings()
        provider = "anthropic" if settings.anthropic_api_key else "openai"
        llm = build_client(provider, settings.llm_model)

        # Run episode
        loop = TrainingLoop(llm=llm, prompt_version=prompt_version, use_react=react)
        config = EpisodeConfig(
            vulnerability_class=vuln,
            language=lang,
            context_hint=hint,
            max_retries=retries,
        )
        trace = loop.run_episode(config, current_ratings=current_ratings)

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

    # Output JSON
    result = {
        "episode_id": trace.episode_id,
        "status": "completed" if not trace.error else "failed",
        "vulnerability_class": vuln,
        "language": lang,
        "difficulty_tier": trace.difficulty_tier,
        "judge_outcome": trace.judge_outcome,
        "judge_outcome_text": "VULNERABLE" if trace.judge_outcome == 1 else "SECURE",
        "judge_verdict": trace.judge_verdict,
        "rule_distilled": trace.distilled_rule is not None and trace.regression_passed,
        "rule_text": trace.distilled_rule.rule_text if trace.distilled_rule else None,
        "regression_passed": trace.regression_passed,
        "elo_before": trace.elo_before,
        "elo_after": trace.elo_after,
        "duration_s": trace.duration_s,
        "error": trace.error,
    }
    click.echo(json.dumps(result, indent=2))


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
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_episodes(limit: int, vuln: Optional[str], db: str) -> None:
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

    result = [
        {
            "id": ep.id,
            "status": ep.status,
            "vulnerability_class": ep.vulnerability_class,
            "difficulty_tier": ep.difficulty_tier,
            "outcome": ep.outcome,
            "outcome_text": "VULNERABLE" if ep.outcome == 1 else "SECURE",
            "judge_verdict": ep.judge_verdict,
            "attacker_rating": ep.attacker_rating,
            "developer_rating": ep.developer_rating,
            "prompt_version": ep.prompt_version,
            "error": ep.error,
            "created_at": str(ep.created_at) if ep.created_at else None,
        }
        for ep in episodes
    ]
    click.echo(json.dumps(result, indent=2))


@query.command("rules")
@click.option("--vuln", default=None, help="Filter by vulnerability class")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_rules(vuln: Optional[str], db: str) -> None:
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

    result = [
        {
            "id": rule.id,
            "rule_text": rule.rule_text,
            "vulnerability_class": rule.vulnerability_class,
            "source_pattern": rule.source_pattern,
            "recommended_fix": rule.recommended_fix,
            "approved": rule.approved,
            "prompt_version": rule.prompt_version,
            "created_at": str(rule.created_at) if rule.created_at else None,
        }
        for rule in rules
    ]
    click.echo(json.dumps(result, indent=2))


@query.command("elo")
@click.option("--db", default="sqlite:///./coevolve.db", help="Database URL")
def query_elo(db: str) -> None:
    """Show current Elo ratings."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from ..api.models import EloRecord

    engine = create_engine(db)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as sess:
        elo = sess.get(EloRecord, "global")

    if elo:
        result = {
            "attacker_rating": elo.attacker_rating,
            "developer_rating": elo.developer_rating,
            "episodes_played": elo.episodes_played,
            "last_updated": str(elo.updated_at) if elo.updated_at else None,
        }
    else:
        result = {
            "attacker_rating": 1500.0,
            "developer_rating": 1500.0,
            "episodes_played": 0,
            "last_updated": None,
        }
    click.echo(json.dumps(result, indent=2))


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
        click.echo(f"Exported {len(rules)} rules to {output}")
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

    result = {
        "total_episodes": episode_count,
        "total_rules": rule_count,
        "attacker_rating": elo.attacker_rating if elo else 1500.0,
        "developer_rating": elo.developer_rating if elo else 1500.0,
        "episodes_played": elo.episodes_played if elo else 0,
    }
    click.echo(json.dumps(result, indent=2))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
