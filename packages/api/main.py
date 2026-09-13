"""CoEvolve API — simplified for Render free tier deployment."""

from __future__ import annotations
from typing import Optional


import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import APIKey, require_api_key_if_enabled
from .config import get_settings
from .database import Base, get_db, get_engine, get_session_factory
from .models import EloRecord, EpisodeRecord, PromptRecord, RuleRecord
from .schemas import (
    EloHistoryResponse,
    EpisodeRead,
    EpisodeStopResponse,
    MetricsSnapshot,
    PromptDiffResponse,
    PromptRead,
    RuleDetailRead,
    RuleRead,
    TrainingJobEnqueueRequest,
    TrainingJobRead,
    TrainingRunRequest,
    TrainingRunResponse,
    VulnerabilityCoverage,
)
from .task_queue import TrainingJob, get_task_queue
from .training_service import get_current_ratings, get_prompt_version, persist_episode

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        engine = get_engine()
        Base.metadata.create_all(engine)
        _seed_elo()
        # Warm the key store so ADMIN_API_KEY bootstrap registers at startup
        # (works for both memory and db backends).
        from .auth import get_key_store

        get_key_store()
        # Mirror prompt versions into the DB so /prompts/* is never stale.
        _sync_db = get_session_factory()()
        try:
            _sync_prompt_records(_sync_db)
        finally:
            _sync_db.close()
        logger.info("Database connected successfully")
    except Exception as exc:
        # Log and continue so /health stays available; training endpoints
        # will surface DB errors per-request. Fail-fast is handled by
        # docker-compose.prod.yml required-var validation instead.
        logger.error("Database connection failed: %s", exc)
        logger.error("Check your DATABASE_URL environment variable")
    yield


app = FastAPI(
    title="CoEvolve API",
    version="0.1.0",
    description="Adversarial Training as a Service",
    lifespan=lifespan,
)


def _configure_cors() -> None:
    settings = get_settings()
    origins = settings.cors_origin_list
    if "*" in origins:
        # Browsers reject allow_credentials with "*"; disable credentials
        # in wildcard mode (dev default). Set CORS_ORIGINS to explicit
        # origins in production to re-enable credentials.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


_configure_cors()


def _seed_elo() -> None:
    db = get_session_factory()()
    try:
        if db.query(EloRecord).count() == 0:
            db.add(EloRecord(id="global", attacker_rating=1500.0, developer_rating=1500.0))
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Health / Metrics
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/metrics", response_model=MetricsSnapshot)
def metrics(db: Session = Depends(get_db)) -> MetricsSnapshot:
    total = db.query(func.count(EpisodeRecord.id)).scalar() or 0
    secure = db.query(func.count(EpisodeRecord.id)).filter(EpisodeRecord.outcome == 0).scalar() or 0
    rules_count = db.query(func.count(RuleRecord.id)).scalar() or 0
    elo = db.get(EloRecord, "global")
    ratings = {
        "attacker": elo.attacker_rating if elo else 1500.0,
        "developer": elo.developer_rating if elo else 1500.0,
    }
    return MetricsSnapshot(
        total_episodes=total,
        secure_rate=secure / total if total else 0.0,
        epo=ratings,
        elo=ratings,
        rules_count=rules_count,
    )


# ---------------------------------------------------------------------------
# Episodes
# ---------------------------------------------------------------------------
@app.get("/episodes", response_model=list[EpisodeRead])
def list_episodes(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> list[EpisodeRecord]:
    q = db.query(EpisodeRecord)
    if status:
        q = q.filter(EpisodeRecord.status == status)
    return q.order_by(EpisodeRecord.created_at.desc()).offset(offset).limit(limit).all()


@app.get("/episodes/{episode_id}", response_model=EpisodeRead)
def get_episode(episode_id: str, db: Session = Depends(get_db)) -> EpisodeRecord:
    ep = db.get(EpisodeRecord, episode_id)
    if not ep:
        raise HTTPException(404, "Episode not found")
    return ep


# ---------------------------------------------------------------------------
# ELO
# ---------------------------------------------------------------------------
@app.get("/elo")
def elo(db: Session = Depends(get_db)) -> dict[str, float]:
    record = db.get(EloRecord, "global")
    return {
        "attacker": record.attacker_rating if record else 1500.0,
        "developer": record.developer_rating if record else 1500.0,
    }


@app.get("/elo/history", response_model=EloHistoryResponse)
def elo_history(db: Session = Depends(get_db)) -> EloHistoryResponse:
    record = db.get(EloRecord, "global")
    return EloHistoryResponse(
        history=[],
        current={
            "attacker": record.attacker_rating if record else 1500.0,
            "developer": record.developer_rating if record else 1500.0,
        },
    )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
@app.get("/rules", response_model=list[RuleRead])
def list_rules(
    vuln_class: Optional[str] = Query(None),
    approved_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[RuleRecord]:
    q = db.query(RuleRecord)
    if vuln_class:
        q = q.filter(RuleRecord.vulnerability_class == vuln_class)
    if approved_only:
        q = q.filter(RuleRecord.approved.is_(True))
    return q.order_by(RuleRecord.created_at.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
def _sync_prompt_records(db: Session) -> None:
    """Mirror PromptStore (git-backed source of truth) into PromptRecord rows.

    The store auto-creates v1 on first use, so after sync at least one row
    always exists. Idempotent — only missing versions are inserted.
    """
    from datetime import datetime, timezone

    from ..evolution.store import PromptStore

    try:
        versions = PromptStore().history()
    except Exception as exc:
        logger.warning("PromptStore sync skipped: %s", exc)
        return
    existing = {v for (v,) in db.query(PromptRecord.version).all()}
    for entry in versions:
        if entry["version"] in existing:
            continue
        created = entry.get("created_at") or 0
        db.add(
            PromptRecord(
                id=f"v{entry['version']:04d}",
                version=entry["version"],
                base_prompt=entry.get("base_prompt", ""),
                rules=entry.get("rules", []),
                commit_message=entry.get("commit_message", ""),
                parent_version=entry.get("parent_version"),
                created_at=datetime.fromtimestamp(created, tz=timezone.utc),
            )
        )
    db.commit()


@app.get("/prompts/current", response_model=PromptRead)
def get_current_prompt(db: Session = Depends(get_db)) -> PromptRecord:
    _sync_prompt_records(db)
    prompt = db.query(PromptRecord).order_by(PromptRecord.version.desc()).first()
    if not prompt:
        raise HTTPException(404, "No prompt versions found")
    return prompt


@app.get("/prompts/history", response_model=list[PromptRead])
def get_prompt_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[PromptRecord]:
    _sync_prompt_records(db)
    return db.query(PromptRecord).order_by(PromptRecord.version.desc()).limit(limit).all()


@app.get("/prompts/diff/{v1}/{v2}", response_model=PromptDiffResponse)
def get_prompt_diff(v1: int, v2: int, db: Session = Depends(get_db)) -> PromptDiffResponse:
    from ..evolution.store import PromptStore

    store = PromptStore()
    try:
        diff = store.diff(v1, v2)
    except KeyError as exc:
        raise HTTPException(404, f"Version {v1} or {v2} not found") from exc
    return PromptDiffResponse(
        from_version=diff["from"],
        to_version=diff["to"],
        added=diff["added"],
        removed=diff["removed"],
    )


# ---------------------------------------------------------------------------
# Rules — single rule
# ---------------------------------------------------------------------------
@app.get("/rules/{rule_id}", response_model=RuleDetailRead)
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> RuleRecord:
    rule = db.get(RuleRecord, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return rule


# ---------------------------------------------------------------------------
# Vulnerabilities — coverage report
# ---------------------------------------------------------------------------
@app.get("/vulnerabilities/coverage", response_model=list[VulnerabilityCoverage])
def get_vulnerability_coverage(db: Session = Depends(get_db)) -> list[VulnerabilityCoverage]:
    from sqlalchemy import case

    rows = (
        db.query(
            EpisodeRecord.vulnerability_class,
            func.count(EpisodeRecord.id).label("total"),
            func.sum(case((EpisodeRecord.outcome == 1, 1), else_=0)).label("detected"),
            func.sum(case((EpisodeRecord.outcome == 0, 1), else_=0)).label("secure"),
        )
        .filter(EpisodeRecord.vulnerability_class.isnot(None))
        .group_by(EpisodeRecord.vulnerability_class)
        .all()
    )
    result = []
    for row in rows:
        total = row.total or 0
        detected = row.detected or 0
        result.append(
            VulnerabilityCoverage(
                vulnerability_class=row.vulnerability_class,
                total_episodes=total,
                detected_count=detected,
                secure_count=row.secure or 0,
                coverage_rate=(total - detected) / total if total else 0.0,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Episodes — stop (auth enforced when REQUIRE_AUTH=true)
# ---------------------------------------------------------------------------
@app.post("/episodes/{episode_id}/stop", response_model=EpisodeStopResponse)
def stop_episode(
    episode_id: str,
    db: Session = Depends(get_db),
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> EpisodeStopResponse:
    ep = db.get(EpisodeRecord, episode_id)
    if not ep:
        raise HTTPException(404, "Episode not found")
    if ep.status in ("completed", "failed"):
        return EpisodeStopResponse(
            episode_id=episode_id,
            status=ep.status,
            message=f"Episode already {ep.status}",
        )
    ep.status = "failed"
    ep.error = "Stopped by user"
    db.commit()
    return EpisodeStopResponse(
        episode_id=episode_id,
        status="failed",
        message="Episode stopped",
    )


# ---------------------------------------------------------------------------
# Training — Synchronous Run
# ---------------------------------------------------------------------------
# NOTE: this is a sync `def` endpoint, so FastAPI runs it in a threadpool —
# it does not block the async event loop. For long-running jobs prefer the
# TaskQueue/worker path (packages/api/task_queue.py + worker.py).
@app.post("/training/run", response_model=TrainingRunResponse)
def run_training_episode(
    body: TrainingRunRequest,
    db: Session = Depends(get_db),
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> TrainingRunResponse:
    """Execute one co-evolutionary training episode (blocks until done)."""
    from ..agents.training_loop import EpisodeConfig
    from .training_service import build_loop

    current_ratings = get_current_ratings(db)
    prompt_version = get_prompt_version(db)

    loop = build_loop(prompt_version, use_react=body.use_react)
    config = EpisodeConfig(
        vulnerability_class=body.vulnerability_class,
        language=body.language,
        context_hint=body.context_hint,
        max_retries=body.max_retries,
    )
    trace = loop.run_episode(config, current_ratings=current_ratings)

    persist_episode(
        db,
        trace=trace,
        vulnerability_class=body.vulnerability_class,
        current_ratings=current_ratings,
    )

    return TrainingRunResponse(
        episode_id=trace.episode_id,
        status="completed" if not trace.error else "failed",
        difficulty_tier=trace.difficulty_tier,
        judge_outcome=trace.judge_outcome,
        judge_verdict=trace.judge_verdict,
        rule_distilled=trace.distilled_rule is not None and trace.regression_passed,
        rule_text=trace.distilled_rule.rule_text if trace.distilled_rule else None,
        regression_passed=trace.regression_passed,
        elo_before=trace.elo_before,
        elo_after=trace.elo_after,
        duration_s=trace.duration_s,
        error=trace.error or None,
    )


# ---------------------------------------------------------------------------
# File Upload — Scan uploaded code for vulnerabilities
# ---------------------------------------------------------------------------
@app.post("/training/upload")
async def upload_and_scan(
    files: list[UploadFile] = File(...),
    vulnerability_class: str = Query("SQLi"),
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> dict:
    """Upload code files, scan with SAST, and return detailed findings."""
    import tempfile
    import time
    from collections import Counter, defaultdict
    from datetime import datetime, timezone
    from pathlib import Path
    from ..judge.sast.scanner import SemgrepScanner, VULN_METADATA

    if not files:
        return {"total_findings": 0, "files": [], "findings": [], "summary": {}, "scan_info": {}, "recommendations": [], "error": "No files provided"}

    scanner = SemgrepScanner()
    start = time.time()

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            uploaded: list[dict] = []
            for upload in files:
                content = await upload.read()
                raw_name = upload.filename or "upload.py"
                safe_name = raw_name.lstrip("/\\")
                file_path = tmp_path / safe_name
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(content)
                # detect language from extension
                ext = Path(safe_name).suffix.lower()
                lang = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java"}.get(ext, ext.lstrip(".") or "unknown")
                uploaded.append({"filename": safe_name, "size": len(content), "tmp_path": file_path, "language": lang, "ext": ext})

            result = scanner.scan_directory(tmp_path)
            duration_ms = int((time.time() - start) * 1000)

            # Load exploit payloads for DAST simulation
            import json as _json
            payload_path = Path(__file__).resolve().parents[2] / "data" / "exploit_payloads.json"
            try:
                exploit_db = _json.loads(payload_path.read_text()) if payload_path.exists() else {}
            except Exception:
                exploit_db = {}
            # Normalize keys for lookup (lowercase, no hyphen)
            def _payloads_for(rule_id: str):
                key_map = {
                    "sql-injection": "SQLi", "sql": "SQLi",
                    "path-traversal": "PathTraversal",
                    "command-injection": "CommandInjection",
                    "xss": "XSS", "ssti": "SSTI", "xxe": "XXE",
                    "ssrf": "SSRF", "deserialization": "Deserialization",
                    "open-redirect": "OpenRedirect", "prototype-pollution": "PrototypePollution",
                }
                k = key_map.get(rule_id, rule_id)
                vals = exploit_db.get(k) or exploit_db.get(k.lower()) or exploit_db.get(rule_id) or []
                # handle duplicate XSS key
                if not vals and rule_id == "xss":
                    vals = exploit_db.get("XSS", [])
                return vals

            # Cache file contents for code context
            file_cache: dict[str, list[str]] = {}
            for info in uploaded:
                try:
                    file_cache[info["filename"]] = (tmp_path / info["filename"]).read_text(errors="ignore").splitlines()
                except Exception:
                    file_cache[info["filename"]] = []

            all_findings: list[dict] = []
            sast_logs: list[str] = []
            dast_logs: list[str] = []
            for f in result.findings:
                d = f.as_dict()
                try:
                    rel = str(Path(d["file"]).relative_to(tmp_path))
                except Exception:
                    rel = Path(d["file"]).name
                d["file"] = rel
                d["language"] = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java"}.get(Path(rel).suffix.lower(), "unknown")
                # Code context (2 lines before/after)
                lines = file_cache.get(rel, [])
                ctx = []
                if lines and d["line"] > 0:
                    start_l = max(1, d["line"] - 2)
                    end_l = min(len(lines), d["line"] + 2)
                    for ln in range(start_l, end_l + 1):
                        ctx.append({"line": ln, "content": lines[ln-1] if 0 < ln <= len(lines) else "", "is_target": ln == d["line"]})
                else:
                    ctx = [{"line": d["line"], "content": d.get("message","")[:80], "is_target": True}]
                d["code_context"] = ctx
                # SAST log
                sast_entry = f"[SAST] {d['rule_id']} ({d.get('cwe','')}) at {rel}:{d['line']} | severity={d['severity']} | keyword={d.get('metadata',{}).get('keyword','')} | confidence={d['confidence']}"
                d["sast_log"] = sast_entry
                sast_logs.append(sast_entry)
                # DAST payloads and logs
                payloads = _payloads_for(d["rule_id"])
                dast_payload = payloads[0] if payloads else {"payload": "N/A", "description": "No payload mapped"}
                d["exploit_payload"] = dast_payload
                d["exploit_payloads"] = payloads[:3]
                # Simulated DAST log
                status = "VULNERABLE (simulated)" if d["severity"] == "ERROR" else "POTENTIALLY VULNERABLE"
                dast_entry = f"[DAST] {d['rule_id']} payload={dast_payload.get('payload','')} | target={rel}:{d['line']} | result={status} | expected: {VULN_METADATA.get(d['rule_id'],{}).get('title','')}"
                d["dast_log"] = dast_entry
                d["dast_status"] = status
                dast_logs.append(dast_entry)
                # Fix code snippet helper
                d["fix_code"] = f"// Fix for {d['rule_id']}: {VULN_METADATA.get(d['rule_id'],{}).get('fix','')}"
                all_findings.append(d)

            # Per-file summaries
            file_summaries = []
            for info in uploaded:
                fname = info["filename"]
                file_findings = [f for f in all_findings if f["file"] == fname]
                # severity breakdown per file
                sev_counts = Counter(f["severity"] for f in file_findings)
                file_summaries.append({
                    "filename": fname,
                    "size": info["size"],
                    "language": info["language"],
                    "findings_count": len(file_findings),
                    "severity_counts": dict(sev_counts),
                    "risk": "High" if any(f["severity"] == "ERROR" for f in file_findings) else ("Medium" if file_findings else "Low"),
                })

            # Summary aggregates
            by_class = dict(Counter(f["rule_id"] for f in all_findings))
            by_severity = dict(Counter(f["severity"] for f in all_findings))
            by_confidence = dict(Counter(f["confidence"] for f in all_findings))
            by_file = {info["filename"]: len([f for f in all_findings if f["file"] == info["filename"]]) for info in uploaded}
            by_language = dict(Counter(info["language"] for info in uploaded))
            by_risk = dict(Counter(f.get("risk", f["severity"]) for f in all_findings))
            # Languages with findings
            langs_with_findings = dict(Counter(f["language"] for f in all_findings))

            total = len(all_findings)
            critical = by_severity.get("ERROR", 0)
            warning = by_severity.get("WARNING", 0)
            # Risk score 0-100: weighted
            risk_score = min(100, critical * 10 + warning * 3 + len(by_class) * 5) if total else 0
            risk_level = "Critical" if risk_score >= 70 else "High" if risk_score >= 40 else "Medium" if risk_score >= 10 else "Low"

            # Recommendations grouped by class
            grouped: dict[str, list[dict]] = defaultdict(list)
            for f in all_findings:
                grouped[f["rule_id"]].append(f)
            recommendations = []
            priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            for rule_id, items in grouped.items():
                meta = VULN_METADATA.get(rule_id, {})
                recommendations.append({
                    "rule_id": rule_id,
                    "title": meta.get("title", rule_id),
                    "cwe": meta.get("cwe", ""),
                    "owasp": meta.get("owasp", ""),
                    "severity": meta.get("severity", items[0]["severity"]),
                    "risk": meta.get("risk", "Medium"),
                    "count": len(items),
                    "fix": meta.get("fix", ""),
                    "files_affected": sorted(set(f["file"] for f in items)),
                    "example": items[0]["message"][:120],
                })
            recommendations.sort(key=lambda r: (priority_order.get(r["risk"], 99), -r["count"]))

            scan_info = {
                "duration_ms": duration_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "files_scanned": len(uploaded),
                "total_bytes": sum(i["size"] for i in uploaded),
                "languages_detected": sorted(set(i["language"] for i in uploaded)),
                "rules_used": len(list(scanner.rules_dir.glob("*.yml"))),
            }

            summary = {
                "total_findings": total,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "by_class": by_class,
                "by_severity": by_severity,
                "by_confidence": by_confidence,
                "by_file": by_file,
                "by_language": by_language,
                "by_risk": by_risk,
                "langs_with_findings": langs_with_findings,
                "critical_count": critical,
                "warning_count": warning,
                "files_affected": len([f for f in file_summaries if f["findings_count"] > 0]),
            }

            # Full tabular summary (one row per finding, combining SAST+DAST)
            tabular_summary = []
            for idx, f in enumerate(all_findings, 1):
                tabular_summary.append({
                    "id": idx,
                    "file": f["file"],
                    "line": f["line"],
                    "language": f["language"],
                    "rule_id": f["rule_id"],
                    "title": f.get("title", ""),
                    "cwe": f.get("cwe", ""),
                    "owasp": f.get("owasp", ""),
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "risk": f.get("risk", ""),
                    "sast_log": f.get("sast_log", ""),
                    "dast_payload": f.get("exploit_payload", {}).get("payload", "") if isinstance(f.get("exploit_payload"), dict) else str(f.get("exploit_payload", "")),
                    "dast_payload_desc": f.get("exploit_payload", {}).get("description", "") if isinstance(f.get("exploit_payload"), dict) else "",
                    "dast_log": f.get("dast_log", ""),
                    "dast_status": f.get("dast_status", ""),
                    "message": f["message"],
                    "fix": f.get("fix", ""),
                    "code_context": f.get("code_context", []),
                })

            return {
                "total_findings": len(all_findings),
                "files": file_summaries,
                "findings": all_findings,
                "summary": summary,
                "scan_info": scan_info,
                "recommendations": recommendations,
                "sast_logs": sast_logs,
                "dast_logs": dast_logs,
                "tabular_summary": tabular_summary,
            }
    except Exception as e:
        return {
            "total_findings": 0,
            "files": [],
            "findings": [],
            "summary": {},
            "scan_info": {},
            "recommendations": [],
            "sast_logs": [],
            "dast_logs": [],
            "tabular_summary": [],
            "error": f"Scan failed: {str(e)}",
        }


def _job_to_read(job: TrainingJob, queue_position: Optional[int] = None) -> TrainingJobRead:
    return TrainingJobRead(
        job_id=job.job_id,
        status=job.status.value,
        vulnerability_class=job.vulnerability_class,
        language=job.language,
        context_hint=job.context_hint,
        max_retries=job.max_retries,
        use_react=job.use_react,
        queue_position=queue_position,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        result=job.result,
        error=job.error,
    )


# ---------------------------------------------------------------------------
# Training — Async Jobs (non-blocking; processed by worker.py)
# ---------------------------------------------------------------------------
# NOTE: with the in-memory queue backend this only works single-process.
# Multi-process deployments (uvicorn --workers + separate worker) require
# REDIS_URL so the API and worker share queue state.
@app.post("/training/jobs", response_model=TrainingJobRead, status_code=202)
def enqueue_training_job(
    body: TrainingJobEnqueueRequest,
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
) -> TrainingJobRead:
    """Enqueue a training episode and return immediately (202 Accepted)."""
    queue = get_task_queue()
    job = queue.enqueue(
        TrainingJob(
            vulnerability_class=body.vulnerability_class,
            language=body.language,
            context_hint=body.context_hint,
            max_retries=body.max_retries,
            use_react=body.use_react,
        )
    )
    return _job_to_read(job, queue_position=queue.queue_length())


@app.get("/training/jobs", response_model=list[TrainingJobRead])
def list_training_jobs(
    limit: int = Query(50, ge=1, le=200),
) -> list[TrainingJobRead]:
    """List recent training jobs (newest first)."""
    return [_job_to_read(j) for j in get_task_queue().list_jobs(limit=limit)]


@app.get("/training/jobs/{job_id}", response_model=TrainingJobRead)
def get_training_job(job_id: str) -> TrainingJobRead:
    """Poll a training job's status and result."""
    job = get_task_queue().get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return _job_to_read(job)


# ---------------------------------------------------------------------------
# Training — SSE Stream (real-time progress)
# ---------------------------------------------------------------------------
@app.get("/training/stream")
async def training_stream(
    vulnerability_class: str = "SQLi",
    language: str = "python",
    _auth: Optional[APIKey] = Depends(require_api_key_if_enabled),
):
    """Stream training progress via Server-Sent Events.

    Auth enforced when REQUIRE_AUTH=true. Browsers/EventSource cannot set
    headers, so pass ``?api_key=<key>`` (supported by the API key query
    scheme) for this endpoint.
    """
    import json

    from ..agents.training_loop import EpisodeConfig
    from .training_service import build_loop

    async def event_generator():
        db = get_session_factory()()

        try:
            current_ratings = get_current_ratings(db)
            prompt_version = get_prompt_version(db)

            loop_inst = build_loop(prompt_version, use_react=True)
            config = EpisodeConfig(
                vulnerability_class=vulnerability_class,
                language=language,
                context_hint="",
                max_retries=3,
            )

            yield f"data: {json.dumps({'type': 'start', 'vuln': vulnerability_class, 'lang': language, 'elo': list(current_ratings)})}\n\n"
            await asyncio.sleep(0.1)

            # Run blocking training loop in a threadpool; do not hold the
            # DB connection open longer than needed — persist after completion.
            trace = await asyncio.to_thread(
                loop_inst.run_episode, config, current_ratings=current_ratings
            )

            outcome_text = "SECURE" if trace.judge_outcome == 0 else "VULNERABLE"

            steps = [
                {
                    "type": "agent",
                    "agent": "attacker",
                    "status": "done",
                    "message": f"Task generated (tier {trace.difficulty_tier}/10)",
                },
                {
                    "type": "agent",
                    "agent": "developer",
                    "status": "done",
                    "message": f"Patch built ({len(trace.patch_text)} chars)",
                },
                {
                    "type": "agent",
                    "agent": "judge",
                    "status": "done",
                    "message": f"Outcome: {outcome_text}",
                },
            ]
            if trace.distilled_rule and trace.regression_passed:
                steps.append(
                    {
                        "type": "agent",
                        "agent": "distiller",
                        "status": "done",
                        "message": f"Rule: {trace.distilled_rule.rule_text[:80]}",
                    }
                )
            else:
                steps.append(
                    {
                        "type": "agent",
                        "agent": "distiller",
                        "status": "skip",
                        "message": "No rule distilled",
                    }
                )

            for step in steps:
                yield f"data: {json.dumps(step)}\n\n"
                await asyncio.sleep(0.1)

            yield f"data: {json.dumps({'type': 'elo', 'before': trace.elo_before, 'after': trace.elo_after})}\n\n"

            # Persist via shared helper (single source of truth)
            persist_episode(
                db,
                trace=trace,
                vulnerability_class=vulnerability_class,
                current_ratings=current_ratings,
            )

            yield f"data: {json.dumps({'type': 'complete', 'episode_id': trace.episode_id, 'outcome': trace.judge_outcome, 'rule_distilled': trace.distilled_rule is not None and trace.regression_passed, 'duration_s': trace.duration_s})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            db.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
