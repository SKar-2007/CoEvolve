# Build Plan: CoEvolve Sandbox Implementation Roadmap

## Phased Implementation from Core Infrastructure to Full System

---

## 1. Implementation Overview

### 1.1 Build Philosophy

CoEvolve Sandbox is built incrementally in 6 phases, each delivering a functional subsystem that can be tested and validated independently. The architecture follows a bottom-up approach: infrastructure first, then agents, then intelligence, then operations.

### 1.2 Timeline Summary

| Phase | Name | Duration | Deliverable |
|-------|------|----------|-------------|
| 1 | Core Infrastructure | 4 weeks | Docker sandboxing, container lifecycle, basic API |
| 2 | Agent Implementation | 6 weeks | Attacker, Developer, Judge agents |
| 3 | Prompt Evolution Engine | 4 weeks | Distillation, versioning, regression guarding |
| 4 | Elo Rating System | 2 weeks | Dynamic difficulty matching |
| 5 | Telemetry & Dashboard | 3 weeks | Monitoring, metrics, visualization |
| 6 | Benchmarking & Validation | 3 weeks | Cold start demo, coverage validation |
| **Total** | | **22 weeks** | **Full system operational** |

### 1.3 Team Structure

| Role | Count | Responsibilities |
|------|-------|------------------|
| Backend Engineer | 2 | API, database, orchestration |
| Infrastructure Engineer | 1 | Docker, security hardening, deployment |
| ML/AI Engineer | 2 | LLM integration, prompt engineering, evaluation |
| Security Engineer | 1 | Vulnerability taxonomy, Semgrep rules, exploit payloads |
| DevOps/SRE | 1 | CI/CD, monitoring, deployment |

---

## 2. Phase 1: Core Infrastructure (Weeks 1-4)

### 2.1 Objectives
- Establish Docker-based isolated execution environment
- Build core API and database schema
- Implement container lifecycle management
- Create basic training loop controller

### 2.2 Tasks

#### Week 1: Project Setup
```
□ Initialize monorepo structure
□ Set up development environment
□ Configure CI/CD pipeline
□ Create Docker base image
□ Set up PostgreSQL database
□ Set up Redis cache
□ Define API specification (OpenAPI 3.0)
```

#### Week 2: Container Orchestration
```
□ Implement Docker container manager
□ Create hardened container configuration:
  □ --network none
  □ --read-only
  □ --cap-drop ALL
  □ --security-opt no-new-privileges
  □ Seccomp profile
  □ Resource limits (CPU, memory, PIDs)
  □ Non-root user (UID 1000)
  □ tmpfs scratch spaces
□ Implement container lifecycle (create, start, stop, destroy)
□ Add container health monitoring
□ Create container pool for reuse
```

#### Week 3: API & Database
```
□ Design database schema:
  □ episodes table
  □ tasks table
  □ patches table
  □ judge_results table
  □ rules table
  □ elo_ratings table
  □ prompt_versions table
□ Implement REST API endpoints:
  □ POST /api/v1/episodes
  □ GET /api/v1/episodes/{id}
  □ POST /api/v1/episodes/{id}/stop
  □ GET /api/v1/prompts/current
  □ GET /api/v1/elo
□ Set up database migrations
□ Implement connection pooling
□ Add request validation and error handling
```

#### Week 4: Training Loop Controller
```
□ Implement episode orchestrator
□ Create state machine for episode lifecycle
□ Implement task queue (Redis-based)
□ Add retry logic for transient failures
□ Create basic logging infrastructure
□ Write integration tests for container lifecycle
□ Write integration tests for API endpoints
```

### 2.3 Deliverables
- Docker image with hardened security configuration
- REST API with core endpoints
- PostgreSQL database with schema
- Container lifecycle manager
- Basic training loop controller

### 2.4 Validation Criteria
- [ ] Container starts and stops within 5 seconds
- [ ] Container has no network access
- [ ] Container runs as non-root user
- [ ] Container enforces resource limits
- [ ] API responds to all defined endpoints
- [ ] Database stores and retrieves data correctly

---

## 3. Phase 2: Agent Implementation (Weeks 5-10)

### 3.1 Objectives
- Implement Attacker Agent for task generation
- Implement Developer Agent for code patching
- Implement Hybrid Judge Engine (SAST + DAST)
- Establish agent communication protocol

### 3.2 Tasks

#### Week 5-6: LLM Integration Layer
```
□ Create LLM client abstraction:
  □ Anthropic Claude integration
  □ OpenAI GPT-4 integration
  □ Open-source model integration (vLLM/Ollama)
□ Implement prompt templating system
□ Add streaming response support
□ Implement token counting and cost tracking
□ Add retry logic with exponential backoff
□ Create LLM call logging and caching
□ Write unit tests for LLM integration
```

#### Week 7-8: Attacker Agent
```
□ Design Attacker system prompt (see agent.md §2.2)
□ Implement vulnerability schema:
  □ SQLi task templates
  □ Path Traversal task templates
  □ SSRF task templates
  □ Deserialization task templates
  □ XSS task templates
  □ Command Injection task templates
  □ SSTI task templates
□ Implement task generation pipeline
□ Add difficulty tier mapping
□ Create task validation logic
□ Write integration tests for task generation
□ Test with 100+ task generations across vulnerability classes
```

#### Week 8-9: Developer Agent
```
□ Design Developer system prompt (see agent.md §3.2)
□ Implement ReAct tool-use framework:
  □ read_file() tool
  □ write_file() tool
  □ run_shell() tool
  □ search_code() tool
  □ run_tests() tool
  □ git_diff() tool
  □ git_commit() tool
□ Implement tool execution sandboxing
□ Add tool call logging
□ Create code patch extraction logic
□ Write integration tests for Developer execution
□ Test with sample tasks from various vulnerability classes
```

#### Week 9-10: Hybrid Judge Engine
```
□ Integrate Semgrep SAST:
  □ Install Semgrep in evaluation container
  □ Configure vulnerability-specific rules
  □ Implement rule matching and reporting
□ Implement Dynamic DAST:
  □ Create exploit payload library (30+ payloads)
  □ Implement exploit execution harness
  □ Add success indicator detection
  □ Implement evidence capture
□ Implement dual-stage evaluation logic
□ Add judge result logging
□ Write integration tests for Judge
□ Test with known vulnerable and secure code samples
```

### 3.3 Deliverables
- LLM client abstraction layer
- Attacker Agent with 7 vulnerability class templates
- Developer Agent with 7 tools
- Hybrid Judge Engine with SAST + DAST
- Agent communication protocol

### 3.4 Validation Criteria
- [ ] Attacker generates realistic tasks for all vulnerability classes
- [ ] Developer completes tasks using tool-use framework
- [ ] Judge correctly identifies vulnerable code (precision > 90%)
- [ ] Judge correctly identifies secure code (recall > 95%)
- [ ] Full agent loop completes end-to-end

---

## 4. Phase 3: Prompt Evolution Engine (Weeks 11-14)

### 4.1 Objectives
- Implement failure trace capture and storage
- Build Distiller Agent for rule generation
- Create prompt version control system
- Implement regression guarding

### 4.2 Tasks

#### Week 11-12: Distiller Agent
```
□ Design Distiller system prompt (see agent.md §5.2)
□ Implement trace capture pipeline:
  □ Code patch diff extraction
  □ SAST rule match extraction
  □ Dynamic exploit output extraction
  □ Raw log aggregation
□ Implement trace → rule distillation
□ Add semantic deduplication:
  □ Sentence-transformers embedding model
  □ Cosine similarity comparison
  □ Duplicate threshold configuration
□ Create rule quality validation
□ Write unit tests for distillation pipeline
□ Test with 50+ failure traces
```

#### Week 13: Prompt Version Control
```
□ Design prompt versioning schema:
  □ Version ID (incremental)
  □ Parent version reference
  □ Rule additions/removals
  □ Commit message
  □ Timestamp
□ Implement Git-based prompt store:
  □ Each version is a Git commit
  □ Full diff history between versions
  □ Branch support for experimental rules
□ Implement prompt retrieval by version
□ Add prompt diff visualization
□ Create prompt rollback capability
□ Write integration tests for versioning
```

#### Week 14: Regression Guarding
```
□ Implement Historical Archive:
  □ Task storage with outcomes
  □ Prompt version association
  □ Outcome tracking
□ Implement regression detection:
  □ Run candidate prompt against passing tasks
  □ Detect outcome changes (0→1)
  □ Identify specific regression causes
□ Implement rule refinement pipeline:
  □ Feed regression traces back to Distiller
  □ Generate refined rules
  □ Retry with refined rules (max 3 attempts)
□ Add regression metrics tracking
□ Write integration tests for regression guarding
```

### 4.3 Deliverables
- Distiller Agent with trace-to-rule conversion
- Semantic deduplication system
- Git-based prompt version control
- Regression Guard with retroactive evaluation

### 4.4 Validation Criteria
- [ ] Distiller generates clear, actionable rules from failure traces
- [ ] Deduplication prevents redundant rules (>85% similarity threshold)
- [ ] Prompt versioning maintains full history with diffs
- [ ] Regression Guard detects 100% of regressions on historical tasks
- [ ] Rule refinement pipeline resolves regressions within 3 attempts

---

## 5. Phase 4: Elo Rating System (Weeks 15-16)

### 5.1 Objectives
- Implement Elo rating calculator
- Map ratings to difficulty tiers
- Integrate with training loop controller

### 5.2 Tasks

#### Week 15: Elo Calculator
```
□ Implement Elo rating calculation:
  □ Expected score function (logistic)
  □ Rating update function
  □ Rating bounds enforcement
□ Implement rating persistence:
  □ Store ratings in database
  □ Load ratings on startup
  □ Update ratings after each episode
□ Implement difficulty tier mapping:
  □ Rating difference → tier (1-10)
  □ Tier validation and bounds
□ Add rating history tracking
□ Write unit tests for Elo calculations
```

#### Week 16: Integration
```
□ Integrate Elo with training loop:
  □ Pass ratings to Attacker Agent
  □ Use ratings for difficulty tier selection
  □ Update ratings after Judge evaluation
□ Implement rating visualization:
  □ Elo history API endpoint
  □ Rating convergence tracking
□ Add K-factor tuning interface
□ Write integration tests for full loop with Elo
□ Test convergence over 100+ episodes
```

### 5.3 Deliverables
- Elo rating calculator
- Difficulty tier mapper
- Rating persistence and history
- Integration with training loop

### 5.4 Validation Criteria
- [ ] Elo ratings converge after 50+ episodes
- [ ] Difficulty tiers correlate with rating differences
- [ ] Ratings persist across system restarts
- [ ] Full training loop uses Elo for difficulty matching

---

## 6. Phase 5: Telemetry & Dashboard (Weeks 17-19)

### 6.1 Objectives
- Implement metrics collection
- Build Grafana dashboards
- Create alerting rules
- Add export capabilities

### 6.2 Tasks

#### Week 17: Metrics Collection
```
□ Set up Prometheus metrics server
□ Define core metrics:
  □ Episode count (total, by outcome)
  □ Elo ratings (attacker, developer)
  □ Win rates (attacker, developer)
  □ Rule count (total, by vulnerability class)
  □ Judge evaluation time
  □ LLM call latency
  □ Container lifecycle duration
  □ Cost per episode
□ Implement metrics exporters:
  □ Application metrics
  □ Database metrics
  □ Container metrics
  □ LLM API metrics
□ Add metric labels and dimensions
```

#### Week 18: Dashboards
```
□ Create Grafana dashboards:
  □ Executive Summary:
    □ Total episodes, success rate, trend
    □ Current Elo ratings
    □ Vulnerability coverage heatmap
  □ Training Dynamics:
    □ Elo rating history (dual-axis chart)
    □ Win rate over time
    □ Difficulty tier distribution
  □ System Health:
    □ Container lifecycle metrics
    □ LLM API latency and errors
    □ Database performance
  □ Cost Analysis:
    □ Cost per episode trend
    □ LLM token usage breakdown
    □ Total cost to date
  □ Security Coverage:
    □ Rules by vulnerability class
    □ Regression detection events
    □ Rule quality metrics
□ Add dashboard annotations for key events
□ Create dashboard sharing and export
```

#### Week 19: Alerting & Export
```
□ Configure Prometheus alerting rules:
  □ High error rate (>5%)
  □ LLM API failures
  □ Container crashes
  □ Database connection issues
  □ Cost anomalies
□ Implement alert notification:
  □ Slack integration
  □ Email alerts
  □ PagerDuty integration
□ Create data export capabilities:
  □ JSON export of all metrics
  □ CSV export for analysis
  □ API endpoint for external tools
□ Write documentation for dashboard usage
```

### 6.3 Deliverables
- Prometheus metrics collection
- Grafana dashboards (5 panels)
- Alerting rules and notifications
- Data export capabilities

### 6.4 Validation Criteria
- [ ] Metrics are collected and stored correctly
- [ ] Dashboards display real-time data
- [ ] Alerts trigger on defined conditions
- [ ] Data export produces valid JSON/CSV

---

## 7. Phase 6: Benchmarking & Validation (Weeks 20-22)

### 7.1 Objectives
- Run Cold Start demonstration
- Validate vulnerability coverage
- Stress test the system
- Create benchmarking report

### 7.2 Tasks

#### Week 20: Cold Start Demo
```
□ Run Cold Start Phase:
  □ Initialize Developer with empty P_0
  □ Generate Attacker task (SQLi)
  □ Developer fails (introduces vulnerability)
  □ Judge confirms J=1
  □ Distiller generates rule ρ_1
  □ Rule added to P_D^(1)
  □ Log all metrics
□ Run Live Rule Distillation Phase:
  □ Generate new Attacker task (SQLi, different context)
  □ Developer succeeds with new rule (J=0)
  □ Judge confirms secure code
  □ Elo ratings updated
  □ Log all metrics
□ Run Immediate Regression Check Phase:
  □ Verify no regressions on historical tasks
  □ Document rule effectiveness
□ Record video demo of full cycle
```

#### Week 21: Coverage Validation
```
□ Run 500+ training episodes across all vulnerability classes:
  □ SQLi: 100 episodes
  □ Path Traversal: 100 episodes
  □ SSRF: 80 episodes
  □ Deserialization: 70 episodes
  □ XSS: 60 episodes
  □ Command Injection: 50 episodes
  □ SSTI: 40 episodes
□ Measure:
  □ Vulnerability detection rate per class
  □ False positive rate
  □ Rule generation rate
  □ Regression rate
  □ Elo convergence behavior
  □ Cost per episode
□ Create coverage heatmap
□ Document failure modes and edge cases
```

#### Week 22: Stress Testing & Documentation
```
□ Stress test:
  □ Run 100 concurrent episodes
  □ Measure system throughput
  □ Identify bottlenecks
  □ Document scaling limits
□ Performance benchmarks:
  □ Container startup time
  □ Judge evaluation latency
  □ Distillation pipeline throughput
  □ API response times
□ Create final documentation:
  □ System architecture document
  □ API reference
  □ Deployment guide
  □ Operations runbook
  □ Benchmarking report
□ Prepare release package
```

### 7.3 Deliverables
- Cold Start demonstration (video + documentation)
- Coverage validation report (500+ episodes)
- Performance benchmarks
- Complete documentation suite
- Release package

### 7.4 Validation Criteria
- [ ] Cold Start demo completes successfully
- [ ] Vulnerability detection rate >95% across all classes
- [ ] False positive rate <5%
- [ ] System handles 100 concurrent episodes
- [ ] All documentation complete and reviewed

---

## 8. Project Structure

### 8.1 Monorepo Layout

```
coevolve-sandbox/
├── README.md
├── LICENSE
├── docker-compose.yml
├── Makefile
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── deploy.yml
│       └── release.yml
├── packages/
│   ├── api/                          # REST API server
│   │   ├── src/
│   │   │   ├── routes/
│   │   │   ├── models/
│   │   │   ├── services/
│   │   │   └── middleware/
│   │   ├── tests/
│   │   └── package.json
│   ├── agents/                       # Agent implementations
│   │   ├── attacker/
│   │   │   ├── prompts/
│   │   │   ├── templates/
│   │   │   └── generator.py
│   │   ├── developer/
│   │   │   ├── prompts/
│   │   │   ├── tools/
│   │   │   └── executor.py
│   │   ├── distiller/
│   │   │   ├── prompts/
│   │   │   └── pipeline.py
│   │   └── regression_guard/
│   │       └── guard.py
│   ├── judge/                        # Hybrid Judge Engine
│   │   ├── sast/
│   │   │   ├── semgrep_rules/
│   │   │   └── scanner.py
│   │   ├── dast/
│   │   │   ├── payloads/
│   │   │   └── executor.py
│   │   └── engine.py
│   ├── elo/                          # Elo Rating System
│   │   ├── calculator.py
│   │   ├── difficulty.py
│   │   └── history.py
│   ├── evolution/                    # Prompt Evolution Engine
│   │   ├── versioning.py
│   │   ├── store.py
│   │   └── regression.py
│   ├── sandbox/                      # Container Orchestration
│   │   ├── docker/
│   │   │   ├── Dockerfile
│   │   │   ├── hardened.Dockerfile
│   │   │   └── seccomp-profile.json
│   │   ├── manager.py
│   │   └── lifecycle.py
│   └── telemetry/                    # Monitoring & Metrics
│       ├── prometheus/
│       │   └── config.yml
│       ├── grafana/
│       │   └── dashboards/
│       └── exporters/
├── data/
│   ├── vulnerability_taxonomy/
│   ├── semgrep_rules/
│   └── exploit_payloads/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── docs/
│   ├── architecture.md
│   ├── api-reference.md
│   ├── deployment.md
│   └── operations.md
└── scripts/
    ├── setup.sh
    ├── test.sh
    └── deploy.sh
```

### 8.2 Key Files

| File | Purpose | Lines (Est.) |
|------|---------|--------------|
| `packages/sandbox/manager.py` | Container lifecycle management | 500 |
| `packages/agents/attacker/generator.py` | Task generation pipeline | 800 |
| `packages/agents/developer/executor.py` | Developer execution with tools | 1000 |
| `packages/judge/engine.py` | Hybrid Judge orchestration | 600 |
| `packages/judge/sast/scanner.py` | Semgrep integration | 400 |
| `packages/judge/dast/executor.py` | Exploit execution harness | 700 |
| `packages/agents/distiller/pipeline.py` | Failure → rule distillation | 500 |
| `packages/elo/calculator.py` | Elo rating mathematics | 200 |
| `packages/evolution/versioning.py` | Prompt version control | 400 |
| `packages/evolution/regression.py` | Regression detection | 300 |
| `packages/api/src/routes/*.py` | REST API endpoints | 1500 |
| **Total Estimated** | | **~7000** |

---

## 9. Risk Mitigation

### 9.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| LLM API rate limits | High | Medium | Implement request queuing, use multiple providers |
| Container escape vulnerability | Low | High | Use gVisor/Firecracker, regular security audits |
| Semgrep false negatives | Medium | Medium | Expand rule set, regular rule updates |
| Distillation produces poor rules | Medium | High | Human review of first 50 rules, quality metrics |
| Elo system oscillates | Low | Medium | K-factor tuning, rating bounds |
| Regression Guard misses cases | Low | High | Expand historical archive, increase test coverage |

### 9.2 Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Database corruption | Low | High | Regular backups, WAL mode, replication |
| LLM provider outage | Medium | Medium | Multi-provider fallback, local model backup |
| Disk space exhaustion | Medium | Medium | Log rotation, container cleanup, monitoring |
| Cost overruns | Medium | Medium | Cost tracking, budget alerts, rate limiting |

### 9.3 Timeline Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Phase 1 delays | Medium | High | Parallel workstreams, MVP scope |
| LLM integration issues | Medium | High | Early prototyping, provider support |
| Judge accuracy insufficient | Medium | High | Iterative rule refinement, expert review |
| Performance bottlenecks | Low | Medium | Load testing from Week 15 |

---

## 10. Success Metrics

### 10.1 Build Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Code coverage | >80% | Unit + integration tests |
| API response time | <200ms p95 | Load testing |
| Container startup | <5s | Lifecycle metrics |
| Judge evaluation | <30s per episode | Timing metrics |
| System uptime | >99.5% | Monitoring |

### 10.2 Training Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Vulnerability detection | >95% | Judge results |
| False positive rate | <5% | Audit of rules |
| Elo convergence | <50 episodes | Rating history |
| Rule quality | >90% actionable | Manual review |
| Regression rate | <1% | Regression Guard |

### 10.3 Business Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Cost per episode | <$0.20 | Token tracking |
| Episodes per hour | >100 | Throughput metrics |
| Time to first rule | <10 episodes | Training metrics |
| Coverage of vulnerability classes | 100% | Coverage report |

---

## 11. Dependencies

### 11.1 External Dependencies

| Dependency | Version | Purpose | License |
|-----------|---------|---------|---------|
| Python | 3.11+ | Core language | PSF |
| Docker | 24.0+ | Container runtime | Apache 2.0 |
| PostgreSQL | 15+ | Primary database | PostgreSQL License |
| Redis | 7.0+ | Cache and queue | BSD-3 |
| Semgrep | 1.50+ | Static analysis | LGPL-2.1 |
| Grafana | 10.0+ | Dashboards | AGPL-3.0 |
| Prometheus | 2.45+ | Metrics | Apache 2.0 |
| Anthropic SDK | Latest | Claude integration | MIT |
| OpenAI SDK | Latest | GPT integration | Apache 2.0 |
| sentence-transformers | 2.2+ | Semantic deduplication | Apache 2.0 |
| FastAPI | 0.100+ | REST API framework | MIT |
| SQLAlchemy | 2.0+ | Database ORM | MIT |

### 11.2 Internal Dependencies

```
api → agents, sandbox, elo, evolution
agents/attacker → api (task storage)
agents/developer → sandbox (container execution), api (patch storage)
agents/distiller → evolution (prompt store)
judge → sandbox (exploit execution), api (results storage)
elo → api (rating storage)
evolution → api (prompt storage)
telemetry → prometheus, grafana
```

---

## 12. Definition of Done

### Phase Done Criteria
Each phase is complete when:
1. All tasks marked as complete
2. All deliverables produced
3. All validation criteria met
4. Code reviewed and merged
5. Tests passing (unit + integration)
6. Documentation updated
7. Demo/verification completed

### Project Done Criteria
The project is complete when:
1. All 6 phases complete
2. 500+ training episodes executed
3. Vulnerability detection rate >95%
4. False positive rate <5%
5. Cold Start demo recorded
6. Full documentation suite published
7. Release package prepared
