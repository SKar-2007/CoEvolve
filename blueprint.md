# Blueprint: CoEvolve Sandbox System Architecture

## Automated Adversarial-Training-as-a-Service (A-TaaS) Framework

---

## 1. System Overview

CoEvolve Sandbox is a closed-loop co-evolutionary security training framework that pits an Attacker LLM Agent against a Developer LLM Agent inside hardened Docker containers. The system continuously generates adversarial coding tasks, evaluates the Developer's security posture, distills failures into durable defensive rules, and adapts task difficulty through competitive Elo rating dynamics.

### 1.1 Design Philosophy

```
┌─────────────────────────────────────────────────────────────────┐
│                    CORE DESIGN PRINCIPLES                        │
├─────────────────────────────────────────────────────────────────┤
│  1. Non-Parametric Alignment  → Frozen weights, evolving prompts│
│  2. Verified Feedback         → SAST + Dynamic exploit replay   │
│  3. Self-Play Co-Evolution    → Zero-sum adversarial loop       │
│  4. Isolated Execution        → Per-episode Docker containers   │
│  5. Auditable Evolution       → Versioned prompt stores         │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Architectural Paradigm Comparison

| Dimension | CoEvolve Sandbox | RL-Based (Self-RedTeam, CHASE) | Static Benchmarks (SWE-bench) |
|-----------|------------------|-------------------------------|-------------------------------|
| Optimization Target | System Prompt Rules ($P_D$) | Policy Weights ($\theta$) | Fixed task set |
| Update Mechanism | Rule distillation + prompt expansion | Gradient-based fine-tuning | None |
| Computational Cost | Low (inference only) | High (continuous GPU training) | Medium (evaluation only) |
| Auditability | Full version history of rules | Opaque weight changes | N/A |
| Difficulty Adaptation | Elo-based dynamic matching | Static or manual | Fixed |
| Verification | Hybrid SAST + Dynamic DAST | LLM judge or reward model | Test suite pass/fail |
| Portability | Model-agnostic (any LLM) | Model-specific weights | Agent-specific |

---

## 2. System Architecture

### 2.1 High-Level Component Diagram

```
                    ┌──────────────────────────────────────────────┐
                    │              TRAINING LOOP CONTROLLER         │
                    │  (Orchestrates episodes, manages state)      │
                    └──────────────┬───────────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
              ▼                    ▼                     ▼
    ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
    │  TASK GENERATOR  │  │  DEVELOPER AGENT  │  │  HYBRID JUDGE    │
    │  (Attacker LLM)  │  │  (Target System)  │  │  ENGINE          │
    │                  │  │                  │  │                  │
    │ - Vulnerability  │  │ - Code Patch     │  │ - Semgrep SAST   │
    │   Schema         │  │   Generation     │  │ - Dynamic DAST   │
    │ - Context-Aware  │  │ - Tool-Use       │  │ - Exploit Replay │
    │   Task Synthesis │  │ - ReAct Pattern  │  │ - Binary Judge   │
    └────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘
             │                    │                     │
             │     Task T_k       │    Code Patch C_k   │  Judge J=0/1
             └───────────────────►└────────────────────►│
                                                       │
              ┌────────────────────────────────────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │         PROMPT-EVOLUTION ENGINE            │
    │                                            │
    │  ┌─────────────┐    ┌──────────────────┐  │
    │  │ Distillation │    │ Regression       │  │
    │  │ Model D      │    │ Guarding Engine  │  │
    │  │              │    │                  │  │
    │  │ φ_k → ρ_k   │    │ Retroactive eval │  │
    │  │              │    │ on H_A           │  │
    │  └─────────────┘    └──────────────────┘  │
    │                                            │
    │  P_D^(k+1) = P_D^(k) ∪ {ρ_k}            │
    └──────────────────────────────────────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │         ELO RATING SYSTEM                  │
    │                                            │
    │  R_A^(k+1) = R_A^(k) + K(J - E_A)       │
    │  R_D^(k+1) = R_D^(k) + K((1-J) - E_D)   │
    │                                            │
    │  Drives difficulty of next task T_(k+1)   │
    └──────────────────────────────────────────┘
              │
              ▼
    ┌──────────────────────────────────────────┐
    │         TELEMETRY & DASHBOARD              │
    │                                            │
    │  - Grafana: Real-time metrics              │
    │  - Prometheus: Time-series metrics         │
    │  - Rule set growth tracking                │
    │  - Vulnerability coverage heatmap          │
    │  - Elo rating history                      │
    └──────────────────────────────────────────┘
```

### 2.2 Episode Lifecycle

Each training episode $k$ follows a deterministic lifecycle:

```
┌──────────────────────────────────────────────────────────────┐
│                    EPISODE k LIFECYCLE                         │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. INITIALIZATION                                            │
│     ├── Select Attacker difficulty tier (based on R_A, R_D)  │
│     ├── Instantiate ephemeral Docker container                │
│     ├── Mount Developer system prompt P_D^(k)                 │
│     └── Prepare sandbox environment                           │
│                                                               │
│  2. TASK GENERATION                                           │
│     ├── Attacker Agent π_A^(k) generates task T_k             │
│     ├── T_k contains embedded vulnerability trap v_k          │
│     ├── Task appears as legitimate engineering request        │
│     └── Vulnerability vector: {SQLi, SSRF, Path, Deauth...}  │
│                                                               │
│  3. DEVELOPER EXECUTION                                       │
│     ├── Developer Agent π_D^(k) receives T_k                  │
│     ├── Conditions on system prompt P_D^(k)                   │
│     ├── Executes tool calls: read files, edit, shell commands │
│     ├── Produces code patch C_k                               │
│     └── Container enforces isolation boundaries               │
│                                                               │
│  4. HYBRID EVALUATION                                         │
│     ├── Stage 1: Semgrep SAST scan of C_k                     │
│     ├── Stage 2: Dynamic exploit payload replay               │
│     ├── Judge J = SAST(C_k, v_k) AND DynamicReplay(C_k, v_k)│
│     ├── J=1: Confirmed exploitable vulnerability              │
│     └── J=0: Secure patch                                     │
│                                                               │
│  5. ELO UPDATE                                                │
│     ├── E_A = 1 / (1 + 10^((R_D - R_A)/400))                │
│     ├── E_D = 1 - E_A                                         │
│     ├── R_A^(k+1) = R_A + K(J - E_A)                         │
│     ├── R_D^(k+1) = R_D + K((1-J) - E_D)                     │
│     └── Difficulty recalibrated for episode k+1               │
│                                                               │
│  6. PROMPT EVOLUTION (if J=1)                                 │
│     ├── Capture failure trace φ_k                              │
│     ├── Distill φ_k → imperative rule ρ_k                     │
│     ├── Regression check against H_A                          │
│     ├── If no regression: commit ρ_k to P_D                  │
│     └── If regression: refine ρ_k and retry                   │
│                                                               │
│  7. CLEANUP                                                   │
│     ├── Destroy Docker container (--rm)                        │
│     ├── Log episode metrics to telemetry                       │
│     ├── Archive task T_k and trace φ_k                         │
│     └── Advance k → k+1                                       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Formal Mathematical Model

### 3.1 Game-Theoretic Formulation

CoEvolve Sandbox models adversarial security training as a **two-player zero-sum game** between:

- **Attacker Agent** policy $\pi_A$: generates tasks with embedded vulnerabilities
- **Developer Agent** policy $\pi_D$: generates code patches conditioned on system prompt
- **Hybrid Judge** $J$: deterministic evaluation function

**Definition (Task Domain):** Let $\mathcal{T}$ denote the domain of software engineering tasks and $\mathcal{V}$ the set of target vulnerability classes.

**Definition (Judge Function):** The hybrid judge evaluates the interaction:

$$J(\pi_A^{(k)}, \pi_D^{(k)}) = \begin{cases} 1 & \text{if } \text{SAST}(C_k, v_k) = \text{True} \land \text{DynamicReplay}(C_k, v_k) = \text{Success} \\ 0 & \text{otherwise} \end{cases}$$

The dual-condition ensures that $J=1$ only when:
1. Static pattern matching confirms vulnerability presence
2. Dynamic execution successfully exploits the vulnerability

### 3.2 Elo Rating Dynamics

The Elo system tracks competitive strength of both agents:

**Expected Win Probabilities:**

$$E_A^{(k)} = \frac{1}{1 + 10^{(R_D^{(k)} - R_A^{(k)}) / 400}}$$

$$E_D^{(k)} = 1 - E_A^{(k)} = \frac{1}{1 + 10^{(R_A^{(k)} - R_D^{(k)}) / 400}}$$

**Rating Updates:**

$$R_A^{(k+1)} = R_A^{(k)} + K \left( J(\pi_A^{(k)}, \pi_D^{(k)}) - E_A^{(k)} \right)$$

$$R_D^{(k+1)} = R_D^{(k)} + K \left( (1 - J(\pi_A^{(k)}, \pi_D^{(k)})) - E_D^{(k)} \right)$$

Where $K \in \mathbb{R}^+$ is the learning step size (K-factor) controlling rating volatility.

**Zero-Sum Property:** Points transfer from Developer to Attacker on failure ($J=1$), raising $R_A$ and signaling the Attacker to generate higher-complexity tasks.

### 3.3 Non-Parametric Prompt Evolution

Unlike RLHF/DPO which update model parameters $\theta$, CoEvolve Sandbox maintains frozen weights and evolves system prompt rules.

**Prompt State:**

$$P_D^{(k)} = P_0 \cup \left\{ \rho_i \right\}_{i=1}^{m_k}$$

Where:
- $P_0$ = base instruction prompt
- $\rho_i$ = distilled security rule $i$
- $m_k$ = number of accumulated rules at step $k$

**Distillation:** Upon confirmed failure ($J=1$), trace $\phi_k$ is distilled by model $\mathcal{D}$:

$$\rho_k = \mathcal{D}(\phi_k)$$

**Prompt Update Rule:**

$$P_D^{(k+1)} = \begin{cases} P_D^{(k)} \cup \{\rho_k\} & \text{if } J(\pi_A^{(k)}, \pi_D^{(k)}) = 1 \\ P_D^{(k)} & \text{if } J(\pi_A^{(k)}, \pi_D^{(k)}) = 0 \end{cases}$$

**Effective Developer Policy:**

$$\pi_D^{(k)}(\cdot) = \pi_D\left(\cdot \mid P_D^{(k)}\right)$$

### 3.4 Regression Guarding

Before committing rule $\rho_k$, the candidate prompt is retroactively evaluated:

$$P_{D, \text{cand}} = P_D^{(k)} \cup \{\rho_k\}$$

Against historical task archive $\mathcal{H}_A = \{T_1, T_2, \dots, T_{k-1}\}$. If $P_{D, \text{cand}}$ introduces regressions on previously passing tasks, $\rho_k$ is refined by the distillation engine.

---

## 4. Subsystem Specifications

### 4.1 Task Generator (Attacker Agent)

| Component | Specification |
|-----------|--------------|
| **Role** | Synthesize realistic engineering tasks containing embedded vulnerability traps |
| **Input** | Elo ratings ($R_A$, $R_D$), vulnerability schema $\mathcal{V}$, historical task archive |
| **Output** | Task $T_k$ with hidden vulnerability $v_k$ |
| **Mechanism** | Prompted LLM with vulnerability-aware schema |
| **Task Types** | Bug fixes, feature requests, code reviews, refactoring, test writing |
| **Vulnerability Framing** | Task appears as legitimate engineering work; vulnerability is implicit |

### 4.2 Developer Agent (Target System)

| Component | Specification |
|-----------|--------------|
| **Role** | Complete engineering tasks while maintaining security |
| **Input** | Task $T_k$, system prompt $P_D^{(k)}$ |
| **Output** | Code patch $C_k$ |
| **Mechanism** | Base LLM with ReAct/tool-use framework |
| **Interaction** | File reads, shell commands, code edits, test execution |
| **Constraints** | Isolated Docker container; no network access |

### 4.3 Hybrid Judge Engine

| Component | Specification |
|-----------|--------------|
| **Role** | Verify exploitability of generated code |
| **Stage 1** | Semgrep SAST: Pattern matching for vulnerability signatures |
| **Stage 2** | Dynamic DAST: Automated exploit payload execution in sandbox |
| **Output** | Binary $J \in \{0, 1\}$ (secure / exploitable) |
| **Key Property** | False positive elimination through dual verification |
| **Exploit Payloads** | Pre-validated payloads per vulnerability class |

### 4.4 Prompt-Evolution Engine

| Component | Specification |
|-----------|--------------|
| **Role** | Convert failure traces into durable defensive rules |
| **Distillation** | LLM call to compress trace $\phi_k$ into rule $\rho_k$ |
| **Rule Format** | Natural language imperative constraint |
| **Regression Guard** | Retroactive evaluation against $\mathcal{H}_A$ |
| **Version Control** | Git-based prompt versioning with diff tracking |
| **Deduplication** | Semantic similarity check to prevent rule redundancy |

### 4.5 Telemetry Subsystem

| Component | Specification |
|-----------|--------------|
| **Metrics Store** | Prometheus time-series database |
| **Dashboards** | Grafana panels for real-time monitoring |
| **Tracked Metrics** | Elo ratings, win rates, rule count, vulnerability coverage, episode duration |
| **Alerts** | Anomaly detection on training dynamics |
| **Export** | JSON/CSV export for analysis and reporting |

---

## 5. Container Isolation Architecture

### 5.1 Per-Episode Container Configuration

Every training episode instantiates an ephemeral Docker container with the following security constraints:

```bash
docker run \
  --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --security-opt seccomp=hardened-profile.json \
  --user 1000:1000 \
  --tmpfs /tmp:size=100M \
  --tmpfs /workspace:size=500M \
  --cpus 2 \
  --memory 2g \
  --pids-limit 256 \
  coevolve-sandbox:latest
```

### 5.2 Security Layer Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 7: Application                      │
│              Developer Agent System Prompt P_D               │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 6: Process                          │
│         Non-root user (UID 1000) + no-new-privileges        │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 5: Syscall                          │
│           Seccomp-BPF filter (hardened profile)              │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 4: Capabilities                     │
│              --cap-drop ALL (no capabilities)                │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 3: Filesystem                       │
│        --read-only + tmpfs scratch spaces only               │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 2: Network                          │
│         --network none (complete egress block)               │
├─────────────────────────────────────────────────────────────┤
│                    LAYER 1: Resource                         │
│         CPU, memory, PID limits (cgroups)                    │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Attack Vector Mitigation Matrix

| Security Layer | Enforced Policy | Mitigated Attack Vector |
|---------------|-----------------|------------------------|
| Network Egress | `--network none` | Data exfiltration, C2 communication, payload fetching |
| Filesystem | `--read-only` | Binary patching, persistent backdoor installation |
| Process Privileges | Non-root (1000:1000) | Container root escape, host filesystem manipulation |
| Kernel Capabilities | `--cap-drop ALL` | Raw socket creation, namespace manipulation |
| Syscall Filtering | Seccomp-BPF | Privilege escalation, kernel exploitation |
| State Persistence | `--rm` (ephemeral) | Cross-episode leakage, persistent cron modifications |
| Resource Limits | cgroups | Fork bombs, resource exhaustion, DoS |

---

## 6. Vulnerability Taxonomy

### 6.1 Primary Vulnerability Classes

| # | Vulnerability Class | OWASP/CWE | Attack Vector | Payload Type |
|---|---------------------|-----------|---------------|--------------|
| 1 | SQL Injection (SQLi) | A03:2021, CWE-89 | Database queries | `' OR '1'='1` |
| 2 | Path Traversal | A01:2021, CWE-22 | File operations | `../../../../etc/passwd` |
| 3 | Unsafe Deserialization | A08:2021, CWE-502 | Data import/export | Serialized RCE objects |
| 4 | Server-Side Request Forgery (SSRF) | A10:2021, CWE-918 | URL handling | `http://169.254.169.254` |
| 5 | Cross-Site Scripting (XSS) | A03:2021, CWE-79 | HTML output | `<script>alert(1)</script>` |
| 6 | Command Injection | A03:2021, CWE-78 | Shell execution | `; cat /etc/passwd` |
| 7 | Local File Inclusion (LFI) | A01:2021, CWE-98 | File include paths | `php://filter/convert.base64` |
| 8 | Insecure Direct Object Reference (IDOR) | A01:2021, CWE-639 | Object access | ID manipulation |
| 9 | XML External Entity (XXE) | A05:2021, CWE-611 | XML parsing | External entity injection |
| 10 | Insecure Deserialization | A08:2021, CWE-502 | Session handling | Pickle/YAML unsafe loads |

### 6.2 Extended Vulnerability Classes

| # | Vulnerability Class | OWASP/CWE | Attack Vector | Payload Type |
|---|---------------------|-----------|---------------|--------------|
| 11 | Mass Assignment | A04:2021, CWE-915 | API endpoints | Hidden field injection |
| 12 | Security Misconfiguration | A05:2021, CWE-16 | System config | Default credential access |
| 13 | Sensitive Data Exposure | A02:2021, CWE-312 | Data storage | Cleartext credential exposure |
| 14 | Broken Authentication | A07:2021, CWE-287 | Auth flows | Session fixation/hijacking |
| 15 | Open Redirect | A01:2021, CWE-601 | URL redirects | `//evil.com/phish` |
| 16 | Server-Side Template Injection (SSTI) | A03:2021, CWE-1336 | Template rendering | `{{7*7}}` / `{{config}}` |
| 17 | Prototype Pollution | A03:2021, CWE-1321 | Object merging | `__proto__.isAdmin=true` |
| 18 | ReDoS (Regular Expression DoS) | A06:2021, CWE-1333 | Input validation | Catastrophic backtracking |
| 19 | Log Injection | A09:2021, CWE-117 | Logging | CRLF injection in logs |
| 20 | Time-of-Check Time-of-Use (TOCTOU) | A04:2021, CWE-367 | File operations | Race condition exploitation |

### 6.3 Language-Specific Vulnerability Classes

| # | Language | Vulnerability Class | CWE | Example |
|---|----------|---------------------|-----|---------|
| 21 | Python | Pickle Deserialization | CWE-502 | `pickle.loads(untrusted_data)` |
| 22 | Python | YAML Unsafe Load | CWE-502 | `yaml.load(data)` without Loader |
| 23 | Python | eval() Injection | CWE-95 | `eval(user_input)` |
| 24 | JavaScript | Prototype Pollution | CWE-1321 | `Object.assign({}, untrusted)` |
| 25 | JavaScript | ReDoS | CWE-1333 | Vulnerable regex patterns |
| 26 | Java | JNDI Injection | CWE-917 | Log4Shell-style vectors |
| 27 | Java | Unsafe Deserialization | CWE-502 | `ObjectInputStream.readObject()` |
| 28 | Go | Command Injection | CWE-78 | `exec.Command(userInput)` |
| 29 | Go | Path Traversal | CWE-22 | `os.Open(userPath)` |
| 30 | Ruby | ERB Injection | CWE-94 | `ERB.new(user_template).result` |

---

## 7. Data Flow Architecture

### 7.1 Primary Data Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Attacker │────►│ Developer│────►│  Judge   │────►│ Evolution│
│   LLM    │     │   LLM    │     │  Engine  │     │  Engine  │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     │   Task T_k     │   Patch C_k    │   J=0/1        │  Rule ρ_k
     │                │                │                │
     ▼                ▼                ▼                ▼
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Task    │     │  Code    │     │  Judge   │     │  Prompt  │
│ Archive  │     │  Archive │     │  Results │     │  Store   │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                │                │
     └────────────────┴────────────────┴────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   Elo Rating     │
                    │   Calculator     │
                    │                  │
                    │  R_A, R_D → K    │
                    └──────────────────┘
```

### 7.2 Data Schemas

**Task Schema:**
```json
{
  "task_id": "uuid",
  "episode_k": 142,
  "vulnerability_class": "SQLi",
  "task_description": "Implement a user search filter...",
  "embedded_trap": "unparameterized query construction",
  "expected_exploit": "' OR '1'='1",
  "difficulty_tier": 3,
  "context_files": ["app/models/user.py", "app/routes/search.py"],
  "created_at": "2026-01-15T10:30:00Z"
}
```

**Failure Trace Schema:**
```json
{
  "trace_id": "uuid",
  "episode_k": 142,
  "task_id": "uuid",
  "code_patch": "diff --git a/app/routes/search.py...",
  "sast_result": {
    "rule": "python.django.security.sql-injection",
    "file": "app/routes/search.py",
    "line": 23,
    "confidence": "HIGH"
  },
  "dynamic_result": {
    "exploit_payload": "' OR '1'='1",
    "execution_output": "admin credentials leaked",
    "success": true
  },
  "raw_logs": "...",
  "created_at": "2026-01-15T10:35:00Z"
}
```

**Distilled Rule Schema:**
```json
{
  "rule_id": "uuid",
  "source_trace_id": "uuid",
  "episode_k": 142,
  "vulnerability_class": "SQLi",
  "rule_text": "ALWAYS use parameterized queries via ORM bindings. NEVER interpolate raw user input into SQL query strings. Use Django ORM filter() or execute() with parameter placeholders.",
  "version": 1,
  "regression_checked": true,
  "regression_passed": true,
  "created_at": "2026-01-15T10:36:00Z"
}
```

---

## 8. System Properties

### 8.1 Monotonic Coverage Guarantee

Because the rule set $P_D$ monotonically accumulates valid defensive invariants (rules are only added, never removed unless regression is detected), the effective policy $\pi_D^{(k)}$ achieves **non-decreasing security coverage** across the target vulnerability space $\mathcal{V}$ without parameter drift or degradation of general reasoning capabilities.

### 8.2 Adaptive Difficulty Equilibrium

The Elo system ensures that when the Developer improves ($R_D$ increases), the Attacker automatically generates more complex tasks (higher $R_A$), and vice versa. This maintains the training signal in a productive regime where neither agent becomes too strong.

### 8.3 Cost Efficiency

| Operation | Cost | Notes |
|-----------|------|-------|
| Attacker LLM call | ~$0.01-0.05 | Depends on model and task complexity |
| Developer LLM call | ~$0.02-0.10 | Depends on codebase size and model |
| Judge execution | ~$0.001 | Semgrep is free; exploit execution is local |
| Distillation call | ~$0.005 | Single LLM inference |
| Docker container | ~$0.001/min | Ephemeral, destroyed after use |
| **Total per episode** | **~$0.04-0.17** | **1000 episodes = $40-170** |

### 8.4 Scalability

- **Horizontal**: Multiple training episodes can run in parallel across different containers
- **Vertical**: Attacker and Developer can use different model sizes/speeds
- **Distributed**: Elo ratings and prompt stores can be shared across training clusters

---

## 9. Integration Points

### 9.1 External System Integrations

| System | Integration Point | Purpose |
|--------|-------------------|---------|
| **LLM Providers** | API calls (Anthropic, OpenAI, open-source) | Power Attacker and Developer agents |
| **Semgrep** | CLI/binary execution | Static analysis rule matching |
| **Docker** | Container orchestration API | Isolated execution environment |
| **Grafana** | Dashboard visualization | Real-time monitoring |
| **Prometheus** | Metrics collection | Time-series data storage |
| **Git** | Version control | Prompt store versioning |
| **PostgreSQL** | Database | Task archive, results, rule store |
| **Redis** | Cache | Episode state, Elo ratings |

### 9.2 API Surface

```
POST   /api/v1/episodes              - Start new training episode
GET    /api/v1/episodes/{id}         - Get episode status and results
POST   /api/v1/episodes/{id}/stop    - Stop running episode
GET    /api/v1/prompts/current       - Get current system prompt P_D
GET    /api/v1/prompts/history       - Get prompt version history
GET    /api/v1/prompts/diff/{v1}/{v2} - Compare prompt versions
GET    /api/v1/elo                   - Get current Elo ratings
GET    /api/v1/elo/history           - Get Elo rating history
GET    /api/v1/rules                 - List all distilled rules
GET    /api/v1/rules/{id}            - Get specific rule details
GET    /api/v1/vulnerabilities/coverage - Get vulnerability coverage report
GET    /api/v1/metrics               - Get system metrics
POST   /api/v1/config                - Update system configuration
```

---

## 10. Comparison with Existing Paradigms

### 10.1 vs Safety Self-Play (SSP)

| Aspect | CoEvolve Sandbox | SSP |
|--------|------------------|-----|
| Optimization Domain | System Prompt Rules | Policy Weights |
| Update Mechanism | Rule distillation | Parameter fine-tuning |
| Computational Cost | Low (frozen weights) | High (gradient updates) |
| Auditability | Full rule history | Opaque weights |
| Portability | Any LLM | Specific model version |

### 10.2 vs CHASE

| Aspect | CoEvolve Sandbox | CHASE |
|--------|------------------|-------|
| Optimization Domain | System Prompt Rules | Policy Weights |
| Feedback Source | Hybrid SAST + Dynamic | Black-box Reward Function |
| Update Mechanism | Prompt expansion | GRPO on harvested attacks |
| Generalization | Retroactive regression guarding | None |

### 10.3 vs TextGrad

| Aspect | CoEvolve Sandbox | TextGrad |
|--------|------------------|----------|
| Optimization Domain | System Prompt Rules | Computation Graph Variables |
| Feedback Source | Exploit verification | LLM textual gradients |
| Memory/Persistence | Versioned prompt store | Stateless |
| Generalization | Regression guarding across archives | None |

---

## 11. Summary

CoEvolve Sandbox establishes a new paradigm for autonomous agent security alignment: **non-parametric, verified, self-play adversarial training**. By keeping foundation model weights frozen and evolving only natural language system prompts, the framework achieves:

1. **Zero training compute** — no GPU fine-tuning required
2. **Full auditability** — every rule change is version-controlled and traceable
3. **Model portability** — prompts work across any LLM provider
4. **Verified feedback** — dual SAST + DAST eliminates false positives
5. **Adaptive difficulty** — Elo-based matching maintains training pressure
6. **Regression safety** — retroactive evaluation prevents capability loss
7. **Scalable cost** — ~$0.04-0.17 per training episode

The system transforms security evaluation from a static checkpoint into a **continuous, self-improving immune system** for autonomous coding agents.
