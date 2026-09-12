# Problem Statement: CoEvolve Sandbox

## Automated Adversarial Security Training for Autonomous Coding Agents

---

## 1. The Security Gap

### 1.1 The Rise of Autonomous Coding Agents

Autonomous software engineering agents have moved from research prototypes to production-deployed tools within 18 months. Systems like Devin, SWE-agent, Claude Code, GitHub Copilot Workspace, and OpenHands now execute shell commands, modify system files, compile dependencies, and commit code changes with minimal or zero human oversight. These agents operate in a perceive-reason-act loop with direct access to terminals, file systems, and compilers.

The operational reality is stark: **AI coding agents now have more access than senior developers**. They can execute arbitrary shell commands, modify production configurations, install packages, and make network requests. A single misconfigured agent running on a developer's machine or in a CI/CD pipeline can exfiltrate credentials, install persistent backdoors, or corrupt production databases.

### 1.2 The Evaluation Blind Spot

The dominant benchmark for autonomous coding agents is **SWE-bench** (and its variants: SWE-bench Verified, SWE-bench Lite, SWE-bench Multimodal). SOTA agents have progressed from 1.96% (2023) to 79.2% (2025) on SWE-bench Verified. However, SWE-bench evaluates **only functional correctness**:

- Does the patch resolve the described issue?
- Does the test suite pass?
- Are there regressions?

**SWE-bench does not evaluate whether the generated code introduces security vulnerabilities.** An agent can achieve a perfect score on SWE-bench while systematically introducing SQL injection, path traversal, unsafe deserialization, and server-side request forgery vulnerabilities into production codebases.

This is not a theoretical concern. Recent research demonstrates that:

- SOTA code agents achieve only **18% success rate** on security-relevant tasks (PoC generation) and **34% on vulnerability patching** (SEC-bench, NeurIPS 2025)
- **63.4% of LLM agents** without proper isolation leak sensitive data through conversation (Washington University research)
- Agents are vulnerable to **ToolLeak** attacks that perform malicious prompt exfiltration through benign argument retrieval during tool invocation
- The **jqwik supply chain attack** demonstrated that AI coding agents can be tricked into deleting evidence of malicious code through prompt injection hidden in npm packages

### 1.3 Why Existing Solutions Fall Short

#### Static Application Security Testing (SAST)
- **Coverage**: Limited to known pattern signatures; misses novel or context-dependent vulnerabilities
- **Adaptability**: Static rule sets cannot evolve with new attack vectors
- **False Positives**: High false-positive rates lead to developer fatigue and ignored warnings
- **Scope**: Cannot evaluate runtime behavior, data flow, or exploitability

#### Manual Red-Teaming
- **Cost**: Expert security engineers command $200-500+/hour
- **Latency**: Manual testing takes days to weeks per assessment
- **Coverage**: Human testers cannot cover the full combinatorial space of vulnerability × context × codebase combinations
- **Scalability**: Does not scale to the pace of autonomous agent deployment

#### Existing AI Safety Benchmarks
- **Agent-SafetyBench**: Evaluates LLM agent safety, but none achieve above 60% safety score
- **SecureVibeBench**: 105 C/C++ tasks; limited scope, no adversarial co-evolution
- **CVE-Bench**: Focuses on exploitation, not defense building
- **SEC-bench**: Real-world CVEs but static, non-adaptive evaluation

#### Reinforcement Learning-Based Approaches (Self-RedTeam, CHASE, ARLAS)
- **Computational Cost**: Require continuous gradient updates, expensive GPU compute
- **Catastrophic Forgetting**: Fine-tuning can degrade previously learned capabilities
- **Non-Interpretable**: Updated weights are opaque; no audit trail
- **Deployment Risk**: Modified models must be re-validated before production use

---

## 2. The Core Problem

**There exists no scalable, adaptive, and auditable system for continuously training autonomous coding agents to resist and avoid introducing security vulnerabilities — without requiring model weight updates.**

Specifically, the problem decomposes into four sub-problems:

### Problem 1: Static Evaluation

Current benchmarks evaluate agents against fixed, static datasets. As agents improve, the benchmarks saturate and lose discriminative power. SWE-bench Verified has gone from 1.96% to 79.2% in two years. Security benchmarks need to be **dynamic and self-refreshing** to maintain evaluative pressure.

### Problem 2: Non-Adaptive Difficulty

Existing evaluation frameworks assign uniform difficulty to all tasks. A task that is trivial for a defensively capable agent is wasted compute. There is no mechanism to **automatically calibrate task difficulty to match the current defensive capability** of the target agent.

### Problem 3: Brittle Defense Mechanisms

RL-based safety alignment (RLHF, DPO, PPO) updates model weights to improve safety. This approach is:
- **Expensive**: Requires GPU compute for every alignment step
- **Opaque**: Updated weights cannot be audited or version-controlled meaningfully
- **Risky**: Weight updates can degrade general reasoning and coding capability
- **Non-portable**: Alignment is specific to a model version; must be re-applied for every new model release

### Problem 4: Absence of Continuous Feedback Loops

When an agent introduces a vulnerability, the failure trace (what went wrong, why, and how) is typically discarded. There is no mechanism to **distill failure experience into durable, actionable defensive rules** that persist across training episodes and adapt the agent's behavior.

---

## 3. The Opportunity

### 3.1 Non-Parametric Alignment

The key insight: **system prompts are a non-parametric alignment mechanism**. Unlike weight updates, system prompts are:
- **Transparent**: Human-readable, auditable, version-controllable
- **Portable**: Work across any foundation model (Claude, GPT-4, Qwen, Llama, etc.)
- **Composable**: Rules can be added, removed, and prioritized without side effects
- **Instant**: No training compute required; takes effect on the next inference call

### 3.2 Self-Play as Training

Two-player zero-sum self-play has demonstrated remarkable effectiveness in training superhuman game-playing agents (AlphaGo, AlphaStar). Applied to security alignment:
- The **Attacker Agent** continuously discovers new vulnerability vectors
- The **Developer Agent** continuously defends against them
- Both agents co-evolve, maintaining competitive balance through Elo rating dynamics

### 3.3 Verified Feedback

Unlike LLM-as-a-judge approaches (which can be gamed or hallucinate), a **hybrid judge** combining static analysis (Semgrep) with dynamic exploit payload execution inside isolated containers provides **cryptographically verifiable** feedback. A vulnerability is confirmed if and only if both static patterns match AND the exploit payload executes successfully.

---

## 4. Success Criteria

CoEvolve Sandbox succeeds when it achieves the following measurable outcomes:

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Vulnerability Detection Rate** | >95% across all target vulnerability classes | Verified exploit payloads in isolated containers |
| **False Positive Rate** | <5% (rules only generated from confirmed failures) | Audit of generated rules against regression archive |
| **Difficulty Tracking** | Elo rating correlation >0.8 with empirical win rate | Pearson correlation between predicted and observed outcomes |
| **Prompt Bloat Control** | <100 rules after 1000 training episodes | Rule set size tracking with semantic deduplication |
| **Regression Prevention** | 0 regressions on historical tasks after rule addition | Retroactive evaluation against task archive |
| **Cold Start to Competence** | <50 episodes to first secure defense | Episodes to first J=0 against primary vulnerability classes |
| **Model Agnosticism** | Same system works with Claude, GPT-4, Qwen, Llama | Cross-model validation on identical task sets |

---

## 5. Scope and Boundaries

### In Scope
- Automated adversarial task generation by Attacker Agent
- Security evaluation of Developer Agent code patches
- Non-parametric prompt evolution via failure distillation
- Elo-based difficulty matching
- Docker-based runtime isolation
- Static (SAST) and dynamic (DAST) vulnerability verification
- Regression guarding across training history

### Out of Scope
- Model weight fine-tuning or parameter updates
- Network-level attack simulation (agents run with `--network none`)
- Physical hardware security testing
- Compliance certification (SOC2, ISO 27001) — though the system can inform such audits
- Real-world production deployment of defended agents (training only)

---

## 6. Stakeholder Impact

| Stakeholder | Pain Point | CoEvolve Sandbox Solution |
|-------------|-----------|--------------------------|
| **AI Safety Teams** | Cannot scale manual red-teaming to match agent deployment velocity | Automated adversarial training with continuous coverage |
| **Security Engineers** | SAST produces too many false positives; no exploit verification | Hybrid Judge with dynamic exploit confirmation |
| **ML/AI Engineers** | RLHF/DPO degrades model capabilities; expensive to maintain | Non-parametric prompt evolution with zero weight updates |
| **Platform Engineers** | Agent sandboxing is complex and error-prone | Pre-configured, hardened Docker container orchestration |
| **Compliance Officers** | No audit trail for model alignment decisions | Versioned prompt stores with full change history |
| **DevOps/SRE** | Cannot verify agent-generated code is production-safe | Verified vulnerability coverage before deployment |

---

## 7. References

1. **SWE-bench**: Jimenez et al., "SWE-bench: Can Language Models Resolve Real-World GitHub Issues?" ICLR 2024
2. **SEC-bench**: Lee et al., "SEC-bench: Automated Benchmarking of LLM Agents on Real-World Software Security Tasks" NeurIPS 2025
3. **SecureVibeBench**: Chen et al., "SecureVibeBench: Benchmarking Secure Vibe Coding of AI Agents" ACL 2026
4. **Self-RedTeam**: Liu et al., "Chasing Moving Targets with Online Self-Play Reinforcement Learning for Safer Language Models" ICML 2026
5. **CHASE**: "CHASE: Adversarial Red-Blue Teaming for Improving LLM Safety using Reinforcement Learning" 2026
6. **TextGrad**: Yuksekgonul et al., "Optimizing generative AI by backpropagating language model feedback" Nature 2025
7. **SePO**: Tao et al., "SePO: Self-Evolving Prompt Agent for System Prompt Optimization" 2026
8. **PromptBreeder**: Fernando et al., "Promptbreeder: Self-Referential Self-Improvement Via Prompt Evolution" 2023
9. **COvolve**: "COvolve: Adversarial Co-Evolution of LLM-Generated Policies and Environments" 2026
10. **OWASP Top 10 for LLM Applications 2026**: OWASP GenAI Security Project
11. **OWASP Top 10 for Agentic Applications 2026**: OWASP GenAI Security Project
12. **Chatbot Arena**: Zheng et al., "Chatbot Arena: Benchmarking LLMs in the Wild with Elo Ratings" 2023
