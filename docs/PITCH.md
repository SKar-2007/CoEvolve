# CoEvolve — A-TaaS Pitch

## What Is This Project?

**Adversarial Training as a Service (A-TaaS)** — a platform where multiple AI sub-agents work together to automatically discover and fix security vulnerabilities.

---

## The Problem

70% of data breaches start with known vulnerabilities that already have fixes. The problem isn't that we don't know how to fix them — it's that developers don't have time to find and fix them all.

---

## The Solution

Five specialized sub-agents working together as a platform:

| Sub-Agent | Job |
|-----------|-----|
| **Attacker** | Generates adversarial coding tasks across 10+ vulnerability classes |
| **Developer** | Uses ReAct tool loop (7 tools) to read code and build patches |
| **Judge** | Evaluates with Semgrep SAST + real DAST exploit replay |
| **Distiller** | Converts failure traces into reusable security rules |
| **Training Loop Controller** | Orchestrates the entire pipeline |

---

## How It Works

1. Attacker generates an adversarial task
2. Developer reads code and builds a patch
3. Judge runs SAST scan + DAST exploit replay against 19 live applications
4. If the patch fails, Distiller creates a new security rule
5. Regression Guard validates the rule doesn't break existing ones
6. Elo ratings update, difficulty adapts, loop repeats

Every failure makes the system stronger.

---

## Key Numbers

- 19 vulnerable applications (Python, JavaScript, Java)
- 29 Semgrep security rules
- 22 API endpoints
- 162 tests passing
- 3 language support
- 10 vulnerability classes

---

## Platform Features

- **Plug in your codebase** — run adversarial training on any project
- **Auto-generated security rules** — distilled from failures, portable as JSON
- **Elo rating system** — tracks sub-agent performance, auto-tunes difficulty
- **Full API** — 22 endpoints for episodes, training, rules, prompts, auth
- **Production-ready** — PostgreSQL, Redis, Docker, Prometheus, CI/CD
- **Open source** — MIT License

---

## The Pitch (3 Minutes)

> We built an Adversarial Training as a Service platform — A-TaaS.
>
> Instead of one AI doing security, we have five specialized sub-agents working together.
>
> The Attacker Agent generates adversarial coding tasks. The Developer Agent uses a ReAct tool loop — reading code, writing patches, running tests — to fix them. The Judge evaluates with real exploit replay across 19 live applications. The Distiller Agent converts failures into new security rules. And the Training Loop Controller orchestrates the entire pipeline.
>
> Every sub-agent has a job. Together, they form an evolving security system.
>
> The whole thing is a service. 22 API endpoints. Anyone can plug in their codebase, run training episodes, and get auto-generated security rules. Rules are portable — export them as JSON packages, import them into other projects.
>
> Elo ratings track each sub-agent's performance. As the developer improves, the attacker adapts. The system self-tunes.
>
> We built a live demo. Pick a vulnerability class, pick a language, click run — watch five sub-agents work in real-time.
>
> CoEvolve isn't a tool. It's a platform that gets smarter with every episode.

---

## Links

- **GitHub:** https://github.com/SKar-2007/CoEvolve
- **Live Demo:** https://frontend-three-azure-92.vercel.app
- **API Docs:** http://localhost:8000/docs (when running locally)

---

## Quick Start

```bash
git clone https://github.com/SKar-2007/CoEvolve.git
cd CoEvolve
make install
make run-api
make dast
make demo
```
