# How CoEvolve Is Different

## The Confusion

Judges are asking: "How is this different from Cursor bug finder or CodeRabbit?"

---

## Short Answer

Cursor and CodeRabbit **find bugs**. CoEvolve **trains agents to find and fix bugs** — and gets better every time.

---

## Comparison

| | Cursor Bug Finder | CodeRabbit | CoEvolve |
|---|---|---|---|
| **What it does** | Finds bugs while you code | Reviews pull requests | Trains adversarial agents |
| **When it works** | Reactive (after you write) | Reactive (after you push) | Proactive (runs training loops) |
| **How it works** | One model scans code | One model reviews diffs | 5 sub-agents compete |
| **Gets smarter?** | No | No | Yes — distills failures into rules |
| **Output** | Bug report | Review comment | Security rules + patches |
| **Portable?** | No (IDE lock-in) | No (GitHub only) | Yes — export rules as JSON |
| **Difficulty adapts?** | No | No | Yes — Elo rating system |
| **Architecture** | Single model | Single model | Multi-agent pipeline |
| **Deployment** | IDE plugin | GitHub app | API service (22 endpoints) |

---

## Key Differentiators

### 1. Platform vs Tool
- **Cursor/CodeRabbit:** Tools you use in one context (IDE or GitHub)
- **CoEvolve:** A service you plug into any project via API

### 2. Training vs Detection
- **Cursor/CodeRabbit:** Detect bugs in your current code
- **CoEvolve:** Runs adversarial episodes that train agents to get better at finding AND fixing bugs

### 3. Multi-Agent Architecture
- **Cursor/CodeRabbit:** One model does everything
- **CoEvolve:** Five specialized sub-agents:
  - Attacker (generates threats)
  - Developer (builds patches)
  - Judge (verifies with real exploits)
  - Distiller (learns from failures)
  - Training Loop Controller (orchestrates)

### 4. Learning System
- **Cursor/CodeRabbit:** Static — same model, same capabilities
- **CoEvolve:** Dynamic — every failure creates a new security rule that improves future episodes

### 5. Portable Security Rules
- **Cursor/CodeRabbit:** Rules stay in their system
- **CoEvolve:** Export rules as JSON packages, import into other projects, share with teams

### 6. Adaptive Difficulty
- **Cursor/CodeRabbit:** Same sensitivity always
- **CoEvolve:** Elo ratings auto-adjust — as developer improves, attacker gets harder

---

## The One-Liner

> Cursor finds bugs. CodeRabbit reviews code. CoEvolve **trains an evolving security system** that gets smarter with every episode.

---

## For Judges Who Ask

"Cursor and CodeRabbit are detection tools. CoEvolve is a training platform. We're not competing with them — we're building the layer above them. Our distilled rules could actually be fed INTO tools like Cursor to make them smarter."
