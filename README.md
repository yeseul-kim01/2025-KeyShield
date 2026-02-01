# KeyShield

**Browser-based Secret(DLP) Protection with Context-Aware Zero Trust Policy Automation**

---

## Overview

During development and operations, sensitive data such as API keys, OAuth tokens, JWTs, and secrets are most often leaked **not by attacks**, but by **simple human mistakes** — copy & paste into GitHub issues, Notion, Slack, AI tools, or web consoles.

KeyShield is a **browser-first DLP platform** that prevents secret leakage *before it happens* by enforcing security policies directly at the user’s browser.

Instead of detecting leaks after the fact, KeyShield blocks, warns, or masks secrets **at paste-time**, and automatically strengthens policies when risky behavior is repeatedly observed.

---

## Problem Statement

Traditional DLP solutions focus on:
- Network-level inspection
- Server-side scanning
- Post-incident detection

These approaches are **too late** for modern developer workflows.

Most leaks happen:
- In browsers
- During copy & paste
- Across SaaS tools and AI input fields
- Due to momentary carelessness

Once a secret is pasted and shared, **revocation is costly, slow, and often incomplete**.

---

## Key Idea

**Move DLP enforcement to the browser, and manage decisions using Zero Trust principles.**

KeyShield is built around:
- **Preventive enforcement**, not reactive detection
- **Context-aware policies**, not static rules
- **Automatic policy tightening**, not manual intervention

---

## Architecture (Zero Trust: PEP / PDP / PIP)

KeyShield follows a clear Zero Trust separation of responsibilities.

### PEP — Policy Enforcement Point (Chrome Extension)
- Detects user actions:
  - paste
  - input/textarea typing
  - drag & drop
  - file upload (metadata-based)
- Detects secrets using:
  - regex-based patterns
  - entropy-based validation
- Enforces decisions:
  - `BLOCK`
  - `WARN`
  - `MASK`
  - `ALLOW`

### PDP — Policy Decision Point (Spring Boot)
- Central policy evaluation engine
- Decides actions based on:
  - detected secret type & severity
  - user state
  - domain context
  - active policy versions
- Manages:
  - policy versioning
  - conflict resolution
  - audit logs
  - tenant/user-level policies

### PIP — Policy Information Point (Python)
- Context handler and risk engine
- Accumulates user risk scores
- Applies time-based decay
- Triggers automatic policy overlays (e.g. Restricted mode)
- Handles policy rollback after TTL expiration

---

## Event Flow (Paste Example)

1. User pastes text in a browser input field
2. Extension detects a potential secret
3. Extension requests a decision from PDP (`/policy/decide`)
4. PDP evaluates active policies and user context
5. Decision is returned to the extension
6. Extension enforces the action immediately
7. Audit event is stored (without raw secret)
8. Event is forwarded to PIP for risk evaluation
9. Policies may be automatically tightened or relaxed

---

## Security Principles (Non-Negotiable)

KeyShield **never stores raw secrets**.

- ❌ No raw secret transmission to server
- ❌ No raw secret storage in logs or databases
- ✅ Fingerprint (hashed with salt) only
- ✅ Partial masking (prefix/suffix) when needed
- ✅ Audit logs contain metadata only

Security is enforced by design, not convention.

---

## Repository Structure

```

keyshield/
├─ apps/
│  ├─ extension/      # Chrome Extension (PEP)
│  ├─ pdp/            # Spring Boot Policy Server (PDP)
│  └─ pip/            # Python Context Handler (PIP)
├─ infra/             # Docker Compose, env, deployment configs
├─ docs/              # Architecture, policy schema, threat model
└─ README.md

```

---

## Goals of This Project

This project is both **a learning exercise and a real, deployable service**.

Technical goals:
- Zero Trust PEP / PDP / PIP separation
- Policy engines with priority, conflict resolution, TTL, and rollback
- Context-aware risk scoring
- Browser-level security enforcement

Engineering goals:
- Clean architecture
- Auditability by default
- Operational realism (deployment, failure modes)
- Clear trade-offs between false positives and usability

---

## Status

🚧 **Work in Progress**

The project is being developed incrementally with a 7-day MVP roadmap, focusing on:
- Paste-time secret blocking
- Policy-based decisions
- Automatic risk-based policy enforcement

---

## Development Log

This project is documented as a full design → implementation → review series.

> Detailed architecture, policy design, and implementation notes will be published alongside development progress.

---
## License

MIT License

