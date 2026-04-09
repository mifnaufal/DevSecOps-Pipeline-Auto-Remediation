# DevSecOps Pipeline with Auto-Remediation

An enterprise-grade, deterministic security vulnerability detection and auto-remediation pipeline implementing Secure SDLC practices.

## Architecture Overview

```
[Commit/Push] → [CI Trigger] → [Parallel Scan: Semgrep + Trivy + ZAP]
       ↓ (SARIF/JSON)
[Triage & Correlation] → Filter severity ≥ High + tag `remediable`
       ↓
[Remediation Engine] → AST Codemod → [Validation Gate]
       ↓ (If pass) → [PR Automation] → [Policy Check (OPA)] → [Human Review]
       ↓ (If fail) → [Fallback: LLM constrained / Manual annotation]
       ↓
[Observability] → PostgreSQL ← Dashboard & Metrics
```

## Key Principles

- **Deterministic-First:** All remediations use AST/Tree-sitter transformations. LLM is fallback-only.
- **Least Privilege:** CI/CD tokens scoped to minimum required permissions.
- **Zero Auto-Merge:** All PRs require human approval and OPA policy evaluation.
- **Supply Chain Security:** SBOM generation, dependency pinning, artifact signature verification.
- **Audit & Immutability:** All pipeline decisions logged to WORM/SIEM-ready storage.

## Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd devsecops-auto-remediation
cp .env.example .env

# Run locally with Docker Compose
docker-compose up -d

# Execute end-to-end test
./scripts/e2e-test.sh
```

## Project Structure

See [docs/STRUCTURE.md](docs/STRUCTURE.md) for detailed module documentation.

## Benchmark Targets

| Metric | Target |
|--------|--------|
| Fix Accuracy Rate | ≥ 85% |
| False Positive Rate | ≤ 5% |
| Regression Incidence | 0% |
| Pipeline Duration | ≤ 120s (<500 files) |
| Policy Compliance | 100% |

## License

MIT

## Security

Report vulnerabilities via SECURITY.md process.
