# Changelog

## [Unreleased]

### Added - All Deliverables Complete

#### Core Engine (Go)
- `cmd/triage-engine/main.go` — CLI for SARIF parsing, triage, dedup, CWE mapping
- `cmd/remediation-runner/main.go` — CLI for codemod orchestration
- `cmd/validation-gate/main.go` — CLI for test/lint/rescan validation
- `cmd/prbot/main.go` — CLI for PR creation with branch management
- `cmd/api-server/main.go` — Full REST API (Chi router) with all CRUD endpoints

#### Internal Packages
- `internal/models/` — Finding, Scan, Pipeline, FixRecord, PolicyDecision types
- `internal/sarif/` — SARIF v2.1.0 parser, models, normalization, CWE mapping, unit tests
- `internal/triage/` — Deduplicator, Correlator, grouping utilities, unit tests
- `internal/remediation/` — CodemodRegistry, Executor, Patcher
- `internal/validation/` — Gate, TestRunner, Linter, Rescan
- `internal/prbot/` — GitHubClient, BranchManager, CommitManager, PRMetadata
- `internal/policy/` — OPA/Rego evaluator, unit tests

#### Codemods (4 total + tests)
- `codemods/python/insecure_crypto.py` — MD5/SHA1 → SHA256
- `codemods/python/sql_injection.py` — Raw SQL → parameterized queries
- `codemods/javascript/insecure_crypto.js` — createHash('md5') → 'sha256'
- `codemods/javascript/xss_sanitization.js` — innerHTML → textContent, eval → blocked
- `codemods/python/tests/test_insecure_crypto.py` — 9 unit tests
- `codemods/python/tests/test_sql_injection.py` — 5 unit tests
- `codemods/javascript/tests/test_insecure_crypto.js` — 8 Jest tests
- `codemods/javascript/tests/test_xss_sanitization.js` — 6 Jest tests

#### OPA/Rego Policies (4 files)
- `policies/pr_approval.rego` — File/line limits, required labels, branch protection
- `policies/scope_limit.rego` — Blocks config/migration/secrets modifications
- `policies/license_compliance.rego` — Blocks GPL/AGPL dependencies
- `policies/violation_report.rego` — SIEM/audit-ready violation formatting

#### GitHub Actions (3 workflows)
- `.github/workflows/ci-security-scan.yml` — Parallel Semgrep + Trivy + ZAP
- `.github/workflows/triage-and-remediate.yml` — Triage → Codemod → Validate → PR
- `.github/workflows/policy-evaluation.yml` — OPA policy gate on PRs

#### Database
- `db/migrations/001_create_scans.sql`
- `db/migrations/002_create_findings.sql`
- `db/migrations/003_create_fixes.sql`
- `db/migrations/004_create_policy_decisions.sql`
- `db/migrations/005_create_pipeline_metrics.sql`
- `db/seed/sample_data.sql` — Development seed data

#### Frontend (Next.js + Tailwind + Recharts)
- `frontend/pages/index.tsx` — Dashboard overview with KPI cards
- `frontend/pages/scans.tsx` — Scan history with pagination
- `frontend/pages/findings.tsx` — Interactive findings explorer with status management
- `frontend/pages/_app.tsx` — App wrapper
- `frontend/components/MetricCard.tsx` — KPI display
- `frontend/components/SeverityChart.tsx` — Recharts bar chart
- `frontend/components/PipelineTimeline.tsx` — Recharts line chart
- `frontend/components/FindingTable.tsx` — Sortable findings table
- `frontend/lib/api.ts` — Full API client with TypeScript types
- `frontend/lib/utils.ts` — Utility functions
- `frontend/styles/globals.css` — Tailwind styles
- `frontend/next.config.js`, `tailwind.config.js`, `postcss.config.js`, `tsconfig.json`

#### Docker & Infrastructure
- `docker-compose.yml` — Full stack: PostgreSQL, API, Frontend, OPA, Prometheus, Grafana
- `docker/triage-engine/Dockerfile`
- `docker/remediation-runner/Dockerfile`
- `docker/validation-gate/Dockerfile`
- `docker/api-server/Dockerfile`
- `docker/frontend/Dockerfile`
- `docker/prometheus/prometheus.yml`
- `docker/grafana/provisioning/dashboards.yaml`
- `docker/grafana/provisioning/datasources.yaml`
- `docker/grafana/dashboards/devsecops-overview.json`

#### Scripts
- `scripts/e2e-test.sh` — End-to-end pipeline test
- `scripts/benchmark.sh` — Benchmark execution with report generation
- `scripts/validation-gate.sh` — Standalone validation script
- `scripts/setup-env.sh` — Environment initialization

#### Documentation
- `docs/STRUCTURE.md` — Complete directory structure with module descriptions
- `docs/ARCHITECTURE.md` — Mermaid architecture diagram + design trade-offs
- `docs/INSTALLATION.md` — Full setup guide with troubleshooting
- `docs/BENCHMARK.md` — Benchmark methodology with report template
- `api/openapi.yaml` — OpenAPI 3.0 specification
- `README.md` — Project overview
- `SECURITY.md` — Vulnerability reporting process
- `Makefile` — Build/test/lint/docker targets
