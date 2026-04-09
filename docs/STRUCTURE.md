# Project Structure Documentation

## Directory Layout

```
devsecops-auto-remediation/
├── .github/
│   └── workflows/
│       ├── ci-security-scan.yml          # Main pipeline: parallel scanning
│       ├── triage-and-remediate.yml      # Triage, codemod, validation, PR
│       └── policy-evaluation.yml          # OPA policy checks
│
├── cmd/
│   ├── triage-engine/
│   │   └── main.go                       # Entry point for triage service
│   ├── remediation-runner/
│   │   └── main.go                       # Entry point for codemod executor
│   ├── validation-gate/
│   │   └── main.go                       # Entry point for validation service
│   └── api-server/
│       └── main.go                       # Backend API for dashboard
│
├── internal/
│   ├── sarif/
│   │   ├── parser.go                     # SARIF v2.1.0 parser implementation
│   │   ├── models.go                     # SARIF type definitions
│   │   └── parser_test.go                # Parser unit tests
│   ├── triage/
│   │   ├── engine.go                     # Core triage logic: severity filtering
│   │   ├── dedup.go                      # Finding deduplication with CWE mapping
│   │   ├── correlator.go                 # Cross-scanner result correlation
│   │   └── triage_test.go                # Triage unit tests
│   ├── remediation/
│   │   ├── codemod.go                    # Tree-sitter codemod orchestrator
│   │   ├── patcher.go                    # AST patch application
│   │   └── remediation_test.go           # Remediation unit tests
│   ├── validation/
│   │   ├── gate.go                       # Validation gate coordinator
│   │   ├── test_runner.go                # Language-specific test execution
│   │   ├── linter.go                     # Linter integration
│   │   └── rescan.go                     # Lightweight security rescan
│   ├── prbot/
│   │   ├── github.go                     # GitHub API client wrapper
│   │   ├── branch.go                     # Branch creation logic
│   │   ├── commit.go                     # Structured commit generation
│   │   └── metadata.go                   # PR metadata attachment
│   ├── policy/
│   │   ├── opa.go                        # OPA/Rego evaluation engine
│   │   └── policy_test.go                # Policy unit tests
│   └── models/
│       ├── finding.go                    # Unified finding model
│       ├── scan.go                       # Scan metadata
│       └── pipeline.go                   # Pipeline metrics model
│
├── codemods/
│   ├── python/
│   │   ├── insecure_crypto.py            # MD5/SHA1 → SHA256 replacement
│   │   ├── sql_injection.py              # Raw SQL → parameterized query fix
│   │   └── tests/
│   │       ├── test_insecure_crypto.py   # Crypto codemod tests
│   │       └── test_sql_injection.py     # SQLi codemod tests
│   └── javascript/
│       ├── insecure_crypto.js            # crypto.createHash('md5') → 'sha256'
│       ├── xss_sanitization.js           # InnerHTML → safe DOM APIs
│       └── tests/
│           ├── test_insecure_crypto.js   # JS crypto codemod tests
│           └── test_xss_sanitization.js  # XSS codemod tests
│
├── policies/
│   ├── pr_approval.rego                  # PR scope, severity threshold rules
│   ├── license_compliance.rego           # Dependency license checking
│   ├── scope_limit.rego                  # Change scope boundaries
│   └── violation_report.rego             # Policy violation formatting
│
├── scripts/
│   ├── run-pipeline.sh                   # Local pipeline execution
│   ├── validation-gate.sh                # Standalone validation script
│   ├── e2e-test.sh                       # End-to-end test orchestrator
│   ├── benchmark.sh                      # Benchmark execution
│   └── setup-env.sh                      # Environment initialization
│
├── db/
│   ├── migrations/
│   │   ├── 001_create_scans.sql          # Scans table DDL
│   │   ├── 002_create_findings.sql       # Findings table DDL
│   │   ├── 003_create_fixes.sql          # Fixes table DDL
│   │   ├── 004_create_policy_decisions.sql  # Policy decisions DDL
│   │   └── 005_create_pipeline_metrics.sql  # Metrics table DDL
│   └── seed/
│       └── sample_data.sql               # Development seed data
│
├── api/
│   ├── handlers/
│   │   ├── scans.go                      # Scan CRUD endpoints
│   │   ├── findings.go                   # Finding query/update
│   │   ├── fixes.go                      # Fix status tracking
│   │   ├── metrics.go                    # Prometheus metrics export
│   │   └── dashboard.go                  # Dashboard data aggregation
│   ├── middleware/
│   │   ├── auth.go                       # JWT/OAuth2 middleware
│   │   ├── logging.go                    # Structured JSON logging
│   │   └── ratelimit.go                  # Rate limiting
│   ├── router.go                         # HTTP router setup
│   └── openapi.yaml                      # OpenAPI 3.0 specification
│
├── frontend/
│   ├── pages/
│   │   ├── index.tsx                     # Dashboard overview
│   │   ├── scans.tsx                     # Scan history view
│   │   ├── findings.tsx                  # Findings explorer
│   │   └── [id]/report.tsx               # Individual scan report
│   ├── components/
│   │   ├── MetricCard.tsx                # KPI display component
│   │   ├── FindingTable.tsx              # Sortable findings table
│   │   ├── SeverityChart.tsx             # Recharts severity visualization
│   │   └── PipelineTimeline.tsx          # Pipeline execution timeline
│   ├── lib/
│   │   ├── api.ts                        # API client
│   │   └── utils.ts                      # Utility functions
│   ├── styles/
│   │   └── globals.css                   # Tailwind global styles
│   ├── next.config.js                    # Next.js configuration
│   └── tailwind.config.js                # Tailwind configuration
│
├── docker/
│   ├── triage-engine/
│   │   └── Dockerfile                    # Triage service container
│   ├── remediation-runner/
│   │   └── Dockerfile                    # Codemod executor container
│   ├── validation-gate/
│   │   └── Dockerfile                    # Validation service container
│   ├── api-server/
│   │   └── Dockerfile                    # API server container
│   └── frontend/
│       └── Dockerfile                    # Next.js frontend container
│
├── reports/                              # Generated reports (gitignored)
│   ├── sarif/                            # Raw SARIF outputs
│   ├── fixes/                            # Generated patches
│   └── benchmarks/                       # Benchmark results
│
├── docs/
│   ├── ARCHITECTURE.md                   # System architecture documentation
│   ├── STRUCTURE.md                      # This file
│   ├── CODEMOD_DESIGN.md                 # Codemod design guide
│   ├── API.md                            # API reference
│   └── BENCHMARK.md                      # Benchmark methodology
│
├── docker-compose.yml                    # Local development stack
├── Makefile                              # Build/test/lint targets
├── .env.example                          # Environment template
├── go.mod                                # Go module definition
├── go.sum                                # Go dependency lock
├── package.json                          # Frontend dependencies
└── README.md                             # Project overview
```

## Module Responsibilities

### Core Services (Go - `cmd/` + `internal/`)

| Module | Responsibility | Entry Point |
|--------|---------------|-------------|
| `triage-engine` | Parse SARIF, deduplicate findings, correlate scanner results | `cmd/triage-engine/main.go` |
| `remediation-runner` | Execute Tree-sitter codemods, generate patches | `cmd/remediation-runner/main.go` |
| `validation-gate` | Run tests, linting, rescan on modified files | `cmd/validation-gate/main.go` |
| `api-server` | Serve dashboard API, metrics, finding queries | `cmd/api-server/main.go` |

### Codemods (`codemods/`)

Language-specific AST transformations. Each codemod:
1. Parses source files into AST using Tree-sitter
2. Identifies vulnerable patterns via node queries
3. Applies deterministic transformations
4. Outputs patched source code

Current supported patterns:
- **Python:** `hashlib.md5()`/`hashlib.sha1()` → `hashlib.sha256()`, raw SQL → parameterized queries
- **JavaScript:** `crypto.createHash('md5')` → `crypto.createHash('sha256')`, `innerHTML` → `textContent`

### Policies (`policies/`)

Rego files evaluated by OPA:
- **PR Approval:** Enforce severity thresholds, change scope limits, required reviewers
- **License Compliance:** Block disallowed licenses (GPL, AGPL)
- **Scope Limit:** Prevent codemods from touching files outside security-relevant paths
- **Violation Report:** Format policy failures for audit logging

### Database (`db/`)

PostgreSQL schema with 5 core tables:
- `scans` - Pipeline execution metadata
- `findings` - Deduplicated vulnerability records
- `fixes` - Applied remediation patches
- `policy_decisions` - OPA evaluation results
- `pipeline_metrics` - Performance and accuracy tracking

### Frontend (`frontend/`)

Next.js + Tailwind + Recharts dashboard providing:
- Real-time pipeline status
- Finding exploration with filtering/sorting
- Severity distribution charts
- Per-scan detailed reports with CSV/PDF export

### CI/CD (`.github/workflows/`)

Three workflow files implementing the full pipeline:
1. `ci-security-scan.yml` - Parallel scanner execution
2. `triage-and-remediate.yml` - Triage → Codemod → Validate → PR
3. `policy-evaluation.yml` - OPA gate checks

### Docker (`docker/`)

Ephemeral container definitions for each pipeline stage, ensuring isolation and reproducibility.
