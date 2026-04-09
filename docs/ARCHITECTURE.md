# System Architecture

## Architecture Diagram

```mermaid
graph TB
    subgraph "Developer Workflow"
        Dev[Developer] -->|git push| GH[GitHub Repository]
        GH -->|push event| CI[GitHub Actions]
    end

    subgraph "CI/CD Pipeline"
        CI -->|trigger| SCAN[Parallel Security Scan]
        
        subgraph "Stage 1: Scanning"
            SCAN -->|SAST| SEMGREP[Semgrep]
            SCAN -->|SCA| TRIVY[Trivy + Syft SBOM]
            SCAN -->|DAST| ZAP[OWASP ZAP]
        end
        
        SEMGREP -->|SARIF v2.1.0| TRIAGE
        TRIVY -->|SARIF| TRIAGE
        ZAP -->|SARIF| TRIAGE
        
        subgraph "Stage 2: Triage & Correlation"
            TRIAGE[SARIF Parser + Triage Engine]
            TRIAGE -->|dedup + CWE mapping| CORRELATE[Finding Correlator]
            CORRELATE -->|filtered findings| FINDINGS[(Findings DB)]
        end
        
        CORRELATE -->|remediable findings| REMEDIATE
        
        subgraph "Stage 3: Remediation Engine"
            REMEDIATE[AST Codemod Runner]
            REMEDIATE -->|Python files| PY_MOD[Insecure Crypto / SQLi Codemods]
            REMEDIATE -->|JavaScript files| JS_MOD[Crypto / XSS Codemods]
            PY_MOD -->|patched files| VALIDATE
            JS_MOD -->|patched files| VALIDATE
        end
        
        subgraph "Stage 4: Validation Gate"
            VALIDATE[Validation Coordinator]
            VALIDATE -->|unit tests| TEST[Test Runner]
            VALIDATE -->|linting| LINT[Linter]
            VALIDATE -->|rescan| RESCAN[Semgrep Rescan]
            TEST -->|pass/fail| VALIDATE
            LINT -->|pass/fail| VALIDATE
            RESCAN -->|pass/fail| VALIDATE
        end
        
        VALIDATE -->|if pass| PRBOT[PR Automation Bot]
        VALIDATE -->|if fail| FALLBACK[Fallback: Manual Issue]
        
        subgraph "Stage 5: PR & Policy"
            PRBOT -->|create branch + commit| GITHUB[GitHub PR]
            GITHUB -->|PR metadata| OPA[OPA Policy Engine]
            OPA -->|pr_approval.rego| APPROVE{Policy Pass?}
            OPA -->|scope_limit.rego| APPROVE
            OPA -->|license_compliance.rego| APPROVE
            APPROVE -->|yes| REVIEW[Human Review Required]
            APPROVE -->|no| BLOCK[PR Blocked]
        end
    end

    subgraph "Observability"
        FINDINGS -.->|query| API[REST API Server]
        FINDINGS -.->|metrics| METRICS[Pipeline Metrics]
        METRICS --> PROM[Prometheus]
        PROM --> GRAF[Grafana Dashboard]
        API --> FRONTEND[Next.js Dashboard]
        
        OPA -.->|decisions| POLDEC[(Policy Decisions DB)]
        VALIDATE -.->|results| METRICS
    end

    subgraph "Data Store"
        FINDINGS[(PostgreSQL)]
        POLDEC[(PostgreSQL)]
        METRICS[(PostgreSQL)]
    end

    classDef pipeline fill:#e1f5fe
    classDef scan fill:#fff3e0
    classDef storage fill:#f3e5f5
    classDef external fill:#e8f5e9
    
    class SCAN,SEMGREP,TRIVY,ZAP scan
    class TRIAGE,CORRELATE,REMEDIATE,VALIDATE,PRBOT,OPA pipeline
    class FINDINGS,POLDEC,METRICS storage
    class Dev,GH,GITHUB,REVIEW,BLOCK external
```

## Component Interactions

### 1. Scan Stage (Parallel)
- **Semgrep**: SAST scanning with OWASP Top 10 + CWE Top 25 rules
- **Trivy**: SCA scanning for vulnerable dependencies + SBOM generation via Syft
- **ZAP**: DAST scanning for running applications (optional, schedule-only)
- All scanners output SARIF v2.1.0 format for unified downstream processing
- **Security constraint**: No external network access except internal artifact registry

### 2. Triage Stage
- **SARIF Parser** (`internal/sarif/`): Normalizes SARIF into unified `models.Finding`
  - Extracts: file path, line numbers, rule IDs, severity, code snippets
  - Maps rule IDs → CWE identifiers via built-in dictionary
  - Generates deterministic fingerprints (SHA-256 of file + rule + line + code)
- **Deduplicator** (`internal/triage/dedup.go`): Removes duplicate findings across scanners
  - Uses fingerprint comparison; keeps first occurrence
- **Correlator** (`internal/triage/correlator.go`): Cross-references findings from multiple scanners
  - Boosts confidence when 2+ scanners detect the same issue
  - Groups findings by file and CWE for efficient review

### 3. Remediation Stage
- **Codemod Runner** (`cmd/remediation-runner/`): Orchestrates AST transformations
  - Maps finding rule IDs → codemod scripts via registry
  - Executes language-specific codemods (Python/JavaScript)
  - Records all changes for audit trail
- **Codemods** (`codemods/`):
  - `python/insecure_crypto.py`: `hashlib.md5()`/`hashlib.sha1()` → `hashlib.sha256()`
  - `python/sql_injection.py`: String concatenation → parameterized queries
  - `javascript/insecure_crypto.js`: `createHash('md5')` → `createHash('sha256')`
  - `javascript/xss_sanitization.js`: `innerHTML` → `textContent`, `eval()` → blocked
- **Security constraint**: Deterministic-only by default; LLM fallback disabled in production

### 4. Validation Stage
- **Test Runner**: Detects project type (Go/Node.js/Python) and runs appropriate test suite
- **Linter**: Runs `go vet` / ESLint / Ruff based on project type
- **Rescan**: Runs lightweight Semgrep scan only on modified files
- **Rollback**: If any check fails, patches are reverted via `git checkout -- .`

### 5. PR & Policy Stage
- **PR Bot** (`cmd/prbot/`): Creates structured PRs
  - Branch naming: `auto-fix/security-<timestamp>`
  - Commit message includes fix summary, file table, and pipeline metadata
  - PR body contains change table, validation checklist, and human review notice
- **OPA Policies** (`policies/`):
  - `pr_approval.rego`: File/line limits, required labels, branch protection
  - `scope_limit.rego`: Blocks modifications to config, migration, and secrets files
  - `license_compliance.rego`: Blocks GPL/AGPL dependencies
  - `violation_report.rego`: Formats violations for SIEM/audit export

## Design Decisions & Trade-offs

### Why Go for Backend Services?
- **Concurrency**: Goroutines for parallel SARIF parsing and codemod execution
- **Single binary**: No runtime dependencies in container images
- **Type safety**: Compile-time checks reduce runtime errors in pipeline logic
- **Trade-off**: Longer development time vs Python, but better production reliability

### Why AST over Regex for Codemods?
- **Precision**: AST understands code structure; regex cannot distinguish between string literals and actual function calls
- **Safety**: Deterministic transformations with zero false positives on structural matches
- **Trade-off**: Requires Tree-sitter parser installation; regex fallback available but less accurate

### Why SARIF as Intermediate Format?
- **Standardization**: OASIS standard supported by Semgrep, GitHub CodeQL, ESLint, and others
- **Interoperability**: Single parser handles all scanner outputs; no per-scanner adapters needed
- **Trade-off**: ZAP doesn't natively output SARIF; requires conversion step

### Why OPA for Policy?
- **Declarative**: Rego is purpose-built for policy evaluation; cleaner than embedding policy in Go
- **Auditability**: Policy decisions are JSON-serializable for logging and review
- **Trade-off**: Additional service to deploy; but can run as sidecar via Docker Compose

### Why PostgreSQL?
- **JSONB support**: Policy decisions and SARIF data stored as JSON with GIN indexes
- **Array types**: CWE and CVE arrays for multi-value vulnerability classifications
- **Partial indexes**: Efficient queries for "find all high-severity new findings"
- **Trade-off**: Heavier than SQLite; but required for production concurrent access
