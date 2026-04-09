# Installation & Setup Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.21+ | Backend services compilation |
| Python | 3.11+ | Codemod execution |
| Node.js | 20+ | Frontend + JS codemods |
| Docker + Compose | 24+ / 2.20+ | Container orchestration |
| PostgreSQL | 15+ | Observability database |
| Semgrep | latest | SAST scanning |
| OPA | 0.60+ | Policy evaluation |
| gh CLI | 2.40+ | PR automation |

## Quick Start (Docker Compose)

### 1. Clone and Configure

```bash
git clone https://github.com/mifnaufal/devsecops-auto-remediation.git
cd devsecops-auto-remediation
cp .env.example .env
```

Edit `.env` with your configuration:
```bash
# Minimum required settings
DATABASE_URL=postgres://devsecops:devsecops@localhost:5432/devsecops?sslmode=disable
GITHUB_TOKEN=ghp_your_token_with_pr_write_access
```

### 2. Start the Stack

```bash
docker-compose up -d
```

This starts:
- **PostgreSQL** on `:5432` (auto-runs migrations from `db/migrations/`)
- **API Server** on `:8080`
- **Frontend** on `:3000`
- **OPA** on `:8181`
- **Prometheus** on `:9090`
- **Grafana** on `:3001` (admin/admin)

### 3. Verify Services

```bash
# Health check
curl http://localhost:8080/api/v1/health

# OPA health
curl http://localhost:8181/health

# PostgreSQL connection
docker exec devsecops-postgres pg_isready -U devsecops
```

### 4. Run End-to-End Test

```bash
chmod +x scripts/*.sh
./scripts/e2e-test.sh
```

Expected output:
```
=== DevSecOps Pipeline E2E Test ===
✅ Semgrep complete
✅ Triage complete: 6 findings
✅ Codemods complete
✅ Validation gate passed
🎉 E2E Test PASSED
```

## Local Development (Without Docker)

### 1. Install Dependencies

```bash
# Go services
go mod download

# Python codemods
pip install tree-sitter tree-sitter-python tree-sitter-javascript

# Node.js frontend
npm install

# Semgrep (for scanning)
pip install semgrep

# OPA (for policy evaluation)
# Download from: https://github.com/open-policy-agent/opa/releases
chmod +x opa && sudo mv opa /usr/local/bin/
```

### 2. Initialize Database

```bash
# Start PostgreSQL
docker run -d --name devsecops-db \
  -e POSTGRES_USER=devsecops \
  -e POSTGRES_PASSWORD=devsecops \
  -e POSTGRES_DB=devsecops \
  -p 5432:5432 \
  postgres:16-alpine

# Run migrations
for f in db/migrations/*.sql; do
  docker exec -i devsecops-db psql -U devsecops -d devsecops < "$f"
done
```

### 3. Build Go Services

```bash
go build -o triage-engine ./cmd/triage-engine/
go build -o remediation-runner ./cmd/remediation-runner/
go build -o validation-gate ./cmd/validation-gate/
go build -o prbot ./cmd/prbot/
go build -o api-server ./cmd/api-server/
```

### 4. Start API Server

```bash
./api-server &
# API available at http://localhost:8080
```

## CI/CD Configuration

### 1. GitHub Secrets Required

| Secret | Description | Required Permissions |
|--------|-------------|---------------------|
| `SEMGREP_APP_TOKEN` | Semgrep Pro API token | Free tier sufficient |
| `AUTO_FIX_PAT` | GitHub Personal Access Token | `contents:read`, `pull_requests:write`, `statuses:write` |

### 2. Create PAT for PR Bot

```bash
# In GitHub → Settings → Developer Settings → Personal Access Tokens
# Create token with:
#   ✅ contents (read)
#   ✅ pull_requests (write)
#   ✅ statuses (write)
#   ❌ NO admin or full repo access

# Save as repository secret
gh secret set AUTO_FIX_PAT --body "ghp_your_token"
```

### 3. Install Workflows

Copy workflow files to `.github/workflows/`:
```bash
# Already included if cloned
ls .github/workflows/
# ci-security-scan.yml
# triage-and-remediate.yml
# policy-evaluation.yml
```

## End-to-End Verification

### Step 1: Run Local Pipeline

```bash
./scripts/e2e-test.sh
```

### Step 2: Verify Database

```bash
docker exec devsecops-postgres psql -U devsecops -d devsecops -c "
  SELECT table_name FROM information_schema.tables 
  WHERE table_schema = 'public' ORDER BY table_name;"
```

Expected tables: `scans`, `findings`, `fixes`, `policy_decisions`, `pipeline_metrics`

### Step 3: Verify API

```bash
# List scans
curl http://localhost:8080/api/v1/scans

# List findings
curl http://localhost:8080/api/v1/findings?severity=high

# Get metrics summary
curl http://localhost:8080/api/v1/metrics/summary
```

### Step 4: Verify OPA Policies

```bash
# Test PR approval policy
opa eval \
  --data policies/pr_approval.rego \
  --input '{"files_changed": 3, "additions": 50, "deletions": 20, "is_auto_fix": true, "pr_labels": ["security", "auto-remediation"], "base_ref": "main"}' \
  'data.pr_approval.allow'

# Expected: true
```

### Step 5: Run Benchmark

```bash
./scripts/benchmark.sh ./test-fixtures/sample-app 3
```

## Troubleshooting

### SARIF Parsing Fails
```bash
# Validate SARIF format
cat reports/sarif/semgrep-results.sarif | jq '.version'
# Expected: "2.1.0"
```

### Codemod Doesn't Apply Fixes
```bash
# Run in dry-run mode to see what would change
python3 codemods/python/insecure_crypto.py ./target --dry-run
node codemods/javascript/insecure_crypto.js ./target --dry-run
```

### Validation Gate Fails
```bash
# Check individual validation steps
./scripts/validation-gate.sh --run-tests false --run-rescan false --output result.json
```

### Database Connection Issues
```bash
# Test connection
docker exec devsecops-postgres pg_isready -U devsecops
# Check tables exist
docker exec devsecops-postgres psql -U devsecops -d devsecops -c "\dt"
```

### OPA Policy Denies Unexpectedly
```bash
# Debug policy evaluation
opa eval \
  --data policies/pr_approval.rego \
  --input test_input.json \
  --explain=full \
  'data.pr_approval'
```

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://devsecops:devsecops@localhost:5432/devsecops` | PostgreSQL connection string |
| `API_PORT` | `8080` | API server listen port |
| `TRIAGE_MIN_SEVERITY` | `high` | Minimum severity level for triage |
| `REMEDIATION_DETERMINISTIC_ONLY` | `true` | Only run deterministic codemods |
| `VALIDATION_RUN_TESTS` | `true` | Enable test execution in validation |
| `VALIDATION_RUN_LINTER` | `true` | Enable linting in validation |
| `VALIDATION_RUN_RESCAN` | `true` | Enable security rescan in validation |
| `GITHUB_TOKEN` | (env) | GitHub PAT for PR creation |
| `SEMGRP_RULES_PATH` | `./rules/semgrep/` | Custom Semgrep rules directory |
