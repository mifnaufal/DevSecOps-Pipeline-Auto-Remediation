# API Reference

## Base URL
```
http://localhost:8080/api/v1
```

## Authentication
All endpoints require a valid GitHub token with the following scopes:
- `contents:read` — for reading repository content
- `pull_requests:write` — for creating remediation PRs
- `statuses:write` — for updating commit status with policy evaluation results

Pass the token via the `Authorization: Bearer <token>` header.

---

## Endpoints

### Health Check

#### `GET /api/v1/health`

Returns the service health status including database connectivity.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "database": "connected"
}
```

---

### Scans

#### `GET /api/v1/scans`

List all security scan executions with pagination.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Maximum number of scans to return |
| `page` | int | 1 | Page number for pagination |

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "repository": "org/sample-app",
    "commit_sha": "abc123def456",
    "branch": "main",
    "trigger_type": "push",
    "scan_type": "sast",
    "tool": "semgrep",
    "status": "completed",
    "finding_count": 12,
    "critical_count": 2,
    "high_count": 5,
    "medium_count": 3,
    "low_count": 2,
    "started_at": "2024-01-15T10:00:00Z",
    "completed_at": "2024-01-15T10:02:30Z",
    "duration_seconds": 150,
    "created_at": "2024-01-15T10:00:00Z"
  }
]
```

#### `GET /api/v1/scans/{id}`

Get detailed information about a specific scan.

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string (UUID) | Scan identifier |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "repository": "org/sample-app",
  "commit_sha": "abc123def456",
  "branch": "main",
  "trigger_type": "push",
  "scan_type": "sast",
  "tool": "semgrep",
  "tool_version": "1.50.0",
  "status": "completed",
  "files_scanned": 245,
  "finding_count": 12,
  "critical_count": 2,
  "high_count": 5,
  "medium_count": 3,
  "low_count": 2,
  "sarif_path": "/reports/sarif/semgrep-results.sarif",
  "started_at": "2024-01-15T10:00:00Z",
  "completed_at": "2024-01-15T10:02:30Z",
  "duration_seconds": 150,
  "error_message": null,
  "created_at": "2024-01-15T10:00:00Z"
}
```

---

### Findings

#### `GET /api/v1/findings`

List security findings with optional filtering.

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | all | Filter by severity: `critical`, `high`, `medium`, `low` |
| `status` | string | all | Filter by status: `new`, `confirmed`, `remediated`, `false_positive`, `accepted_risk` |
| `scanner` | string | all | Filter by scanner: `semgrep`, `trivy`, `zap` |
| `limit` | int | 100 | Maximum number of findings to return |

**Response:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "external_id": "semgrep-rule-001",
    "scanner": "semgrep",
    "rule_id": "md5-used",
    "cwe": ["CWE-328"],
    "cve": [],
    "title": "Use of MD5 hash function",
    "description": "MD5 is cryptographically broken and should not be used",
    "severity": "high",
    "confidence": "high",
    "file_path": "app/auth.py",
    "start_line": 42,
    "end_line": 42,
    "code_snippet": "hashlib.md5(password.encode()).hexdigest()",
    "remediable": true,
    "remediation_hint": "Replace MD5 with SHA-256 or stronger hash function",
    "status": "new",
    "created_at": "2024-01-15T10:02:30Z"
  }
]
```

#### `GET /api/v1/findings/{id}`

Get detailed information about a specific finding.

**Response:** Same as list response, plus `fingerprint` and `updated_at` fields.

#### `PUT /api/v1/findings/{id}/status`

Update the remediation status of a finding.

**Request Body:**
```json
{
  "status": "confirmed"
}
```

**Valid Statuses:**
| Status | Description |
|--------|-------------|
| `new` | Initial state after detection |
| `confirmed` | Verified as genuine vulnerability |
| `remediated` | Fixed via codemod or manual patch |
| `false_positive` | Scanner incorrectly flagged this |
| `accepted_risk` | Known risk accepted by security team |

**Response:**
```json
{
  "status": "confirmed",
  "id": "550e8400-e29b-41d4-a716-446655440001"
}
```

---

### Fixes

#### `GET /api/v1/fixes`

List all remediation attempts.

**Response:**
```json
[
  {
    "id": "fix-001",
    "finding_id": "550e8400-e29b-41d4-a716-446655440001",
    "codemod_name": "insecure_crypto.py",
    "file_path": "app/auth.py",
    "status": "success",
    "validation_passed": true,
    "rescan_passed": true,
    "pr_url": "https://github.com/org/sample-app/pull/42",
    "pr_number": 42,
    "error": null,
    "applied_at": "2024-01-15T10:05:00Z"
  }
]
```

#### `GET /api/v1/fixes/{id}`

Get detailed information about a specific fix, including `original_code` and `fixed_code` diff.

---

### Metrics

#### `GET /api/v1/metrics`

List pipeline execution metrics (last 50 runs).

**Response:**
```json
[
  {
    "id": "metric-001",
    "pipeline_run_id": "run-001",
    "repository": "org/sample-app",
    "commit_sha": "abc123",
    "total_duration_sec": 95,
    "scan_duration_sec": 45,
    "triage_duration_sec": 10,
    "remediation_duration_sec": 20,
    "validation_duration_sec": 20,
    "total_findings": 12,
    "high_critical_findings": 7,
    "fixes_attempted": 5,
    "fixes_successful": 4,
    "fix_accuracy_rate": 80.0,
    "false_positive_rate": 3.2,
    "regression_count": 0,
    "pr_created": true,
    "pr_url": "https://github.com/org/sample-app/pull/42",
    "policy_compliant": true,
    "timestamp": "2024-01-15T10:10:00Z"
  }
]
```

#### `GET /api/v1/metrics/summary`

Get aggregated metrics summary.

**Response:**
```json
{
  "total_scans": 150,
  "avg_duration_sec": 98.5,
  "avg_fix_accuracy_rate": 87.3,
  "avg_false_positive_rate": 2.8,
  "total_findings": 1245,
  "total_fixes": 423,
  "compliant_scans": 148
}
```

---

### Policy Decisions

#### `GET /api/v1/policies`

List OPA policy evaluation decisions.

**Response:**
```json
[
  {
    "id": "policy-001",
    "policy_name": "pr_approval.rego",
    "decision": "allow",
    "violations": [],
    "evaluated_at": "2024-01-15T10:08:00Z"
  },
  {
    "id": "policy-002",
    "policy_name": "scope_limit.rego",
    "decision": "deny",
    "violations": [
      "Auto-fix PR cannot modify files in db/migrations/ directory"
    ],
    "evaluated_at": "2024-01-15T10:08:00Z"
  }
]
```

---

### Prometheus Metrics

#### `GET /metrics/prometheus`

Exposes Prometheus-compatible metrics for pipeline monitoring.

**Metrics Include:**
- `http_requests_total` — Total HTTP requests
- `http_request_duration_seconds` — Request latency histogram
- `go_goroutines` — Active goroutines
- `go_memstats_alloc_bytes` — Memory usage

---

## Error Responses

All endpoints return standard HTTP status codes with error details:

| Status Code | Description |
|-------------|-------------|
| `400 Bad Request` | Invalid input or parameters |
| `404 Not Found` | Resource does not exist |
| `500 Internal Server Error` | Server-side error |

**Error Format:**
```json
{
  "error": "descriptive error message"
}
```

---

## OpenAPI Specification

The complete OpenAPI 3.0.3 specification is available at:
```
api/openapi.yaml
```

Import this file into Swagger UI, Postman, or similar tools for interactive API exploration.
