# Benchmark Methodology

## Overview

This document defines the benchmarking approach for validating the DevSecOps Auto-Remediation Pipeline against target performance and accuracy metrics.

## Target Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Fix Accuracy Rate | ≥ 85% | (Fixes passing validation / Total fixes attempted) × 100 |
| False Positive Rate | ≤ 5% | (Findings marked false_positive / Total findings) × 100 |
| Regression Incidence | 0% | Failed unit tests or linter checks after fix application |
| Pipeline Duration | ≤ 120s | Wall-clock time from scan start to PR creation |
| Policy Compliance | 100% | PRs passing all OPA policy evaluations |

## Test Scenarios

### Scenario 1: OWASP Juice Shop
- **Target**: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (v15.x)
- **Type**: Node.js/Angular e-commerce application with intentional vulnerabilities
- **Expected vulnerabilities**: XSS, SQLi, insecure crypto, hardcoded secrets
- **Baseline**: ~50-100 high/critical findings from Semgrep + Trivy
- **Success criteria**: ≥ 85% of deterministic findings (MD5, SHA1, innerHTML) are auto-fixed

### Scenario 2: DVWA (Damn Vulnerable Web App)
- **Target**: [DVWA](https://github.com/digininja/DVWA) (latest)
- **Type**: PHP/MySQL application with categorized vulnerability levels
- **Expected vulnerabilities**: SQLi, command injection, weak crypto
- **Baseline**: ~20-40 high/critical findings
- **Success criteria**: SQL injection codemod produces valid parameterized queries

### Scenario 3: Custom Test Fixtures
- **Target**: `test-fixtures/sample-app/` (included in repository)
- **Type**: Minimal Python + JavaScript files with known vulnerability patterns
- **Expected vulnerabilities**: MD5, SHA1, SQLi, XSS, eval()
- **Baseline**: 6-8 specific, known findings
- **Success criteria**: 100% fix rate on deterministic patterns

### Scenario 4: Real-World Repository
- **Target**: Any production repository with <500 files
- **Type**: Mixed-language codebase with organic vulnerability density
- **Expected vulnerabilities**: Real findings from actual code review
- **Baseline**: Variable
- **Success criteria**: Pipeline completes in ≤ 120s, 0 regressions

## Benchmark Execution

### Step 1: Prepare Target

```bash
# Clone target repository
git clone https://github.com/juice-shop/juice-shop.git test-fixtures/juice-shop

# Or use built-in fixtures
mkdir -p test-fixtures/sample-app
./scripts/e2e-test.sh  # Creates fixtures automatically
```

### Step 2: Run Benchmark

```bash
# Run 3 iterations against target
./scripts/benchmark.sh ./test-fixtures/juice-shop 3

# Output: reports/benchmarks/benchmark-<timestamp>.json
```

### Step 3: Analyze Results

```bash
# View benchmark report
cat reports/benchmarks/benchmark-*.json | jq '.pass_fail'

# Expected output:
# {
#   "fix_accuracy_rate": true,
#   "false_positive_rate": true,
#   "regression_count": true,
#   "pipeline_duration": true,
#   "policy_compliant": true
# }
```

## Report Template

```markdown
# DevSecOps Pipeline Benchmark Report

## Execution Details
- **Date:** 2024-01-15
- **Target:** OWASP Juice Shop v15.0.0
- **Runs:** 3
- **Pipeline Version:** 1.0.0

## Results Summary

| Metric | Target | Run 1 | Run 2 | Run 3 | Average | Status |
|--------|--------|-------|-------|-------|---------|--------|
| Fix Accuracy | ≥ 85% | 92% | 89% | 91% | 90.7% | ✅ PASS |
| False Positive | ≤ 5% | 2% | 3% | 2% | 2.3% | ✅ PASS |
| Regressions | 0 | 0 | 0 | 0 | 0 | ✅ PASS |
| Duration | ≤ 120s | 45s | 42s | 48s | 45s | ✅ PASS |
| Policy Compliance | 100% | 100% | 100% | 100% | 100% | ✅ PASS |

## Detailed Findings

### Fixed Vulnerabilities
| Rule | Files Fixed | Success Rate |
|------|-------------|--------------|
| md5-used | 5 | 100% |
| sha1-used | 3 | 100% |
| insecure_crypto (JS) | 4 | 100% |
| xss-innerhtml | 8 | 87.5% |
| sql-injection | 2 | 100% |

### Failed Fixes
| Rule | File | Failure Reason |
|------|------|---------------|
| xss-innerhtml | component.tsx | Complex template literal, requires manual fix |

## Conclusion

Pipeline meets all benchmark targets. Recommended for production deployment.
```

## Continuous Monitoring

Benchmark metrics are stored in the `pipeline_metrics` PostgreSQL table for trend analysis:

```sql
-- 7-day rolling average
SELECT 
  date_trunc('day', timestamp) as day,
  avg(fix_accuracy_rate) as avg_accuracy,
  avg(false_positive_rate) as avg_fp_rate,
  avg(total_duration_sec) as avg_duration
FROM pipeline_metrics
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY day
ORDER BY day DESC;
```
