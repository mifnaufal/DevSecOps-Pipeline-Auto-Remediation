# Codemod Design Specification

## Overview

This document describes the AST-based codemod architecture used for deterministic security vulnerability remediation. All codemods follow a strict design philosophy: **deterministic first, LLM fallback only**, with zero tolerance for logic regression.

## Design Principles

### 1. Deterministic Transformation
- Every codemod must produce identical output for identical input
- No random, time-dependent, or environment-dependent behavior
- All transformations are reversible via unified diff

### 2. AST-First Parsing
- Primary parsing uses Tree-sitter for language-accurate AST traversal
- Regex fallback only for patterns that are provably equivalent
- Parse failures result in `skipped` status, never silent corruption

### 3. Conservative Remediation
- If confidence < 100%, annotate with `// TODO(sec-review):` comment
- Never delete code; always transform or annotate
- Complex patterns (e.g., f-string SQL queries) get TODO markers for manual review

### 4. Validation Gate
Every codemod output must pass:
- Language-specific unit tests (zero regressions)
- Linter checks (no new warnings)
- Lightweight Semgrep rescan (original vulnerability eliminated)

## Codemod Registry

The registry maps finding rule IDs to codemod implementations:

| Rule ID Pattern | Codemod | Language | Deterministic | CWE |
|----------------|---------|----------|---------------|-----|
| `md5-used`, `hashlib.md5` | `insecure_crypto.py` | Python | Yes | CWE-328 |
| `sha1-used`, `hashlib.sha1` | `insecure_crypto.py` | Python | Yes | CWE-328 |
| `createHash('md5')` | `insecure_crypto.js` | JavaScript | Yes | CWE-328 |
| `createHash('sha1')` | `insecure_crypto.js` | JavaScript | Yes | CWE-328 |
| `sql-injection` | `sql_injection.py` | Python | Partial | CWE-89 |
| `xss-innerhtml` | `xss_sanitization.js` | JavaScript | Yes | CWE-79 |
| `eval-usage` | `xss_sanitization.js` | JavaScript | Yes | CWE-95 |
| `hardcoded-secret` | _Planned_ | Multi | Yes | CWE-798 |
| `insecure-random` | _Planned_ | Multi | Yes | CWE-330 |
| `tls-insecure` | _Planned_ | Multi | Yes | CWE-295 |

## Codemod Interface

### Input Format
Codemods receive findings via standardized JSON:
```json
{
  "target_dir": "/path/to/repository",
  "findings": [
    {
      "id": "finding-001",
      "rule_id": "md5-used",
      "file_path": "app/auth.py",
      "start_line": 42,
      "code_snippet": "hashlib.md5(password.encode()).hexdigest()",
      "remediation_hint": "Replace MD5 with SHA-256"
    }
  ],
  "dry_run": true
}
```

### Output Format
Codemods produce structured JSON reports:
```json
{
  "total_files_scanned": 15,
  "total_fixes_attempted": 3,
  "success_count": 2,
  "skipped_count": 1,
  "failure_count": 0,
  "fixes": [
    {
      "id": "fix-001",
      "finding_id": "finding-001",
      "codemod_name": "insecure_crypto.py",
      "file_path": "app/auth.py",
      "original_code": "hashlib.md5(password.encode()).hexdigest()",
      "fixed_code": "hashlib.sha256(password.encode()).hexdigest()",
      "status": "success",
      "deterministic": true,
      "validation_passed": true,
      "applied_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

## Implemented Codemods

### 1. `insecure_crypto.py` (Python)

**Purpose:** Replace broken cryptographic hash functions (MD5, SHA1) with SHA-256.

**Detection Strategy:**
- Primary: Tree-sitter AST traversal for `hashlib.md5()` / `hashlib.sha1()` call nodes
- Fallback: Regex pattern `hashlib\.(md5|sha1)\(` for environments without Tree-sitter

**Transformation Rules:**
```python
# Before
hashlib.md5(data.encode()).hexdigest()
# After
hashlib.sha256(data.encode()).hexdigest()

# Before
hashlib.sha1(data.encode()).hexdigest()
# After
hashlib.sha256(data.encode()).hexdigest()
```

**Safety Guarantees:**
- Preserves all method chaining (`.hexdigest()`, `.digest()`, `.update()`)
- Does not modify custom hash object constructions
- Handles both direct calls and variable assignments

**Test Coverage:** 9 unit tests covering direct calls, assignments, chaining, and edge cases.

### 2. `sql_injection.py` (Python)

**Purpose:** Convert string-concatenated SQL queries to parameterized queries.

**Detection Strategy:** Regex-based (AST transformation for SQL is complex due to string interpolation variants)

**Transformation Rules:**
```python
# String concatenation
# Before: "SELECT * FROM users WHERE id = " + user_id
# After:  "SELECT * FROM users WHERE id = ?"  # TODO(sec-review): verify parameterization
# With: cursor.execute(query, (user_id,))

# F-string
# Before: f"SELECT * FROM users WHERE id = {user_id}"
# After:  "SELECT * FROM users WHERE id = ?"  # TODO(sec-review): f-string conversion
# With: cursor.execute(query, (user_id,))

# .format()
# Before: "SELECT * FROM users WHERE id = {}".format(user_id)
# After:  "SELECT * FROM users WHERE id = ?"  # TODO(sec-review): format conversion
# With: cursor.execute(query, (user_id,))

# %-formatting
# Before: "SELECT * FROM users WHERE id = %s" % user_id
# After:  Parameterized query (already uses placeholder, verify cursor.execute)
```

**Conservative Approach:**
- F-string and `.format()` conversions add `# TODO(sec-review):` markers
- Complex expressions (function calls, nested attributes) are skipped with warning
- Only simple variable references are auto-converted

**Test Coverage:** 5 unit tests covering concatenation, f-string, format, and %-formatting patterns.

### 3. `insecure_crypto.js` (JavaScript)

**Purpose:** Replace MD5/SHA1 in Node.js `crypto.createHash()` calls.

**Detection Strategy:** Regex with AST validation
```javascript
// Before
crypto.createHash('md5').update(data).digest('hex')
// After
crypto.createHash('sha256').update(data).digest('hex')
```

**Test Coverage:** 8 Jest tests covering direct calls, destructured imports, and chaining.

### 4. `xss_sanitization.js` (JavaScript)

**Purpose:** Eliminate DOM-based XSS vectors.

**Transformation Rules:**
```javascript
// innerHTML → textContent
// Before: el.innerHTML = userInput
// After:  el.textContent = userInput

// document.write → blocked
// Before: document.write(userInput)
// After:  console.warn('SECURITY: document.write blocked', userInput)

// eval → JSON.parse
// Before: eval('(' + jsonString + ')')
// After:  JSON.parse(jsonString)
```

**Test Coverage:** 6 Jest tests covering innerHTML, document.write, and eval patterns.

## Adding a New Codemod

1. **Create the codemod script** in `codemods/<language>/`
2. **Implement the CLI interface:**
   ```python
   # Python
   python3 codemods/<language>/<name>.py <target_dir> --output <output.json> [--dry-run]
   ```
   ```javascript
   // JavaScript
   node codemods/<language>/<name>.js <target_dir> -o <output.json>
   ```
3. **Register the rule mapping** in `internal/remediation/codemod.go`:
   ```go
   registry := NewCodemodRegistry()
   registry.AddRule("my-new-rule", Codemod{
       Name:     "my_codemod.py",
       Language: "python",
       Deterministic: true,
   })
   ```
4. **Add SARIF parser mapping** in `internal/sarif/parser.go`:
   ```go
   "my-new-rule": {"CWE-XXX"},
   ```
5. **Write unit tests** in `codemods/<language>/tests/`
6. **Update this documentation** with the new entry in the registry table.

## Fallback Strategy

When deterministic codemods cannot handle a finding:

1. **LLM Constrained Fallback** (if enabled):
   - Send minimal context (file path + vulnerability snippet only)
   - Enforce JSON schema validation on response
   - Timeout: 5 seconds maximum
   - Mark result as `non-deterministic` for enhanced validation

2. **Manual Annotation** (default):
   - Create GitHub issue with full vulnerability context
   - Label: `security`, `manual-review-required`
   - Assign to repository security owner

## Benchmarking Methodology

Each codemod is evaluated against:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Fix Accuracy | ≥ 85% | `(successful_fixes / attempted_fixes) × 100` |
| Regression Rate | 0% | `(failed_tests_after_fix / total_tests) × 100` |
| False Positive Rate | ≤ 5% | `(incorrectly_flagged_as_vulnerable / total_findings) × 100` |
| Execution Time | ≤ 10s/repo | Wall-clock time for codemod execution |

Run benchmarks with:
```bash
make benchmark
./scripts/benchmark.sh ./test-fixtures/sample-app 5
```
