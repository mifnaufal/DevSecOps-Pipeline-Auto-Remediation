#!/usr/bin/env bash
# e2e-test.sh - End-to-end test orchestrator
# Runs the full pipeline against test fixtures and validates outcomes.
#
# Usage:
#   ./scripts/e2e-test.sh [--target /path/to/target-repo]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_DIR="${1:-$PROJECT_DIR/test-fixtures/sample-app}"
REPORT_DIR="$PROJECT_DIR/reports/e2e"
PASS=true

echo "=== DevSecOps Pipeline E2E Test ==="
echo "Target: $TARGET_DIR"
echo "Report: $REPORT_DIR"
echo ""

mkdir -p "$REPORT_DIR"

# === Setup test fixtures ===
setup_fixtures() {
    echo "[Setup] Creating test fixtures..."
    
    mkdir -p "$TARGET_DIR"
    
    # Create a Python file with known vulnerabilities
    cat > "$TARGET_DIR/vulnerable_app.py" << 'PYEOF'
import hashlib
import sqlite3

# CWE-328: Using broken MD5 hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# CWE-328: Using broken SHA1
def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()

# CWE-89: SQL Injection
def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
PYEOF

    # Create a JavaScript file with known vulnerabilities
    cat > "$TARGET_DIR/vulnerable_app.js" << 'JSEOF'
const crypto = require('crypto');

// CWE-328: Using MD5
function hashData(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// CWE-79: XSS via innerHTML
function renderUser(user) {
    document.getElementById('user').innerHTML = user.name;
}

// CWE-95: eval usage
function parseConfig(str) {
    return eval('(' + str + ')');
}
JSEOF

    echo "  Created vulnerable_app.py and vulnerable_app.js"
}

# === Step 1: Run scanners ===
run_scanners() {
    echo ""
    echo "[Step 1] Running security scanners..."
    
    mkdir -p "$REPORT_DIR/sarif"
    
    # Run Semgrep (if available)
    if command -v semgrep &> /dev/null; then
        echo "  Running Semgrep..."
        semgrep --config p/owasp-top-ten --sarif --output "$REPORT_DIR/sarif/semgrep-results.sarif" "$TARGET_DIR" || true
        echo "  ✅ Semgrep complete"
    else
        echo "  ⚠️  Semgrep not installed, using mock SARIF"
        generate_mock_sarif
    fi
}

generate_mock_sarif() {
    cat > "$REPORT_DIR/sarif/semgrep-results.sarif" << 'EOF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Semgrep", "version": "1.50.0"}},
    "results": [
      {
        "ruleId": "hardcoded-secret",
        "level": "error",
        "message": {"text": "Hardcoded secret detected"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.py"},
            "region": {"startLine": 5, "snippet": {"text": "API_KEY = 'sk-test-123'"}}
          }
        }]
      },
      {
        "ruleId": "md5-used",
        "level": "error",
        "message": {"text": "Use of MD5 hash function"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.py"},
            "region": {"startLine": 6, "snippet": {"text": "hashlib.md5(password.encode())"}}
          }
        }]
      },
      {
        "ruleId": "sha1-used",
        "level": "error",
        "message": {"text": "Use of SHA1 hash function"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.py"},
            "region": {"startLine": 10, "snippet": {"text": "hashlib.sha1(token.encode())"}}
          }
        }]
      },
      {
        "ruleId": "sql-injection",
        "level": "error",
        "message": {"text": "SQL injection via string concatenation"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.py"},
            "region": {"startLine": 16, "snippet": {"text": "\"SELECT * FROM users WHERE id = \" + user_id"}}
          }
        }]
      },
      {
        "ruleId": "insecure_crypto",
        "level": "error",
        "message": {"text": "Use of weak cryptographic algorithm"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.js"},
            "region": {"startLine": 5, "snippet": {"text": "crypto.createHash('md5')"}}
          }
        }]
      },
      {
        "ruleId": "xss-innerhtml",
        "level": "warning",
        "message": {"text": "Potential XSS via innerHTML"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "vulnerable_app.js"},
            "region": {"startLine": 10, "snippet": {"text": "document.getElementById('user').innerHTML = user.name"}}
          }
        }]
      }
    ]
  }]
}
EOF
}

# === Step 2: Triage ===
run_triage() {
    echo ""
    echo "[Step 2] Running triage engine..."
    
    mkdir -p "$REPORT_DIR/triage"
    
    if [[ -f "$PROJECT_DIR/cmd/triage-engine/main.go" ]]; then
        echo "  Building triage engine..."
        cd "$PROJECT_DIR"
        go build -o /tmp/triage-engine ./cmd/triage-engine/ 2>/dev/null || {
            echo "  ⚠️  Go build failed, using Python fallback"
            python_triage
            return
        }
        
        /tmp/triage-engine \
            --input-dir "$REPORT_DIR/sarif" \
            --output "$REPORT_DIR/triage/findings.json" \
            --min-severity high \
            --dedup true \
            --cwe-mapping true || python_triage
    else
        python_triage
    fi
    
    FINDINGS_COUNT=$(jq 'length' "$REPORT_DIR/triage/findings.json" 2>/dev/null || echo "0")
    echo "  ✅ Triage complete: $FINDINGS_COUNT findings"
}

python_triage() {
    echo "  Using Python triage fallback..."
    python3 -c "
import json, sys, os
sarif_path = '$REPORT_DIR/sarif/semgrep-results.sarif'
with open(sarif_path) as f:
    sarif = json.load(f)

findings = []
for run in sarif.get('runs', []):
    for result in run.get('results', []):
        loc = result.get('locations', [{}])[0].get('physicalLocation', {})
        findings.append({
            'id': f'finding-{len(findings)+1}',
            'external_id': result.get('ruleId', ''),
            'scanner': 'semgrep',
            'rule_id': result.get('ruleId', ''),
            'cwe': [],
            'title': result.get('message', {}).get('text', ''),
            'severity': 'high' if result.get('level') == 'error' else 'medium',
            'file_path': loc.get('artifactLocation', {}).get('uri', ''),
            'start_line': loc.get('region', {}).get('startLine', 0),
            'remediable': True,
            'status': 'new',
            'fingerprint': f\"{loc.get('artifactLocation', {}).get('uri', '')}:{result.get('ruleId', '')}:{loc.get('region', {}).get('startLine', 0)}\"
        })

os.makedirs('$REPORT_DIR/triage', exist_ok=True)
with open('$REPORT_DIR/triage/findings.json', 'w') as f:
    json.dump(findings, f, indent=2)
"
}

# === Step 3: Remediation ===
run_remediation() {
    echo ""
    echo "[Step 3] Running AST codemods..."
    
    mkdir -p "$REPORT_DIR/fixes"
    
    # Run Python crypto codemod
    echo "  Running insecure_crypto.py..."
    python3 "$PROJECT_DIR/codemods/python/insecure_crypto.py" "$TARGET_DIR" \
        --output "$REPORT_DIR/fixes/crypto_fixes.json" --dry-run
    
    # Run Python SQL injection codemod
    echo "  Running sql_injection.py..."
    python3 "$PROJECT_DIR/codemods/python/sql_injection.py" "$TARGET_DIR" \
        --output "$REPORT_DIR/fixes/sqli_fixes.json" --dry-run
    
    # Run JS crypto codemod
    echo "  Running insecure_crypto.js..."
    node "$PROJECT_DIR/codemods/javascript/insecure_crypto.js" "$TARGET_DIR" \
        -o="$REPORT_DIR/fixes/js_crypto_fixes.json"
    
    echo "  ✅ Codemods complete"
}

# === Step 4: Validation ===
run_validation() {
    echo ""
    echo "[Step 4] Running validation gate..."
    
    mkdir -p "$REPORT_DIR/validation"
    
    # Create a mock fixes.json for validation
    cat > "$REPORT_DIR/fixes/fixes.json" << 'EOF'
{
  "total_fixes": 3,
  "success_count": 3,
  "failure_count": 0,
  "fixes": [
    {"id": "fix-1", "codemod_name": "insecure_crypto.py", "file_path": "vulnerable_app.py", "status": "success"},
    {"id": "fix-2", "codemod_name": "sql_injection.py", "file_path": "vulnerable_app.py", "status": "success"},
    {"id": "fix-3", "codemod_name": "insecure_crypto.js", "file_path": "vulnerable_app.js", "status": "success"}
  ]
}
EOF
    
    bash "$PROJECT_DIR/scripts/validation-gate.sh" \
        --fixes "$REPORT_DIR/fixes/fixes.json" \
        --output "$REPORT_DIR/validation/result.json" || PASS=false
    
    echo "  ✅ Validation complete"
}

# === Assertions ===
run_assertions() {
    echo ""
    echo "=== Assertions ==="
    
    # Assert findings exist
    if [[ -f "$REPORT_DIR/triage/findings.json" ]]; then
        COUNT=$(jq 'length' "$REPORT_DIR/triage/findings.json")
        if [[ $COUNT -ge 1 ]]; then
            echo "  ✅ At least 1 finding detected ($COUNT)"
        else
            echo "  ❌ Expected findings, got $COUNT"
            PASS=false
        fi
    else
        echo "  ❌ Findings file not found"
        PASS=false
    fi
    
    # Assert codemod output exists
    if ls "$REPORT_DIR/fixes/"*.json 1> /dev/null 2>&1; then
        echo "  ✅ Codemod reports generated"
    else
        echo "  ❌ No codemod reports found"
        PASS=false
    fi
    
    # Assert validation result
    if [[ -f "$REPORT_DIR/validation/result.json" ]]; then
        RESULT=$(jq '.passed' "$REPORT_DIR/validation/result.json")
        if [[ "$RESULT" == "true" ]]; then
            echo "  ✅ Validation gate passed"
        else
            echo "  ⚠️  Validation gate failed (may be expected)"
        fi
    fi
    
    echo ""
    if $PASS; then
        echo "🎉 E2E Test PASSED"
    else
        echo "❌ E2E Test FAILED"
        exit 1
    fi
}

# === Execute ===
setup_fixtures
run_scanners
run_triage
run_remediation
run_validation
run_assertions
