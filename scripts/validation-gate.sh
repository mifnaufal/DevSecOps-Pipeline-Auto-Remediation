#!/usr/bin/env bash
# validation-gate.sh - Standalone validation gate script
# Can be run independently or as part of the CI pipeline.
#
# Usage:
#   ./scripts/validation-gate.sh --fixes fixes.json --run-tests true \
#       --run-linter true --run-rescan true --output result.json

set -euo pipefail

# Defaults
FIXES_PATH="reports/fixes/fixes.json"
RUN_TESTS="true"
RUN_LINTER="true"
RUN_RESCAN="true"
OUTPUT_PATH="reports/validation/result.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ERRORS=()
FIXED_FILES=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fixes) FIXES_PATH="$2"; shift 2 ;;
        --run-tests) RUN_TESTS="$2"; shift 2 ;;
        --run-linter) RUN_LINTER="$2"; shift 2 ;;
        --run-rescan) RUN_RESCAN="$2"; shift 2 ;;
        --output) OUTPUT_PATH="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== Validation Gate ==="
echo "Fixes: $FIXES_PATH"
echo "Tests: $RUN_TESTS | Linter: $RUN_LINTER | Rescan: $RUN_RESCAN"
echo ""

# Load fixed files from fixes.json
if [[ -f "$FIXES_PATH" ]]; then
    mapfile -t FIXED_FILES < <(jq -r '.fixes[].file_path' "$FIXES_PATH" 2>/dev/null || true)
    echo "Loaded ${#FIXED_FILES[@]} fixed files"
else
    echo "WARNING: Fixes file not found: $FIXES_PATH"
fi

# Create output directory
mkdir -p "$(dirname "$OUTPUT_PATH")"

# === 1. Unit Tests ===
run_tests() {
    echo ""
    echo "[1/3] Running unit tests..."
    
    local test_output=""
    local test_passed=true
    
    if [[ -f "go.mod" ]]; then
        echo "  Running Go tests..."
        test_output=$(go test ./... -v -count=1 -timeout 60s 2>&1) || test_passed=false
    elif [[ -f "package.json" ]]; then
        echo "  Running Node.js tests..."
        if [[ -f "jest.config.js" ]]; then
            test_output=$(npx jest --passWithNoTests 2>&1) || test_passed=false
        else
            test_output=$(npm test 2>&1) || test_passed=false
        fi
    elif [[ -f "requirements.txt" ]] || [[ -f "pytest.ini" ]]; then
        echo "  Running Python tests..."
        test_output=$(pytest -v --tb=short 2>&1) || test_passed=false
    else
        echo "  No test framework detected, skipping"
        return 0
    fi
    
    if $test_passed; then
        echo "  ✅ Tests passed"
    else
        echo "  ❌ Tests failed"
        ERRORS+=("Unit tests failed")
    fi
    
    echo "$test_passed"
}

# === 2. Linter ===
run_linter() {
    echo ""
    echo "[2/3] Running linter checks..."
    
    local lint_output=""
    local lint_passed=true
    
    if [[ -f "go.mod" ]]; then
        echo "  Running Go vet..."
        lint_output=$(go vet ./... 2>&1) || lint_passed=false
    elif [[ -f "package.json" ]]; then
        echo "  Running ESLint..."
        lint_output=$(npx eslint . --ext .js,.ts,.jsx,.tsx --max-warnings 0 2>&1) || lint_passed=false
    elif [[ -f "requirements.txt" ]]; then
        echo "  Running Ruff..."
        lint_output=$(ruff check . 2>&1) || lint_passed=false
    else
        echo "  No linter configured, skipping"
        return 0
    fi
    
    if $lint_passed; then
        echo "  ✅ Linter passed"
    else
        echo "  ❌ Linter failed"
        echo "$lint_output"
        ERRORS+=("Linter checks failed")
    fi
    
    echo "$lint_passed"
}

# === 3. Security Rescan ===
run_rescan() {
    echo ""
    echo "[3/3] Running lightweight security rescan..."
    
    local rescan_passed=true
    local new_findings=0
    local rescan_output=""
    
    if [[ ${#FIXED_FILES[@]} -eq 0 ]]; then
        echo "  No files to rescan"
        echo "true"
        return
    fi
    
    if command -v semgrep &> /dev/null; then
        echo "  Running Semgrep on modified files..."
        rescan_output=$(semgrep --config p/owasp-top-ten --quiet "${FIXED_FILES[@]}" 2>&1) || {
            new_findings=$(echo "$rescan_output" | grep -c '"ruleId"' || true)
            if [[ $new_findings -gt 0 ]]; then
                rescan_passed=false
            fi
        }
    else
        echo "  Semgrep not installed, skipping rescan"
        echo "true"
        return
    fi
    
    if $rescan_passed; then
        echo "  ✅ No new findings"
    else
        echo "  ❌ Found $new_findings new finding(s)"
        ERRORS+=("Security rescan found $new_findings new findings")
    fi
    
    echo "$rescan_passed"
}

# Execute
TESTS_RESULT=true
LINTER_RESULT=true
RESCAN_RESULT=true

if [[ "$RUN_TESTS" == "true" ]]; then
    TESTS_RESULT=$(run_tests)
fi

if [[ "$RUN_LINTER" == "true" ]]; then
    LINTER_RESULT=$(run_linter)
fi

if [[ "$RUN_RESCAN" == "true" ]]; then
    RESCAN_RESULT=$(run_rescan)
fi

# Determine overall result
PASSED=true
if [[ "$TESTS_RESULT" != "true" ]] || [[ "$LINTER_RESULT" != "true" ]] || [[ "$RESCAN_RESULT" != "true" ]]; then
    PASSED=false
fi

# Write JSON result
ERRORS_JSON="[]"
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    ERRORS_JSON=$(printf '%s\n' "${ERRORS[@]}" | jq -R . | jq -s .)
fi

FILES_JSON="[]"
if [[ ${#FIXED_FILES[@]} -gt 0 ]]; then
    FILES_JSON=$(printf '%s\n' "${FIXED_FILES[@]}" | jq -R . | jq -s .)
fi

cat > "$OUTPUT_PATH" << EOF
{
  "passed": $PASSED,
  "timestamp": "$TIMESTAMP",
  "tests_result": $([[ "$TESTS_RESULT" == "true" ]] && echo "true" || echo "false"),
  "linter_result": $([[ "$LINTER_RESULT" == "true" ]] && echo "true" || echo "false"),
  "rescan_result": $([[ "$RESCAN_RESULT" == "true" ]] && echo "true" || echo "false"),
  "fixed_files": $FILES_JSON,
  "errors": $ERRORS_JSON
}
EOF

echo ""
if $PASSED; then
    echo "✅ Validation gate PASSED"
    exit 0
else
    echo "❌ Validation gate FAILED"
    for err in "${ERRORS[@]}"; do
        echo "  - $err"
    done
    exit 1
fi
