package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEvaluator(t *testing.T) {
	e := New("./policies", 10)
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.policyDir != "./policies" {
		t.Errorf("Expected policyDir './policies', got '%s'", e.policyDir)
	}
	if e.timeoutSec != 10 {
		t.Errorf("Expected timeout 10, got %d", e.timeoutSec)
	}
}

func TestEvaluate_PolicyFileNotFound(t *testing.T) {
	e := New("/nonexistent", 5)
	_, err := e.Evaluate(context.Background(), "nonexistent.rego", "data.test.allow", nil)
	if err == nil {
		t.Error("Expected error for nonexistent policy file")
	}
}

func TestEvaluatePRApproval_Allow(t *testing.T) {
	// Create temp policy directory
	tmpDir := t.TempDir()
	policyContent := `package pr_approval

allow {
	input.file_count <= 10
	input.line_changes <= 500
	input.has_security_label == true
	input.branch != "main"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "pr_approval.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: should allow
	input := map[string]interface{}{
		"file_count":         3,
		"line_changes":       150,
		"has_security_label": true,
		"branch":             "auto-fix/security-20240115",
	}

	dec, err := e.Evaluate(context.Background(), "pr_approval.rego", "data.pr_approval.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if !dec.Allowed {
		t.Errorf("Expected policy to allow, but got denied. Result: %+v", dec.Result)
	}
}

func TestEvaluatePRApproval_Deny_TooManyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package pr_approval

allow {
	input.file_count <= 10
	input.line_changes <= 500
	input.has_security_label == true
	input.branch != "main"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "pr_approval.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: too many files
	input := map[string]interface{}{
		"file_count":         15,
		"line_changes":       150,
		"has_security_label": true,
		"branch":             "auto-fix/security-20240115",
	}

	dec, err := e.Evaluate(context.Background(), "pr_approval.rego", "data.pr_approval.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if dec.Allowed {
		t.Errorf("Expected policy to deny (too many files), but got allowed. Result: %+v", dec.Result)
	}
}

func TestEvaluatePRApproval_Deny_TooManyLines(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package pr_approval

allow {
	input.file_count <= 10
	input.line_changes <= 500
	input.has_security_label == true
	input.branch != "main"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "pr_approval.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: too many lines changed
	input := map[string]interface{}{
		"file_count":         5,
		"line_changes":       750,
		"has_security_label": true,
		"branch":             "auto-fix/security-20240115",
	}

	dec, err := e.Evaluate(context.Background(), "pr_approval.rego", "data.pr_approval.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if dec.Allowed {
		t.Errorf("Expected policy to deny (too many lines), but got allowed. Result: %+v", dec.Result)
	}
}

func TestEvaluatePRApproval_Deny_TargetMain(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package pr_approval

allow {
	input.file_count <= 10
	input.line_changes <= 500
	input.has_security_label == true
	input.branch != "main"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "pr_approval.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: targeting main branch directly
	input := map[string]interface{}{
		"file_count":         3,
		"line_changes":       150,
		"has_security_label": true,
		"branch":             "main",
	}

	dec, err := e.Evaluate(context.Background(), "pr_approval.rego", "data.pr_approval.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if dec.Allowed {
		t.Errorf("Expected policy to deny (targeting main), but got allowed. Result: %+v", dec.Result)
	}
}

func TestEvaluateScopeLimit_Allow(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package scope_limit

allow {
	not touches_restricted(input.changed_files)
}

restricted_paths = ["db/migrations/", ".env", "secrets/", "Dockerfile", ".github/workflows/"]

touches_restricted(files) {
	file := files[_]
	path := restricted_paths[_]
	startswith(file, path)
}`
	err := os.WriteFile(filepath.Join(tmpDir, "scope_limit.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: safe files only
	input := map[string]interface{}{
		"changed_files": []interface{}{
			"app/auth.py",
			"lib/utils.js",
			"tests/test_auth.py",
		},
	}

	dec, err := e.Evaluate(context.Background(), "scope_limit.rego", "data.scope_limit.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if !dec.Allowed {
		t.Errorf("Expected policy to allow (safe files), but got denied. Result: %+v", dec.Result)
	}
}

func TestEvaluateScopeLimit_Deny(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package scope_limit

allow {
	not touches_restricted(input.changed_files)
}

restricted_paths = ["db/migrations/", ".env", "secrets/", "Dockerfile", ".github/workflows/"]

touches_restricted(files) {
	file := files[_]
	path := restricted_paths[_]
	startswith(file, path)
}`
	err := os.WriteFile(filepath.Join(tmpDir, "scope_limit.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: touches restricted path
	input := map[string]interface{}{
		"changed_files": []interface{}{
			"app/auth.py",
			"db/migrations/001_add_users.sql",
		},
	}

	dec, err := e.Evaluate(context.Background(), "scope_limit.rego", "data.scope_limit.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if dec.Allowed {
		t.Errorf("Expected policy to deny (restricted path), but got allowed. Result: %+v", dec.Result)
	}
}

func TestEvaluateLicenseCompliance_Allow(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package license_compliance

allow {
	not has_blocked_license(input.dependencies)
}

blocked_licenses = ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]

has_blocked_license(deps) {
	dep := deps[_]
	license := dep.license
	blocked := blocked_licenses[_]
	license == blocked
}`
	err := os.WriteFile(filepath.Join(tmpDir, "license_compliance.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: all permissive licenses
	input := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{"name": "express", "license": "MIT"},
			map[string]interface{}{"name": "lodash", "license": "MIT"},
			map[string]interface{}{"name": "pgx", "license": "MIT"},
		},
	}

	dec, err := e.Evaluate(context.Background(), "license_compliance.rego", "data.license_compliance.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if !dec.Allowed {
		t.Errorf("Expected policy to allow (MIT licenses), but got denied. Result: %+v", dec.Result)
	}
}

func TestEvaluateLicenseCompliance_Deny(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package license_compliance

allow {
	not has_blocked_license(input.dependencies)
}

blocked_licenses = ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"]

has_blocked_license(deps) {
	dep := deps[_]
	license := dep.license
	blocked := blocked_licenses[_]
	license == blocked
}`
	err := os.WriteFile(filepath.Join(tmpDir, "license_compliance.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	// Test case: GPL dependency
	input := map[string]interface{}{
		"dependencies": []interface{}{
			map[string]interface{}{"name": "express", "license": "MIT"},
			map[string]interface{}{"name": "some-gpl-lib", "license": "GPL-3.0"},
		},
	}

	dec, err := e.Evaluate(context.Background(), "license_compliance.rego", "data.license_compliance.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	if dec.Allowed {
		t.Errorf("Expected policy to deny (GPL dependency), but got allowed. Result: %+v", dec.Result)
	}
}

func TestEvaluateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	policyContent := `package test

allow {
	input.value > 10
}`
	err := os.WriteFile(filepath.Join(tmpDir, "test.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 5)

	inputJSON := []byte(`{"value": 42}`)
	result, err := e.EvaluateJSON(context.Background(), "test.rego", "data.test.allow", inputJSON)
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}

	if string(result) == "" {
		t.Error("Expected non-empty result")
	}
}

func TestEvaluateJSON_InvalidInput(t *testing.T) {
	e := New(t.TempDir(), 5)

	_, err := e.EvaluateJSON(context.Background(), "test.rego", "data.test.allow", []byte(`{invalid json}`))
	if err == nil {
		t.Error("Expected error for invalid JSON input")
	}
}

func TestEvaluate_Timeout(t *testing.T) {
	tmpDir := t.TempDir()
	// Policy that references nonexistent data (fast evaluation)
	policyContent := `package slow

allow {
	input.foo == "bar"
}`
	err := os.WriteFile(filepath.Join(tmpDir, "slow.rego"), []byte(policyContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	e := New(tmpDir, 1) // 1 second timeout

	input := map[string]interface{}{"foo": "baz"}
	dec, err := e.Evaluate(context.Background(), "slow.rego", "data.slow.allow", input)
	if err != nil {
		t.Fatalf("Evaluation failed: %v", err)
	}

	// Should complete well within timeout
	if dec == nil {
		t.Error("Expected decision, got nil")
	}
}
