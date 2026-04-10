package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodemodRegistry_Entries(t *testing.T) {
	if len(CodemodRegistry) == 0 {
		t.Error("Expected codemod registry to have entries")
	}

	expected := []string{"md5-used", "sha1-used", "sql-injection", "xss", "eval-usage"}
	for _, rule := range expected {
		if _, exists := CodemodRegistry[rule]; !exists {
			t.Errorf("Expected rule '%s' to be registered", rule)
		}
	}
}

func TestCodemodRegistry_Deterministic(t *testing.T) {
	deterministic := []string{"md5-used", "sha1-used", "xss", "eval-usage"}
	for _, rule := range deterministic {
		if !IsDeterministic(rule) {
			t.Errorf("Expected rule '%s' to be deterministic", rule)
		}
	}

	if IsDeterministic("sql-injection") {
		t.Error("Expected sql-injection to be non-deterministic")
	}
}

func TestCodemodRegistry_UnknownRule(t *testing.T) {
	if IsDeterministic("unknown-rule-xyz") {
		t.Error("Expected unknown rule to return false for deterministic")
	}
}

func TestCodemodRegistry_ScriptPaths(t *testing.T) {
	for ruleID, info := range CodemodRegistry {
		if info.Script == "" {
			t.Errorf("Rule '%s' has empty script path", ruleID)
		}
		if info.Language == "" {
			t.Errorf("Rule '%s' has empty language", ruleID)
		}
		if len(info.CWE) == 0 {
			t.Errorf("Rule '%s' has no CWE mappings", ruleID)
		}
	}
}

func TestNewExecutor(t *testing.T) {
	exec := NewExecutor("/tmp/codemods", true)
	if exec == nil {
		t.Fatal("NewExecutor() returned nil")
	}
	if exec.codemodsDir != "/tmp/codemods" {
		t.Errorf("Expected codemodsDir '/tmp/codemods', got '%s'", exec.codemodsDir)
	}
	if !exec.dryRun {
		t.Error("Expected dryRun to be true")
	}
}

func TestExecute_UnknownRule(t *testing.T) {
	exec := NewExecutor("/tmp/codemods", true)
	_, err := exec.Execute("unknown-rule", "/tmp/target", []string{"file.py"})
	if err == nil {
		t.Error("Expected error for unknown rule")
	}
	if !strings.Contains(err.Error(), "no codemod registered") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestExecute_DryRun(t *testing.T) {
	// Create temp directory with a mock codemod script
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "codemods")
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a mock codemod that outputs valid JSON
	mockScript := filepath.Join(scriptDir, "mock_codemod.py")
	mockContent := `import argparse, json, sys, os
parser = argparse.ArgumentParser()
parser.add_argument("target_dir")
parser.add_argument("-o")
parser.add_argument("--dry-run", action="store_true")
args = parser.parse_args()
os.makedirs(os.path.dirname(args.o) or ".", exist_ok=True)
with open(args.o, "w") as f:
    json.dump({"codemod": "mock", "files_scanned": 1, "changes": []}, f)
print("Mock codemod executed", file=sys.stderr)
`
	if err := os.WriteFile(mockScript, []byte(mockContent), 0755); err != nil {
		t.Fatal(err)
	}

	// Register the mock codemod temporarily
	CodemodRegistry["test-mock-rule"] = CodemodInfo{
		Script:        "mock_codemod.py",
		Language:      "python",
		Rule:          "test",
		CWE:           []string{"CWE-999"},
		Deterministic: true,
	}
	defer delete(CodemodRegistry, "test-mock-rule")

	exec := NewExecutor(tmpDir, true)
	targetDir := t.TempDir()

	// Create a target file
	if err := os.WriteFile(filepath.Join(targetDir, "test.py"), []byte("# test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fixes, err := exec.Execute("test-mock-rule", targetDir, []string{"test.py"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(fixes) != 1 {
		t.Errorf("Expected 1 fix record, got %d", len(fixes))
	}
	if fixes[0].FilePath != "test.py" {
		t.Errorf("Expected file path 'test.py', got '%s'", fixes[0].FilePath)
	}
}

func TestGenerateDiff(t *testing.T) {
	diff := GenerateDiff("test.py", "old_line", "new_line")

	if diff == "" {
		t.Fatal("Expected non-empty diff")
	}
	// Verify it contains the expected elements
	if !strings.Contains(diff, "old_line") {
		t.Error("Expected diff to contain old line")
	}
	if !strings.Contains(diff, "new_line") {
		t.Error("Expected diff to contain new line")
	}
	t.Logf("Generated diff:\n%s", diff)
}

func TestPatcher_Apply_InvalidPath(t *testing.T) {
	p := NewPatcher("/tmp/patches")
	err := p.ApplyPatch("/nonexistent/patch/file.patch")

	if err == nil {
		t.Error("Expected error for nonexistent patch file")
	}
}

func TestPatcher_Apply_EmptyPatch(t *testing.T) {
	tmpDir := t.TempDir()
	patchPath := filepath.Join(tmpDir, "empty.patch")

	if err := os.WriteFile(patchPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewPatcher(tmpDir)
	err := p.ApplyPatch(patchPath)

	// Should not crash, may return error or succeed
	if err != nil {
		t.Logf("ApplyPatch returned error (expected for empty patch): %v", err)
	}
}

func TestCodemodRegistry_LanguageCoverage(t *testing.T) {
	languages := make(map[string]bool)
	for _, info := range CodemodRegistry {
		languages[info.Language] = true
	}

	// Verify we have both Python and JavaScript codemods
	if !languages["python"] {
		t.Error("Expected Python codemods in registry")
	}
	if !languages["javascript"] {
		t.Error("Expected JavaScript codemods in registry")
	}
}
