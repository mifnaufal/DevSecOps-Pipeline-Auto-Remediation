package validation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	g := New(true, true, true)
	if g == nil {
		t.Fatal("New() returned nil")
	}
	if !g.RunTests {
		t.Error("Expected RunTests to be true")
	}
	if !g.RunLinter {
		t.Error("Expected RunLinter to be true")
	}
	if !g.RunRescan {
		t.Error("Expected RunRescan to be true")
	}
}

func TestNew_DisableAll(t *testing.T) {
	g := New(false, false, false)
	if g.RunTests {
		t.Error("Expected RunTests to be false")
	}
	if g.RunLinter {
		t.Error("Expected RunLinter to be false")
	}
	if g.RunRescan {
		t.Error("Expected RunRescan to be false")
	}
}

func TestGate_Run_NoFiles(t *testing.T) {
	// Run with all checks disabled — should always pass
	g := New(false, false, false)
	result := g.Run([]string{})

	if !result.Passed {
		t.Errorf("Expected Passed=true when all checks disabled, got %+v", result)
	}
	if result.DurationSec < 0 {
		t.Error("Expected non-negative duration")
	}
	if result.Timestamp == "" {
		t.Error("Expected non-empty timestamp")
	}
}

func TestGate_Run_SkippedChecks(t *testing.T) {
	// Run with checks enabled but no files — should still pass (tools may not be installed)
	g := New(true, true, true)
	result := g.Run([]string{})

	// Should not panic even without files
	if result.Timestamp == "" {
		t.Error("Expected timestamp")
	}
}

func TestGate_Save(t *testing.T) {
	g := New(false, false, false)
	result := g.Run([]string{})

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "result.json")

	err := g.Save(result, outputPath)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify file exists and contains valid JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("Expected non-empty JSON output")
	}
}

func TestResult_Initial(t *testing.T) {
	g := New(false, false, false)
	result := g.Run([]string{})

	if result.Passed != true {
		t.Errorf("Expected Passed=true, got %v", result.Passed)
	}
	if len(result.Errors) != 0 {
		t.Errorf("Expected no errors, got %v", result.Errors)
	}
}

func TestDetectTestCommand(t *testing.T) {
	// This function depends on the environment — just verify it doesn't crash
	cmd := DetectTestCommand()
	// May be nil if no test framework is installed — that's valid
	if cmd != nil {
		t.Logf("Detected test command: %s", cmd.String())
	}
}

func TestDetectLinterCommand_NoFiles(t *testing.T) {
	cmd := DetectLinterCommand([]string{})
	// With no files, should return nil or a default
	if cmd != nil {
		t.Logf("Detected linter command: %s", cmd.String())
	}
}

func TestDetectLinterCommand_GoFiles(t *testing.T) {
	cmd := DetectLinterCommand([]string{"main.go", "util.go"})
	if cmd == nil {
		t.Skip("No Go linter detected")
	}
	t.Logf("Detected Go linter: %s", cmd.String())
}

func TestDetectLinterCommand_JSFiles(t *testing.T) {
	cmd := DetectLinterCommand([]string{"app.js", "index.ts"})
	if cmd == nil {
		t.Skip("No JS linter detected")
	}
	t.Logf("Detected JS linter: %s", cmd.String())
}

func TestDetectLinterCommand_PyFiles(t *testing.T) {
	cmd := DetectLinterCommand([]string{"app.py", "lib.py"})
	if cmd == nil {
		t.Skip("No Python linter detected")
	}
	t.Logf("Detected Python linter: %s", cmd.String())
}

func TestRescan_NoFiles(t *testing.T) {
	r := NewRescan()
	result := r.Run([]string{})

	if !result.Passed {
		t.Error("Expected rescan to pass with no files")
	}
	if result.NewFindings != 0 {
		t.Errorf("Expected 0 findings, got %d", result.NewFindings)
	}
}

func TestRescan_NonExistentFiles(t *testing.T) {
	r := NewRescan()
	result := r.Run([]string{"/nonexistent/file.go"})

	// Should pass because semgrep won't find files to scan
	if !result.Passed {
		t.Error("Expected rescan to pass with nonexistent files")
	}
}

func TestRescan_EmptyFileList(t *testing.T) {
	r := NewRescan()
	result := r.Run(nil)

	if !result.Passed {
		t.Error("Expected rescan to pass with nil file list")
	}
	if result.Output == "" {
		t.Error("Expected non-empty output")
	}
}

func TestLinter_RunGoVet(t *testing.T) {
	l := NewLinter()
	result := l.RunGoVet()

	// May fail if there are vet issues — just verify structure
	if result.Command == "" {
		t.Error("Expected non-empty command")
	}
	// Output may be empty or contain errors — just verify it ran
	t.Logf("go vet result: passed=%v, output_len=%d", result.Passed, len(result.Output))
}

func TestTestRunner_RunPytest(t *testing.T) {
	r := NewTestRunner()
	result := r.RunPytest()

	// Will likely fail if pytest isn't installed — verify structure
	if result.Command == "" {
		t.Error("Expected non-empty command")
	}
	t.Logf("pytest result: passed=%v, output_len=%d", result.Passed, len(result.Output))
}
