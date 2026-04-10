package validation

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Gate coordinates all validation checks.
type Gate struct {
	RunTests  bool
	RunLinter bool
	RunRescan bool
}

// Result holds the combined validation outcome.
type Result struct {
	Passed       bool       `json:"passed"`
	Timestamp    string     `json:"timestamp"`
	DurationSec  float64    `json:"duration_sec"`
	TestsResult  *CheckResult `json:"tests_result,omitempty"`
	LinterResult *CheckResult `json:"linter_result,omitempty"`
	RescanResult *RescanResult `json:"rescan_result,omitempty"`
	Errors       []string   `json:"errors"`
}

// CheckResult holds the outcome of a single check.
type CheckResult struct {
	Passed  bool   `json:"passed"`
	Output  string `json:"output"`
	Command string `json:"command"`
}

// RescanResult holds security rescan outcome.
type RescanResult struct {
	Passed      bool   `json:"passed"`
	NewFindings int    `json:"new_findings"`
	Output      string `json:"output"`
}

// New creates a validation gate.
func New(tests, linter, rescan bool) *Gate {
	return &Gate{RunTests: tests, RunLinter: linter, RunRescan: rescan}
}

// Run executes all enabled validation checks.
func (g *Gate) Run(files []string) Result {
	start := time.Now()
	result := Result{
		Passed:    true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if g.RunTests {
		r := runTests()
		result.TestsResult = &r
		if !r.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, "Unit tests failed")
		}
	}

	if g.RunLinter {
		r := runLinter(files)
		result.LinterResult = &r
		if !r.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, "Linter checks failed")
		}
	}

	if g.RunRescan {
		r := runRescan(files)
		result.RescanResult = &r
		if !r.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, fmt.Sprintf("Security rescan found %d new findings", r.NewFindings))
		}
	}

	result.DurationSec = time.Since(start).Seconds()
	return result
}

// Save writes the result to a JSON file.
func (g *Gate) Save(result Result, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

func writeFile(path string, data []byte) error {
	return exec.Command("sh", "-c", fmt.Sprintf("mkdir -p $(dirname %s) && echo '%s' > %s",
		path, string(data), path)).Run()
}

// DetectTestCommand finds the appropriate test runner for the project.
func DetectTestCommand() *exec.Cmd {
	if _, err := exec.LookPath("go"); err == nil {
		if _, err := exec.LookPath("go"); err == nil {
			if _, err := exec.Command("go", "list", "./...").CombinedOutput(); err == nil {
				return exec.Command("go", "test", "./...", "-v", "-count=1", "-timeout", "60s")
			}
		}
	}

	if _, err := exec.LookPath("npm"); err == nil {
		return exec.Command("npm", "test")
	}

	if _, err := exec.LookPath("pytest"); err == nil {
		return exec.Command("pytest", "-v", "--tb=short")
	}

	return nil
}

// DetectLinterCommand finds the appropriate linter for the project.
func DetectLinterCommand(files []string) *exec.Cmd {
	hasGo := false
	hasJS := false
	hasPy := false

	for _, f := range files {
		if strings.HasSuffix(f, ".go") {
			hasGo = true
		}
		if strings.HasSuffix(f, ".js") || strings.HasSuffix(f, ".ts") {
			hasJS = true
		}
		if strings.HasSuffix(f, ".py") {
			hasPy = true
		}
	}

	if hasGo {
		if _, err := exec.LookPath("golangci-lint"); err == nil {
			return exec.Command("golangci-lint", "run", "--timeout", "60s")
		}
		return exec.Command("go", "vet", "./...")
	}

	if hasJS {
		return exec.Command("npx", "eslint", ".", "--ext", ".js,.ts,.jsx,.tsx", "--max-warnings", "0")
	}

	if hasPy {
		if _, err := exec.LookPath("ruff"); err == nil {
			return exec.Command("ruff", "check", ".")
		}
	}

	return nil
}
