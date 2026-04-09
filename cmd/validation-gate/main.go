// Package main implements the validation gate CLI.
//
// Usage:
//
//	validation-gate --fixes fixes.json --run-tests true \
//	  --run-linter true --run-rescan true --output result.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ValidationResult struct {
	Passed        bool      `json:"passed"`
	Timestamp     string    `json:"timestamp"`
	DurationSec   float64   `json:"duration_sec"`
	TestsResult   *TestResult   `json:"tests_result,omitempty"`
	LinterResult  *LinterResult `json:"linter_result,omitempty"`
	RescanResult  *RescanResult `json:"rescan_result,omitempty"`
	FixedFiles    []string  `json:"fixed_files"`
	Errors        []string  `json:"errors"`
}

type TestResult struct {
	Passed  bool   `json:"passed"`
	Output  string `json:"output"`
	Command string `json:"command"`
}

type LinterResult struct {
	Passed  bool   `json:"passed"`
	Output  string `json:"output"`
	Command string `json:"command"`
}

type RescanResult struct {
	Passed       bool     `json:"passed"`
	NewFindings  int      `json:"new_findings"`
	Output       string   `json:"output"`
}

func main() {
	var (
		fixesPath  = flag.String("fixes", "reports/fixes/fixes.json", "Path to fixes.json")
		runTests   = flag.Bool("run-tests", true, "Run unit tests on modified files")
		runLinter  = flag.Bool("run-linter", true, "Run linter on modified files")
		runRescan  = flag.Bool("run-rescan", true, "Run lightweight security rescan")
		output     = flag.String("output", "reports/validation/result.json", "Output validation result")
	)
	flag.Parse()

	startTime := time.Now()
	result := ValidationResult{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Passed:     true,
		FixedFiles: []string{},
		Errors:     []string{},
	}

	// Load fixes to identify modified files
	fixes, err := loadFixes(*fixesPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to load fixes: %v", err))
		result.Passed = false
		writeResult(result, *output, startTime)
		return
	}

	for _, fix := range fixes {
		if fix.FilePath != "" {
			result.FixedFiles = append(result.FixedFiles, fix.FilePath)
		}
	}

	// 1. Run unit tests
	if *runTests {
		result.TestsResult = runTestsOnFiles(result.FixedFiles)
		if !result.TestsResult.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, "Unit tests failed")
		}
	}

	// 2. Run linter
	if *runLinter {
		result.LinterResult = runLinterOnFiles(result.FixedFiles)
		if !result.LinterResult.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, "Linter checks failed")
		}
	}

	// 3. Run lightweight rescan
	if *runRescan {
		result.RescanResult = runRescan(result.FixedFiles)
		if !result.RescanResult.Passed {
			result.Passed = false
			result.Errors = append(result.Errors, fmt.Sprintf("Security rescan found %d new findings", result.RescanResult.NewFindings))
		}
	}

	writeResult(result, *output, startTime)

	if result.Passed {
		log.Println("✅ Validation gate PASSED")
		os.Exit(0)
	} else {
		log.Printf("❌ Validation gate FAILED: %v", result.Errors)
		os.Exit(1)
	}
}

type FixRecord struct {
	FilePath string `json:"file_path"`
	Status   string `json:"status"`
}

func loadFixes(path string) ([]FixRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report map[string]interface{}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	var fixes []FixRecord
	if fixesRaw, ok := report["fixes"].([]interface{}); ok {
		for _, f := range fixesRaw {
			fixMap := f.(map[string]interface{})
			fixes = append(fixes, FixRecord{
				FilePath: fmt.Sprintf("%v", fixMap["file_path"]),
				Status:   fmt.Sprintf("%v", fixMap["status"]),
			})
		}
	}

	return fixes, nil
}

func runTestsOnFiles(files []string) *TestResult {
	log.Println("Running unit tests...")

	// Detect project type and run appropriate test command
	testCmd := detectTestCommand()
	if testCmd == nil {
		return &TestResult{
			Passed:  true, // No tests to run
			Output:  "No test framework detected",
			Command: "none",
		}
	}

	output, err := testCmd.CombinedOutput()
	return &TestResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: testCmd.String(),
	}
}

func detectTestCommand() *exec.Cmd {
	// Check for Go tests
	if _, err := os.Stat("go.mod"); err == nil {
		return exec.Command("go", "test", "./...", "-v", "-count=1", "-timeout", "60s")
	}

	// Check for Node.js tests
	if _, err := os.Stat("package.json"); err == nil {
		// Check for jest
		if _, err := os.Stat("jest.config.js"); err == nil {
			return exec.Command("npx", "jest", "--passWithNoTests")
		}
		// Check for mocha
		if _, err := os.Stat("mocha.opts"); err == nil {
			return exec.Command("npx", "mocha")
		}
		// Default to npm test
		return exec.Command("npm", "test")
	}

	// Check for Python tests
	if _, err := os.Stat("pytest.ini"); err == nil {
		return exec.Command("pytest", "-v", "--tb=short")
	}
	if _, err := os.Stat("setup.py"); err == nil {
		return exec.Command("python", "-m", "unittest", "discover")
	}
	if _, err := os.Stat("requirements.txt"); err == nil {
		return exec.Command("pytest", "-v", "--tb=short")
	}

	return nil
}

func runLinterOnFiles(files []string) *LinterResult {
	log.Println("Running linter checks...")

	var cmd *exec.Cmd

	// Go linting
	if _, err := os.Stat("go.mod"); err == nil {
		cmd = exec.Command("golangci-lint", "run", "--timeout", "60s")
		if _, err := exec.LookPath("golangci-lint"); err != nil {
			cmd = exec.Command("go", "vet", "./...")
		}
	} else if _, err := os.Stat("package.json"); err == nil {
		cmd = exec.Command("npx", "eslint", ".", "--ext", ".js,.ts,.jsx,.tsx", "--max-warnings", "0")
	} else if _, err := os.Stat("requirements.txt"); err == nil {
		cmd = exec.Command("ruff", "check", ".")
	}

	if cmd == nil {
		return &LinterResult{
			Passed:  true,
			Output:  "No linter configured",
			Command: "none",
		}
	}

	output, err := cmd.CombinedOutput()
	return &LinterResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

func runRescan(files []string) *RescanResult {
	log.Println("Running lightweight security rescan...")

	// Run semgrep only on modified files
	var targets []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			targets = append(targets, f)
		}
	}

	if len(targets) == 0 {
		return &RescanResult{
			Passed:      true,
			NewFindings: 0,
			Output:      "No files to rescan",
		}
	}

	cmd := exec.Command("semgrep", append([]string{
		"--config", "p/owasp-top-ten",
		"--json",
		"--quiet",
	}, targets...)...)

	output, err := cmd.CombinedOutput()

	// Parse semgrep JSON output to count new findings
	newFindings := 0
	if err == nil {
		// No findings = clean
		newFindings = 0
	} else {
		// Count findings from semgrep output
		newFindings = strings.Count(string(output), `"ruleId"`)
	}

	return &RescanResult{
		Passed:      newFindings == 0,
		NewFindings: newFindings,
		Output:      string(output),
	}
}

func writeResult(result ValidationResult, outputPath string, startTime time.Time) {
	result.DurationSec = time.Since(startTime).Seconds()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal result: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Fatalf("Failed to write result: %v", err)
	}

	log.Printf("Validation result written to %s", outputPath)
}
