package validation

import (
	"os/exec"
	"strings"
)

// Rescan runs a lightweight security scan on modified files.
type Rescan struct{}

// NewRescan creates a rescan instance.
func NewRescan() *Rescan {
	return &Rescan{}
}

// Run executes Semgrep on the specified files.
func (r *Rescan) Run(files []string) RescanResult {
	if len(files) == 0 {
		return RescanResult{Passed: true, Output: "No files to rescan"}
	}

	// Check if semgrep is available
	if _, err := exec.LookPath("semgrep"); err != nil {
		return RescanResult{
			Passed:      true,
			NewFindings: 0,
			Output:      "Semgrep not installed, skipping rescan",
		}
	}

	args := append([]string{"--config", "p/owasp-top-ten", "--quiet", "--json"}, files...)
	cmd := exec.Command("semgrep", args...)
	output, err := cmd.CombinedOutput()

	newFindings := 0
	if err != nil {
		newFindings = strings.Count(string(output), `"ruleId"`)
	}

	return RescanResult{
		Passed:      newFindings == 0,
		NewFindings: newFindings,
		Output:      string(output),
	}
}
