package validation

import "os/exec"

// Linter executes linting checks.
type Linter struct{}

// NewLinter creates a linter.
func NewLinter() *Linter {
	return &Linter{}
}

// RunGoVet runs go vet.
func (l *Linter) RunGoVet() CheckResult {
	cmd := exec.Command("go", "vet", "./...")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

// RunGolangciLint runs golangci-lint.
func (l *Linter) RunGolangciLint() CheckResult {
	cmd := exec.Command("golangci-lint", "run", "--timeout", "60s")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

// RunESLint runs ESLint.
func (l *Linter) RunESLint() CheckResult {
	cmd := exec.Command("npx", "eslint", ".", "--ext", ".js,.ts,.jsx,.tsx", "--max-warnings", "0")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

// RunRuff runs ruff for Python.
func (l *Linter) RunRuff() CheckResult {
	cmd := exec.Command("ruff", "check", ".")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}
