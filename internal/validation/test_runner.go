package validation

import "os/exec"

// TestRunner executes language-specific unit tests.
type TestRunner struct{}

// NewTestRunner creates a test runner.
func NewTestRunner() *TestRunner {
	return &TestRunner{}
}

// RunGoTests executes Go tests.
func (r *TestRunner) RunGoTests() CheckResult {
	cmd := exec.Command("go", "test", "./...", "-v", "-count=1", "-timeout", "60s")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

// RunNpmTests executes npm tests.
func (r *TestRunner) RunNpmTests() CheckResult {
	cmd := exec.Command("npm", "test")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}

// RunPytest executes Python tests.
func (r *TestRunner) RunPytest() CheckResult {
	cmd := exec.Command("pytest", "-v", "--tb=short")
	output, err := cmd.CombinedOutput()
	return CheckResult{
		Passed:  err == nil,
		Output:  string(output),
		Command: cmd.String(),
	}
}
