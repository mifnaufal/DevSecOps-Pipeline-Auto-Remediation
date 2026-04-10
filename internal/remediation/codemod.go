package remediation

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

// CodemodRegistry maps rule patterns to codemod scripts and their properties.
var CodemodRegistry = map[string]CodemodInfo{
	"md5-used": {
		Script:    "codemods/python/insecure_crypto.py",
		Language:  "python",
		Rule:      "insecure-crypto",
		CWE:       []string{"CWE-327", "CWE-328"},
		Deterministic: true,
	},
	"sha1-used": {
		Script:    "codemods/python/insecure_crypto.py",
		Language:  "python",
		Rule:      "insecure-crypto",
		CWE:       []string{"CWE-327", "CWE-328"},
		Deterministic: true,
	},
	"insecure-crypto": {
		Script:    "codemods/python/insecure_crypto.py",
		Language:  "python",
		Rule:      "insecure-crypto",
		CWE:       []string{"CWE-327", "CWE-328"},
		Deterministic: true,
	},
	"insecure_crypto_js": {
		Script:    "codemods/javascript/insecure_crypto.js",
		Language:  "javascript",
		Rule:      "insecure-crypto",
		CWE:       []string{"CWE-327", "CWE-328"},
		Deterministic: true,
	},
	"sql-injection": {
		Script:    "codemods/python/sql_injection.py",
		Language:  "python",
		Rule:      "sql-injection",
		CWE:       []string{"CWE-89"},
		Deterministic: false, // requires human verification
	},
	"xss": {
		Script:    "codemods/javascript/xss_sanitization.js",
		Language:  "javascript",
		Rule:      "xss",
		CWE:       []string{"CWE-79"},
		Deterministic: true,
	},
	"eval-usage": {
		Script:    "codemods/javascript/xss_sanitization.js",
		Language:  "javascript",
		Rule:      "xss-eval",
		CWE:       []string{"CWE-95"},
		Deterministic: true,
	},
}

// CodemodInfo describes a codemod script and its properties.
type CodemodInfo struct {
	Script        string
	Language      string
	Rule          string
	CWE           []string
	Deterministic bool
}

// Executor runs codemod scripts against target files.
type Executor struct {
	codemodsDir string
	dryRun      bool
}

// NewExecutor creates a new codemod executor.
func NewExecutor(codemodsDir string, dryRun bool) *Executor {
	return &Executor{
		codemodsDir: codemodsDir,
		dryRun:      dryRun,
	}
}

// Execute runs a codemod against a target directory.
func (e *Executor) Execute(ruleID, targetDir string, files []string) ([]models.FixRecord, error) {
	info, exists := CodemodRegistry[ruleID]
	if !exists {
		return nil, fmt.Errorf("no codemod registered for rule: %s", ruleID)
	}

	scriptPath := fmt.Sprintf("%s/%s", e.codemodsDir, info.Script)

	// Build command based on language
	var cmd *exec.Cmd
	var args []string

	if info.Language == "python" {
		args = []string{"python3", scriptPath, targetDir}
	} else if info.Language == "javascript" {
		args = []string{"node", scriptPath, targetDir}
	} else {
		return nil, fmt.Errorf("unsupported language: %s", info.Language)
	}

	if e.dryRun {
		args = append(args, "--dry-run")
	}

	outputPath := fmt.Sprintf("/tmp/codemod_%s_output.json", strings.ReplaceAll(ruleID, "-", "_"))
	args = append(args, "-o="+outputPath)

	cmd = exec.Command(args[0], args[1:]...)
	cmd.Dir = targetDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("codemod %s failed: %v, output: %s", ruleID, err, string(output))
	}

	// Parse output JSON (handled by caller)
	var fixes []models.FixRecord
	for _, file := range files {
		fixes = append(fixes, models.FixRecord{
			CodemodName: info.Script,
			FilePath:    file,
			Status:      "success",
		})
	}

	return fixes, nil
}

// IsDeterministic checks if a rule has a fully deterministic codemod.
func IsDeterministic(ruleID string) bool {
	info, exists := CodemodRegistry[ruleID]
	if !exists {
		return false
	}
	return info.Deterministic
}
