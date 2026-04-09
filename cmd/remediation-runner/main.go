// Package main implements the remediation runner CLI.
//
// Usage:
//
//	remediation-runner --findings findings.json --codemods-dir codemods/ \
//	  --output-dir reports/fixes/ --deterministic-only true --max-files 10
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

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

// CodemodRegistry maps rule patterns to codemod scripts.
var codemodRegistry = map[string]string{
	"md5-used":           "codemods/python/insecure_crypto.py",
	"sha1-used":          "codemods/python/insecure_crypto.py",
	"insecure-crypto":    "codemods/python/insecure_crypto.py",
	"sql-injection":      "codemods/python/sql_injection.py",
	"insecure_crypto_js": "codemods/javascript/insecure_crypto.js",
	"xss":                "codemods/javascript/xss_sanitization.js",
	"eval-usage":         "codemods/javascript/xss_sanitization.js",
}

func main() {
	var (
		findingsPath     = flag.String("findings", "reports/triage/findings.json", "Path to triage findings JSON")
		codemodsDir      = flag.String("codemods-dir", "codemods/", "Directory containing codemod scripts")
		outputDir        = flag.String("output-dir", "reports/fixes/", "Output directory for fix reports")
		deterministic    = flag.Bool("deterministic-only", true, "Only run deterministic codemods")
		maxFiles         = flag.Int("max-files", 10, "Maximum number of files to modify per PR")
	)
	flag.Parse()

	startTime := time.Now()

	// Load findings
	data, err := os.ReadFile(*findingsPath)
	if err != nil {
		log.Fatalf("Failed to read findings: %v", err)
	}

	var findings []models.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		log.Fatalf("Failed to parse findings: %v", err)
	}

	log.Printf("Loaded %d findings", len(findings))

	// Group findings by codemod type
	codemodGroups := groupFindingsByCodemod(findings)

	// Execute codemods
	var fixRecords []models.FixRecord
	filesModified := 0

	for ruleID, ruleFindings := range codemodGroups {
		codemodScript, exists := codemodRegistry[ruleID]
		if !exists {
			log.Printf("No codemod for rule: %s (skipping %d findings)", ruleID, len(ruleFindings))
			continue
		}

		if *deterministic && !isDeterministic(ruleID) {
			log.Printf("Rule %s not deterministic (skipping)", ruleID)
			continue
		}

		// Collect unique file paths for this rule
		uniqueFiles := uniqueFilePaths(ruleFindings)

		// Determine target directory (parent of first file)
		targetDir := "."
		if len(uniqueFiles) > 0 {
			targetDir = filepath.Dir(uniqueFiles[0])
		}

		log.Printf("Running codemod %s on %d files", codemodScript, len(uniqueFiles))

		// Execute the codemod
		fixes, err := executeCodemod(*codemodsDir, codemodScript, targetDir, uniqueFiles)
		if err != nil {
			log.Printf("Codemod %s failed: %v", codemodScript, err)
			// Record failures
			for _, f := range ruleFindings {
				fixRecords = append(fixRecords, models.FixRecord{
					ID:            fmt.Sprintf("fix-%s-%d", ruleID, len(fixRecords)),
					FindingID:     f.ID,
					CodemodName:   codemodScript,
					FilePath:      f.FilePath,
					Status:        "failed",
					Error:         err.Error(),
					AppliedAt:     time.Now(),
				})
			}
			continue
		}

		filesModified += len(uniqueFiles)
		if filesModified > *maxFiles {
			log.Printf("Max files limit reached (%d), stopping", *maxFiles)
			break
		}

		// Record successes
		for _, fix := range fixes {
			fixRecords = append(fixRecords, fix)
		}
	}

	// Write fix report
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	report := map[string]interface{}{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"duration_seconds": time.Since(startTime).Seconds(),
		"total_fixes":     len(fixRecords),
		"success_count":   countByStatus(fixRecords, "success"),
		"failure_count":   countByStatus(fixRecords, "failed"),
		"fixes":           fixRecords,
	}

	outputPath := filepath.Join(*outputDir, "fixes.json")
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal fix report: %v", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Fatalf("Failed to write fix report: %v", err)
	}

	log.Printf("Remediation complete: %d fixes (%d success, %d failed) in %s",
		len(fixRecords),
		countByStatus(fixRecords, "success"),
		countByStatus(fixRecords, "failed"),
		time.Since(startTime))
}

// groupFindingsByCodemod groups findings by their rule ID for batch codemod execution.
func groupFindingsByCodemod(findings []models.Finding) map[string][]models.Finding {
	groups := make(map[string][]models.Finding)
	for _, f := range findings {
		if f.Remediable {
			groups[f.RuleID] = append(groups[f.RuleID], f)
		}
	}
	return groups
}

// isDeterministic checks if a rule has a fully deterministic codemod.
func isDeterministic(ruleID string) bool {
	deterministic := map[string]bool{
		"md5-used":        true,
		"sha1-used":       true,
		"insecure-crypto": true,
		"xss":             true,
		"eval-usage":      true,
		"sql-injection":   false, // requires human verification
	}
	return deterministic[ruleID]
}

// uniqueFilePaths extracts unique file paths from findings.
func uniqueFilePaths(findings []models.Finding) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, f := range findings {
		if !seen[f.FilePath] {
			seen[f.FilePath] = true
			paths = append(paths, f.FilePath)
		}
	}
	return paths
}

// executeCodemod runs a codemod script against the target directory.
func executeCodemod(codemodsDir, script, targetDir string, files []string) ([]models.FixRecord, error) {
	scriptPath := filepath.Join(codemodsDir, script)

	// Check if script exists
	if _, err := os.Stat(scriptPath); err != nil {
		return nil, fmt.Errorf("codemod script not found: %s", scriptPath)
	}

	// Determine interpreter
	var cmd *exec.Cmd
	if strings.HasSuffix(script, ".py") {
		cmd = exec.Command("python3", scriptPath, targetDir, "--output", "/tmp/codemod_output.json")
	} else if strings.HasSuffix(script, ".js") {
		cmd = exec.Command("node", scriptPath, targetDir, "-o=/tmp/codemod_output.json")
	} else {
		return nil, fmt.Errorf("unsupported codemod type: %s", script)
	}

	cmd.Dir = targetDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("codemod execution failed: %v, output: %s", err, string(output))
	}

	// Parse codemod output
	data, err := os.ReadFile("/tmp/codemod_output.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read codemod output: %v", err)
	}

	var codemodResult map[string]interface{}
	if err := json.Unmarshal(data, &codemodResult); err != nil {
		return nil, fmt.Errorf("failed to parse codemod output: %v", err)
	}

	// Convert to fix records
	var fixes []models.FixRecord
	if changes, ok := codemodResult["changes"].([]interface{}); ok {
		for _, c := range changes {
			change := c.(map[string]interface{})
			fix := models.FixRecord{
				ID:            fmt.Sprintf("fix-%d", len(fixes)),
				CodemodName:   script,
				FilePath:      fmt.Sprintf("%v", change["file"]),
				OriginalCode:  fmt.Sprintf("%v", change["original"]),
				FixedCode:     fmt.Sprintf("%v", change["fixed"]),
				Status:        "success",
				ValidationPassed: false, // Set by validation gate
				RescanPassed:  false,   // Set by rescan
				AppliedAt:     time.Now(),
			}
			fixes = append(fixes, fix)
		}
	}

	return fixes, nil
}

// countByStatus counts fix records with a specific status.
func countByStatus(records []models.FixRecord, status string) int {
	count := 0
	for _, r := range records {
		if r.Status == status {
			count++
		}
	}
	return count
}
