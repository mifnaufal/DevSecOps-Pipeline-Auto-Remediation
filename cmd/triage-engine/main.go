// Package triage implements the main entry point for the triage engine CLI.
//
// Usage:
//
//	triage-engine --input-dir <sarif_dir> --output findings.json \
//	  --min-severity high --dedup true --cwe-mapping true
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
	"github.com/evsecops/devsecops-auto-remediation/internal/sarif"
	"github.com/evsecops/devsecops-auto-remediation/internal/triage"
)

func main() {
	var (
		inputDir    = flag.String("input-dir", "reports/sarif", "Directory containing SARIF files")
		output      = flag.String("output", "reports/triage/findings.json", "Output findings JSON path")
		minSeverity = flag.String("min-severity", "high", "Minimum severity to include (info, low, medium, high, critical)")
		dedup       = flag.Bool("dedup", true, "Enable finding deduplication")
		cweMapping  = flag.Bool("cwe-mapping", true, "Enable CWE mapping")
	)
	flag.Parse()

	startTime := time.Now()

	// Parse all SARIF files in input directory
	var allFindings []models.Finding
	sarifParser := sarif.NewParser()

	entries, err := os.ReadDir(*inputDir)
	if err != nil {
		log.Fatalf("Failed to read input directory %s: %v", *inputDir, err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".sarif") {
			continue
		}

		filePath := filepath.Join(*inputDir, entry.Name())
		scanID := strings.TrimSuffix(entry.Name(), ".sarif")

		log.Printf("Parsing SARIF: %s", filePath)
		sarifLog, err := sarifParser.ParseFile(filePath)
		if err != nil {
			log.Printf("WARNING: Failed to parse %s: %v", filePath, err)
			continue
		}

		// Determine scanner type from file name
		scanner := detectScanner(entry.Name(), sarifLog)

		findings := sarifParser.Normalize(sarifLog, scanner, scanID)
		allFindings = append(allFindings, findings...)
	}

	log.Printf("Total raw findings: %d", len(allFindings))

	// Apply CWE mapping if enabled
	if *cweMapping {
		log.Println("Applying CWE mapping...")
		// CWE mapping is already done during SARIF normalization
		// Additional enrichment can be added here
	}

	// Deduplicate findings
	if *dedup {
		log.Println("Deduplicating findings...")
		dedup := triage.NewDeduplicator()
		allFindings = dedup.Deduplicate(allFindings)
		log.Printf("Findings after dedup: %d", dedup.Count())
	}

	// Correlate across scanners
	correlator := triage.NewCorrelator()
	allFindings = correlator.Correlate(allFindings)

	// Filter by minimum severity
	allFindings = filterBySeverity(allFindings, *minSeverity)
	log.Printf("Findings after severity filter (≥%s): %d", *minSeverity, len(allFindings))

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Write output
	data, err := json.MarshalIndent(allFindings, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal findings: %v", err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("Failed to write findings: %v", err)
	}

	duration := time.Since(startTime)
	log.Printf("Triage completed in %s. Output: %s", duration, *output)
}

// detectScanner determines the scanner type from SARIF filename or content.
func detectScanner(filename string, log *sarif.SARIFLog) string {
	name := strings.ToLower(filename)
	switch {
	case strings.Contains(name, "semgrep"):
		return "semgrep"
	case strings.Contains(name, "trivy"):
		return "trivy"
	case strings.Contains(name, "zap"):
		return "zap"
	default:
		if len(log.Runs) > 0 {
			return strings.ToLower(log.Runs[0].Tool.Driver.Name)
		}
		return "unknown"
	}
}

// severityOrder defines the severity hierarchy.
var severityOrder = map[models.Severity]int{
	models.SeverityInfo:     0,
	models.SeverityLow:      1,
	models.SeverityMedium:   2,
	models.SeverityHigh:     3,
	models.SeverityCritical: 4,
}

// filterBySeverity returns findings at or above the minimum severity level.
func filterBySeverity(findings []models.Finding, minSeverity string) []models.Finding {
	minLevel, ok := severityOrder[models.Severity(minSeverity)]
	if !ok {
		minLevel = 3 // default to high
	}

	var filtered []models.Finding
	for _, f := range findings {
		if level, exists := severityOrder[f.Severity]; exists && level >= minLevel {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
