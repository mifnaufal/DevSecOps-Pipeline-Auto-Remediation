package triage

import (
	"strings"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

// Correlator cross-references findings from multiple scanners
// to identify overlapping vulnerabilities and boost confidence.
type Correlator struct {
	// fileRuleIndex maps file_path + rule_pattern -> []finding indices
	fileRuleIndex map[string][]int
}

// NewCorrelator creates a correlation engine instance.
func NewCorrelator() *Correlator {
	return &Correlator{
		fileRuleIndex: make(map[string][]int),
	}
}

// Correlate analyzes findings from multiple scanners and enhances them
// with cross-reference metadata (confidence boost, scanner agreement).
func (c *Correlator) Correlate(findings []models.Finding) []models.Finding {
	// Build index: normalized rule pattern -> finding indices
	for i, f := range findings {
		key := c.correlationKey(f)
		c.fileRuleIndex[key] = append(c.fileRuleIndex[key], i)
	}

	// Enhance findings with correlation data
	for i := range findings {
		key := c.correlationKey(findings[i])
		scanners := c.uniqueScannersFor(findings, c.fileRuleIndex[key])

		// Boost confidence if multiple scanners agree
		if len(scanners) > 1 {
			findings[i].Confidence = "high"
		}

		// Mark as confirmed if detected by 2+ scanners
		if len(scanners) >= 2 {
			findings[i].Status = models.FindingStatusConfirmed
		}
	}

	return findings
}

// correlationKey generates a normalized key for matching findings across scanners.
func (c *Correlator) correlationKey(f models.Finding) string {
	// Normalize rule ID: lowercase, remove version suffixes
	rule := strings.ToLower(f.RuleID)
	rule = strings.Split(rule, "@")[0]
	rule = strings.Split(rule, ".")[0]

	return strings.ToLower(f.FilePath) + "|" + rule
}

// uniqueScannersFor returns the list of unique scanner names for given finding indices.
func (c *Correlator) uniqueScannersFor(findings []models.Finding, indices []int) []string {
	seen := make(map[string]bool)
	var scanners []string

	for _, idx := range indices {
		scanner := findings[idx].Scanner
		if !seen[scanner] {
			seen[scanner] = true
			scanners = append(scanners, scanner)
		}
	}

	return scanners
}

// MergeCWE merges CWE lists from correlated findings, removing duplicates.
func MergeCWE(findings []models.Finding) []string {
	cweSet := make(map[string]bool)
	var cwes []string

	for _, f := range findings {
		for _, cwe := range f.CWE {
			if !cweSet[cwe] {
				cweSet[cwe] = true
				cwes = append(cwes, cwe)
			}
		}
	}

	return cwes
}

// GroupByFile groups findings by file path for efficient review.
func GroupByFile(findings []models.Finding) map[string][]models.Finding {
	grouped := make(map[string][]models.Finding)

	for _, f := range findings {
		grouped[f.FilePath] = append(grouped[f.FilePath], f)
	}

	return grouped
}

// GroupByCWE groups findings by CWE identifier for vulnerability category analysis.
func GroupByCWE(findings []models.Finding) map[string][]models.Finding {
	grouped := make(map[string][]models.Finding)

	for _, f := range findings {
		for _, cwe := range f.CWE {
			grouped[cwe] = append(grouped[cwe], f)
		}
		if len(f.CWE) == 0 {
			grouped["uncategorized"] = append(grouped["uncategorized"], f)
		}
	}

	return grouped
}
