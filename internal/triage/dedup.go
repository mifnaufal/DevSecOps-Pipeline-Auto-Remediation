package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

// Deduplicator handles finding deduplication using fingerprint comparison.
type Deduplicator struct {
	seen map[string]*models.Finding // fingerprint -> first occurrence
}

// NewDeduplicator creates a new deduplicator instance.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]*models.Finding),
	}
}

// ComputeFingerprint generates a deterministic hash for a finding.
// Uses file_path + rule_id + normalized code content for uniqueness.
func (d *Deduplicator) ComputeFingerprint(f *models.Finding) string {
	// Normalize inputs for consistent hashing
	filePath := strings.ToLower(strings.TrimSpace(f.FilePath))
	ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))

	// Create canonical string for hashing
	canonical := fmt.Sprintf("%s|%s|%d|%s",
		filePath,
		ruleID,
		f.StartLine,
		normalizeCodeSnippet(f.CodeSnippet),
	)

	hash := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(hash[:])
}

// normalizeCodeSnippet normalizes code for consistent fingerprinting.
// Removes whitespace variations and normalizes string literals.
func normalizeCodeSnippet(code string) string {
	if code == "" {
		return ""
	}
	// Normalize whitespace
	normalized := strings.TrimSpace(code)
	// Truncate to avoid huge hashes
	if len(normalized) > 200 {
		normalized = normalized[:200]
	}
	return strings.ToLower(normalized)
}

// Add attempts to add a finding. Returns (added, duplicate_of).
// If the finding is a duplicate, returns the original finding.
func (d *Deduplicator) Add(f *models.Finding) (bool, *models.Finding) {
	fp := d.ComputeFingerprint(f)
	f.Fingerprint = fp

	if existing, ok := d.seen[fp]; ok {
		return false, existing
	}

	d.seen[fp] = f
	return true, nil
}

// Deduplicate processes a list of findings and returns unique findings.
func (d *Deduplicator) Deduplicate(findings []models.Finding) []models.Finding {
	var unique []models.Finding
	duplicates := 0

	for i := range findings {
		added, _ := d.Add(&findings[i])
		if added {
			unique = append(unique, findings[i])
		} else {
			duplicates++
		}
	}

	// Log deduplication stats (handled by caller's logger)
	_ = duplicates
	return unique
}

// Count returns the number of unique findings tracked.
func (d *Deduplicator) Count() int {
	return len(d.seen)
}
