package triage

import (
	"testing"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

func TestDeduplicator_ComputeFingerprint(t *testing.T) {
	d := NewDeduplicator()

	f1 := &models.Finding{
		FilePath:  "config.py",
		RuleID:    "hardcoded-secret",
		StartLine: 10,
	}

	f2 := &models.Finding{
		FilePath:  "config.py",
		RuleID:    "hardcoded-secret",
		StartLine: 10,
	}

	fp1 := d.ComputeFingerprint(f1)
	fp2 := d.ComputeFingerprint(f2)

	if fp1 != fp2 {
		t.Errorf("Fingerprints should match: %s vs %s", fp1, fp2)
	}
}

func TestDeduplicator_Add(t *testing.T) {
	d := NewDeduplicator()

	f1 := &models.Finding{
		FilePath:  "auth.py",
		RuleID:    "md5-used",
		StartLine: 25,
	}

	f2 := &models.Finding{
		FilePath:  "auth.py",
		RuleID:    "md5-used",
		StartLine: 25,
	}

	f3 := &models.Finding{
		FilePath:  "api.py",
		RuleID:    "sql-injection",
		StartLine: 45,
	}

	added1, _ := d.Add(f1)
	added2, dupOf := d.Add(f2)
	added3, _ := d.Add(f3)

	if !added1 {
		t.Error("First finding should be added")
	}
	if added2 {
		t.Error("Duplicate finding should not be added")
	}
	if dupOf == nil {
		t.Error("Duplicate should reference original")
	}
	if !added3 {
		t.Error("Different finding should be added")
	}
}

func TestDeduplicator_Deduplicate(t *testing.T) {
	d := NewDeduplicator()

	findings := []models.Finding{
		{FilePath: "a.py", RuleID: "md5-used", StartLine: 1},
		{FilePath: "a.py", RuleID: "md5-used", StartLine: 1}, // dup
		{FilePath: "b.py", RuleID: "sha1-used", StartLine: 5},
		{FilePath: "b.py", RuleID: "sha1-used", StartLine: 5}, // dup
		{FilePath: "c.py", RuleID: "xss", StartLine: 10},
	}

	unique := d.Deduplicate(findings)

	if len(unique) != 3 {
		t.Errorf("Expected 3 unique findings, got %d", len(unique))
	}
	if d.Count() != 3 {
		t.Errorf("Expected count 3, got %d", d.Count())
	}
}

func TestCorrelator_Correlate(t *testing.T) {
	c := NewCorrelator()

	findings := []models.Finding{
		{FilePath: "auth.py", RuleID: "md5", Scanner: "semgrep", CWE: []string{"CWE-327"}},
		{FilePath: "auth.py", RuleID: "md5", Scanner: "trivy", CWE: []string{"CWE-328"}},
		{FilePath: "api.py", RuleID: "sqli", Scanner: "semgrep", CWE: []string{"CWE-89"}},
	}

	result := c.Correlate(findings)

	// First two should be correlated (same file+rule, different scanners)
	if result[0].Confidence != "high" {
		t.Errorf("Expected high confidence for correlated finding, got %s", result[0].Confidence)
	}
	if result[1].Confidence != "high" {
		t.Errorf("Expected high confidence for correlated finding, got %s", result[1].Confidence)
	}
	// Third one has no match
	if result[2].Confidence == "high" {
		t.Error("Expected non-high confidence for non-correlated finding")
	}
}

func TestMergeCWE(t *testing.T) {
	findings := []models.Finding{
		{CWE: []string{"CWE-327", "CWE-328"}},
		{CWE: []string{"CWE-328", "CWE-89"}},
		{CWE: []string{"CWE-79"}},
	}

	cwes := MergeCWE(findings)

	// Should have 4 unique CWEs
	if len(cwes) != 4 {
		t.Errorf("Expected 4 unique CWEs, got %d: %v", len(cwes), cwes)
	}
}

func TestGroupByFile(t *testing.T) {
	findings := []models.Finding{
		{FilePath: "auth.py", RuleID: "md5"},
		{FilePath: "auth.py", RuleID: "sha1"},
		{FilePath: "api.py", RuleID: "sqli"},
	}

	grouped := GroupByFile(findings)

	if len(grouped["auth.py"]) != 2 {
		t.Errorf("Expected 2 findings for auth.py, got %d", len(grouped["auth.py"]))
	}
	if len(grouped["api.py"]) != 1 {
		t.Errorf("Expected 1 finding for api.py, got %d", len(grouped["api.py"]))
	}
}

func TestGroupByCWE(t *testing.T) {
	findings := []models.Finding{
		{CWE: []string{"CWE-327"}},
		{CWE: []string{"CWE-327"}},
		{CWE: []string{"CWE-89"}},
		{}, // no CWE
	}

	grouped := GroupByCWE(findings)

	if len(grouped["CWE-327"]) != 2 {
		t.Errorf("Expected 2 findings for CWE-327, got %d", len(grouped["CWE-327"]))
	}
	if len(grouped["uncategorized"]) != 1 {
		t.Errorf("Expected 1 uncategorized finding, got %d", len(grouped["uncategorized"]))
	}
}
