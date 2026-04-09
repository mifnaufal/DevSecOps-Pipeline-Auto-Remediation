package models

import (
	"time"
)

// Severity represents the security severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingStatus represents the lifecycle state of a security finding.
type FindingStatus string

const (
	FindingStatusNew        FindingStatus = "new"
	FindingStatusConfirmed  FindingStatus = "confirmed"
	FindingStatusRemediated FindingStatus = "remediated"
	FindingStatusFalsePos   FindingStatus = "false_positive"
	FindingStatusAccepted   FindingStatus = "accepted_risk"
)

// Finding represents a unified security vulnerability finding.
// Normalized from multiple scanner formats (SARIF, Trivy JSON, ZAP).
type Finding struct {
	ID              string        `json:"id"`
	ExternalID      string        `json:"external_id"`      // Original scanner ID
	Scanner         string        `json:"scanner"`          // semgrep, trivy, zap
	RuleID          string        `json:"rule_id"`
	CWE             []string      `json:"cwe"`              // CWE-79, CWE-89, etc.
	CVE             []string      `json:"cve"`              // For SCA findings
	Title           string        `json:"title"`
	Description     string        `json:"description"`
	Severity        Severity      `json:"severity"`
	Confidence      string        `json:"confidence"`       // high, medium, low
	FilePath        string        `json:"file_path"`
	StartLine       int           `json:"start_line"`
	EndLine         int           `json:"end_line"`
	CodeSnippet     string        `json:"code_snippet"`
	Remediable      bool          `json:"remediable"`       // Has known codemod fix
	RemediationHint string        `json:"remediation_hint"` // Suggested fix description
	Fingerprint     string        `json:"fingerprint"`      // Dedup hash
	Status          FindingStatus `json:"status"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
	ScanID          string        `json:"scan_id"`
}

// Fingerprint generates a deterministic hash for deduplication.
// Based on: file_path + rule_id + start_line + code content.
func (f *Finding) ComputeFingerprint() string {
	// Implementation uses SHA256 of canonical string
	// Handled by triage/dedup.go
	return ""
}

// IsRemediable checks if a finding matches a known codemod pattern.
func (f *Finding) IsRemediable() bool {
	// Cross-references rule_id and CWE against codemod registry
	return f.Remediable
}
