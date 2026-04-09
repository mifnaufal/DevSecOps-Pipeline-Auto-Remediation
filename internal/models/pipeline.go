package models

import "time"

// PipelineMetric tracks performance and outcome data for each pipeline execution.
type PipelineMetric struct {
	ID                  string    `json:"id"`
	PipelineRunID       string    `json:"pipeline_run_id"`
	Repository          string    `json:"repository"`
	CommitSHA           string    `json:"commit_sha"`
	TotalDurationSec    int       `json:"total_duration_sec"`
	ScanDurationSec     int       `json:"scan_duration_sec"`
	TriageDurationSec   int       `json:"triage_duration_sec"`
	RemediationDuration int       `json:"remediation_duration_sec"`
	ValidationDuration  int       `json:"validation_duration_sec"`
	TotalFindings       int       `json:"total_findings"`
	HighCriticalFindings int      `json:"high_critical_findings"`
	FixesAttempted      int       `json:"fixes_attempted"`
	FixesSuccessful     int       `json:"fixes_successful"`
	FixAccuracyRate     float64   `json:"fix_accuracy_rate"`
	FalsePositiveRate   float64   `json:"false_positive_rate"`
	RegressionCount     int       `json:"regression_count"`
	PRCreated           bool      `json:"pr_created"`
	PRURL               string    `json:"pr_url"`
	PolicyCompliant     bool      `json:"policy_compliant"`
	Timestamp           time.Time `json:"timestamp"`
}

// FixRecord tracks an individual remediation attempt.
type FixRecord struct {
	ID                string    `json:"id"`
	FindingID         string    `json:"finding_id"`
	CodemodName       string    `json:"codemod_name"`
	FilePath          string    `json:"file_path"`
	OriginalCode      string    `json:"original_code"`
	FixedCode         string    `json:"fixed_code"`
	Status            string    `json:"status"` // success, failed, skipped
	ValidationPassed  bool      `json:"validation_passed"`
	RescanPassed      bool      `json:"rescan_passed"`
	Error             string    `json:"error"`
	AppliedAt         time.Time `json:"applied_at"`
}

// PolicyDecision records an OPA policy evaluation outcome.
type PolicyDecision struct {
	ID          string    `json:"id"`
	PolicyName  string    `json:"policy_name"`
	Input       string    `json:"input"`        // JSON input to OPA
	Result      string    `json:"result"`       // JSON result from OPA
	Decision    string    `json:"decision"`     // allow, deny, warn
	Violations  []string  `json:"violations"`   // Human-readable violation list
	EvaluatedAt time.Time `json:"evaluated_at"`
}
