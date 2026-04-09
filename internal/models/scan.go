package models

import (
	"time"
)

// ScanStatus represents the state of a security scan execution.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// ScanType represents the type of security scan.
type ScanType string

const (
	ScanTypeSAST    ScanType = "sast"     // Static Analysis (Semgrep)
	ScanTypeSCA     ScanType = "sca"      // Software Composition Analysis (Trivy)
	ScanTypeDAST    ScanType = "dast"     // Dynamic Analysis (ZAP)
	ScanTypeSecrets ScanType = "secrets"  // Secret detection
)

// Scan represents a pipeline scan execution metadata.
type Scan struct {
	ID              string     `json:"id"`
	Repository      string     `json:"repository"`
	CommitSHA       string     `json:"commit_sha"`
	Branch          string     `json:"branch"`
	Trigger         string     `json:"trigger"`          // push, pull_request, schedule
	ScanType        ScanType   `json:"scan_type"`
	Tool            string     `json:"tool"`             // semgrep, trivy, zap
	ToolVersion     string     `json:"tool_version"`
	Status          ScanStatus `json:"status"`
	FilesScanned    int        `json:"files_scanned"`
	FindingCount    int        `json:"finding_count"`
	CriticalCount   int        `json:"critical_count"`
	HighCount       int        `json:"high_count"`
	MediumCount     int        `json:"medium_count"`
	LowCount        int        `json:"low_count"`
	SARIFPath       string     `json:"sarif_path"`       // Path to SARIF output
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	DurationSeconds int        `json:"duration_seconds"`
	ErrorMessage    string     `json:"error_message"`
}
