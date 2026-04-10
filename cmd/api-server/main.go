// Package main implements the REST API server for the security dashboard.
//
// Provides endpoints for querying scans, findings, fixes, metrics,
// and aggregated dashboard data.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var db *pgxpool.Pool

func main() {
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://devsecops:devsecops@localhost:5432/devsecops?sslmode=disable"
	}

	var err error
	db, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	// Routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", healthCheck)

		// Scans
		r.Get("/scans", listScans)
		r.Get("/scans/{id}", getScan)

		// Findings
		r.Get("/findings", listFindings)
		r.Get("/findings/{id}", getFinding)
		r.Put("/findings/{id}/status", updateFindingStatus)

		// Fixes
		r.Get("/fixes", listFixes)
		r.Get("/fixes/{id}", getFix)

		// Metrics
		r.Get("/metrics", getMetrics)
		r.Get("/metrics/summary", getMetricsSummary)

		// Policy decisions
		r.Get("/policies", listPolicyDecisions)
	})

	// Prometheus metrics endpoint
	r.Handle("/metrics/prometheus", promhttp.Handler())

	log.Printf("API server starting on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"database":  "connected",
	})
}

// === Scan Endpoints ===

func listScans(w http.ResponseWriter, r *http.Request) {
	limit := 50
	page := 1

	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if p := r.URL.Query().Get("page"); p != "" {
		fmt.Sscanf(p, "%d", &page)
	}

	offset := (page - 1) * limit

	rows, err := db.Query(r.Context(),
		`SELECT id, repository, commit_sha, branch, trigger_type, scan_type, tool,
			status, finding_count, critical_count, high_count, medium_count, low_count,
			started_at, completed_at, duration_seconds, created_at
		 FROM scans ORDER BY started_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan map[string]interface{}
		scan = make(map[string]interface{})
		var id, repo, commitSHA, branch, trigger, scanType, tool, status string
		var findings, critical, high, medium, low, duration int
		var startedAt time.Time
		var completedAt, createdAt *time.Time

		if err := rows.Scan(&id, &repo, &commitSHA, &branch, &trigger, &scanType, &tool,
			&status, &findings, &critical, &high, &medium, &low,
			&startedAt, &completedAt, &duration, &createdAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		scan["id"] = id
		scan["repository"] = repo
		scan["commit_sha"] = commitSHA
		scan["branch"] = branch
		scan["trigger_type"] = trigger
		scan["scan_type"] = scanType
		scan["tool"] = tool
		scan["status"] = status
		scan["finding_count"] = findings
		scan["critical_count"] = critical
		scan["high_count"] = high
		scan["medium_count"] = medium
		scan["low_count"] = low
		scan["started_at"] = startedAt
		scan["completed_at"] = completedAt
		scan["duration_seconds"] = duration
		scan["created_at"] = createdAt
		scans = append(scans, scan)
	}

	render.JSON(w, r, scans)
}

func getScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var idVal, repo, commitSHA, branch, trigger, scanType, tool, toolVer, status, sarifPath, errMsg string
	var filesScanned, findings, critical, high, medium, low, duration int
	var startedAt time.Time
	var completedAt, createdAt *time.Time

	err := db.QueryRow(r.Context(),
		`SELECT id, repository, commit_sha, branch, trigger_type, scan_type, tool,
			tool_version, status, files_scanned, finding_count, critical_count, high_count,
			medium_count, low_count, sarif_path, started_at, completed_at, duration_seconds,
			error_message, created_at
		 FROM scans WHERE id = $1`,
		id).Scan(
		&idVal, &repo, &commitSHA, &branch, &trigger, &scanType, &tool, &toolVer,
		&status, &filesScanned, &findings, &critical, &high, &medium, &low, &sarifPath,
		&startedAt, &completedAt, &duration, &errMsg, &createdAt,
	)

	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	scan := map[string]interface{}{
		"id": idVal, "repository": repo, "commit_sha": commitSHA, "branch": branch,
		"trigger_type": trigger, "scan_type": scanType, "tool": tool, "tool_version": toolVer,
		"status": status, "files_scanned": filesScanned, "finding_count": findings,
		"critical_count": critical, "high_count": high, "medium_count": medium, "low_count": low,
		"sarif_path": sarifPath, "started_at": startedAt, "completed_at": completedAt,
		"duration_seconds": duration, "error_message": errMsg, "created_at": createdAt,
	}

	render.JSON(w, r, scan)
}

// === Finding Endpoints ===

func listFindings(w http.ResponseWriter, r *http.Request) {
	limit := 100
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	scanner := r.URL.Query().Get("scanner")

	query := `SELECT id, scan_id, external_id, scanner, rule_id, cwe, cve,
		title, description, severity, confidence, file_path, start_line, end_line,
		code_snippet, remediable, remediation_hint, status, created_at
		FROM findings WHERE 1=1`
	args := []interface{}{}
	argCount := 1

	if severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, severity)
		argCount++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argCount)
		args = append(args, status)
		argCount++
	}
	if scanner != "" {
		query += fmt.Sprintf(" AND scanner = $%d", argCount)
		args = append(args, scanner)
		argCount++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argCount)
	args = append(args, limit)

	rows, err := db.Query(r.Context(), query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var findings []map[string]interface{}
	for rows.Next() {
		var id, scanID, extID, scanner, ruleID, title, desc, severity, confidence string
		var filePath, snippet, hint, status string
		var startLine, endLine int
		var remediable bool
		var createdAt time.Time
		var cwes, cves []string

		if err := rows.Scan(
			&id, &scanID, &extID, &scanner, &ruleID,
			&cwes, &cves, &title, &desc, &severity, &confidence,
			&filePath, &startLine, &endLine, &snippet,
			&remediable, &hint, &status, &createdAt,
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		f := map[string]interface{}{
			"id": id, "scan_id": scanID, "external_id": extID, "scanner": scanner,
			"rule_id": ruleID, "cwe": cwes, "cve": cves, "title": title,
			"description": desc, "severity": severity, "confidence": confidence,
			"file_path": filePath, "start_line": startLine, "end_line": endLine,
			"code_snippet": snippet, "remediable": remediable, "remediation_hint": hint,
			"status": status, "created_at": createdAt,
		}
		findings = append(findings, f)
	}

	render.JSON(w, r, findings)
}

func getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var idVal, scanID, extID, scanner, ruleID, title, desc, severity, confidence string
	var filePath, snippet, hint, fingerprint, status string
	var startLine, endLine int
	var remediable bool
	var createdAt, updatedAt time.Time
	var cwes, cves []string

	err := db.QueryRow(r.Context(),
		`SELECT id, scan_id, external_id, scanner, rule_id, cwe, cve,
			title, description, severity, confidence, file_path, start_line, end_line,
			code_snippet, remediable, remediation_hint, fingerprint, status, created_at, updated_at
		 FROM findings WHERE id = $1`,
		id).Scan(
		&idVal, &scanID, &extID, &scanner, &ruleID,
		&cwes, &cves, &title, &desc, &severity, &confidence,
		&filePath, &startLine, &endLine, &snippet,
		&remediable, &hint, &fingerprint, &status, &createdAt, &updatedAt,
	)

	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	f := map[string]interface{}{
		"id": idVal, "scan_id": scanID, "external_id": extID, "scanner": scanner,
		"rule_id": ruleID, "cwe": cwes, "cve": cves, "title": title,
		"description": desc, "severity": severity, "confidence": confidence,
		"file_path": filePath, "start_line": startLine, "end_line": endLine,
		"code_snippet": snippet, "remediable": remediable, "remediation_hint": hint,
		"fingerprint": fingerprint, "status": status, "created_at": createdAt, "updated_at": updatedAt,
	}

	render.JSON(w, r, f)
}

type StatusUpdateRequest struct {
	Status string `json:"status"`
}

func (r *StatusUpdateRequest) Bind(_ *http.Request) error { return nil }

func updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req StatusUpdateRequest
	if err := render.Bind(r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	validStatuses := map[string]bool{
		"new": true, "confirmed": true, "remediated": true,
		"false_positive": true, "accepted_risk": true,
	}
	if !validStatuses[req.Status] {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}

	_, err := db.Exec(r.Context(),
		"UPDATE findings SET status = $1, updated_at = NOW() WHERE id = $2",
		req.Status, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.JSON(w, r, map[string]string{"status": req.Status, "id": id})
}

// === Fix Endpoints ===

func listFixes(w http.ResponseWriter, r *http.Request) {
	limit := 100
	rows, err := db.Query(r.Context(),
		`SELECT id, finding_id, codemod_name, file_path, status,
			validation_passed, rescan_passed, pr_url, pr_number, error, applied_at
		 FROM fixes ORDER BY applied_at DESC LIMIT $1`,
		limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var fixes []map[string]interface{}
	for rows.Next() {
		var id, findingID, codemodName, filePath, status string
		var validationPassed, rescanPassed bool
		var prURL, prNum, errMsg *string
		var appliedAt *time.Time

		if err := rows.Scan(&id, &findingID, &codemodName, &filePath,
			&status, &validationPassed, &rescanPassed,
			&prURL, &prNum, &errMsg, &appliedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		f := map[string]interface{}{
			"id": id, "finding_id": findingID, "codemod_name": codemodName,
			"file_path": filePath, "status": status,
			"validation_passed": validationPassed, "rescan_passed": rescanPassed,
			"pr_url": prURL, "pr_number": prNum, "error": errMsg, "applied_at": appliedAt,
		}
		fixes = append(fixes, f)
	}

	render.JSON(w, r, fixes)
}

func getFix(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var idVal, findingID, codemodName, filePath, status string
	var originalCode, fixedCode, prURL, prNum, errMsg *string
	var validationPassed, rescanPassed bool
	var appliedAt *time.Time

	err := db.QueryRow(r.Context(),
		`SELECT id, finding_id, codemod_name, file_path, original_code, fixed_code,
			status, validation_passed, rescan_passed, pr_url, pr_number, error, applied_at
		 FROM fixes WHERE id = $1`,
		id).Scan(
		&idVal, &findingID, &codemodName, &filePath,
		&originalCode, &fixedCode, &status,
		&validationPassed, &rescanPassed, &prURL,
		&prNum, &errMsg, &appliedAt,
	)

	if err != nil {
		http.Error(w, "fix not found", http.StatusNotFound)
		return
	}

	f := map[string]interface{}{
		"id": idVal, "finding_id": findingID, "codemod_name": codemodName,
		"file_path": filePath, "original_code": originalCode, "fixed_code": fixedCode,
		"status": status, "validation_passed": validationPassed, "rescan_passed": rescanPassed,
		"pr_url": prURL, "pr_number": prNum, "error": errMsg, "applied_at": appliedAt,
	}

	render.JSON(w, r, f)
}

// === Metrics Endpoints ===

func getMetrics(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(r.Context(),
		`SELECT id, pipeline_run_id, repository, commit_sha, total_duration_sec,
			scan_duration_sec, triage_duration_sec, remediation_duration_sec,
			validation_duration_sec, total_findings, high_critical_findings,
			fixes_attempted, fixes_successful, fix_accuracy_rate,
			false_positive_rate, regression_count, pr_created, pr_url,
			policy_compliant, timestamp
		 FROM pipeline_metrics ORDER BY timestamp DESC LIMIT 50`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var metrics []map[string]interface{}
	for rows.Next() {
		var id, pipelineRunID, repo, commitSHA, prURL string
		var totalDur, scanDur, triageDur, remediationDur, validationDur *int
		var totalFindings, highCritical, fixesAttempted, fixesSuccessful, regression *int
		var fixAccuracy, falsePositiveRate *float64
		var prCreated, policyCompliant bool
		var ts time.Time

		if err := rows.Scan(&id, &pipelineRunID, &repo, &commitSHA,
			&totalDur, &scanDur, &triageDur,
			&remediationDur, &validationDur,
			&totalFindings, &highCritical, &fixesAttempted,
			&fixesSuccessful, &fixAccuracy, &falsePositiveRate,
			&regression, &prCreated, &prURL,
			&policyCompliant, &ts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		m := map[string]interface{}{
			"id": id, "pipeline_run_id": pipelineRunID, "repository": repo, "commit_sha": commitSHA,
			"total_duration_sec": totalDur, "scan_duration_sec": scanDur, "triage_duration_sec": triageDur,
			"remediation_duration_sec": remediationDur, "validation_duration_sec": validationDur,
			"total_findings": totalFindings, "high_critical_findings": highCritical,
			"fixes_attempted": fixesAttempted, "fixes_successful": fixesSuccessful,
			"fix_accuracy_rate": fixAccuracy, "false_positive_rate": falsePositiveRate,
			"regression_count": regression, "pr_created": prCreated, "pr_url": prURL,
			"policy_compliant": policyCompliant, "timestamp": ts,
		}
		metrics = append(metrics, m)
	}

	render.JSON(w, r, metrics)
}

func getMetricsSummary(w http.ResponseWriter, r *http.Request) {
	var totalScans int
	var avgDuration, avgFixAccuracy, avgFalsePositive float64
	var totalFindings, totalFixes, compliantScans int

	err := db.QueryRow(r.Context(),
		`SELECT
			COUNT(*) as total_scans,
			COALESCE(AVG(total_duration_sec), 0) as avg_duration,
			COALESCE(AVG(fix_accuracy_rate), 0) as avg_fix_accuracy,
			COALESCE(AVG(false_positive_rate), 0) as avg_false_positive,
			COALESCE(SUM(total_findings), 0) as total_findings,
			COALESCE(SUM(fixes_successful), 0) as total_fixes,
			COUNT(CASE WHEN policy_compliant THEN 1 END) as compliant_scans
		 FROM pipeline_metrics`).Scan(
		&totalScans, &avgDuration,
		&avgFixAccuracy, &avgFalsePositive,
		&totalFindings, &totalFixes, &compliantScans,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	summary := map[string]interface{}{
		"total_scans":             totalScans,
		"avg_duration_sec":        avgDuration,
		"avg_fix_accuracy_rate":   avgFixAccuracy,
		"avg_false_positive_rate": avgFalsePositive,
		"total_findings":          totalFindings,
		"total_fixes":             totalFixes,
		"compliant_scans":         compliantScans,
	}

	render.JSON(w, r, summary)
}

// === Policy Decision Endpoints ===

func listPolicyDecisions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	rows, err := db.Query(r.Context(),
		`SELECT id, policy_name, decision, violations, evaluated_at
		 FROM policy_decisions ORDER BY evaluated_at DESC LIMIT $1`,
		limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var decisions []map[string]interface{}
	for rows.Next() {
		var id, policyName, decision string
		var violations string
		var evaluatedAt time.Time

		if err := rows.Scan(&id, &policyName, &decision, &violations, &evaluatedAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		d := map[string]interface{}{
			"id": id, "policy_name": policyName, "decision": decision,
			"violations": violations, "evaluated_at": evaluatedAt,
		}
		decisions = append(decisions, d)
	}

	render.JSON(w, r, decisions)
}
