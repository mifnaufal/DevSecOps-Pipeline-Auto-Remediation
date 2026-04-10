// Package main implements the REST API server for the security dashboard.
//
// Provides endpoints for querying scans, findings, fixes, metrics,
// and aggregated dashboard data.
package main

import (
	"context"
	"encoding/json"
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
		f := make(map[string]interface{})
		var cwes, cves []string
		if err := rows.Scan(
			&f["id"], &f["scan_id"], &f["external_id"], &f["scanner"], &f["rule_id"],
			&cwes, &cves, &f["title"], &f["description"], &f["severity"], &f["confidence"],
			&f["file_path"], &f["start_line"], &f["end_line"], &f["code_snippet"],
			&f["remediable"], &f["remediation_hint"], &f["status"], &f["created_at"],
		); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f["cwe"] = cwes
		f["cve"] = cves
		findings = append(findings, f)
	}

	render.JSON(w, r, findings)
}

func getFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	f := make(map[string]interface{})
	var cwes, cves []string
	err := db.QueryRow(r.Context(),
		`SELECT id, scan_id, external_id, scanner, rule_id, cwe, cve,
			title, description, severity, confidence, file_path, start_line, end_line,
			code_snippet, remediable, remediation_hint, fingerprint, status, created_at, updated_at
		 FROM findings WHERE id = $1`,
		id).Scan(
		&f["id"], &f["scan_id"], &f["external_id"], &f["scanner"], &f["rule_id"],
		&cwes, &cves, &f["title"], &f["description"], &f["severity"], &f["confidence"],
		&f["file_path"], &f["start_line"], &f["end_line"], &f["code_snippet"],
		&f["remediable"], &f["remediation_hint"], &f["fingerprint"], &f["status"],
		&f["created_at"], &f["updated_at"],
	)

	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	f["cwe"] = cwes
	f["cve"] = cves
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
		f := make(map[string]interface{})
		rows.Scan(&f["id"], &f["finding_id"], &f["codemod_name"], &f["file_path"],
			&f["status"], &f["validation_passed"], &f["rescan_passed"],
			&f["pr_url"], &f["pr_number"], &f["error"], &f["applied_at"])
		fixes = append(fixes, f)
	}

	render.JSON(w, r, fixes)
}

func getFix(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := make(map[string]interface{})
	err := db.QueryRow(r.Context(),
		`SELECT id, finding_id, codemod_name, file_path, original_code, fixed_code,
			status, validation_passed, rescan_passed, pr_url, pr_number, error, applied_at
		 FROM fixes WHERE id = $1`,
		id).Scan(
		&f["id"], &f["finding_id"], &f["codemod_name"], &f["file_path"],
		&f["original_code"], &f["fixed_code"], &f["status"],
		&f["validation_passed"], &f["rescan_passed"], &f["pr_url"],
		&f["pr_number"], &f["error"], &f["applied_at"],
	)

	if err != nil {
		http.Error(w, "fix not found", http.StatusNotFound)
		return
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
		m := make(map[string]interface{})
		rows.Scan(&m["id"], &m["pipeline_run_id"], &m["repository"], &m["commit_sha"],
			&m["total_duration_sec"], &m["scan_duration_sec"], &m["triage_duration_sec"],
			&m["remediation_duration_sec"], &m["validation_duration_sec"],
			&m["total_findings"], &m["high_critical_findings"], &m["fixes_attempted"],
			&m["fixes_successful"], &m["fix_accuracy_rate"], &m["false_positive_rate"],
			&m["regression_count"], &m["pr_created"], &m["pr_url"],
			&m["policy_compliant"], &m["timestamp"])
		metrics = append(metrics, m)
	}

	render.JSON(w, r, metrics)
}

func getMetricsSummary(w http.ResponseWriter, r *http.Request) {
	var summary map[string]interface{}
	summary = make(map[string]interface{})

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
		&summary["total_scans"], &summary["avg_duration_sec"],
		&summary["avg_fix_accuracy_rate"], &summary["avg_false_positive_rate"],
		&summary["total_findings"], &summary["total_fixes"], &summary["compliant_scans"],
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		d := make(map[string]interface{})
		rows.Scan(&d["id"], &d["policy_name"], &d["decision"], &d["violations"], &d["evaluated_at"])
		decisions = append(decisions, d)
	}

	render.JSON(w, r, decisions)
}
