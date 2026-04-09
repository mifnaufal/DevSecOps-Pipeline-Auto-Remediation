-- Migration 005: Create pipeline_metrics table
-- Tracks performance and outcome metrics for benchmarking.

CREATE TABLE IF NOT EXISTS pipeline_metrics (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_run_id         VARCHAR(100) NOT NULL,
    repository              VARCHAR(255) NOT NULL,
    commit_sha              VARCHAR(40) NOT NULL,
    total_duration_sec      INTEGER NOT NULL DEFAULT 0,
    scan_duration_sec        INTEGER NOT NULL DEFAULT 0,
    triage_duration_sec      INTEGER NOT NULL DEFAULT 0,
    remediation_duration_sec INTEGER NOT NULL DEFAULT 0,
    validation_duration_sec  INTEGER NOT NULL DEFAULT 0,
    total_findings           INTEGER NOT NULL DEFAULT 0,
    high_critical_findings   INTEGER NOT NULL DEFAULT 0,
    fixes_attempted          INTEGER NOT NULL DEFAULT 0,
    fixes_successful         INTEGER NOT NULL DEFAULT 0,
    fix_accuracy_rate        NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    false_positive_rate      NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    regression_count         INTEGER NOT NULL DEFAULT 0,
    pr_created               BOOLEAN NOT NULL DEFAULT false,
    pr_url                   TEXT,
    policy_compliant         BOOLEAN NOT NULL DEFAULT false,
    timestamp                TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_pipeline_metrics_repository ON pipeline_metrics(repository);
CREATE INDEX idx_pipeline_metrics_commit_sha ON pipeline_metrics(commit_sha);
CREATE INDEX idx_pipeline_metrics_timestamp ON pipeline_metrics(timestamp DESC);
CREATE INDEX idx_pipeline_metrics_policy_compliant ON pipeline_metrics(policy_compliant);
CREATE INDEX idx_pipeline_metrics_pr_created ON pipeline_metrics(pr_created);

-- Comment
COMMENT ON TABLE pipeline_metrics IS 'Pipeline performance and outcome metrics for benchmarking';
COMMENT ON COLUMN pipeline_metrics.fix_accuracy_rate IS 'Percentage of fixes that passed validation (0-100)';
COMMENT ON COLUMN pipeline_metrics.false_positive_rate IS 'Percentage of findings that were false positives (0-100)';
