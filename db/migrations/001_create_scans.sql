-- Migration 001: Create scans table
-- Stores metadata for each pipeline scan execution.

CREATE TABLE IF NOT EXISTS scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository      VARCHAR(255) NOT NULL,
    commit_sha      VARCHAR(40) NOT NULL,
    branch          VARCHAR(255) NOT NULL,
    trigger_type    VARCHAR(50) NOT NULL,  -- push, pull_request, schedule, manual
    scan_type       VARCHAR(50) NOT NULL,  -- sast, sca, dast, secrets
    tool            VARCHAR(100) NOT NULL, -- semgrep, trivy, zap
    tool_version    VARCHAR(50),
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    sarif_path      TEXT,
    started_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    error_message   TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_scans_repository ON scans(repository);
CREATE INDEX idx_scans_commit_sha ON scans(commit_sha);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX idx_scans_tool ON scans(tool);

-- Partial index for incomplete scans
CREATE INDEX idx_scans_incomplete ON scans(id) WHERE status NOT IN ('completed', 'failed', 'cancelled');

-- Comment
COMMENT ON TABLE scans IS 'Pipeline scan execution metadata';
COMMENT ON COLUMN scans.commit_sha IS 'Full 40-character Git commit SHA';
COMMENT ON COLUMN scans.sarif_path IS 'Path to SARIF output file in artifact storage';
