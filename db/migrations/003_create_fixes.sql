-- Migration 003: Create fixes table
-- Tracks applied remediation patches.

CREATE TABLE IF NOT EXISTS fixes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id          UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    codemod_name        VARCHAR(255) NOT NULL,
    file_path           TEXT NOT NULL,
    original_code       TEXT,
    fixed_code          TEXT,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    validation_passed   BOOLEAN NOT NULL DEFAULT false,
    rescan_passed       BOOLEAN NOT NULL DEFAULT false,
    pr_url              TEXT,
    pr_number           INTEGER,
    error               TEXT,
    applied_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_fixes_finding_id ON fixes(finding_id);
CREATE INDEX idx_fixes_status ON fixes(status);
CREATE INDEX idx_fixes_file_path ON fixes(file_path);
CREATE INDEX idx_fixes_codemod_name ON fixes(codemod_name);
CREATE INDEX idx_fixes_validation_passed ON fixes(validation_passed);
CREATE INDEX idx_fixes_applied_at ON fixes(applied_at DESC);

-- Partial indexes
CREATE INDEX idx_fixes_successful ON fixes(id) WHERE status = 'success';
CREATE INDEX idx_fixes_failed ON fixes(id) WHERE status = 'failed';

COMMENT ON TABLE fixes IS 'Applied security remediation patches';
COMMENT ON COLUMN fixes.status IS 'pending, success, failed, reverted';
