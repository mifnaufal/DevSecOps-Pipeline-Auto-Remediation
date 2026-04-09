-- Migration 002: Create findings table
-- Stores deduplicated security vulnerability findings.

CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    external_id     VARCHAR(255),
    scanner         VARCHAR(100) NOT NULL,
    rule_id         VARCHAR(255) NOT NULL,
    cwe             VARCHAR(50)[],
    cve             VARCHAR(50)[],
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL,
    confidence      VARCHAR(20),
    file_path       TEXT NOT NULL,
    start_line      INTEGER,
    end_line        INTEGER,
    code_snippet    TEXT,
    remediable      BOOLEAN NOT NULL DEFAULT false,
    remediation_hint TEXT,
    fingerprint     VARCHAR(64) NOT NULL,  -- SHA-256 hash for dedup
    status          VARCHAR(20) NOT NULL DEFAULT 'new',
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Ensure unique fingerprint per scan (dedup constraint)
    CONSTRAINT uq_finding_fingerprint UNIQUE (fingerprint, scan_id)
);

-- Indexes for common queries
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_scanner ON findings(scanner);
CREATE INDEX idx_findings_file_path ON findings(file_path);
CREATE INDEX idx_findings_cwe ON findings USING GIN(cwe);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);

-- Partial indexes
CREATE INDEX idx_findings_high_critical ON findings(id) WHERE severity IN ('high', 'critical');
CREATE INDEX idx_findings_remediable ON findings(id) WHERE remediable = true;
CREATE INDEX idx_findings_new ON findings(id) WHERE status = 'new';

-- Comment
COMMENT ON TABLE findings IS 'Deduplicated security vulnerability findings';
COMMENT ON COLUMN findings.fingerprint IS 'SHA-256 hash of file_path + rule_id + start_line + code content';
COMMENT ON COLUMN findings.cwe IS 'Array of CWE identifiers (e.g., {"CWE-89", "CWE-79"})';
