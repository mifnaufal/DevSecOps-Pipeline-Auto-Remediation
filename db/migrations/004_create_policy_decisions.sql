-- Migration 004: Create policy_decisions table
-- Records OPA policy evaluation results for audit.

CREATE TABLE IF NOT EXISTS policy_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name     VARCHAR(255) NOT NULL,
    input_json      JSONB NOT NULL,
    result_json     JSONB NOT NULL,
    decision        VARCHAR(20) NOT NULL,  -- allow, deny, warn
    violations      TEXT[],
    evaluated_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_policy_decisions_policy_name ON policy_decisions(policy_name);
CREATE INDEX idx_policy_decisions_decision ON policy_decisions(decision);
CREATE INDEX idx_policy_decisions_evaluated_at ON policy_decisions(evaluated_at DESC);
CREATE INDEX idx_policy_decisions_violations ON policy_decisions USING GIN(violations);
CREATE INDEX idx_policy_decisions_input_gin ON policy_decisions USING GIN(input_json);

-- Partial index for denied decisions
CREATE INDEX idx_policy_decisions_denied ON policy_decisions(id) WHERE decision = 'deny';

COMMENT ON TABLE policy_decisions IS 'OPA policy evaluation results for audit trail';
COMMENT ON COLUMN policy_decisions.input_json IS 'JSON input sent to OPA';
COMMENT ON COLUMN policy_decisions.result_json IS 'JSON result returned from OPA';
COMMENT ON COLUMN policy_decisions.violations IS 'Array of human-readable violation messages';
