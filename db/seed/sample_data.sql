-- Sample development data for testing the dashboard.

-- Insert a sample scan
INSERT INTO scans (id, repository, commit_sha, branch, trigger_type, scan_type, tool, tool_version, status, files_scanned, finding_count, critical_count, high_count, medium_count, low_count, started_at, completed_at, duration_seconds) VALUES
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'myorg/webapp', 'abc123def456789012345678901234567890abcd', 'main', 'push', 'sast', 'semgrep', '1.50.0', 'completed', 342, 15, 3, 8, 4, 0, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour' + INTERVAL '45 seconds', 45),
  ('b2c3d4e5-f6a7-8901-bcde-f12345678901', 'myorg/webapp', 'def456789012345678901234567890abcdef1234', 'main', 'push', 'sca', 'trivy', '0.48.0', 'completed', 1, 8, 1, 5, 2, 0, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours' + INTERVAL '30 seconds', 30);

-- Insert sample findings
INSERT INTO findings (id, scan_id, external_id, scanner, rule_id, cwe, title, description, severity, confidence, file_path, start_line, end_line, code_snippet, remediable, remediation_hint, fingerprint, status) VALUES
  ('f1a2b3c4-d5e6-7890-abcd-ef1234567890', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'hardcoded-secret', 'semgrep', 'hardcoded-secret', ARRAY['CWE-798'], 'Hardcoded secret detected', 'API key found in source code', 'critical', 'high', 'config/settings.py', 12, 12, 'API_KEY = "sk-test-12345"', true, 'Move secret to environment variable or secret manager', 'fp001', 'new'),
  ('f2a2b3c4-d5e6-7890-abcd-ef1234567890', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'md5-used', 'semgrep', 'md5-used', ARRAY['CWE-327', 'CWE-328'], 'Use of MD5 hash function', 'MD5 is cryptographically broken', 'high', 'high', 'auth/hasher.py', 25, 25, 'hashlib.md5(password.encode()).hexdigest()', true, 'Replace MD5 with SHA-256 or stronger hash function', 'fp002', 'confirmed'),
  ('f3a2b3c4-d5e6-7890-abcd-ef1234567890', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'sql-injection', 'semgrep', 'sql-injection', ARRAY['CWE-89'], 'SQL injection via string concatenation', 'User input directly concatenated into SQL query', 'critical', 'high', 'api/users.py', 45, 45, '"SELECT * FROM users WHERE id = " + user_id', true, 'Use parameterized queries or ORM instead of string concatenation', 'fp003', 'new'),
  ('f4a2b3c4-d5e6-7890-abcd-ef1234567890', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'xss-innerhtml', 'semgrep', 'xss', ARRAY['CWE-79'], 'Potential XSS via innerHTML', 'User input rendered via innerHTML', 'high', 'medium', 'frontend/components/UserCard.jsx', 18, 18, 'element.innerHTML = userData.name', true, 'Replace innerHTML with textContent or use safe DOM APIs', 'fp004', 'new'),
  ('f5a2b3c4-d5e6-7890-abcd-ef1234567890', 'b2c3d4e5-f6a7-8901-bcde-f12345678901', 'CVE-2024-1234', 'trivy', 'CVE-2024-1234', ARRAY['CWE-502'], 'Insecure deserialization in express', 'express < 4.18.3 allows prototype pollution', 'high', 'high', 'package-lock.json', 0, 0, 'express@4.17.1', false, 'Update express to version >= 4.18.3', 'fp005', 'new');

-- Insert sample fixes
INSERT INTO fixes (id, finding_id, codemod_name, file_path, original_code, fixed_code, status, validation_passed, rescan_passed, applied_at) VALUES
  ('fx1a2b3c-d4e5-6789-abcd-ef1234567890', 'f2a2b3c4-d5e6-7890-abcd-ef1234567890', 'insecure_crypto.py', 'auth/hasher.py', 'hashlib.md5(password.encode()).hexdigest()', 'hashlib.sha256(password.encode()).hexdigest()', 'success', true, true, NOW() - INTERVAL '30 minutes'),
  ('fx2a2b3c-d4e5-6789-abcd-ef1234567890', 'f4a2b3c4-d5e6-7890-abcd-ef1234567890', 'xss_sanitization.js', 'frontend/components/UserCard.jsx', 'element.innerHTML = userData.name', 'element.textContent = userData.name', 'success', true, true, NOW() - INTERVAL '25 minutes');

-- Insert sample policy decisions
INSERT INTO policy_decisions (policy_name, input_json, result_json, decision, violations, evaluated_at) VALUES
  ('pr_approval', '{"files_changed": 2, "additions": 15, "deletions": 10, "is_auto_fix": true, "pr_labels": ["security", "auto-remediation"], "base_ref": "main"}', '{"allowed": true, "violations": []}', 'allow', '{}', NOW() - INTERVAL '20 minutes'),
  ('scope_limit', '{"changed_files": ["auth/hasher.py", "frontend/components/UserCard.jsx"], "is_auto_fix": true}', '{"within_bounds": true}', 'allow', '{}', NOW() - INTERVAL '19 minutes');

-- Insert sample pipeline metrics
INSERT INTO pipeline_metrics (pipeline_run_id, repository, commit_sha, total_duration_sec, scan_duration_sec, triage_duration_sec, remediation_duration_sec, validation_duration_sec, total_findings, high_critical_findings, fixes_attempted, fixes_successful, fix_accuracy_rate, false_positive_rate, regression_count, pr_created, pr_url, policy_compliant, timestamp) VALUES
  ('run-001', 'myorg/webapp', 'abc123def456789012345678901234567890abcd', 75, 45, 10, 8, 12, 15, 11, 5, 4, 95.00, 2.50, 0, true, 'https://github.com/myorg/webapp/pull/123', true, NOW() - INTERVAL '1 hour'),
  ('run-002', 'myorg/webapp', 'def456789012345678901234567890abcdef1234', 68, 30, 12, 10, 16, 8, 6, 3, 3, 100.00, 1.00, 0, true, 'https://github.com/myorg/webapp/pull/124', true, NOW() - INTERVAL '2 hours');
