package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/evsecops/devsecops-auto-remediation/internal/models"
)

// Parser handles SARIF file parsing and normalization.
type Parser struct {
	// cweMap maps common rule patterns to CWE identifiers
	cweMap map[string][]string
}

// NewParser creates a SARIF parser with CWE mapping.
func NewParser() *Parser {
	return &Parser{
		cweMap: map[string][]string{
			// OWASP Top 10 CWE mappings
			"hardcoded-secret":         {"CWE-798"},
			"hardcoded-password":       {"CWE-259"},
			"sql-injection":            {"CWE-89"},
			"xss":                      {"CWE-79"},
			"path-traversal":           {"CWE-22"},
			"ssrf":                     {"CWE-918"},
			"insecure-deserialization": {"CWE-502"},
			"xxe":                      {"CWE-611"},
			"open-redirect":            {"CWE-601"},
			"command-injection":        {"CWE-78"},
			"weak-crypto":              {"CWE-327", "CWE-328"},
			"insecure-crypto":          {"CWE-327", "CWE-328"},
			"insecure_crypto":          {"CWE-327", "CWE-328"},
			"md5-used":                 {"CWE-328"},
			"sha1-used":                {"CWE-328"},
			"insecure-random":          {"CWE-330"},
			"tls-insecure":             {"CWE-295"},
			"eval-usage":               {"CWE-95"},
		},
	}
}

// ParseFile reads a SARIF file from disk and returns the parsed log.
func (p *Parser) ParseFile(path string) (*SARIFLog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF file %s: %w", path, err)
	}
	return p.ParseBytes(data)
}

// ParseBytes parses SARIF JSON from byte slice.
func (p *Parser) ParseBytes(data []byte) (*SARIFLog, error) {
	var log SARIFLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	if log.Version != "2.1.0" && log.Version != "2.0.0" {
		return nil, fmt.Errorf("unsupported SARIF version: %s (expected 2.1.0)", log.Version)
	}

	return &log, nil
}

// ParseString parses SARIF JSON from string.
func (p *Parser) ParseString(data string) (*SARIFLog, error) {
	return p.ParseBytes([]byte(data))
}

// Normalize converts a SARIF log into unified Finding models.
func (p *Parser) Normalize(log *SARIFLog, scanner string, scanID string) []models.Finding {
	var findings []models.Finding

	for _, run := range log.Runs {
		toolName := run.Tool.Driver.Name
		if scanner != "" {
			toolName = scanner
		}

		for _, result := range run.Results {
			finding := p.resultToFinding(result, run, toolName, scanID)
			findings = append(findings, finding)
		}
	}

	return findings
}

// resultToFinding converts a single SARIF result to a unified Finding.
func (p *Parser) resultToFinding(result Result, run Run, toolName string, scanID string) models.Finding {
	finding := models.Finding{
		ExternalID:  result.RuleID,
		Scanner:     toolName,
		RuleID:      result.RuleID,
		Title:       result.Message.Text,
		Description: result.Message.Text,
		Severity:    p.mapSeverity(result.Level, result.Properties),
		Confidence:  p.mapConfidence(result.Kind),
		Remediable:  p.isRemediable(result.RuleID),
		Status:      models.FindingStatusNew,
		ScanID:      scanID,
	}

	// Extract CWE from rule properties or tags
	cweExtracted := false
	if run.Tool.Driver.Rules != nil {
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID == result.RuleID && rule.Properties != nil {
				cwes := p.mapCWE(rule.Properties.CWE)
				if len(cwes) > 0 {
					finding.CWE = cwes
					cweExtracted = true
				}
				break
			}
		}
	}

	// Fallback: use internal cweMap based on rule_id pattern matching
	// This handles SARIF files without full rule metadata (e.g., mock SARIF, older tools)
	if !cweExtracted {
		if fallback := p.lookupCWEByRuleID(result.RuleID); len(fallback) > 0 {
			finding.CWE = fallback
		}
	}

	// Extract location info
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		finding.FilePath = loc.PhysicalLocation.ArtifactLocation.URI
		finding.StartLine = loc.PhysicalLocation.Region.StartLine
		finding.EndLine = loc.PhysicalLocation.Region.EndLine
		finding.CodeSnippet = loc.PhysicalLocation.Region.Snippet.Text
	}

	// Generate fingerprint (deferred to dedup module)
	finding.Fingerprint = fmt.Sprintf("%s:%s:%d", finding.FilePath, finding.RuleID, finding.StartLine)

	// Set remediation hint based on rule pattern
	finding.RemediationHint = p.getRemediationHint(result.RuleID)

	return finding
}

// mapSeverity converts SARIF level to our Severity type.
func (p *Parser) mapSeverity(level string, props *ResultProperties) models.Severity {
	// Check for Semgrep security-severity property first
	if props != nil && props.SecuritySeverity != "" {
		switch props.SecuritySeverity {
		case "10.0", "9.0", "8.0":
			return models.SeverityCritical
		case "7.0", "6.0":
			return models.SeverityHigh
		case "5.0", "4.0":
			return models.SeverityMedium
		case "3.0", "2.0", "1.0":
			return models.SeverityLow
		}
	}

	switch strings.ToLower(level) {
	case "error":
		return models.SeverityHigh
	case "warning":
		return models.SeverityMedium
	case "note":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

// mapConfidence converts SARIF kind to confidence level.
func (p *Parser) mapConfidence(kind string) string {
	switch kind {
	case "fail":
		return "high"
	case "review":
		return "medium"
	case "pass":
		return "low"
	default:
		return "medium"
	}
}

// mapCWE parses CWE identifiers from rule metadata.
func (p *Parser) mapCWE(cweStr string) []string {
	if cweStr == "" {
		return nil
	}

	// Handle formats: "CWE-89", "CWE-89,CWE-123", "89"
	var cwes []string
	parts := strings.Split(cweStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CWE-") {
			cwes = append(cwes, part)
		} else if num := strings.TrimSpace(strings.TrimPrefix(part, "CWE")); num != "" {
			cwes = append(cwes, "CWE-"+num)
		}
	}
	return cwes
}

// lookupCWEByRuleID falls back to internal cweMap when SARIF rule metadata is empty.
// Uses substring matching to find the best CWE for a given rule ID.
func (p *Parser) lookupCWEByRuleID(ruleID string) []string {
	ruleIDLower := strings.ToLower(ruleID)

	// Exact match first
	if cwes, ok := p.cweMap[ruleIDLower]; ok {
		return cwes
	}

	// Substring match — longer patterns first for specificity
	type patternMatch struct {
		pattern string
		cwes    []string
	}
	var matches []patternMatch
	for pattern, cwes := range p.cweMap {
		if strings.Contains(ruleIDLower, pattern) {
			matches = append(matches, patternMatch{pattern, cwes})
		}
	}

	if len(matches) == 0 {
		return nil
	}

	// Pick the match with the longest pattern (most specific)
	best := matches[0]
	for _, m := range matches[1:] {
		if len(m.pattern) > len(best.pattern) {
			best = m
		}
	}
	return best.cwes
}

// isRemediable checks if a rule ID has a known codemod fix.
func (p *Parser) isRemediable(ruleID string) bool {
	remediablePatterns := []string{
		"hardcoded-secret",
		"hardcoded-password",
		"md5-used",
		"sha1-used",
		"insecure-crypto",
		"sql-injection",
		"xss",
		"eval-usage",
		"insecure-random",
		"tls-insecure",
	}

	ruleIDLower := strings.ToLower(ruleID)
	for _, pattern := range remediablePatterns {
		if strings.Contains(ruleIDLower, pattern) {
			return true
		}
	}
	return false
}

// getRemediationHint returns a human-readable hint for fixing the vulnerability.
func (p *Parser) getRemediationHint(ruleID string) string {
	hints := map[string]string{
		"hardcoded-secret":   "Move secret to environment variable or secret manager",
		"hardcoded-password": "Use environment variable or vault for password storage",
		"md5-used":           "Replace MD5 with SHA-256 or stronger hash function",
		"sha1-used":          "Replace SHA-1 with SHA-256 or stronger hash function",
		"insecure-crypto":    "Use AES-GCM or ChaCha20-Poly1305 for encryption",
		"sql-injection":      "Use parameterized queries or ORM instead of string concatenation",
		"xss":                "Sanitize output with context-appropriate encoding",
		"eval-usage":         "Replace eval() with safer alternative (JSON.parse, Function constructor with validation)",
		"insecure-random":    "Use crypto/rand instead of math/rand for security-sensitive operations",
		"tls-insecure":       "Enable TLS certificate verification",
	}

	ruleIDLower := strings.ToLower(ruleID)
	for pattern, hint := range hints {
		if strings.Contains(ruleIDLower, pattern) {
			return hint
		}
	}
	return "Review and fix vulnerability according to OWASP guidelines"
}
