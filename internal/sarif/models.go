package sarif

// SARIF v2.1.0 type definitions based on OASIS SARIF specification.
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

// SARIFLog represents the top-level SARIF object containing one or more runs.
type SARIFLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single analysis run by a tool.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that produced the SARIF log.
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent provides metadata about the analysis tool.
type ToolComponent struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule describes a rule or check that can produce results.
type Rule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name,omitempty"`
	ShortDescription *Message    `json:"shortDescription,omitempty"`
	FullDescription  *Message    `json:"fullDescription,omitempty"`
	DefaultConfig    *RuleConfig `json:"defaultConfiguration,omitempty"`
	Properties       *Properties `json:"properties,omitempty"`
}

// RuleConfig contains the default configuration for a rule.
type RuleConfig struct {
	Level string `json:"level,omitempty"` // warning, error, note
}

// Message represents a SARIF message (can be plain text or markdown).
type Message struct {
	Text string `json:"text"`
}

// Result represents a single finding/alert from a rule.
type Result struct {
	RuleID        string      `json:"ruleId"`
	RuleIndex     int         `json:"ruleIndex"`
	Level         string      `json:"level"` // warning, error, note, none
	Kind          string      `json:"kind"`  // fail, pass, review, informational
	Message       Message     `json:"message"`
	Locations     []Location  `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties    *ResultProperties `json:"properties,omitempty"`
}

// Location describes where a result was detected.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation specifies a file and region within that file.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation identifies the file analyzed.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region describes a range within a file.
type Region struct {
	StartLine   int    `json:"startLine"`
	EndLine     int    `json:"endLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	Snippet     Snippet `json:"snippet,omitempty"`
}

// Snippet contains the relevant code snippet.
type Snippet struct {
	Text string `json:"text"`
}

// ResultProperties holds tool-specific result properties.
type ResultProperties struct {
	Tags        []string `json:"tags,omitempty"`
	Precision   string   `json:"precision,omitempty"`
	SecuritySeverity string `json:"security-severity,omitempty"` // Semgrep-specific
}

// Properties holds rule properties (tool-specific).
type Properties struct {
	Tags        []string `json:"tags,omitempty"`
	SecuritySeverity string `json:"security-severity,omitempty"`
	CWE           string   `json:"cwe,omitempty"`
	Precision     string   `json:"precision,omitempty"`
}
