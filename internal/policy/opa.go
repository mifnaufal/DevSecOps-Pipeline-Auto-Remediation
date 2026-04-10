package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

// Evaluator evaluates OPA policies.
type Evaluator struct {
	policyDir   string
	timeoutSec  int
}

// Decision holds the outcome of a policy evaluation.
type Decision struct {
	PolicyName string    `json:"policy_name"`
	Input      any       `json:"input"`
	Result     any       `json:"result"`
	Allowed    bool      `json:"allowed"`
	Violations []string  `json:"violations"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// New creates an OPA policy evaluator.
func New(policyDir string, timeoutSec int) *Evaluator {
	return &Evaluator{
		policyDir:  policyDir,
		timeoutSec: timeoutSec,
	}
}

// Evaluate evaluates input against a specific policy query.
func (e *Evaluator) Evaluate(ctx context.Context, policyFile, query string, input any) (*Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.timeoutSec)*time.Second)
	defer cancel()

	// Load policy
	r := rego.New(
		rego.Query(query),
		rego.Load([]string{e.policyDir + "/" + policyFile}, nil),
		rego.Input(input),
	)

	// Prepare and evaluate
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare policy: %w", err)
	}

	results, err := pq.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluate policy: %w", err)
	}

	dec := &Decision{
		PolicyName:  policyFile,
		Input:       input,
		EvaluatedAt: time.Now(),
		Violations:  []string{},
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		dec.Result = results[0].Expressions[0].Value

		// Extract violations from result
		if resultMap, ok := results[0].Expressions[0].Value.(map[string]interface{}); ok {
			if allowed, exists := resultMap["allowed"]; exists {
				if b, ok := allowed.(bool); ok {
					dec.Allowed = b
				}
			}
			if violations, exists := resultMap["violations"]; exists {
				if vSlice, ok := violations.([]interface{}); ok {
					for _, v := range vSlice {
						dec.Violations = append(dec.Violations, fmt.Sprintf("%v", v))
					}
				}
			}
		}

		// Simple boolean result
		if b, ok := results[0].Expressions[0].Value.(bool); ok {
			dec.Allowed = b
		}
	}

	return dec, nil
}

// EvaluateJSON evaluates policy with raw JSON input and returns JSON result.
func (e *Evaluator) EvaluateJSON(ctx context.Context, policyFile, query string, inputJSON json.RawMessage) (json.RawMessage, error) {
	var input any
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("unmarshal input: %w", err)
	}

	dec, err := e.Evaluate(ctx, policyFile, query, input)
	if err != nil {
		return nil, err
	}

	return json.Marshal(dec)
}
