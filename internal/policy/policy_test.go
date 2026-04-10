package policy

import (
	"context"
	"testing"
)

func TestNewEvaluator(t *testing.T) {
	e := New("./policies", 10)
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.policyDir != "./policies" {
		t.Errorf("Expected policyDir './policies', got '%s'", e.policyDir)
	}
	if e.timeoutSec != 10 {
		t.Errorf("Expected timeout 10, got %d", e.timeoutSec)
	}
}

func TestEvaluate_PolicyFileNotFound(t *testing.T) {
	e := New("/nonexistent", 5)
	_, err := e.Evaluate(context.Background(), "nonexistent.rego", "data.test.allow", nil)
	if err == nil {
		t.Error("Expected error for nonexistent policy file")
	}
}
