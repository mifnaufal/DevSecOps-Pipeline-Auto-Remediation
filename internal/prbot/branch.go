package prbot

import (
	"fmt"
	"time"
)

// BranchManager handles branch creation and management.
type BranchManager struct {
	repo       string
	baseBranch string
}

// NewBranchManager creates a branch manager.
func NewBranchManager(repo, baseBranch string) *BranchManager {
	return &BranchManager{
		repo:       repo,
		baseBranch: baseBranch,
	}
}

// GenerateBranchName creates a branch name for auto-fix PRs.
func (m *BranchManager) GenerateBranchName() string {
	return fmt.Sprintf("auto-fix/security-%s", time.Now().Format("20060102-150405"))
}

// CreateBranch creates a new branch from the base branch.
func (m *BranchManager) CreateBranch(name string) error {
	// Fetch latest
	if err := RunGit("fetch", "origin", m.baseBranch); err != nil {
		return err
	}

	// Create and checkout
	return RunGit("checkout", "-b", name, fmt.Sprintf("origin/%s", m.baseBranch))
}

// PushBranch pushes the branch to remote.
func (m *BranchManager) PushBranch(name string) error {
	return RunGit("push", "-u", "origin", name, "--force-with-lease")
}

// DeleteBranch deletes a remote branch.
func (m *BranchManager) DeleteBranch(name string) error {
	return RunGit("push", "origin", "--delete", name)
}
