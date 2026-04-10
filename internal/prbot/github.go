package prbot

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// GitHubClient wraps gh CLI and GitHub API interactions.
type GitHubClient struct {
	token  string
	repo   string
}

// NewGitHubClient creates a new GitHub API client.
func NewGitHubClient(token, repo string) *GitHubClient {
	return &GitHubClient{
		token: token,
		repo:  repo,
	}
}

// CreatePR creates a pull request using gh CLI.
func (c *GitHubClient) CreatePR(baseBranch, headBranch, title, body, labels string) (string, error) {
	cmd := exec.Command("gh", "pr", "create",
		"--repo", c.repo,
		"--base", baseBranch,
		"--head", headBranch,
		"--title", title,
		"--body", body,
		"--label", labels,
	)

	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback: construct compare URL
		parts := c.repo
		return fmt.Sprintf("https://github.com/%s/compare/%s?expand=1", parts, headBranch), nil
	}

	return string(output), nil
}

// AddComment adds a comment to a PR.
func (c *GitHubClient) AddComment(prNumber int, body string) error {
	cmd := exec.Command("gh", "pr", "comment",
		fmt.Sprintf("%d", prNumber),
		"--repo", c.repo,
		"--body", body,
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	_, err := cmd.CombinedOutput()
	return err
}

// AddLabels adds labels to a PR.
func (c *GitHubClient) AddLabels(prNumber int, labels []string) error {
	cmd := exec.Command("gh", "issue", "edit",
		fmt.Sprintf("%d", prNumber),
		"--repo", c.repo,
		"--add-label", joinLabels(labels),
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	_, err := cmd.CombinedOutput()
	return err
}

func joinLabels(labels []string) string {
	result := ""
	for i, l := range labels {
		if i > 0 {
			result += ","
		}
		result += l
	}
	return result
}

// GetPRMetadata retrieves PR metadata as JSON.
func (c *GitHubClient) GetPRMetadata(prNumber int) (map[string]interface{}, error) {
	cmd := exec.Command("gh", "pr", "view",
		fmt.Sprintf("%d", prNumber),
		"--repo", c.repo,
		"--json", "number,title,body,state,labels,headRefName,baseRefName",
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(output, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// UpdatePRStatus updates commit status.
func (c *GitHubClient) UpdatePRStatus(sha, context, state, description string) error {
	cmd := exec.Command("gh", "api",
		fmt.Sprintf("repos/%s/statuses/%s", c.repo, sha),
		"--method", "POST",
		"--field", fmt.Sprintf("state=%s", state),
		"--field", fmt.Sprintf("context=%s", context),
		"--field", fmt.Sprintf("description=%s", description),
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	_, err := cmd.CombinedOutput()
	return err
}

// CheckPRApprovals checks if a PR has required approvals.
func (c *GitHubClient) CheckPRApprovals(prNumber int) (bool, error) {
	cmd := exec.Command("gh", "pr", "view",
		fmt.Sprintf("%d", prNumber),
		"--repo", c.repo,
		"--json", "reviews",
	)
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", c.token))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return false, err
	}

	reviews, ok := data["reviews"].([]interface{})
	if !ok {
		return false, nil
	}

	for _, r := range reviews {
		review := r.(map[string]interface{})
		if review["state"] == "APPROVED" {
			return true, nil
		}
	}

	return false, nil
}

// RunGit executes a git command.
func RunGit(args ...string) error {
	cmd := exec.Command("git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %v failed: %v, output: %s", args, err, string(output))
	}
	return nil
}
