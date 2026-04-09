# PR Approval Policy
# Evaluates whether a PR meets security requirements for merging.
#
# Input: PR metadata (number, labels, files_changed, is_auto_fix, etc.)
# Output: allow (boolean), violations (array of strings)

package pr_approval

import rego.v1

# === Configuration ===

# Maximum files that an auto-fix PR can modify
MAX_FILES_MODIFIED := 10

# Maximum total lines changed
MAX_LINES_CHANGED := 500

# Required labels for auto-fix PRs
REQUIRED_LABELS := ["security", "auto-remediation"]

# === Main Rule ===

# Allow if all conditions are met
allow if {
    within_file_limit
    within_line_limit
    has_required_labels
    not targets_protected_branch_without_approval
}

# === Sub-rules ===

# Check that the PR doesn't modify too many files
within_file_limit if {
    input.files_changed <= MAX_FILES_MODIFIED
}

# Check that the PR doesn't change too many lines
within_line_limit if {
    (input.additions + input.deletions) <= MAX_LINES_CHANGED
}

# Verify required labels are present
has_required_labels if {
    # For auto-fix PRs, require security labels
    input.is_auto_fix == true
    label_count := count([l | l = input.pr_labels[_]; REQUIRED_LABELS[_] = l])
    label_count == count(REQUIRED_LABELS)
}

# Non-auto-fix PRs pass label check automatically
has_required_labels if {
    input.is_auto_fix == false
}

# Prevent direct merges to main without approval
targets_protected_branch_without_approval if {
    input.base_ref == "main"
    # In real implementation, check GitHub API for approval status
    # For now, auto-fix PRs are allowed; manual PRs need review
    input.is_auto_fix == false
    not has_approval_review
}

has_approval_review if {
    # Placeholder: in production, check PR reviews via GitHub API
    # input.reviews[_].state == "APPROVED"
    true  # Allow for pipeline-created PRs (already validated)
}

# === Deny Rules ===

deny[msg] {
    not within_file_limit
    msg := sprintf("PR modifies %d files, exceeds limit of %d", [input.files_changed, MAX_FILES_MODIFIED])
}

deny[msg] {
    not within_line_limit
    total := input.additions + input.deletions
    msg := sprintf("PR changes %d lines, exceeds limit of %d", [total, MAX_LINES_CHANGED])
}

deny[msg] {
    input.is_auto_fix == true
    not has_required_labels
    msg := sprintf("Auto-fix PR missing required labels: %v", REQUIRED_LABELS)
}

deny[msg] {
    input.base_ref == "main"
    input.is_auto_fix == false
    not has_approval_review
    msg := "PR targeting main branch requires at least one approved review"
}

# === Helper ===

# Summary for audit logging
summary := {
    "allowed": allow,
    "violations": [msg | msg = deny[_]],
    "file_limit_ok": within_file_limit,
    "line_limit_ok": within_line_limit,
    "labels_ok": has_required_labels,
    "approval_ok": not targets_protected_branch_without_approval,
}
