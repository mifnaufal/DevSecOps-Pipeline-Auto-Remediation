package policies

// OPA/Rego policies for PR approval gate.
//
// This policy enforces:
// 1. PRs must not change more than MAX_FILES_MODIFIED files
// 2. PRs must not exceed MAX_LINES_CHANGED total
// 3. Auto-fix PRs must have the security label
// 4. PRs targeting main branch require at least 1 reviewer
// 5. PRs with critical findings require security team approval
