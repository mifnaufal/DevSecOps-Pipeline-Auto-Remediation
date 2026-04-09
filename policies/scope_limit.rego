# Scope Limit Policy
# Ensures codemod PRs only touch security-relevant files.
#
# Prevents auto-remediation from modifying:
# - Configuration files that control deployment
# - Database migration files
# - Production secrets or env files
# - Build/CI configuration beyond security rules

package scope_limit

import rego.v1

# === Allowed Path Patterns ===

# Directories that auto-fix PRs are allowed to modify
ALLOWED_EXTENSIONS := [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php"]

# Directories/patterns that are NEVER allowed in auto-fix PRs
BLOCKED_PATHS := [
    ".env",
    ".env.production",
    "secrets",
    "credentials",
    "database/migrations",
    "migrations",
    ".github/workflows",
    "Dockerfile",
    "docker-compose",
    "Makefile",
    "package.json",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
]

# === Main Rule ===

within_bounds if {
    not input.is_auto_fix
}

within_bounds if {
    input.is_auto_fix == true
    all_files_allowed
}

# === Sub-rules ===

all_files_allowed if {
    # In production, input.changed_files would be an array of file paths
    # For now, this is evaluated per-file
    count([f | f = input.changed_files[_]; not is_blocked(f)]) == 0
}

is_blocked(path) {
    blocked_pattern = BLOCKED_PATHS[_]
    contains(lower(path), lower(blocked_pattern))
}

has_allowed_extension(path) {
    ext = ALLOWED_EXTENSIONS[_]
    ends_with(lower(path), lower(ext))
}

# === Deny Rules ===

deny[msg] {
    input.is_auto_fix == true
    path = input.changed_files[_]
    is_blocked(path)
    msg := sprintf("Auto-fix PR modifies blocked path: %s", [path])
}

deny[msg] {
    input.is_auto_fix == true
    path = input.changed_files[_]
    not has_allowed_extension(path)
    msg := sprintf("Auto-fix PR modifies file with non-allowed extension: %s", [path])
}
