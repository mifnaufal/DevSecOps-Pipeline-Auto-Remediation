# Violation Report Policy
# Formats policy violations into structured audit-ready output.
# Used for SIEM integration and compliance reporting.

package violation_report

import rego.v1

# === Report Generation ===

report := {
    "timestamp": time.now_ns() / 1000000000,
    "pipeline_run_id": input.pipeline_run_id,
    "repository": input.repository,
    "commit_sha": input.commit_sha,
    "violations": violation_details,
    "total_violations": count(violation_details),
    "severity": report_severity,
    "action_required": action_required,
}

# === Violation Details ===

violation_details := [v |
    v = {
        "policy": v.policy,
        "rule": v.rule,
        "message": v.message,
        "severity": severity_for_policy(v.policy),
        "remediation": remediation_for_policy(v.policy),
        "timestamp": time.now_ns() / 1000000000,
    }
    violation = input.violations[_]
    v := violation
]

# === Severity Classification ===

report_severity := severity {
    violation_count := count(violation_details)
    severity := case violation_count of {
        violation_count == 0 -> "info"
        violation_count <= 2 -> "medium"
        violation_count <= 5 -> "high"
        else -> "critical"
    }
}

# === Action Determination ===

action_required := true if {
    count(violation_details) > 0
}

action_required := false if {
    count(violation_details) == 0
}

# === Policy Metadata ===

severity_for_policy("pr_approval") := "high"
severity_for_policy("scope_limit") := "critical"
severity_for_policy("license_compliance") := "medium"
severity_for_policy(policy) := "medium"  # default

remediation_for_policy("pr_approval") := "Review PR scope and ensure it meets security requirements"
remediation_for_policy("scope_limit") := "Remove non-security files from auto-fix PR"
remediation_for_policy("license_compliance") := "Replace dependency with approved-license alternative or obtain legal approval"
remediation_for_policy(policy) := "Review and resolve policy violation"

# === Audit Log Format ===

audit_log := {
    "event_type": "policy_violation",
    "source": "devsecops-pipeline",
    "data": report,
    "format_version": "1.0",
}
