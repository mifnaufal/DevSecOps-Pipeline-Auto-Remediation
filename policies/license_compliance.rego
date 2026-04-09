# License Compliance Policy
# Checks that dependencies use approved licenses.
# Blocks GPL, AGPL, and other copyleft licenses that may conflict
# with the project's distribution model.

package license_compliance

import rego.v1

# === License Classifications ===

ALLOWED_LICENSES := {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
    "0BSD",
    "BlueOak-1.0.0",
    "Python-2.0",
    "Zlib",
}

DISALLOWED_LICENSES := {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "SSPL-1.0",
    "EUPL-1.1",
    "MPL-2.0",  # May require review
    "CC-BY-NC-4.0",
    "BUSL-1.1",
}

# === Main Rule ===

compliant if {
    no_disallowed_licenses
}

# === Sub-rules ===

no_disallowed_licenses if {
    # Check all dependencies in the input
    # Input format: array of {name, version, license}
    disallowed := [dep | dep = input.dependencies[_]; is_disallowed(dep.license)]
    count(disallowed) == 0
}

is_disallowed(license_name) {
    normalized := normalize_license(license_name)
    DISALLOWED_LICENSES[normalized]
}

is_allowed(license_name) {
    normalized := normalize_license(license_name)
    ALLOWED_LICENSES[normalized]
}

normalize_license(license) := lower(replace(license, " ", "-"))

# === Deny Rules ===

deny[msg] {
    dep = input.dependencies[_]
    is_disallowed(dep.license)
    msg := sprintf("Dependency '%s' uses disallowed license: %s", [dep.name, dep.license])
}

# === Warnings ===

warn[msg] {
    dep = input.dependencies[_]
    not is_allowed(dep.license)
    not is_disallowed(dep.license)
    msg := sprintf("Dependency '%s' uses unclassified license: %s (requires manual review)", [dep.name, dep.license])
}

# === Summary ===

summary := {
    "compliant": compliant,
    "violations": [msg | msg = deny[_]],
    "warnings": [msg | msg = warn[_]],
    "total_dependencies": count(input.dependencies),
}
