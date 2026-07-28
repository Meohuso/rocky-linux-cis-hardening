#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Shared Bats test helpers
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_TEST_REPOSITORY_ROOT="$(
    cd "${BATS_TEST_DIRNAME}/.." && pwd
)"

create_test_module() {
    local module_root="${1:?Module root is required.}"
    local module_identifier="${2:?Module identifier is required.}"
    local module_directory

    module_directory="${module_root}/${module_identifier//./\/}"

    mkdir -p "${module_directory}"

    cat >"${module_directory}/metadata.conf" <<EOF
RLCH_MODULE_ID="${module_identifier}"
RLCH_MODULE_TITLE="Test module ${module_identifier}"
RLCH_MODULE_DESCRIPTION="Description"
RLCH_MODULE_RATIONALE="Rationale"
RLCH_MODULE_LEVEL="1"
RLCH_MODULE_ENABLED="true"
RLCH_MODULE_REQUIRES_REBOOT="false"
RLCH_MODULE_OPENSCAP_RULE="xccdf_org.ssgproject.content_rule_test"
EOF

    cat >"${module_directory}/module.sh" <<'EOF'
#!/usr/bin/env bash

check() {
    return 0
}

apply() {
    return 0
}

validate() {
    return 0
}

rollback() {
    return 0
}
EOF

    chmod 0755 "${module_directory}/module.sh"

    printf '%s\n' "${module_directory}"
}

create_incomplete_test_module() {
    local module_root="${1:?Module root is required.}"
    local module_identifier="${2:?Module identifier is required.}"
    local module_directory

    module_directory="${module_root}/${module_identifier//./\/}"

    mkdir -p "${module_directory}"
    touch "${module_directory}/metadata.conf"

    printf '%s\n' "${module_directory}"
}

log_debug() {
    return 0
}

log_warn() {
    return 0
}

error_message() {
    printf '%s\n' "${1:-}" >&2
}