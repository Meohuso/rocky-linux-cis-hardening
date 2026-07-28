#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.1.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=lib/common.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"

    # shellcheck source=lib/modules.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-cis-1.1.1.1.XXXXXX"
    )"

    RLCH_TEST_BIN_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/bin"
    RLCH_TEST_MODPROBE_CONFIGURATION="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-showconfig"
    RLCH_TEST_MODINFO_RESULT="${RLCH_TEST_TEMPORARY_DIRECTORY}/modinfo-result"
    RLCH_TEST_PROC_MODULES="${RLCH_TEST_TEMPORARY_DIRECTORY}/proc-modules"
    RLCH_TEST_MODPROBE_REMOVE_LOG="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-remove.log"

    mkdir -p \
        "${RLCH_TEST_BIN_DIRECTORY}" \
        "${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe.d"

    : >"${RLCH_TEST_MODPROBE_CONFIGURATION}"
    : >"${RLCH_TEST_PROC_MODULES}"
    : >"${RLCH_TEST_MODPROBE_REMOVE_LOG}"

    printf '%s\n' "0" >"${RLCH_TEST_MODINFO_RESULT}"

    create_mock_commands

    PATH="${RLCH_TEST_BIN_DIRECTORY}:${PATH}"
    export PATH
    export RLCH_TEST_MODPROBE_CONFIGURATION
    export RLCH_TEST_MODINFO_RESULT
    export RLCH_TEST_MODPROBE_REMOVE_LOG

    RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe.d"
    RLCH_CIS_1_1_1_1_CONFIGURATION_FILE="${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY}/rlch-cis-1.1.1.1-cramfs.conf"
    RLCH_CIS_1_1_1_1_EFFECTIVE_UID="0"

    # shellcheck source=modules/cis/1/1/1/1/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/1/1/module.sh"

    _cis_1_1_1_1_module_is_loaded() {
        awk \
            '$1 == "cramfs" { found = 1 } END { exit !found }' \
            "${RLCH_TEST_PROC_MODULES}"
    }
}

teardown() {
    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

create_mock_commands() {
    cat >"${RLCH_TEST_BIN_DIRECTORY}/modprobe" <<'EOF'
#!/usr/bin/env bash

case "${1:-}" in
    --showconfig)
        cat "${RLCH_TEST_MODPROBE_CONFIGURATION}"
        ;;
    -r)
        printf '%s\n' "${2:-}" >>"${RLCH_TEST_MODPROBE_REMOVE_LOG}"
        ;;
    *)
        exit 1
        ;;
esac
EOF

    cat >"${RLCH_TEST_BIN_DIRECTORY}/modinfo" <<'EOF'
#!/usr/bin/env bash

result="$(cat "${RLCH_TEST_MODINFO_RESULT}")"
exit "${result}"
EOF

    chmod 0755 \
        "${RLCH_TEST_BIN_DIRECTORY}/modprobe" \
        "${RLCH_TEST_BIN_DIRECTORY}/modinfo"
}

set_module_available() {
    printf '%s\n' "0" >"${RLCH_TEST_MODINFO_RESULT}"
}

set_module_unavailable() {
    printf '%s\n' "1" >"${RLCH_TEST_MODINFO_RESULT}"
}

set_module_loaded() {
    cat >"${RLCH_TEST_PROC_MODULES}" <<'EOF'
cramfs 16384 0 - Live 0x0000000000000000
EOF
}

set_module_unloaded() {
    : >"${RLCH_TEST_PROC_MODULES}"
}

set_compliant_modprobe_configuration() {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
install cramfs /bin/false
blacklist cramfs
EOF
}

set_install_directive_only() {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
install cramfs /bin/false
EOF
}

set_blacklist_directive_only() {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
blacklist cramfs
EOF
}

create_compliant_managed_file() {
    cat >"${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" <<'EOF'
# Managed by Rocky Linux CIS Hardening Framework.
# CIS 1.1.1.1 - Ensure cramfs kernel module is not available.
install cramfs /bin/false
blacklist cramfs
EOF

    chmod 0644 "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"
}

@test "check succeeds when cramfs is unavailable" {
    set_module_unavailable
    set_module_unloaded

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds when cramfs is disabled and unloaded" {
    set_module_available
    set_module_unloaded
    set_compliant_modprobe_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when cramfs is loaded" {
    set_module_available
    set_module_loaded
    set_compliant_modprobe_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when install directive is missing" {
    set_module_available
    set_module_unloaded
    set_blacklist_directive_only

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when blacklist directive is missing" {
    set_module_available
    set_module_unloaded
    set_install_directive_only

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply creates the managed modprobe configuration" {
    set_module_available
    set_module_unloaded

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ -f "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]

    grep -Fqx \
        "install cramfs /bin/false" \
        "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"

    grep -Fqx \
        "blacklist cramfs" \
        "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"
}

@test "apply is idempotent when managed configuration already exists" {
    set_module_available
    set_module_unloaded
    create_compliant_managed_file

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply unloads cramfs when the module is loaded" {
    set_module_available
    set_module_loaded
    create_compliant_managed_file

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_MODPROBE_REMOVE_LOG}")" = "cramfs" ]
}

@test "apply fails without root privileges" {
    RLCH_CIS_1_1_1_1_EFFECTIVE_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Root privileges are required"* ]]
}

@test "validate delegates to the compliance check" {
    set_module_available
    set_module_unloaded
    set_compliant_modprobe_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback removes the framework-managed configuration" {
    create_compliant_managed_file

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]
}

@test "rollback is idempotent when managed configuration is absent" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges" {
    create_compliant_managed_file
    RLCH_CIS_1_1_1_1_EFFECTIVE_UID="1000"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/1/1/metadata.conf"

    clear_module_metadata_variables

    # shellcheck source=modules/cis/1/1/1/1/metadata.conf
    source "${metadata_file}"

    [ "${RLCH_MODULE_ID}" = "1.1.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled" ]
}