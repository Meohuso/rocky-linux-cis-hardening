#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# Kernel module library tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d "${BATS_TEST_TMPDIR}/rlch-kernel-module.XXXXXX"
    )"

    RLCH_TEST_BIN_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/bin"
    RLCH_TEST_MODPROBE_CONFIGURATION="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-showconfig"
    RLCH_TEST_MODINFO_RESULT="${RLCH_TEST_TEMPORARY_DIRECTORY}/modinfo-result"
    RLCH_TEST_PROC_MODULES="${RLCH_TEST_TEMPORARY_DIRECTORY}/proc-modules"
    RLCH_TEST_MODPROBE_REMOVE_LOG="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-remove.log"
    RLCH_TEST_MODPROBE_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe.d"
    RLCH_TEST_CONFIGURATION_FILE="${RLCH_TEST_MODPROBE_DIRECTORY}/rlch-cis-1.1.1.1-cramfs.conf"

    mkdir -p \
        "${RLCH_TEST_BIN_DIRECTORY}" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}"

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

    RLCH_KERNEL_MODULE_PROC_MODULES="${RLCH_TEST_PROC_MODULES}"

    # shellcheck source=lib/kernel_module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/kernel_module.sh"
}

teardown() {
    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

log_warning() {
    return 0
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

create_compliant_managed_file() {
    cat >"${RLCH_TEST_CONFIGURATION_FILE}" <<'EOF'
# Managed by Rocky Linux CIS Hardening Framework.
# CIS 1.1.1.1 - Ensure cramfs kernel module is not available.
install cramfs /bin/false
blacklist cramfs
EOF

    chmod 0644 "${RLCH_TEST_CONFIGURATION_FILE}"
}

@test "kernel module library prevents multiple sourcing" {
    run source "${RLCH_TEST_REPOSITORY_ROOT}/lib/kernel_module.sh"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_exists detects an available module" {
    set_module_available

    run kernel_module_exists "cramfs"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_exists rejects an unavailable module" {
    set_module_unavailable

    run kernel_module_exists "cramfs"

    [ "${status}" -eq 1 ]
}

@test "kernel_module_is_loaded detects a loaded module" {
    set_module_loaded

    run kernel_module_is_loaded "cramfs"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_is_loaded rejects an unloaded module" {
    set_module_unloaded

    run kernel_module_is_loaded "cramfs"

    [ "${status}" -eq 1 ]
}

@test "kernel_module_has_install_directive accepts false command" {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
install cramfs /usr/bin/false
EOF

    run kernel_module_has_install_directive "cramfs"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_has_install_directive rejects a missing directive" {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
blacklist cramfs
EOF

    run kernel_module_has_install_directive "cramfs"

    [ "${status}" -eq 1 ]
}

@test "kernel_module_has_blacklist_directive detects a blacklist" {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<'EOF'
blacklist cramfs
EOF

    run kernel_module_has_blacklist_directive "cramfs"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_managed_file_is_compliant accepts expected content" {
    create_compliant_managed_file

    run kernel_module_managed_file_is_compliant \
        "cramfs" \
        "${RLCH_TEST_CONFIGURATION_FILE}"

    [ "${status}" -eq 0 ]
}

@test "kernel_module_write_configuration creates expected file" {
    run kernel_module_write_configuration \
        "1.1.1.1" \
        "cramfs" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}" \
        "${RLCH_TEST_CONFIGURATION_FILE}"

    [ "${status}" -eq 0 ]
    [ -f "${RLCH_TEST_CONFIGURATION_FILE}" ]
    [ "$(stat -c '%a' "${RLCH_TEST_CONFIGURATION_FILE}")" = "644" ]
    grep -Fqx "install cramfs /bin/false" "${RLCH_TEST_CONFIGURATION_FILE}"
    grep -Fqx "blacklist cramfs" "${RLCH_TEST_CONFIGURATION_FILE}"
}

@test "kernel_module_unload removes a loaded module" {
    set_module_loaded

    run kernel_module_unload "cramfs"

    [ "${status}" -eq 0 ]
    [ "$(cat "${RLCH_TEST_MODPROBE_REMOVE_LOG}")" = "cramfs" ]
}

@test "kernel_module_check succeeds when module is unavailable" {
    set_module_unavailable
    set_module_unloaded

    run kernel_module_check "cramfs"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "kernel_module_check succeeds when module is disabled and unloaded" {
    set_module_available
    set_module_unloaded
    set_compliant_modprobe_configuration

    run kernel_module_check "cramfs"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "kernel_module_check reports a loaded module" {
    set_module_available
    set_module_loaded
    set_compliant_modprobe_configuration

    run kernel_module_check "cramfs"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "kernel_module_apply creates configuration" {
    set_module_available
    set_module_unloaded

    run kernel_module_apply \
        "1.1.1.1" \
        "cramfs" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ -f "${RLCH_TEST_CONFIGURATION_FILE}" ]
}

@test "kernel_module_apply is idempotent" {
    set_module_available
    set_module_unloaded
    create_compliant_managed_file

    run kernel_module_apply \
        "1.1.1.1" \
        "cramfs" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "kernel_module_apply requires root privileges" {
    run kernel_module_apply \
        "1.1.1.1" \
        "cramfs" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "1000"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Root privileges are required"* ]]
}

@test "kernel_module_rollback removes managed configuration" {
    create_compliant_managed_file

    run kernel_module_rollback \
        "1.1.1.1" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_TEST_CONFIGURATION_FILE}" ]
}

@test "kernel_module_rollback is idempotent" {
    run kernel_module_rollback \
        "1.1.1.1" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "0"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "kernel_module_rollback requires root privileges" {
    create_compliant_managed_file

    run kernel_module_rollback \
        "1.1.1.1" \
        "${RLCH_TEST_CONFIGURATION_FILE}" \
        "1000"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_TEST_CONFIGURATION_FILE}" ]
}
