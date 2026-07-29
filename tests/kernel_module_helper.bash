#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Shared kernel module Bats test helpers.
#
# SPDX-License-Identifier: MIT
#

##
# Initialize an isolated kernel module test environment.
#
# Arguments:
#   $1 CIS control identifier.
#   $2 Kernel module name.
#   $3 Managed configuration filename.
#
# Globals set:
#   RLCH_TEST_KERNEL_CONTROL_ID
#   RLCH_TEST_KERNEL_MODULE_NAME
#   RLCH_TEST_KERNEL_CONFIGURATION_FILENAME
#   RLCH_TEST_TEMPORARY_DIRECTORY
#   RLCH_TEST_BIN_DIRECTORY
#   RLCH_TEST_MODPROBE_CONFIGURATION
#   RLCH_TEST_MODINFO_RESULT
#   RLCH_TEST_PROC_MODULES
#   RLCH_TEST_MODPROBE_REMOVE_LOG
#   RLCH_TEST_MODPROBE_DIRECTORY
#   RLCH_TEST_KERNEL_CONFIGURATION_FILE
#   RLCH_KERNEL_MODULE_PROC_MODULES
#
# Returns:
#   0 on success.
##
setup_kernel_module_test_environment() {
    RLCH_TEST_KERNEL_CONTROL_ID="${1:?Control identifier is required.}"
    RLCH_TEST_KERNEL_MODULE_NAME="${2:?Kernel module name is required.}"
    RLCH_TEST_KERNEL_CONFIGURATION_FILENAME="$(
        printf '%s' "${3:?Configuration filename is required.}"
    )"

    RLCH_TEST_TEMPORARY_DIRECTORY="$(
        mktemp -d \
            "${BATS_TEST_TMPDIR}/rlch-kernel-module.${RLCH_TEST_KERNEL_CONTROL_ID}.XXXXXX"
    )"

    RLCH_TEST_BIN_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/bin"
    RLCH_TEST_MODPROBE_CONFIGURATION="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-showconfig"
    RLCH_TEST_MODINFO_RESULT="${RLCH_TEST_TEMPORARY_DIRECTORY}/modinfo-result"
    RLCH_TEST_PROC_MODULES="${RLCH_TEST_TEMPORARY_DIRECTORY}/proc-modules"
    RLCH_TEST_MODPROBE_REMOVE_LOG="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe-remove.log"
    RLCH_TEST_MODPROBE_DIRECTORY="${RLCH_TEST_TEMPORARY_DIRECTORY}/modprobe.d"
    RLCH_TEST_KERNEL_CONFIGURATION_FILE="${RLCH_TEST_MODPROBE_DIRECTORY}/${RLCH_TEST_KERNEL_CONFIGURATION_FILENAME}"

    mkdir -p \
        "${RLCH_TEST_BIN_DIRECTORY}" \
        "${RLCH_TEST_MODPROBE_DIRECTORY}"

    : >"${RLCH_TEST_MODPROBE_CONFIGURATION}"
    : >"${RLCH_TEST_PROC_MODULES}"
    : >"${RLCH_TEST_MODPROBE_REMOVE_LOG}"
    printf '%s\n' "0" >"${RLCH_TEST_MODINFO_RESULT}"

    _kernel_module_test_create_mock_commands

    PATH="${RLCH_TEST_BIN_DIRECTORY}:${PATH}"
    export PATH

    export RLCH_TEST_MODPROBE_CONFIGURATION
    export RLCH_TEST_MODINFO_RESULT
    export RLCH_TEST_MODPROBE_REMOVE_LOG

    RLCH_KERNEL_MODULE_PROC_MODULES="${RLCH_TEST_PROC_MODULES}"
}

##
# Remove the isolated kernel module test environment.
#
# Returns:
#   0 on success.
##
teardown_kernel_module_test_environment() {
    if [[ -n "${RLCH_TEST_TEMPORARY_DIRECTORY:-}" ]]; then
        rm -rf "${RLCH_TEST_TEMPORARY_DIRECTORY}"
    fi
}

##
# Create mock modprobe and modinfo commands.
#
# Returns:
#   0 on success.
##
_kernel_module_test_create_mock_commands() {
    cat >"${RLCH_TEST_BIN_DIRECTORY}/modprobe" <<'EOF_MODPROBE'
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
EOF_MODPROBE

    cat >"${RLCH_TEST_BIN_DIRECTORY}/modinfo" <<'EOF_MODINFO'
#!/usr/bin/env bash

result="$(cat "${RLCH_TEST_MODINFO_RESULT}")"
exit "${result}"
EOF_MODINFO

    chmod 0755 \
        "${RLCH_TEST_BIN_DIRECTORY}/modprobe" \
        "${RLCH_TEST_BIN_DIRECTORY}/modinfo"
}

##
# Configure the mock module as available.
##
set_kernel_module_available() {
    printf '%s\n' "0" >"${RLCH_TEST_MODINFO_RESULT}"
}

##
# Configure the mock module as unavailable.
##
set_kernel_module_unavailable() {
    printf '%s\n' "1" >"${RLCH_TEST_MODINFO_RESULT}"
}

##
# Configure the mock module as loaded.
##
set_kernel_module_loaded() {
    printf '%s 16384 0 - Live 0x0000000000000000\n' \
        "${RLCH_TEST_KERNEL_MODULE_NAME}" \
        >"${RLCH_TEST_PROC_MODULES}"
}

##
# Configure the mock module as unloaded.
##
set_kernel_module_unloaded() {
    : >"${RLCH_TEST_PROC_MODULES}"
}

##
# Configure effective modprobe output with both required directives.
##
set_kernel_module_compliant_configuration() {
    cat >"${RLCH_TEST_MODPROBE_CONFIGURATION}" <<EOF_CONFIGURATION
install ${RLCH_TEST_KERNEL_MODULE_NAME} /bin/false
blacklist ${RLCH_TEST_KERNEL_MODULE_NAME}
EOF_CONFIGURATION
}

##
# Configure effective modprobe output with only the install directive.
##
set_kernel_module_install_directive_only() {
    printf 'install %s /bin/false\n' \
        "${RLCH_TEST_KERNEL_MODULE_NAME}" \
        >"${RLCH_TEST_MODPROBE_CONFIGURATION}"
}

##
# Configure effective modprobe output with only the blacklist directive.
##
set_kernel_module_blacklist_directive_only() {
    printf 'blacklist %s\n' \
        "${RLCH_TEST_KERNEL_MODULE_NAME}" \
        >"${RLCH_TEST_MODPROBE_CONFIGURATION}"
}

##
# Create a compliant framework-managed modprobe configuration.
##
create_kernel_module_compliant_managed_file() {
    cat >"${RLCH_TEST_KERNEL_CONFIGURATION_FILE}" <<EOF_CONFIGURATION
# Managed by Rocky Linux CIS Hardening Framework.
# CIS ${RLCH_TEST_KERNEL_CONTROL_ID} - Ensure ${RLCH_TEST_KERNEL_MODULE_NAME} kernel module is not available.
install ${RLCH_TEST_KERNEL_MODULE_NAME} /bin/false
blacklist ${RLCH_TEST_KERNEL_MODULE_NAME}
EOF_CONFIGURATION

    chmod 0644 "${RLCH_TEST_KERNEL_CONFIGURATION_FILE}"
}
