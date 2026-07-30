#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.1.6 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    # shellcheck source=tests/test_helper.bash
    source "${BATS_TEST_DIRNAME}/test_helper.bash"

    # shellcheck source=tests/helpers/kernel_module_helper.bash
    source "${BATS_TEST_DIRNAME}/helpers/kernel_module_helper.bash"

    # shellcheck source=lib/common.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    # shellcheck source=lib/modules.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"

    # shellcheck source=lib/module_api.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    # shellcheck source=lib/kernel_module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/kernel_module.sh"

    setup_kernel_module_test_environment \
        "1.1.1.6" \
        "squashfs" \
        "rlch-cis-1.1.1.6-squashfs.conf"
    RLCH_CIS_1_1_1_6_MODPROBE_DIRECTORY="${RLCH_TEST_MODPROBE_DIRECTORY}"
    RLCH_CIS_1_1_1_6_CONFIGURATION_FILE="${RLCH_TEST_KERNEL_CONFIGURATION_FILE}"
    RLCH_CIS_1_1_1_6_EFFECTIVE_UID="0"

    # shellcheck source=modules/cis/1/1/1/6/module.sh
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/1/6/module.sh"
}

teardown() {
    teardown_kernel_module_test_environment
}

@test "check succeeds when squashfs is unavailable" {
    set_kernel_module_unavailable
    set_kernel_module_unloaded
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check succeeds when squashfs is disabled and unloaded" {
    set_kernel_module_available
    set_kernel_module_unloaded
    set_kernel_module_compliant_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when squashfs is loaded" {
    set_kernel_module_available
    set_kernel_module_loaded
    set_kernel_module_compliant_configuration

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when install directive is missing" {
    set_kernel_module_available
    set_kernel_module_unloaded
    set_kernel_module_blacklist_directive_only

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
@test "check reports non-compliance when blacklist directive is missing" {
    set_kernel_module_available
    set_kernel_module_unloaded
    set_kernel_module_install_directive_only

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply creates the managed modprobe configuration" {
    set_kernel_module_available
    set_kernel_module_unloaded

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ -f "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}" ]
    grep -Fqx \
        "install squashfs /bin/false" \
        "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}"

    grep -Fqx \
        "blacklist squashfs" \
        "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}"
}

@test "apply is idempotent when managed configuration already exists" {
    set_kernel_module_available
    set_kernel_module_unloaded
    create_kernel_module_compliant_managed_file

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "apply unloads squashfs when the module is loaded" {
    set_kernel_module_available
    set_kernel_module_loaded
    create_kernel_module_compliant_managed_file

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_MODPROBE_REMOVE_LOG}")" = "squashfs" ]
}

@test "apply fails without root privileges" {
    RLCH_CIS_1_1_1_6_EFFECTIVE_UID="1000"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Root privileges are required"* ]]
}

@test "validate delegates to the compliance check" {
    set_kernel_module_available
    set_kernel_module_unloaded
    set_kernel_module_compliant_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback removes the framework-managed configuration" {
    create_kernel_module_compliant_managed_file

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}" ]
}

@test "rollback is idempotent when managed configuration is absent" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges" {
    create_kernel_module_compliant_managed_file
    RLCH_CIS_1_1_1_6_EFFECTIVE_UID="1000"

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}" ]
}

@test "metadata declares the expected CIS control" {
    local metadata_file

    metadata_file="${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/1/1/6/metadata.conf"

    clear_module_metadata_variables

    # shellcheck source=modules/cis/1/1/1/6/metadata.conf
    source "${metadata_file}"
    [ "${RLCH_MODULE_ID}" = "1.1.1.6" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled" ]
}
