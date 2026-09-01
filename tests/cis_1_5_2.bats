#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.2 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/sysctl_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_sysctl_test_environment
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl.sh"

    RLCH_CIS_1_5_2_PARAMETER="kernel.yama.ptrace_scope"
    RLCH_CIS_1_5_2_VALUE="1"
    RLCH_CIS_1_5_2_CONFIG="${RLCH_TEST_SYSCTL_CONFIG_DIR}/60-rlch-ptrace.conf"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/2/module.sh"
}

teardown() {
    teardown_sysctl_test_environment
}

create_compliant_ptrace_configuration() {
    printf '%s\n' "kernel.yama.ptrace_scope = 1" > "${RLCH_CIS_1_5_2_CONFIG}"
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "1"
}

@test "check succeeds when ptrace_scope is persistently and actively restricted" {
    create_compliant_ptrace_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when persistent ptrace_scope is missing" {
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "1"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when runtime ptrace_scope is unrestricted" {
    printf '%s\n' "kernel.yama.ptrace_scope = 1" > "${RLCH_CIS_1_5_2_CONFIG}"
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "0"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply restricts persistent and runtime ptrace_scope" {
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "0"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.yama.ptrace_scope = 1" "${RLCH_CIS_1_5_2_CONFIG}"
    [ "$(sysctl -n kernel.yama.ptrace_scope)" = "1" ]
}

@test "apply is idempotent when ptrace_scope is already compliant" {
    create_compliant_ptrace_configuration

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root privileges when remediation is needed" {
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "0"
    set_sysctl_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    create_compliant_ptrace_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the previous ptrace_scope configuration" {
    printf '%s\n' "kernel.yama.ptrace_scope = 0" > "${RLCH_CIS_1_5_2_CONFIG}"
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "0"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.yama.ptrace_scope = 0" "${RLCH_CIS_1_5_2_CONFIG}"
    [ "$(sysctl -n kernel.yama.ptrace_scope)" = "0" ]
}

@test "rollback removes a configuration created by the framework" {
    set_sysctl_test_runtime_value "kernel.yama.ptrace_scope" "0"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_5_2_CONFIG}" ]
}

@test "rollback is idempotent when no managed state exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.5.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope" ]
}
