#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.1 tests.
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

    RLCH_CIS_1_5_1_PARAMETER="kernel.randomize_va_space"
    RLCH_CIS_1_5_1_VALUE="2"
    RLCH_CIS_1_5_1_CONFIG="${RLCH_TEST_SYSCTL_CONFIG}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/1/module.sh"
}

teardown() {
    teardown_sysctl_test_environment
}

create_compliant_aslr_configuration() {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 2
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "2"
}

@test "check succeeds when ASLR is persistently and actively enabled" {
    create_compliant_aslr_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when persistent ASLR is missing" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "2"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when runtime ASLR is disabled" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 2
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "0"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply enables persistent and runtime ASLR" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.randomize_va_space = 2" "${RLCH_TEST_SYSCTL_CONFIG}"
    [ "$(sysctl -n kernel.randomize_va_space)" = "2" ]
}

@test "apply is idempotent when ASLR is already compliant" {
    create_compliant_aslr_configuration

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply requires root privileges when remediation is needed" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"
    set_sysctl_test_effective_uid "1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "validate delegates to the compliance check" {
    create_compliant_aslr_configuration

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback restores the previous ASLR configuration" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 1
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.randomize_va_space = 1" "${RLCH_TEST_SYSCTL_CONFIG}"
    [ "$(sysctl -n kernel.randomize_va_space)" = "1" ]
}

@test "rollback is idempotent when no managed state exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/5/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.5.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space" ]
}
