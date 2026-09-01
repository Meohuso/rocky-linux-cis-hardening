#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# sysctl library tests.
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
}

teardown() {
    teardown_sysctl_test_environment
}

@test "sysctl_runtime_value_is succeeds for the expected value" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "2"

    run sysctl_runtime_value_is "kernel.randomize_va_space" "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "sysctl_runtime_value_is reports non-compliance for a different value" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_runtime_value_is "kernel.randomize_va_space" "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "sysctl_config_value_is succeeds for an exact active setting" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 2
EOF

    run sysctl_config_value_is \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "sysctl_config_value_is ignores commented settings" {
    write_sysctl_test_config <<'EOF'
# kernel.randomize_va_space = 2
EOF

    run sysctl_config_value_is \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "sysctl_parameter_is_configured requires persistent and runtime values" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 2
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_parameter_is_configured \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "sysctl_set_parameter creates a managed configuration and updates runtime" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.randomize_va_space = 2" "${RLCH_TEST_SYSCTL_CONFIG}"
    [ "$(sysctl -n kernel.randomize_va_space)" = "2" ]
}

@test "sysctl_set_parameter replaces duplicate active settings" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 0
kernel.randomize_va_space = 1
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(grep -c '^kernel\.randomize_va_space[[:space:]]*=' "${RLCH_TEST_SYSCTL_CONFIG}")" -eq 1 ]
    grep -Fqx "kernel.randomize_va_space = 2" "${RLCH_TEST_SYSCTL_CONFIG}"
}

@test "sysctl_set_parameter is idempotent" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 2
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "2"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_SYSCTL_CONFIG}.rlch.bak" ]
}

@test "sysctl_set_parameter requires root privileges" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"
    set_sysctl_test_effective_uid "1000"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "sysctl_rollback_parameter restores an existing managed configuration" {
    write_sysctl_test_config <<'EOF'
kernel.randomize_va_space = 1
EOF
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run sysctl_rollback_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx "kernel.randomize_va_space = 1" "${RLCH_TEST_SYSCTL_CONFIG}"
    [ "$(sysctl -n kernel.randomize_va_space)" = "1" ]
}

@test "sysctl_rollback_parameter removes a file created by the framework" {
    set_sysctl_test_runtime_value "kernel.randomize_va_space" "1"

    run sysctl_set_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space" \
        "2"
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run sysctl_rollback_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_TEST_SYSCTL_CONFIG}" ]
}

@test "sysctl_rollback_parameter is idempotent without managed state" {
    run sysctl_rollback_parameter \
        "${RLCH_TEST_SYSCTL_CONFIG}" \
        "kernel.randomize_va_space"

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
