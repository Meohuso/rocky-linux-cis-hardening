#!/usr/bin/env bats

# shellcheck disable=SC2034 # Test arrays are consumed through helper namerefs.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/sysctl_control_helper.bash"
    sysctl_control_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/sysctl_control.sh"

    TEST_PARAMETERS=(net.test.alpha net.test.beta)
    TEST_VALUES=(0 1)
    TEST_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-test.conf"
    TEST_STATE="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/test"
    sysctl_control_helper_set_runtime net.test.alpha 1
    sysctl_control_helper_set_runtime net.test.beta 0
}

@test "apply writes persistent and runtime values while preserving unrelated content" {
    local result=0
    sysctl_control_helper_write_config "${TEST_CONFIG}" <<'EOF'
# administrator comment
net.other.value = 7
net.test.alpha = 1
EOF

    sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fqx '# administrator comment' "${TEST_CONFIG}"
    grep -Fqx 'net.other.value = 7' "${TEST_CONFIG}"
    grep -Fqx 'net.test.alpha = 0' "${TEST_CONFIG}"
    grep -Fqx 'net.test.beta = 1' "${TEST_CONFIG}"
    [ "$(sysctl_control_helper_runtime_value net.test.alpha)" = 0 ]
    [ "$(sysctl_control_helper_runtime_value net.test.beta)" = 1 ]
}

@test "apply is idempotent and does not create rollback state" {
    sysctl_control_helper_write_config "${TEST_CONFIG}" <<'EOF'
net.test.alpha = 0
net.test.beta = 1
EOF
    sysctl_control_helper_set_runtime net.test.alpha 0
    sysctl_control_helper_set_runtime net.test.beta 1

    run sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${TEST_STATE}" ]
}

@test "rollback restores exact file and runtime state" {
    local apply_result=0
    local rollback_result=0
    local original_content=$'# original\nnet.other.value = 9\nnet.test.alpha = 1'
    printf '%s\n' "${original_content}" > "${TEST_CONFIG}"

    sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES || apply_result=$?
    sysctl_control_rollback "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${TEST_CONFIG}")" = "${original_content}" ]
    [ "$(sysctl_control_helper_runtime_value net.test.alpha)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.test.beta)" = 0 ]
    [ ! -e "${TEST_STATE}" ]
}

@test "rollback removes only a control-created configuration file" {
    local apply_result=0
    local rollback_result=0

    sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES || apply_result=$?
    sysctl_control_rollback "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${TEST_CONFIG}" ]
}

@test "separate control states do not invalidate each other" {
    local first_result=0
    local second_result=0
    local rollback_result=0
    FIRST_PARAMETERS=(net.test.alpha)
    FIRST_VALUES=(0)
    SECOND_PARAMETERS=(net.test.beta)
    SECOND_VALUES=(1)
    SECOND_CONFIG="${RLCH_TEST_SYSCTL_CONTROL_CONFIG_DIR}/60-second.conf"
    SECOND_STATE="${RLCH_TEST_SYSCTL_CONTROL_ROOT}/state/second"

    sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" FIRST_PARAMETERS FIRST_VALUES || first_result=$?
    sysctl_control_apply "${SECOND_CONFIG}" "${SECOND_STATE}" SECOND_PARAMETERS SECOND_VALUES || second_result=$?
    sysctl_control_rollback "${TEST_CONFIG}" "${TEST_STATE}" FIRST_PARAMETERS || rollback_result=$?

    [ "${first_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${second_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(sysctl_control_helper_runtime_value net.test.alpha)" = 1 ]
    [ "$(sysctl_control_helper_runtime_value net.test.beta)" = 1 ]
    [ -f "${SECOND_CONFIG}" ]
    [ -f "${SECOND_STATE}/state" ]
}

@test "apply keeps complete rollback state when a runtime write fails" {
    RLCH_TEST_SYSCTL_CONTROL_FAIL_WRITE=net.test.beta

    run sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${TEST_STATE}/state" ]
    [ -f "${TEST_STATE}/runtime.state" ]
}

@test "apply requires root before creating state" {
    RLCH_TEST_SYSCTL_CONTROL_UID=1000

    run sysctl_control_apply "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS TEST_VALUES

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${TEST_STATE}" ]
}

@test "rollback rejects incomplete state without changing runtime" {
    mkdir -p "${TEST_STATE}"
    : > "${TEST_STATE}/state"

    run sysctl_control_rollback "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ "$(sysctl_control_helper_runtime_value net.test.alpha)" = 1 ]
}

@test "rollback is idempotent without state" {
    run sysctl_control_rollback "${TEST_CONFIG}" "${TEST_STATE}" TEST_PARAMETERS

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
