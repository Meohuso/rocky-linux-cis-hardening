#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    export RLCH_TEST_IPV6_ROOT="${BATS_TEST_TMPDIR}/cis-3.1.1"
    export RLCH_CIS_3_1_1_IPV6_DISABLE_FILE="${RLCH_TEST_IPV6_ROOT}/disable"
    mkdir -p "${RLCH_TEST_IPV6_ROOT}"
    printf '%s\n' 0 > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/1/module.sh"
}

@test "check identifies enabled IPv6 from a zero kernel parameter" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"IPv6 status: enabled"* ]]
}

@test "check identifies disabled IPv6 from a one kernel parameter" {
    printf '%s\n' 1 > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"IPv6 status: disabled"* ]]
}

@test "check accepts boolean kernel parameter representations" {
    printf '%s\n' Y > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"IPv6 status: disabled"* ]]

    printf '%s\n' n > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"IPv6 status: enabled"* ]]
}

@test "check identifies IPv6 as unavailable when the kernel parameter is absent" {
    rm -f "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"disabled (IPv6 kernel support is unavailable)"* ]]
}

@test "check reports an error for an invalid kernel parameter value" {
    printf '%s\n' unexpected > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to identify the IPv6 status"* ]]
}

@test "check reports an error when the parameter path is not a regular file" {
    rm -f "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"
    mkdir "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply refuses to choose an IPv6 policy automatically" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"observation-only manual control"* ]]
    [[ "${output}" == *"intentionally unsupported"* ]]
}

@test "validate delegates to check" {
    printf '%s\n' 1 > "${RLCH_CIS_3_1_1_IPV6_DISABLE_FILE}"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"IPv6 status: disabled"* ]]
}

@test "rollback succeeds because the manual control makes no changes" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"no rollback action is required"* ]]
}

@test "metadata declares CIS 3.1.1 as a manual Level 1 control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/3/1/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "3.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
