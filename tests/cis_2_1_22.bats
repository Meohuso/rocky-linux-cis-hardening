#!/usr/bin/env bats

# Each Bats test runs in its own subshell; exported fixture variables are
# intentionally reset by setup for every test.
# shellcheck disable=SC2030,SC2031

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/network_listener_inventory_helper.bash"
    network_listener_inventory_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/22/module.sh"
}

@test "check succeeds when no network service is listening" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ -z "${output}" ]
}

@test "check treats whitespace-only socket output as empty" {
    RLCH_TEST_NETWORK_LISTENER_OUTPUT=$' \n\t'

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports listeners for manual approval review" {
    RLCH_TEST_NETWORK_LISTENER_OUTPUT=$'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))\nudp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("NetworkManager",pid=456,fd=5))'

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [[ "${output}" == *"listening network service inventory"* ]]
    [[ "${output}" == *"0.0.0.0:22"* ]]
    [[ "${output}" == *"sshd"* ]]
    [[ "${output}" == *"manual comparison"* ]]
}

@test "check uses ss to inventory TCP UDP processes without a header" {
    local check_result=0

    check || check_result=$?

    [ "${check_result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "$(cat "${RLCH_TEST_NETWORK_LISTENER_ARGUMENT_FILE}")" = "-plntuH" ]
}

@test "check reports an error when ss fails" {
    RLCH_TEST_NETWORK_LISTENER_SS_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inventory listening network services"* ]]
}

@test "apply refuses automatic remediation" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"manual control"* ]]
    [[ "${output}" == *"intentionally unsupported"* ]]
}

@test "validate delegates to check" {
    RLCH_TEST_NETWORK_LISTENER_OUTPUT="tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [[ "${output}" == *"0.0.0.0:22"* ]]
}

@test "rollback succeeds because the manual control makes no changes" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"no rollback action is required"* ]]
}

@test "metadata declares CIS 2.1.22 as a manual Level 1 control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/22/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.22" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
