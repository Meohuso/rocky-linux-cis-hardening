#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/firewalld_inventory_helper.bash"
    firewalld_inventory_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/2/1/module.sh"
}

@test "check inventories firewalld services and ports for manual review" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [[ "${output}" == *"firewalld service and port inventory"* ]]
    [[ "${output}" == *"services: cockpit ssh"* ]]
    [[ "${output}" == *"ports: 6443/tcp"* ]]
    [[ "${output}" == *"approved services and ports for this server role"* ]]
}

@test "check uses the benchmark firewalld inventory command" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [ "$(cat "${RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE}")" = "--list-all" ]
}

@test "check reports an empty configuration for manual review" {
    RLCH_TEST_FIREWALLD_INVENTORY_OUTPUT=""

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [[ "${output}" == *"manual comparison"* ]]
}

@test "check reports an error when firewalld inventory fails" {
    RLCH_TEST_FIREWALLD_INVENTORY_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inventory firewalld services and ports"* ]]
}

@test "apply refuses to invent a generic service or port policy" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"manual control"* ]]
    [[ "${output}" == *"intentionally unsupported"* ]]
    [ ! -e "${RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE}" ]
}

@test "validate delegates to the read-only inventory check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [[ "${output}" == *"services: cockpit ssh"* ]]
    [ "$(cat "${RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE}")" = "--list-all" ]
}

@test "rollback succeeds without changing firewalld" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"does not modify firewalld"* ]]
    [ ! -e "${RLCH_TEST_FIREWALLD_INVENTORY_ARGUMENT_FILE}" ]
}

@test "metadata declares a manual Level 1 control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/2/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.2.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
