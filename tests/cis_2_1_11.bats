#!/usr/bin/env bats

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/cups_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_cups_server_test_environment
    RLCH_CIS_2_1_11_STATE_DIR="${RLCH_TEST_CUPS_STATE}/2.1.11"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/11/module.sh"
}

teardown() {
    teardown_cups_server_test_environment
}

@test "check succeeds when cups is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when cups is active" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "enabled" "active"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when cups is inactive but not masked" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "disabled" "inactive"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when cups is inactive and masked" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "masked" "inactive"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply stops disables and masks cups" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "enabled" "active"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ENABLED}")" = "masked" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ACTIVE}")" = "inactive" ]
}

@test "apply is idempotent when cups is already compliant" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "masked" "inactive"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_11_STATE_DIR}" ]
}

@test "rollback restores enabled and active cups state" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "enabled" "active"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ENABLED}")" = "enabled" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ACTIVE}")" = "active" ]
    [ ! -e "${RLCH_CIS_2_1_11_STATE_DIR}" ]
}

@test "rollback restores disabled and inactive cups state" {
    add_cups_server_test_package "cups"
    set_cups_server_test_state "disabled" "inactive"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ENABLED}")" = "disabled" ]
    [ "$(cat -- "${RLCH_TEST_CUPS_ACTIVE}")" = "inactive" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/11/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.11" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_cups_disabled" ]
}
