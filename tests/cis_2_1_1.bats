#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.1 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/autofs_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_autofs_test_environment

    RLCH_CIS_2_1_1_STATE_DIR="${RLCH_TEST_AUTOFS_STATE}/2.1.1"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/1/module.sh"
}

teardown() {
    teardown_autofs_test_environment
}

@test "check succeeds when autofs package is not installed" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when autofs is active" {
    set_autofs_test_installed true
    set_autofs_test_active_state active
    set_autofs_test_enabled_state disabled

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when autofs is enabled" {
    set_autofs_test_installed true
    set_autofs_test_active_state inactive
    set_autofs_test_enabled_state enabled

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when autofs is disabled but not masked" {
    set_autofs_test_installed true
    set_autofs_test_active_state inactive
    set_autofs_test_enabled_state disabled

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when autofs is inactive and masked" {
    set_autofs_test_installed true
    set_autofs_test_active_state inactive
    set_autofs_test_enabled_state masked

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply stops disables and masks autofs" {
    set_autofs_test_installed true
    set_autofs_test_active_state active
    set_autofs_test_enabled_state enabled

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/active")" = "inactive" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/enabled")" = "masked" ]

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent when autofs is already compliant" {
    set_autofs_test_installed true
    set_autofs_test_active_state inactive
    set_autofs_test_enabled_state masked

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_1_STATE_DIR}" ]
}

@test "rollback restores enabled and active service state" {
    set_autofs_test_installed true
    set_autofs_test_active_state active
    set_autofs_test_enabled_state enabled

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/active")" = "active" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/enabled")" = "enabled" ]
    [ ! -e "${RLCH_CIS_2_1_1_STATE_DIR}" ]
}

@test "rollback restores disabled and inactive service state" {
    set_autofs_test_installed true
    set_autofs_test_active_state inactive
    set_autofs_test_enabled_state disabled

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/active")" = "inactive" ]
    [ "$(cat "${RLCH_TEST_AUTOFS_SYSTEMCTL_STATE}/enabled")" = "disabled" ]
}

@test "rollback is idempotent without saved state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_autofs_disabled" ]
}
