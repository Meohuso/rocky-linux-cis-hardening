#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.8 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/message_access_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_message_access_server_test_environment

    RLCH_CIS_2_1_8_STATE_DIR="${RLCH_TEST_MESSAGE_ACCESS_STATE}/2.1.8"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/8/module.sh"
}

teardown() {
    teardown_message_access_server_test_environment
}

@test "check succeeds when dovecot is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when dovecot is installed" {
    add_message_access_server_test_package "dovecot"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes dovecot when installed" {
    add_message_access_server_test_package "dovecot"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq -- "dovecot" "${RLCH_TEST_MESSAGE_ACCESS_PACKAGES}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent when dovecot is already absent" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_8_STATE_DIR}" ]
}

@test "apply reports error when package removal fails" {
    add_message_access_server_test_package "dovecot"
    set_message_access_server_test_dnf_status 1

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback reinstalls dovecot when removed by module" {
    add_message_access_server_test_package "dovecot"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq -- "dovecot" "${RLCH_TEST_MESSAGE_ACCESS_PACKAGES}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq -- "dovecot" "${RLCH_TEST_MESSAGE_ACCESS_PACKAGES}"
    [ ! -e "${RLCH_CIS_2_1_8_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback reports error when package installation fails" {
    add_message_access_server_test_package "dovecot"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    set_message_access_server_test_dnf_status 1

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_8_STATE_DIR}/state" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/8/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.8" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_dovecot_removed" ]
}
