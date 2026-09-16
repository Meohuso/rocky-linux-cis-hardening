#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
# CIS 2.4.1.2 tests.
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/cron_access_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_cron_access_test_environment
    RLCH_CIS_2_4_1_2_PATH="${RLCH_TEST_CRON_ACCESS_ETC}/crontab"
    RLCH_CIS_2_4_1_2_STATE_DIR="${RLCH_TEST_CRON_ACCESS_STATE}/2.4.1.2"
    RLCH_CIS_2_4_1_2_STATE_FILE="${RLCH_CIS_2_4_1_2_STATE_DIR}/access"
    : > "${RLCH_CIS_2_4_1_2_PATH}"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/2/module.sh"
}

teardown() {
    teardown_cron_access_test_environment
}

@test "check succeeds for root ownership and mode 600" {
    set_cron_access_test_metadata 0 0 600
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts more restrictive permissions" {
    set_cron_access_test_metadata 0 0 400
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects incorrect ownership" {
    set_cron_access_test_metadata 1000 1000 600
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects permissions granted to group or others" {
    set_cron_access_test_metadata 0 0 640
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when crontab is absent" {
    rm -f "${RLCH_CIS_2_4_1_2_PATH}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply configures only required ownership and mode" {
    set_cron_access_test_metadata 1000 100 664
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    sync_cron_access_test_metadata
    [ "${RLCH_TEST_CRON_ACCESS_OWNER}" = "0" ]
    [ "${RLCH_TEST_CRON_ACCESS_GROUP}" = "0" ]
    [ "${RLCH_TEST_CRON_ACCESS_MODE}" = "600" ]
}

@test "apply records the exact initial access state" {
    set_cron_access_test_metadata 1000 100 664
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_2_4_1_2_STATE_FILE}")" = "1000:100:664" ]
}

@test "apply is idempotent when access is compliant" {
    set_cron_access_test_metadata 0 0 400
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_4_1_2_STATE_FILE}" ]
}

@test "rollback restores the exact initial access state" {
    set_cron_access_test_metadata 1000 100 664
    apply || [ "$?" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    sync_cron_access_test_metadata
    [ "${RLCH_TEST_CRON_ACCESS_OWNER}" = "1000" ]
    [ "${RLCH_TEST_CRON_ACCESS_GROUP}" = "100" ]
    [ "${RLCH_TEST_CRON_ACCESS_MODE}" = "664" ]
    [ ! -e "${RLCH_CIS_2_4_1_2_STATE_FILE}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares CIS 2.4.1.2 as a manual composite mapping" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/4/1/2/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.4.1.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
