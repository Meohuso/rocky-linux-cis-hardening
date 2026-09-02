#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.7.6 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/banner_access_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_banner_access_test_environment

    RLCH_CIS_1_7_6_ISSUE_NET_FILE="${RLCH_TEST_BANNER_ACCESS_ETC}/issue.net"
    RLCH_CIS_1_7_6_STATE_DIR="${RLCH_TEST_BANNER_ACCESS_STATE}/1.7.6"
    RLCH_CIS_1_7_6_STATE_FILE="${RLCH_CIS_1_7_6_STATE_DIR}/issue.net.access"

    printf '%s\n' "Authorized users only." > "${RLCH_CIS_1_7_6_ISSUE_NET_FILE}"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/7/6/module.sh"
}

teardown() {
    teardown_banner_access_test_environment
}

@test "check succeeds for root root and mode 644" {
    set_banner_access_test_metadata root root 644

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts more restrictive permissions" {
    set_banner_access_test_metadata root root 600

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check rejects incorrect ownership" {
    set_banner_access_test_metadata nobody root 644

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects incorrect group ownership" {
    set_banner_access_test_metadata root users 644

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects group writable permissions" {
    set_banner_access_test_metadata root root 664

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects executable permissions" {
    set_banner_access_test_metadata root root 755

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when issue.net is absent" {
    rm -f "${RLCH_CIS_1_7_6_ISSUE_NET_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply configures root root and mode 0644" {
    set_banner_access_test_metadata nobody users 666

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    sync_banner_access_test_metadata

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "${RLCH_TEST_BANNER_ACCESS_OWNER}" = "root" ]
    [ "${RLCH_TEST_BANNER_ACCESS_GROUP}" = "root" ]
    [ "${RLCH_TEST_BANNER_ACCESS_MODE}" = "644" ]
}

@test "apply saves original access metadata" {
    set_banner_access_test_metadata nobody users 666

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_7_6_STATE_FILE}")" = "nobody:users:666" ]
}

@test "apply is idempotent when access is already compliant" {
    set_banner_access_test_metadata root root 644

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_7_6_STATE_FILE}" ]
}

@test "rollback restores original access metadata" {
    set_banner_access_test_metadata nobody users 666

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    sync_banner_access_test_metadata

    [ "${RLCH_TEST_BANNER_ACCESS_OWNER}" = "nobody" ]
    [ "${RLCH_TEST_BANNER_ACCESS_GROUP}" = "users" ]
    [ "${RLCH_TEST_BANNER_ACCESS_MODE}" = "666" ]
    [ ! -e "${RLCH_CIS_1_7_6_STATE_FILE}" ]
}

@test "rollback is idempotent when no state exists" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/7/6/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.7.6" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue_net" ]
}
