#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.4 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/dns_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_dns_server_test_environment

    RLCH_CIS_2_1_4_STATE_DIR="${RLCH_TEST_DNS_SERVER_STATE}/2.1.4"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/4/module.sh"
}

teardown() {
    teardown_dns_server_test_environment
}

@test "check succeeds when bind is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when bind is installed" {
    add_dns_server_test_package "bind"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes bind when installed" {
    add_dns_server_test_package "bind"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq -- "bind" "${RLCH_TEST_DNS_SERVER_PACKAGES}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent when bind is already absent" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_4_STATE_DIR}" ]
}

@test "apply reports error when package removal fails" {
    add_dns_server_test_package "bind"
    set_dns_server_test_dnf_status 1

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback reinstalls bind when removed by module" {
    add_dns_server_test_package "bind"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -Fxq -- "bind" "${RLCH_TEST_DNS_SERVER_PACKAGES}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    grep -Fxq -- "bind" "${RLCH_TEST_DNS_SERVER_PACKAGES}"
    [ ! -e "${RLCH_CIS_2_1_4_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback reports error when package installation fails" {
    add_dns_server_test_package "bind"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    set_dns_server_test_dnf_status 1

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_4_STATE_DIR}/state" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/4/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.4" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_bind_removed" ]
}
