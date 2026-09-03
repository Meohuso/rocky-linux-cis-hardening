#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.9 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/nfs_server_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_nfs_server_test_environment
    RLCH_CIS_2_1_9_STATE_DIR="${RLCH_TEST_NFS_STATE}/2.1.9"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/9/module.sh"
}

teardown() {
    teardown_nfs_server_test_environment
}

@test "check succeeds when nfs-utils is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when NFS is active" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "enabled" "active"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when NFS is inactive but not masked" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "disabled" "inactive"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when NFS is inactive and masked" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "masked" "inactive"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply stops disables and masks NFS" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "enabled" "active"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ENABLED}")" = "masked" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ACTIVE}")" = "inactive" ]
}

@test "apply is idempotent when NFS is already compliant" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "masked" "inactive"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_9_STATE_DIR}" ]
}

@test "rollback restores enabled and active NFS state" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "enabled" "active"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ENABLED}")" = "enabled" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ACTIVE}")" = "active" ]
    [ ! -e "${RLCH_CIS_2_1_9_STATE_DIR}" ]
}

@test "rollback restores disabled and inactive NFS state" {
    add_nfs_server_test_package "nfs-utils"
    set_nfs_server_test_state "disabled" "active"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ENABLED}")" = "disabled" ]
    [ "$(cat -- "${RLCH_TEST_NFS_ACTIVE}")" = "active" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/9/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.9" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_nfs_disabled" ]
}
