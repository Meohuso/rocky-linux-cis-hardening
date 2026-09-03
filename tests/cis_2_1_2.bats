#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.2 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/avahi_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_avahi_test_environment

    RLCH_CIS_2_1_2_STATE_DIR="${RLCH_TEST_AVAHI_STATE}/2.1.2"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/2/module.sh"
}

teardown() {
    teardown_avahi_test_environment
}

@test "check succeeds when avahi package is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when avahi service is active" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service active disabled
    set_avahi_test_unit_state socket inactive masked

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when avahi service is not masked" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service inactive disabled
    set_avahi_test_unit_state socket inactive masked

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when avahi socket is active" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service inactive masked
    set_avahi_test_unit_state socket active masked

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when avahi socket is not masked" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service inactive masked
    set_avahi_test_unit_state socket inactive disabled

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check succeeds when avahi service and socket are inactive and masked" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service inactive masked
    set_avahi_test_unit_state socket inactive masked

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply stops disables and masks avahi service and socket" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service active enabled
    set_avahi_test_unit_state socket active enabled

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/service.active")" = "inactive" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/service.enabled")" = "masked" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/socket.active")" = "inactive" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/socket.enabled")" = "masked" ]

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent when avahi is already compliant" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service inactive masked
    set_avahi_test_unit_state socket inactive masked

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_2_STATE_DIR}" ]
}

@test "rollback restores service and socket states" {
    set_avahi_test_installed true
    set_avahi_test_unit_state service active enabled
    set_avahi_test_unit_state socket inactive disabled

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/service.active")" = "active" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/service.enabled")" = "enabled" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/socket.active")" = "inactive" ]
    [ "$(cat "${RLCH_TEST_AVAHI_SYSTEMCTL_STATE}/socket.enabled")" = "disabled" ]
    [ ! -e "${RLCH_CIS_2_1_2_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "2.1.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled" ]
}
