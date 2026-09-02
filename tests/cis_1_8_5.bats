#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.5 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/gdm_screen_lock_override_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_gdm_screen_lock_override_test_environment

    RLCH_CIS_1_8_5_LOCK_DIR="${RLCH_TEST_GDM_SCREEN_LOCK_OVERRIDE_ETC}/dconf/db/local.d/locks"
    RLCH_CIS_1_8_5_LOCK_FILE="${RLCH_CIS_1_8_5_LOCK_DIR}/00-screensaver"
    RLCH_CIS_1_8_5_STATE_DIR="${RLCH_TEST_GDM_SCREEN_LOCK_OVERRIDE_STATE}/1.8.5"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/5/module.sh"
}

teardown() {
    teardown_gdm_screen_lock_override_test_environment
}

write_compliant_gdm_screen_lock_override_configuration() {
    mkdir -p "${RLCH_CIS_1_8_5_LOCK_DIR}"
    cis_1_8_5_expected_lock > "${RLCH_CIS_1_8_5_LOCK_FILE}"
}

@test "check returns not applicable when GDM is not installed" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
}

@test "apply creates no lock configuration when GDM is not installed" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [ ! -e "${RLCH_CIS_1_8_5_LOCK_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_5_STATE_DIR}" ]
}

@test "check succeeds when both screen lock settings are locked" {
    set_gdm_screen_lock_override_test_installed true
    write_compliant_gdm_screen_lock_override_configuration

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when idle-delay lock is absent" {
    set_gdm_screen_lock_override_test_installed true
    mkdir -p "${RLCH_CIS_1_8_5_LOCK_DIR}"
    printf '%s\n' \
        '/org/gnome/desktop/screensaver/lock-delay' \
        > "${RLCH_CIS_1_8_5_LOCK_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when lock-delay lock is absent" {
    set_gdm_screen_lock_override_test_installed true
    mkdir -p "${RLCH_CIS_1_8_5_LOCK_DIR}"
    printf '%s\n' \
        '/org/gnome/desktop/session/idle-delay' \
        > "${RLCH_CIS_1_8_5_LOCK_FILE}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply creates compliant dconf locks" {
    set_gdm_screen_lock_override_test_installed true

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent for compliant dconf locks" {
    set_gdm_screen_lock_override_test_installed true
    write_compliant_gdm_screen_lock_override_configuration

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_8_5_STATE_DIR}" ]
}

@test "rollback restores an existing lock file" {
    set_gdm_screen_lock_override_test_installed true
    mkdir -p "${RLCH_CIS_1_8_5_LOCK_DIR}"
    printf '%s\n' "original lock configuration" > "${RLCH_CIS_1_8_5_LOCK_FILE}"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_8_5_LOCK_FILE}")" = "original lock configuration" ]
    [ ! -e "${RLCH_CIS_1_8_5_STATE_DIR}" ]
}

@test "rollback removes a lock file created by the module" {
    set_gdm_screen_lock_override_test_installed true

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_8_5_LOCK_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_5_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/5/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.8.5" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_dconf_gnome_session_idle_user_locks" ]
}
