#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.8 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/gdm_autorun_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_gdm_autorun_test_environment

    RLCH_CIS_1_8_8_PROFILE_FILE="${RLCH_TEST_GDM_AUTORUN_ETC}/dconf/profile/user"
    RLCH_CIS_1_8_8_CONFIG_FILE="${RLCH_TEST_GDM_AUTORUN_ETC}/dconf/db/local.d/00-media-autorun"
    RLCH_CIS_1_8_8_STATE_DIR="${RLCH_TEST_GDM_AUTORUN_STATE}/1.8.8"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/8/module.sh"
}

teardown() {
    teardown_gdm_autorun_test_environment
}

write_compliant_gdm_autorun_configuration() {
    mkdir -p \
        "$(dirname -- "${RLCH_CIS_1_8_8_PROFILE_FILE}")" \
        "$(dirname -- "${RLCH_CIS_1_8_8_CONFIG_FILE}")"

    cis_1_8_8_expected_profile > "${RLCH_CIS_1_8_8_PROFILE_FILE}"
    cis_1_8_8_expected_config > "${RLCH_CIS_1_8_8_CONFIG_FILE}"
}

@test "check returns not applicable when GDM is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
}

@test "apply creates no configuration when GDM is not installed" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [ ! -e "${RLCH_CIS_1_8_8_PROFILE_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_8_CONFIG_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_8_STATE_DIR}" ]
}

@test "check succeeds when autorun-never is enabled" {
    set_gdm_autorun_test_installed true
    write_compliant_gdm_autorun_configuration
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when autorun-never is false" {
    set_gdm_autorun_test_installed true
    write_compliant_gdm_autorun_configuration
    sed -i 's/autorun-never=true/autorun-never=false/' "${RLCH_CIS_1_8_8_CONFIG_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when profile is missing" {
    set_gdm_autorun_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_8_CONFIG_FILE}")"
    cis_1_8_8_expected_config > "${RLCH_CIS_1_8_8_CONFIG_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply creates compliant configuration" {
    set_gdm_autorun_test_installed true
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent for compliant configuration" {
    set_gdm_autorun_test_installed true
    write_compliant_gdm_autorun_configuration
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_8_8_STATE_DIR}" ]
}

@test "rollback restores existing files" {
    set_gdm_autorun_test_installed true
    mkdir -p \
        "$(dirname -- "${RLCH_CIS_1_8_8_PROFILE_FILE}")" \
        "$(dirname -- "${RLCH_CIS_1_8_8_CONFIG_FILE}")"

    printf '%s\n' "original profile" > "${RLCH_CIS_1_8_8_PROFILE_FILE}"
    printf '%s\n' "original config" > "${RLCH_CIS_1_8_8_CONFIG_FILE}"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_8_8_PROFILE_FILE}")" = "original profile" ]
    [ "$(cat "${RLCH_CIS_1_8_8_CONFIG_FILE}")" = "original config" ]
    [ ! -e "${RLCH_CIS_1_8_8_STATE_DIR}" ]
}

@test "rollback removes files created by module" {
    set_gdm_autorun_test_installed true

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_8_8_PROFILE_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_8_CONFIG_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_8_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/8/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.8.8" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_dconf_gnome_disable_autorun" ]
}
