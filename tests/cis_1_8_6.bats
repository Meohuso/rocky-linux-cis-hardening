#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
# CIS 1.8.6 tests.
# SPDX-License-Identifier: MIT
#
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/gdm_automount_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_gdm_automount_test_environment
    RLCH_CIS_1_8_6_PROFILE_FILE="${RLCH_TEST_GDM_AUTOMOUNT_ETC}/dconf/profile/user"
    RLCH_CIS_1_8_6_CONFIG_FILE="${RLCH_TEST_GDM_AUTOMOUNT_ETC}/dconf/db/local.d/00-media-automount"
    RLCH_CIS_1_8_6_STATE_DIR="${RLCH_TEST_GDM_AUTOMOUNT_STATE}/1.8.6"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/6/module.sh"
}
teardown() { teardown_gdm_automount_test_environment; }
write_compliant() {
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_6_PROFILE_FILE}")" "$(dirname -- "${RLCH_CIS_1_8_6_CONFIG_FILE}")"
    cis_1_8_6_expected_profile > "${RLCH_CIS_1_8_6_PROFILE_FILE}"
    cis_1_8_6_expected_config > "${RLCH_CIS_1_8_6_CONFIG_FILE}"
}
@test "check returns not applicable without GDM" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
}
@test "apply creates nothing without GDM" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [ ! -e "${RLCH_CIS_1_8_6_PROFILE_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_6_CONFIG_FILE}" ]
}
@test "compliant configuration passes" {
    set_gdm_automount_test_installed true
    write_compliant
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "automount true is non-compliant" {
    set_gdm_automount_test_installed true
    write_compliant
    sed -i 's/automount=false/automount=true/' "${RLCH_CIS_1_8_6_CONFIG_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
@test "automount-open true is non-compliant" {
    set_gdm_automount_test_installed true
    write_compliant
    sed -i 's/automount-open=false/automount-open=true/' "${RLCH_CIS_1_8_6_CONFIG_FILE}"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}
@test "apply creates compliant configuration" {
    set_gdm_automount_test_installed true
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}
@test "apply is idempotent" {
    set_gdm_automount_test_installed true
    write_compliant
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_8_6_STATE_DIR}" ]
}
@test "rollback restores existing files" {
    set_gdm_automount_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_6_PROFILE_FILE}")" "$(dirname -- "${RLCH_CIS_1_8_6_CONFIG_FILE}")"
    printf '%s\n' original-profile > "${RLCH_CIS_1_8_6_PROFILE_FILE}"
    printf '%s\n' original-config > "${RLCH_CIS_1_8_6_CONFIG_FILE}"
    result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_8_6_PROFILE_FILE}")" = original-profile ]
    [ "$(cat "${RLCH_CIS_1_8_6_CONFIG_FILE}")" = original-config ]
}
@test "rollback removes files created by module" {
    set_gdm_automount_test_installed true
    result=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_8_6_PROFILE_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_6_CONFIG_FILE}" ]
}
@test "metadata is correct" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/6/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "1.8.6" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount" ]
}
