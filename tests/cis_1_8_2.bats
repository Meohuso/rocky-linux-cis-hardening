#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/gdm_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    setup_gdm_test_environment
    RLCH_CIS_1_8_2_PROFILE_FILE="${RLCH_TEST_GDM_ETC}/dconf/profile/gdm"
    RLCH_CIS_1_8_2_CONFIG_FILE="${RLCH_TEST_GDM_ETC}/dconf/db/gdm.d/01-banner-message"
    RLCH_CIS_1_8_2_STATE_DIR="${RLCH_TEST_GDM_STATE}/1.8.2"
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/2/module.sh"
}
teardown() { teardown_gdm_test_environment; }
write_compliant() {
    mkdir -p "$(dirname "${RLCH_CIS_1_8_2_PROFILE_FILE}")" "$(dirname "${RLCH_CIS_1_8_2_CONFIG_FILE}")"
    cis_1_8_2_expected_profile > "${RLCH_CIS_1_8_2_PROFILE_FILE}"
    cis_1_8_2_expected_config > "${RLCH_CIS_1_8_2_CONFIG_FILE}"
}
@test "not applicable without GDM" { run check; [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]; }
@test "apply does nothing without GDM" { run apply; [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]; [ ! -e "${RLCH_CIS_1_8_2_PROFILE_FILE}" ]; }
@test "compliant configuration passes" { set_gdm_test_installed true; write_compliant; run check; [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]; }
@test "disabled banner fails" { set_gdm_test_installed true; write_compliant; sed -i 's/enable=true/enable=false/' "${RLCH_CIS_1_8_2_CONFIG_FILE}"; run check; [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]; }
@test "apply configures banner" { set_gdm_test_installed true; run apply; [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]; run check; [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]; }
@test "apply is idempotent" { set_gdm_test_installed true; write_compliant; run apply; [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]; }
@test "rollback restores existing files" {
    set_gdm_test_installed true
    mkdir -p "$(dirname "${RLCH_CIS_1_8_2_PROFILE_FILE}")" "$(dirname "${RLCH_CIS_1_8_2_CONFIG_FILE}")"
    printf '%s\n' original-profile > "${RLCH_CIS_1_8_2_PROFILE_FILE}"
    printf '%s\n' original-config > "${RLCH_CIS_1_8_2_CONFIG_FILE}"
    result=0; apply || result=$?; [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback; [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_8_2_PROFILE_FILE}")" = original-profile ]
    [ "$(cat "${RLCH_CIS_1_8_2_CONFIG_FILE}")" = original-config ]
}
@test "rollback removes created files" {
    set_gdm_test_installed true
    result=0; apply || result=$?; [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    run rollback; [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_8_2_PROFILE_FILE}" ]; [ ! -e "${RLCH_CIS_1_8_2_CONFIG_FILE}" ]
}
@test "metadata is correct" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/2/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "1.8.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_dconf_gnome_banner_enabled" ]
}
