#!/usr/bin/env bats
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.10 tests.
#
# SPDX-License-Identifier: MIT
#

setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/helpers/gdm_xdmcp_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/common.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/modules.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"

    setup_gdm_xdmcp_test_environment

    RLCH_CIS_1_8_10_CONFIG_FILE="${RLCH_TEST_GDM_XDMCP_ETC}/gdm/custom.conf"
    RLCH_CIS_1_8_10_STATE_DIR="${RLCH_TEST_GDM_XDMCP_STATE}/1.8.10"

    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/10/module.sh"
}

teardown() {
    teardown_gdm_xdmcp_test_environment
}

@test "check returns not applicable when GDM is not installed" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
}

@test "apply creates no configuration when GDM is not installed" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]
    [ ! -e "${RLCH_CIS_1_8_10_CONFIG_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_10_STATE_DIR}" ]
}

@test "check succeeds when XDMCP is explicitly disabled" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[xdmcp]' 'Enable=false' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when XDMCP is enabled" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[xdmcp]' 'Enable=true' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when xdmcp section is absent" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[daemon]' 'AutomaticLoginEnable=false' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply disables XDMCP while preserving other sections" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' \
        '[daemon]' \
        'AutomaticLoginEnable=false' \
        '' \
        '[xdmcp]' \
        'Enable=true' \
        '' \
        '[security]' \
        'DisallowTCP=true' \
        > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]

    grep -Fxq '[daemon]' "${RLCH_CIS_1_8_10_CONFIG_FILE}"
    grep -Fxq 'AutomaticLoginEnable=false' "${RLCH_CIS_1_8_10_CONFIG_FILE}"
    grep -Fxq '[security]' "${RLCH_CIS_1_8_10_CONFIG_FILE}"
    grep -Fxq 'DisallowTCP=true' "${RLCH_CIS_1_8_10_CONFIG_FILE}"
}

@test "apply creates XDMCP section when missing" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[daemon]' 'AutomaticLoginEnable=false' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    grep -Fxq '[xdmcp]' "${RLCH_CIS_1_8_10_CONFIG_FILE}"
    grep -Fxq 'Enable=false' "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply is idempotent when XDMCP is disabled" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[xdmcp]' 'Enable=false' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_1_8_10_STATE_DIR}" ]
}

@test "rollback restores an existing custom.conf" {
    set_gdm_xdmcp_test_installed true
    mkdir -p "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"
    printf '%s\n' '[xdmcp]' 'Enable=true' > "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "$(cat "${RLCH_CIS_1_8_10_CONFIG_FILE}")" = $'[xdmcp]\nEnable=true' ]
    [ ! -e "${RLCH_CIS_1_8_10_STATE_DIR}" ]
}

@test "rollback removes custom.conf created by module" {
    set_gdm_xdmcp_test_installed true

    apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]

    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ ! -e "${RLCH_CIS_1_8_10_CONFIG_FILE}" ]
    [ ! -e "${RLCH_CIS_1_8_10_STATE_DIR}" ]
}

@test "rollback is idempotent without saved state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "metadata declares the expected CIS control" {
    clear_module_metadata_variables
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/1/8/10/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "1.8.10" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_gnome_gdm_disable_xdmcp" ]
}
