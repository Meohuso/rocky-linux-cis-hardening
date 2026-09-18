#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/firewall_utility_helper.bash"
    firewall_utility_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/1/2/module.sh"
}

cis_4_1_2_write_state() {
    local package_state="${1:-installed}"
    local firewalld_enabled="${2:-disabled}"
    local firewalld_active="${3:-inactive}"
    local nftables_enabled="${4:-enabled}"
    local nftables_active="${5:-active}"

    mkdir -p "${RLCH_CIS_4_1_2_STATE_DIR}"
    printf '%s\n' "${package_state}" > "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}"
    printf '%s\n' "${firewalld_enabled}" > "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}"
    printf '%s\n' "${firewalld_active}" > "${RLCH_CIS_4_1_2_FIREWALLD_ACTIVE_FILE}"
    printf '%s\n' "${nftables_enabled}" > "${RLCH_CIS_4_1_2_NFTABLES_ENABLED_FILE}"
    printf '%s\n' "${nftables_active}" > "${RLCH_CIS_4_1_2_NFTABLES_ACTIVE_FILE}"
    : > "${RLCH_CIS_4_1_2_STATE_FILE}"
}

@test "check succeeds with active enabled firewalld and disabled inactive nftables" {
    firewall_utility_helper_set_firewalld enabled active
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts a masked inactive standalone nftables service" {
    firewall_utility_helper_set_firewalld enabled active
    firewall_utility_helper_set_nftables masked inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when firewalld is absent" {
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when firewalld is inactive" {
    firewall_utility_helper_set_firewalld enabled inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when firewalld is disabled" {
    firewall_utility_helper_set_firewalld disabled active
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when standalone nftables is active" {
    firewall_utility_helper_set_firewalld enabled active
    firewall_utility_helper_set_nftables disabled active
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when standalone nftables is enabled" {
    firewall_utility_helper_set_firewalld enabled active
    firewall_utility_helper_set_nftables enabled inactive
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply installs and activates firewalld without activating nftables" {
    local result=0
    firewall_utility_helper_set_nftables enabled active
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_INSTALLED}" = "true" ]
    [ "${RLCH_TEST_FIREWALLD_ENABLED}" = "enabled" ]
    [ "${RLCH_TEST_FIREWALLD_ACTIVE}" = "active" ]
    [ "${RLCH_TEST_NFTABLES_ENABLED}" = "disabled" ]
    [ "${RLCH_TEST_NFTABLES_ACTIVE}" = "inactive" ]
    [ "$(cat "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}")" = "absent" ]
}

@test "apply repairs a masked pre-installed firewalld" {
    local result=0
    firewall_utility_helper_set_firewalld masked inactive
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_ENABLED}" = "enabled" ]
    [ "${RLCH_TEST_FIREWALLD_ACTIVE}" = "active" ]
    [ "$(cat "${RLCH_CIS_4_1_2_PACKAGE_STATE_FILE}")" = "installed" ]
    [ "$(cat "${RLCH_CIS_4_1_2_FIREWALLD_ENABLED_FILE}")" = "masked" ]
}

@test "apply is idempotent when the firewall utility state is compliant" {
    firewall_utility_helper_set_firewalld enabled active
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_4_1_2_STATE_DIR}" ]
}

@test "apply requires root only when remediation is needed" {
    RLCH_TEST_FIREWALL_EFFECTIVE_UID="1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_4_1_2_STATE_DIR}" ]
}

@test "apply reports an effective uid lookup failure" {
    RLCH_TEST_FIREWALL_ID_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply retains state when firewalld installation fails" {
    RLCH_TEST_FIREWALL_DNF_INSTALL_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]
}

@test "apply retains state when a service action fails" {
    firewall_utility_helper_set_firewalld disabled inactive
    RLCH_TEST_FIREWALL_FAIL_ACTION="start:firewalld.service"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback removes firewalld installed by this control and restores nftables" {
    local apply_result=0 rollback_result=0
    firewall_utility_helper_set_nftables enabled active
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_INSTALLED}" = "false" ]
    [ "${RLCH_TEST_NFTABLES_ENABLED}" = "enabled" ]
    [ "${RLCH_TEST_NFTABLES_ACTIVE}" = "active" ]
    [ ! -e "${RLCH_CIS_4_1_2_STATE_DIR}" ]
}

@test "rollback restores a pre-existing firewalld and nftables state" {
    local apply_result=0 rollback_result=0
    firewall_utility_helper_set_firewalld disabled inactive
    firewall_utility_helper_set_nftables enabled active
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_INSTALLED}" = "true" ]
    [ "${RLCH_TEST_FIREWALLD_ENABLED}" = "disabled" ]
    [ "${RLCH_TEST_FIREWALLD_ACTIVE}" = "inactive" ]
    [ "${RLCH_TEST_NFTABLES_ENABLED}" = "enabled" ]
    [ "${RLCH_TEST_NFTABLES_ACTIVE}" = "active" ]
}

@test "rollback restores masked service states exactly" {
    local apply_result=0 rollback_result=0
    firewall_utility_helper_set_firewalld masked inactive
    firewall_utility_helper_set_nftables masked-runtime inactive
    apply || apply_result=$?
    rollback || rollback_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_ENABLED}" = "masked" ]
    [ "${RLCH_TEST_NFTABLES_ENABLED}" = "masked-runtime" ]
}

@test "rollback is idempotent without saved state" {
    firewall_utility_helper_set_firewalld enabled active
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ "${RLCH_TEST_FIREWALLD_ENABLED}" = "enabled" ]
}

@test "rollback rejects incomplete state" {
    mkdir -p "${RLCH_CIS_4_1_2_STATE_DIR}"
    : > "${RLCH_CIS_4_1_2_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]
}

@test "rollback retains state when firewalld removal fails" {
    firewall_utility_helper_set_firewalld enabled active
    cis_4_1_2_write_state absent absent inactive disabled inactive
    RLCH_TEST_FIREWALL_DNF_REMOVE_FAIL="true"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_1_2_STATE_FILE}" ]
}

@test "metadata uses manual mapping for three ComplianceAsCode rules" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/1/2/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "4.1.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
