#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/squid_server_helper.bash"
    squid_server_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/17/module.sh"
}

@test "check succeeds when squid is not installed" {
    RLCH_TEST_SQUID_INSTALLED="false"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when squid is installed" {
    RLCH_TEST_SQUID_INSTALLED="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes squid when installed" {
    local apply_result=0
    RLCH_TEST_SQUID_INSTALLED="true"
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_SQUID_INSTALLED}" == "false" ]
    [ -f "${RLCH_CIS_2_1_17_STATE_FILE}" ]
    [ "$(cat "${RLCH_CIS_2_1_17_STATE_FILE}")" = "squid" ]
}

@test "apply is idempotent when squid is absent" {
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "apply requires root for remediation" {
    RLCH_TEST_SQUID_INSTALLED="true"
    RLCH_TEST_SQUID_EFFECTIVE_UID="1000"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply errors when effective uid cannot be determined" {
    RLCH_TEST_SQUID_INSTALLED="true"
    RLCH_TEST_SQUID_ID_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to determine effective user ID"* ]]
}

@test "apply errors when dnf removal fails" {
    RLCH_TEST_SQUID_INSTALLED="true"
    RLCH_TEST_SQUID_DNF_REMOVE_FAIL="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "apply errors when squid remains installed" {
    RLCH_TEST_SQUID_INSTALLED="true"
    RLCH_TEST_SQUID_KEEP_INSTALLED_AFTER_REMOVE="true"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    RLCH_TEST_SQUID_INSTALLED="true"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback reinstalls squid when this module removed it" {
    local rollback_result=0
    mkdir -p "${RLCH_CIS_2_1_17_STATE_DIR}"
    printf '%s\n' "squid" > "${RLCH_CIS_2_1_17_STATE_FILE}"
    rollback || rollback_result=$?
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_SQUID_INSTALLED}" == "true" ]
    [ ! -e "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "rollback is idempotent without state" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback requires root for restoration" {
    RLCH_TEST_SQUID_EFFECTIVE_UID="1000"
    mkdir -p "${RLCH_CIS_2_1_17_STATE_DIR}"
    printf '%s\n' "squid" > "${RLCH_CIS_2_1_17_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "rollback errors when dnf installation fails" {
    RLCH_TEST_SQUID_DNF_INSTALL_FAIL="true"
    mkdir -p "${RLCH_CIS_2_1_17_STATE_DIR}"
    printf '%s\n' "squid" > "${RLCH_CIS_2_1_17_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "rollback errors when squid remains absent" {
    RLCH_TEST_SQUID_KEEP_REMOVED_AFTER_INSTALL="true"
    mkdir -p "${RLCH_CIS_2_1_17_STATE_DIR}"
    printf '%s\n' "squid" > "${RLCH_CIS_2_1_17_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_2_1_17_STATE_FILE}" ]
}

@test "metadata declares CIS 2.1.17" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/17/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.1.17" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_squid_removed" ]
}
