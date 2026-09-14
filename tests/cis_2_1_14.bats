#!/usr/bin/env bats

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/snmp_server_helper.bash"
    snmp_server_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/14/module.sh"
}

@test "check succeeds when net-snmp is not installed" {
    RLCH_TEST_SNMP_INSTALLED="false"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when net-snmp is installed" {
    RLCH_TEST_SNMP_INSTALLED="true"
    run check
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "apply removes net-snmp when it is installed" {
    local result=0
    RLCH_TEST_SNMP_INSTALLED="true"
    EUID=0
    apply || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_SNMP_INSTALLED}" == "false" ]
    [ -f "${RLCH_CIS_2_1_14_STATE_FILE}" ]
}

@test "apply is idempotent when net-snmp is already absent" {
    RLCH_TEST_SNMP_INSTALLED="false"
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "apply fails without root privileges when remediation is required" {
    RLCH_TEST_SNMP_INSTALLED="true"
    EUID=1000
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"requires root privileges"* ]]
}

@test "apply returns error when dnf removal fails" {
    RLCH_TEST_SNMP_INSTALLED="true"
    RLCH_TEST_SNMP_DNF_REMOVE_FAIL="true"
    EUID=0
    run apply
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -f "${RLCH_CIS_2_1_14_STATE_FILE}" ]
}

@test "validate delegates to the compliance check" {
    RLCH_TEST_SNMP_INSTALLED="false"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    RLCH_TEST_SNMP_INSTALLED="true"
    run validate
    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback reinstalls net-snmp when this module removed it" {
    local result=0
    RLCH_TEST_SNMP_INSTALLED="false"
    EUID=0
    mkdir -p "${RLCH_CIS_2_1_14_STATE_DIR}"
    printf '%s\n' "net-snmp" > "${RLCH_CIS_2_1_14_STATE_FILE}"
    rollback || result=$?
    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_SNMP_INSTALLED}" == "true" ]
    [ ! -e "${RLCH_CIS_2_1_14_STATE_FILE}" ]
}

@test "rollback is idempotent when no rollback state exists" {
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "rollback fails without root privileges when restoration is required" {
    EUID=1000
    mkdir -p "${RLCH_CIS_2_1_14_STATE_DIR}"
    printf '%s\n' "net-snmp" > "${RLCH_CIS_2_1_14_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "rollback returns error when dnf installation fails" {
    RLCH_TEST_SNMP_DNF_INSTALL_FAIL="true"
    EUID=0
    mkdir -p "${RLCH_CIS_2_1_14_STATE_DIR}"
    printf '%s\n' "net-snmp" > "${RLCH_CIS_2_1_14_STATE_FILE}"
    run rollback
    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "metadata declares the expected CIS control" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/2/1/14/metadata.conf"
    [ "${RLCH_MODULE_ID}" = "2.1.14" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "xccdf_org.ssgproject.content_rule_package_net-snmp_removed" ]
}
