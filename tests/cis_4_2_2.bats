#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/firewalld_loopback_helper.bash"
    firewalld_loopback_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/2/2/module.sh"
}

@test "check succeeds when permanent and runtime loopback policy is complete" {
    firewalld_loopback_helper_set_all present

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check requires the loopback interface in the trusted zone" {
    firewalld_loopback_helper_set_all present
    RLCH_TEST_FIREWALLD_RUNTIME_INTERFACE="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check separately requires IPv4 loopback spoofing protection" {
    firewalld_loopback_helper_set_all present
    RLCH_TEST_FIREWALLD_PERMANENT_IPV4="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires IPv6 loopback protection even when networking does not use IPv6" {
    firewalld_loopback_helper_set_all present
    RLCH_TEST_FIREWALLD_RUNTIME_IPV6="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports firewalld query errors" {
    firewalld_loopback_helper_set_all present
    RLCH_TEST_FIREWALLD_LOOPBACK_FAIL="query:runtime:ipv4"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect CIS 4.2.2 runtime ipv4 state"* ]]
}

@test "apply configures trusted loopback and both anti-spoofing rules" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_INTERFACE}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_IPV4}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_IPV6}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_INTERFACE}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_IPV4}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_IPV6}" = "present" ]
}

@test "apply uses firewalld without a global reload or direct nftables command" {
    local result=0

    apply || result=$?

    [ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -F -- '--reload' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    ! grep -F -- 'nft ' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    grep -F -- '--zone=trusted --add-interface=lo' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    grep -F -- 'source address="127.0.0.1" destination not address="127.0.0.1" drop' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    grep -F -- 'source address="::1" destination not address="::1" drop' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
}

@test "apply is idempotent when loopback policy is complete" {
    firewalld_loopback_helper_set_all present

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
    ! grep -E -- '--(add|remove)-' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
}

@test "apply requires root only when remediation is needed" {
    RLCH_TEST_FIREWALLD_LOOPBACK_UID="1000"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
}

@test "apply reports an effective uid lookup failure" {
    RLCH_TEST_FIREWALLD_LOOPBACK_ID_FAIL="true"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
}

@test "apply retains isolated state when a firewalld change fails" {
    RLCH_TEST_FIREWALLD_LOOPBACK_FAIL="add:runtime:ipv6"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
    [ "$(wc -l < "${RLCH_CIS_4_2_2_STATE_FILE}")" -eq 6 ]
}

@test "apply does not create partial state when initial inspection fails" {
    RLCH_TEST_FIREWALLD_LOOPBACK_FAIL="query:permanent:ipv6"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
}

@test "validate delegates to check" {
    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback restores each permanent and runtime item exactly" {
    local apply_result=0 rollback_result=0
    RLCH_TEST_FIREWALLD_PERMANENT_INTERFACE="present"
    RLCH_TEST_FIREWALLD_RUNTIME_IPV4="present"

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_INTERFACE}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_IPV4}" = "absent" ]
    [ "${RLCH_TEST_FIREWALLD_PERMANENT_IPV6}" = "absent" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_INTERFACE}" = "absent" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_IPV4}" = "present" ]
    [ "${RLCH_TEST_FIREWALLD_RUNTIME_IPV6}" = "absent" ]
    [ ! -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
}

@test "rollback changes no package service or unrelated firewall setting" {
    local apply_result=0 rollback_result=0

    apply || apply_result=$?
    rollback || rollback_result=$?

    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    [ "${rollback_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    ! grep -E -- '--(add|remove)-(service|port)=' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
    ! grep -F -- '--reload' "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}"
}

@test "rollback is idempotent without state" {
    firewalld_loopback_helper_set_all present

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [ ! -e "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}" ]
}

@test "rollback rejects incomplete state without changing firewalld" {
    mkdir -p "${RLCH_CIS_4_2_2_STATE_DIR}"
    printf '%s\n' permanent_interface=absent > "${RLCH_CIS_4_2_2_STATE_FILE}"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ ! -e "${RLCH_TEST_FIREWALLD_LOOPBACK_LOG}" ]
}

@test "rollback retains state when restoration fails" {
    local apply_result=0
    apply || apply_result=$?
    [ "${apply_result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]
    RLCH_TEST_FIREWALLD_LOOPBACK_FAIL="remove:runtime:ipv6"

    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [ -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]
}

@test "metadata uses manual mapping for the two ComplianceAsCode rules" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/2/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.2.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
