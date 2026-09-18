#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/firewalld_backend_loopback_helper.bash"
    firewalld_backend_loopback_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/4/module.sh"
}

@test "check accepts complete permanent and runtime loopback policy" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check requires active firewalld" {
    RLCH_TEST_BACKEND_LOOPBACK_FIREWALLD_ACTIVE="false"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires the firewalld nftables backend table" {
    RLCH_TEST_BACKEND_LOOPBACK_TABLES="table inet unrelated"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports nftables inspection errors" {
    RLCH_TEST_BACKEND_LOOPBACK_NFT_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect the firewalld nftables backend"* ]]
}

@test "check requires loopback trust in permanent configuration" {
    RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_INTERFACE="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires loopback trust at runtime" {
    RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_INTERFACE="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check separately requires permanent IPv4 anti-spoofing" {
    RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_IPV4="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check separately requires runtime IPv4 anti-spoofing" {
    RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_IPV4="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires permanent IPv6 anti-spoofing even when IPv6 networking is disabled" {
    RLCH_TEST_BACKEND_LOOPBACK_PERMANENT_IPV6="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires runtime IPv6 anti-spoofing even when IPv6 networking is disabled" {
    RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_IPV6="absent"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports firewall-cmd errors" {
    RLCH_TEST_BACKEND_LOOPBACK_FAIL="runtime:ipv4"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect CIS 4.3.4 runtime ipv4 state"* ]]
}

@test "apply is idempotent when the backend policy is compliant" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    ! grep -E -- ' --(add-|remove-|set-|reload|complete-reload)' "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
}

@test "apply refuses direct nftables remediation" {
    RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_IPV4="absent"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"remediate CIS 4.2.2"* ]]
    ! grep -E -- 'nft (add|delete|insert|flush|replace)' "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
    ! grep -E -- 'firewall-cmd .* --(add-|remove-|set-|reload|complete-reload)' "${RLCH_TEST_BACKEND_LOOPBACK_LOG}"
}

@test "validate delegates to check" {
    RLCH_TEST_BACKEND_LOOPBACK_RUNTIME_INTERFACE="absent"

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback makes no firewalld or nftables change" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"read-only firewalld backend check"* ]]
    [ ! -e "${RLCH_TEST_BACKEND_LOOPBACK_LOG}" ]
}

@test "metadata records the incompatible standalone nftables rule as manual" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/4/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.3.4" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
