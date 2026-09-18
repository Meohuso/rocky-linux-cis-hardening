#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/nftables_base_chain_helper.bash"
    nftables_base_chain_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/1/module.sh"
}

@test "check accepts firewalld input forward and output filter base chains" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check does not depend on firewalld internal chain names or numeric priorities" {
    RLCH_TEST_NFT_BASE_CHAIN_RULESET=$'table inet firewalld {\n chain arbitrary_a {\n  type filter hook input priority 17; policy drop;\n }\n chain arbitrary_b {\n  type filter hook forward priority -5; policy accept;\n }\n chain arbitrary_c {\n  type filter hook output priority filter + 10; policy accept;\n }\n}'

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when firewalld is inactive" {
    RLCH_TEST_NFT_BASE_CHAIN_FIREWALLD_ACTIVE="false"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
    [ "$(wc -l < "${RLCH_TEST_NFT_BASE_CHAIN_LOG}")" -eq 1 ]
}

@test "check reports non-compliance when the firewalld table is absent" {
    RLCH_TEST_NFT_BASE_CHAIN_TABLES="table inet unrelated"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check requires each benchmark hook" {
    RLCH_TEST_NFT_BASE_CHAIN_RULESET="${RLCH_TEST_NFT_BASE_CHAIN_RULESET/hook forward/hook prerouting}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check rejects a regular chain without type priority and policy" {
    RLCH_TEST_NFT_BASE_CHAIN_RULESET="${RLCH_TEST_NFT_BASE_CHAIN_RULESET/type filter hook input priority filter + 10; policy accept;/jump filter_INPUT_ZONES;}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports an nft table-listing failure" {
    RLCH_TEST_NFT_BASE_CHAIN_LIST_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to list nftables tables"* ]]
}

@test "check reports a firewalld table inspection failure" {
    RLCH_TEST_NFT_BASE_CHAIN_TABLE_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect the firewalld nftables backend"* ]]
}

@test "apply is idempotent for a compliant backend" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    ! grep -E '^nft (add|create|delete|flush|insert|replace)' "${RLCH_TEST_NFT_BASE_CHAIN_LOG}"
}

@test "apply refuses direct nftables remediation" {
    RLCH_TEST_NFT_BASE_CHAIN_RULESET="${RLCH_TEST_NFT_BASE_CHAIN_RULESET/hook output/hook prerouting}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"direct nftables chain creation is intentionally unsupported"* ]]
    ! grep -E '^nft (add|create|delete|flush|insert|replace)' "${RLCH_TEST_NFT_BASE_CHAIN_LOG}"
}

@test "validate delegates to check" {
    RLCH_TEST_NFT_BASE_CHAIN_TABLES=""

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback is a no-op isolated from prior firewall controls" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"read-only backend check"* ]]
    [ ! -e "${RLCH_TEST_NFT_BASE_CHAIN_LOG}" ]
}

@test "metadata records the indirect related-rule mapping as manual" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/1/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.3.1" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_REQUIRES_REBOOT}" = "false" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
