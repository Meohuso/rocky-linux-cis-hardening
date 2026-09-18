#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031 # Bats setup exports fixture state per test.

setup() {
    export RLCH_TEST_REPOSITORY_ROOT="${BATS_TEST_DIRNAME}/.."
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/test_helper.bash"
    source "${RLCH_TEST_REPOSITORY_ROOT}/lib/module_api.sh"
    source "${RLCH_TEST_REPOSITORY_ROOT}/tests/helpers/nftables_established_helper.bash"
    nftables_established_helper_setup
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/2/module.sh"
}

@test "check accepts the firewalld established related state rule" {
    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check accepts nft set notation and formatting variation" {
    RLCH_TEST_NFT_ESTABLISHED_RULESET=$'table inet firewalld {\n chain different_name {\n ct state { RELATED, ESTABLISHED } counter packets 2 bytes 80 ACCEPT\n }\n}'

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check does not require a role-specific new connection rule" {
    [[ "${RLCH_TEST_NFT_ESTABLISHED_RULESET}" != *"ct state new"* ]]

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
}

@test "check reports non-compliance when related state is absent" {
    RLCH_TEST_NFT_ESTABLISHED_RULESET="${RLCH_TEST_NFT_ESTABLISHED_RULESET/established,related/established}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when the stateful rule drops traffic" {
    RLCH_TEST_NFT_ESTABLISHED_RULESET="${RLCH_TEST_NFT_ESTABLISHED_RULESET/established,related accept/established,related drop}"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when firewalld is inactive" {
    RLCH_TEST_NFT_ESTABLISHED_FIREWALLD_ACTIVE="false"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports non-compliance when the firewalld backend table is absent" {
    RLCH_TEST_NFT_ESTABLISHED_TABLES="table inet unrelated"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "check reports nft command errors" {
    RLCH_TEST_NFT_ESTABLISHED_TABLE_FAIL="true"

    run check

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"Unable to inspect the firewalld nftables backend"* ]]
}

@test "apply is idempotent when the backend is compliant" {
    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    ! grep -E '^nft (add|create|delete|flush|insert|replace)' "${RLCH_TEST_NFT_ESTABLISHED_LOG}"
}

@test "apply refuses to create an autonomous nftables rule" {
    RLCH_TEST_NFT_ESTABLISHED_RULESET="table inet firewalld {}"

    run apply

    [ "${status}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]
    [[ "${output}" == *"observation-only manual control"* ]]
    ! grep -E '^nft (add|create|delete|flush|insert|replace)' "${RLCH_TEST_NFT_ESTABLISHED_LOG}"
}

@test "validate delegates to check" {
    RLCH_TEST_NFT_ESTABLISHED_RULESET=""

    run validate

    [ "${status}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]
}

@test "rollback makes no firewall change" {
    run rollback

    [ "${status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]
    [[ "${output}" == *"does not modify the firewalld-generated ruleset"* ]]
    [ ! -e "${RLCH_TEST_NFT_ESTABLISHED_LOG}" ]
}

@test "metadata declares a manual Level 1 control without an invented rule" {
    source "${RLCH_TEST_REPOSITORY_ROOT}/modules/cis/4/3/2/metadata.conf"

    [ "${RLCH_MODULE_ID}" = "4.3.2" ]
    [ "${RLCH_MODULE_LEVEL}" = "1" ]
    [ "${RLCH_MODULE_ENABLED}" = "true" ]
    [ "${RLCH_MODULE_OPENSCAP_RULE}" = "manual" ]
}
