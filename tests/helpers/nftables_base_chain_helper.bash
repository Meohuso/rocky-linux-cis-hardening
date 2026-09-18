#!/usr/bin/env bash
# Test helper for CIS 4.3.1.
# SPDX-License-Identifier: MIT

nftables_base_chain_helper_setup() {
    export RLCH_TEST_NFT_BASE_CHAIN_ROOT="${BATS_TEST_TMPDIR}/cis-4.3.1"
    export RLCH_TEST_NFT_BASE_CHAIN_LOG="${RLCH_TEST_NFT_BASE_CHAIN_ROOT}/commands"
    export RLCH_CIS_4_3_1_SYSTEMCTL_COMMAND="rlch_test_nft_base_chain_systemctl"
    export RLCH_CIS_4_3_1_NFT_COMMAND="rlch_test_nft_base_chain_nft"
    export RLCH_TEST_NFT_BASE_CHAIN_FIREWALLD_ACTIVE="true"
    export RLCH_TEST_NFT_BASE_CHAIN_LIST_FAIL="false"
    export RLCH_TEST_NFT_BASE_CHAIN_TABLE_FAIL="false"
    export RLCH_TEST_NFT_BASE_CHAIN_TABLES="table inet firewalld"
    export RLCH_TEST_NFT_BASE_CHAIN_RULESET=$'table inet firewalld {\n chain filter_INPUT {\n  type filter hook input priority filter + 10; policy accept;\n }\n chain filter_FORWARD {\n  type filter hook forward priority filter + 10; policy accept;\n }\n chain filter_OUTPUT {\n  type filter hook output priority filter + 10; policy accept;\n }\n}'

    mkdir -p "${RLCH_TEST_NFT_BASE_CHAIN_ROOT}"
}

rlch_test_nft_base_chain_systemctl() {
    printf 'systemctl %s\n' "$*" >> "${RLCH_TEST_NFT_BASE_CHAIN_LOG}"
    [[ "$*" == "is-active --quiet firewalld.service" ]] || return 2
    [[ "${RLCH_TEST_NFT_BASE_CHAIN_FIREWALLD_ACTIVE}" == "true" ]]
}

rlch_test_nft_base_chain_nft() {
    printf 'nft %s\n' "$*" >> "${RLCH_TEST_NFT_BASE_CHAIN_LOG}"
    case "$*" in
        "list tables")
            [[ "${RLCH_TEST_NFT_BASE_CHAIN_LIST_FAIL}" != "true" ]] || return 2
            printf '%s\n' "${RLCH_TEST_NFT_BASE_CHAIN_TABLES}"
            ;;
        "list table inet firewalld")
            [[ "${RLCH_TEST_NFT_BASE_CHAIN_TABLE_FAIL}" != "true" ]] || return 2
            printf '%s\n' "${RLCH_TEST_NFT_BASE_CHAIN_RULESET}"
            ;;
        *)
            return 2
            ;;
    esac
}
