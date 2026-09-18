#!/usr/bin/env bash
# Test helper for CIS 4.3.2.
# SPDX-License-Identifier: MIT

nftables_established_helper_setup() {
    export RLCH_TEST_NFT_ESTABLISHED_ROOT="${BATS_TEST_TMPDIR}/cis-4.3.2"
    export RLCH_TEST_NFT_ESTABLISHED_LOG="${RLCH_TEST_NFT_ESTABLISHED_ROOT}/commands"
    export RLCH_CIS_4_3_2_SYSTEMCTL_COMMAND="rlch_test_nft_established_systemctl"
    export RLCH_CIS_4_3_2_NFT_COMMAND="rlch_test_nft_established_nft"
    export RLCH_TEST_NFT_ESTABLISHED_FIREWALLD_ACTIVE="true"
    export RLCH_TEST_NFT_ESTABLISHED_LIST_FAIL="false"
    export RLCH_TEST_NFT_ESTABLISHED_TABLE_FAIL="false"
    export RLCH_TEST_NFT_ESTABLISHED_TABLES="table inet firewalld"
    export RLCH_TEST_NFT_ESTABLISHED_RULESET=$'table inet firewalld {\n chain filter_INPUT {\n  type filter hook input priority filter + 10; policy accept;\n  ct state established,related accept\n }\n}'

    mkdir -p "${RLCH_TEST_NFT_ESTABLISHED_ROOT}"
}

rlch_test_nft_established_systemctl() {
    printf 'systemctl %s\n' "$*" >> "${RLCH_TEST_NFT_ESTABLISHED_LOG}"
    [[ "$*" == "is-active --quiet firewalld.service" ]] || return 2
    [[ "${RLCH_TEST_NFT_ESTABLISHED_FIREWALLD_ACTIVE}" == "true" ]]
}

rlch_test_nft_established_nft() {
    printf 'nft %s\n' "$*" >> "${RLCH_TEST_NFT_ESTABLISHED_LOG}"
    case "$*" in
        "list tables")
            [[ "${RLCH_TEST_NFT_ESTABLISHED_LIST_FAIL}" != "true" ]] || return 2
            printf '%s\n' "${RLCH_TEST_NFT_ESTABLISHED_TABLES}"
            ;;
        "list table inet firewalld")
            [[ "${RLCH_TEST_NFT_ESTABLISHED_TABLE_FAIL}" != "true" ]] || return 2
            printf '%s\n' "${RLCH_TEST_NFT_ESTABLISHED_RULESET}"
            ;;
        *)
            return 2
            ;;
    esac
}
