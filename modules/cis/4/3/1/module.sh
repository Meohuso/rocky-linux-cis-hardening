#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.3.1 - Ensure nftables base chains exist.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_3_1_SYSTEMCTL_COMMAND="${RLCH_CIS_4_3_1_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_4_3_1_NFT_COMMAND="${RLCH_CIS_4_3_1_NFT_COMMAND:-nft}"

cis_4_3_1_firewalld_active() {
    "${RLCH_CIS_4_3_1_SYSTEMCTL_COMMAND}" is-active --quiet firewalld.service
}

cis_4_3_1_list_tables() {
    "${RLCH_CIS_4_3_1_NFT_COMMAND}" list tables
}

cis_4_3_1_list_firewalld_table() {
    "${RLCH_CIS_4_3_1_NFT_COMMAND}" list table inet firewalld
}

cis_4_3_1_table_exists() {
    local table_list="${1:-}"

    grep -Eq '^[[:space:]]*table[[:space:]]+inet[[:space:]]+firewalld[[:space:]]*$' <<< "${table_list}"
}

cis_4_3_1_has_filter_base_chain() {
    local hook="${1:-}"
    local table_output="${2:-}"

    awk -v expected_hook="${hook}" '
        $0 ~ "type[[:space:]]+filter[[:space:]]+hook[[:space:]]+" expected_hook "[[:space:]]+priority[[:space:]]+[^;]+;[[:space:]]+policy[[:space:]]+(accept|drop)[[:space:]]*;" {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' <<< "${table_output}"
}

check() {
    local hook table_list table_output

    if ! cis_4_3_1_firewalld_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! table_list="$(cis_4_3_1_list_tables 2>/dev/null)"; then
        error_message "Unable to list nftables tables for CIS 4.3.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! cis_4_3_1_table_exists "${table_list}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! table_output="$(cis_4_3_1_list_firewalld_table 2>/dev/null)"; then
        error_message "Unable to inspect the firewalld nftables backend for CIS 4.3.1."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    for hook in input forward output; do
        if ! cis_4_3_1_has_filter_base_chain "${hook}" "${table_output}"; then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    if check; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    error_message "CIS 4.3.1 is managed by the firewalld nftables backend; direct nftables chain creation is intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 4.3.1 performs a read-only backend check; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
