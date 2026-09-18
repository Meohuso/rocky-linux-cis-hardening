#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.3.2 - Ensure nftables established connections are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_3_2_SYSTEMCTL_COMMAND="${RLCH_CIS_4_3_2_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_4_3_2_NFT_COMMAND="${RLCH_CIS_4_3_2_NFT_COMMAND:-nft}"

cis_4_3_2_firewalld_active() {
    "${RLCH_CIS_4_3_2_SYSTEMCTL_COMMAND}" is-active --quiet firewalld.service
}

cis_4_3_2_list_tables() {
    "${RLCH_CIS_4_3_2_NFT_COMMAND}" list tables
}

cis_4_3_2_list_firewalld_table() {
    "${RLCH_CIS_4_3_2_NFT_COMMAND}" list table inet firewalld
}

cis_4_3_2_table_exists() {
    grep -Eq '^[[:space:]]*table[[:space:]]+inet[[:space:]]+firewalld[[:space:]]*$' <<< "${1:-}"
}

cis_4_3_2_has_established_related_accept() {
    awk '
        {
            line = tolower($0)
            gsub(/[{},]/, " ", line)
            if (line ~ /ct[[:space:]]+state/ &&
                line ~ /(^|[[:space:]])established([[:space:]]|$)/ &&
                line ~ /(^|[[:space:]])related([[:space:]]|$)/ &&
                line ~ /(^|[[:space:]])accept([[:space:]]|$)/) {
                found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    ' <<< "${1:-}"
}

check() {
    local table_list table_output

    if ! cis_4_3_2_firewalld_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! table_list="$(cis_4_3_2_list_tables 2>/dev/null)"; then
        error_message "Unable to list nftables tables for CIS 4.3.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! cis_4_3_2_table_exists "${table_list}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! table_output="$(cis_4_3_2_list_firewalld_table 2>/dev/null)"; then
        error_message "Unable to inspect the firewalld nftables backend for CIS 4.3.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! cis_4_3_2_has_established_related_accept "${table_output}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    if check; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    error_message "CIS 4.3.2 is an observation-only manual control; direct nftables rule changes are intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 4.3.2 does not modify the firewalld-generated ruleset; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
