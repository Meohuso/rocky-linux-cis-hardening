#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.3.4 - Ensure nftables loopback traffic is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_3_4_SYSTEMCTL_COMMAND="${RLCH_CIS_4_3_4_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_4_3_4_FIREWALL_CMD="${RLCH_CIS_4_3_4_FIREWALL_CMD:-firewall-cmd}"
RLCH_CIS_4_3_4_NFT_COMMAND="${RLCH_CIS_4_3_4_NFT_COMMAND:-nft}"
RLCH_CIS_4_3_4_IPV4_RULE='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
RLCH_CIS_4_3_4_IPV6_RULE='rule family=ipv6 source address="::1" destination not address="::1" drop'

cis_4_3_4_firewalld_active() {
    "${RLCH_CIS_4_3_4_SYSTEMCTL_COMMAND}" is-active --quiet firewalld.service
}

cis_4_3_4_backend_table_present() {
    local tables

    if ! tables="$("${RLCH_CIS_4_3_4_NFT_COMMAND}" list tables 2>/dev/null)"; then
        return 2
    fi
    awk '$1 == "table" && $2 == "inet" && $3 == "firewalld" && NF == 3 { found = 1 } END { exit !found }' <<< "${tables}"
}

cis_4_3_4_firewall_args() {
    local item="${2:?Item is required.}"
    local scope="${1:?Scope is required.}"
    local -a args=()

    [[ "${scope}" == "runtime" ]] || args+=(--permanent)
    args+=(--zone=trusted)

    case "${item}" in
        interface)
            args+=(--query-interface=lo)
            ;;
        ipv4)
            args+=(--query-rich-rule "${RLCH_CIS_4_3_4_IPV4_RULE}")
            ;;
        ipv6)
            args+=(--query-rich-rule "${RLCH_CIS_4_3_4_IPV6_RULE}")
            ;;
        *)
            return 2
            ;;
    esac

    "${RLCH_CIS_4_3_4_FIREWALL_CMD}" "${args[@]}"
}

cis_4_3_4_query() {
    local result=0

    if cis_4_3_4_firewall_args "${1:-}" "${2:-}" >/dev/null 2>&1; then
        return 0
    else
        result=$?
    fi

    [[ "${result}" -eq 1 ]] && return 1
    return 2
}

check() {
    local backend_result=0 item scope result=0
    local non_compliant="false"

    if ! cis_4_3_4_firewalld_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    cis_4_3_4_backend_table_present || backend_result=$?
    if [[ "${backend_result}" -eq 1 ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if [[ "${backend_result}" -ne 0 ]]; then
        error_message "Unable to inspect the firewalld nftables backend for CIS 4.3.4."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    for scope in permanent runtime; do
        for item in interface ipv4 ipv6; do
            if cis_4_3_4_query "${scope}" "${item}"; then
                continue
            else
                result=$?
            fi
            if [[ "${result}" -eq 1 ]]; then
                non_compliant="true"
            else
                error_message "Unable to inspect CIS 4.3.4 ${scope} ${item} state."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        done
    done

    [[ "${non_compliant}" == "false" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]]; then
        error_message "CIS 4.3.4 is managed through firewalld; remediate CIS 4.2.2 instead of writing concurrent nftables rules."
    fi
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 4.3.4 performs a read-only firewalld backend check; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
