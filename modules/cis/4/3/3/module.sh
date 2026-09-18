#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.3.3 - Ensure nftables default deny firewall policy.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_3_3_SYSTEMCTL_COMMAND="${RLCH_CIS_4_3_3_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_4_3_3_FIREWALL_CMD="${RLCH_CIS_4_3_3_FIREWALL_CMD:-firewall-cmd}"

cis_4_3_3_firewalld_active() {
    "${RLCH_CIS_4_3_3_SYSTEMCTL_COMMAND}" is-active --quiet firewalld.service
}

cis_4_3_3_firewall_query() {
    "${RLCH_CIS_4_3_3_FIREWALL_CMD}" "$@"
}

cis_4_3_3_valid_zone_name() {
    [[ "${1:-}" =~ ^[[:alnum:]_-]+$ ]]
}

cis_4_3_3_active_zone_names() {
    awk '/^[^[:space:]]/ { print $1 }' <<< "${1:-}"
}

cis_4_3_3_target_is_default_deny() {
    case "${1:-}" in
        default|DROP|REJECT|%%REJECT%%)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

cis_4_3_3_trusted_is_loopback_only() {
    local interface interfaces sources
    local loopback_seen="false"

    if ! interfaces="$(cis_4_3_3_firewall_query --zone=trusted --list-interfaces 2>/dev/null)" ||
       ! sources="$(cis_4_3_3_firewall_query --zone=trusted --list-sources 2>/dev/null)"; then
        return 2
    fi
    if [[ -n "${sources//[[:space:]]/}" ]]; then
        return 1
    fi
    for interface in ${interfaces}; do
        if [[ "${interface}" != "lo" ]]; then
            return 1
        fi
        loopback_seen="true"
    done

    [[ "${loopback_seen}" == "true" ]]
}

check() {
    local active_output default_zone target trusted_result zone
    local zones=""

    if ! cis_4_3_3_firewalld_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    if ! default_zone="$(cis_4_3_3_firewall_query --get-default-zone 2>/dev/null)" ||
       ! cis_4_3_3_valid_zone_name "${default_zone}"; then
        error_message "Unable to determine a valid firewalld default zone for CIS 4.3.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! active_output="$(cis_4_3_3_firewall_query --get-active-zones 2>/dev/null)"; then
        error_message "Unable to determine active firewalld zones for CIS 4.3.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    zones="$(printf '%s\n%s\n' "${default_zone}" "$(cis_4_3_3_active_zone_names "${active_output}")" | awk 'NF && !seen[$1]++ { print $1 }')"
    while IFS= read -r zone; do
        if ! cis_4_3_3_valid_zone_name "${zone}" ||
           ! target="$(cis_4_3_3_firewall_query --zone="${zone}" --get-target 2>/dev/null)"; then
            error_message "Unable to inspect firewalld zone ${zone:-unknown} for CIS 4.3.3."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if cis_4_3_3_target_is_default_deny "${target}"; then
            continue
        fi
        if [[ "${target}" == "ACCEPT" && "${zone}" == "trusted" && "${default_zone}" != "trusted" ]]; then
            trusted_result=0
            cis_4_3_3_trusted_is_loopback_only || trusted_result=$?
            if [[ "${trusted_result}" -eq 0 ]]; then
                continue
            fi
            if [[ "${trusted_result}" -eq 2 ]]; then
                error_message "Unable to inspect trusted-zone bindings for CIS 4.3.3."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        fi
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    done <<< "${zones}"

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    if check; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    error_message "CIS 4.3.3 requires role-aware firewalld policy review; automatic zone-target changes are intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 4.3.3 performs a read-only firewalld policy check; no rollback action is required."
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
