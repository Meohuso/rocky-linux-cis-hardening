#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 4.2.2 - Ensure firewalld loopback traffic is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_4_2_2_FIREWALL_CMD="${RLCH_CIS_4_2_2_FIREWALL_CMD:-firewall-cmd}"
RLCH_CIS_4_2_2_ID_COMMAND="${RLCH_CIS_4_2_2_ID_COMMAND:-id}"
RLCH_CIS_4_2_2_STATE_DIR="${RLCH_CIS_4_2_2_STATE_DIR:-/var/lib/rlch/cis/4.2.2}"
RLCH_CIS_4_2_2_STATE_FILE="${RLCH_CIS_4_2_2_STATE_FILE:-${RLCH_CIS_4_2_2_STATE_DIR}/state}"
RLCH_CIS_4_2_2_IPV4_RULE='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
RLCH_CIS_4_2_2_IPV6_RULE='rule family=ipv6 source address="::1" destination not address="::1" drop'

cis_4_2_2_firewall_args() {
    local action="${1:?Action is required.}"
    local scope="${2:?Scope is required.}"
    local item="${3:?Item is required.}"
    local -a args=()

    [[ "${scope}" == "runtime" ]] || args+=(--permanent)
    args+=(--zone=trusted)

    case "${item}" in
        interface)
            args+=("--${action}-interface=lo")
            ;;
        ipv4)
            args+=("--${action}-rich-rule" "${RLCH_CIS_4_2_2_IPV4_RULE}")
            ;;
        ipv6)
            args+=("--${action}-rich-rule" "${RLCH_CIS_4_2_2_IPV6_RULE}")
            ;;
        *)
            return 2
            ;;
    esac

    "${RLCH_CIS_4_2_2_FIREWALL_CMD}" "${args[@]}"
}

cis_4_2_2_query() {
    local result=0

    if cis_4_2_2_firewall_args query "${1:-}" "${2:-}" >/dev/null 2>&1; then
        return 0
    else
        result=$?
    fi

    [[ "${result}" -eq 1 ]] && return 1
    return 2
}

cis_4_2_2_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_4_2_2_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 4.2.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 4.2.2 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_2_2_item_state() {
    local result=0

    if cis_4_2_2_query "${1:-}" "${2:-}"; then
        printf '%s\n' present
        return 0
    else
        result=$?
    fi

    if [[ "${result}" -eq 1 ]]; then
        printf '%s\n' absent
        return 0
    fi
    return 1
}

cis_4_2_2_capture_state() {
    local item scope state
    local temporary_state="${RLCH_CIS_4_2_2_STATE_FILE}.tmp.$$"

    [[ ! -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    if ! mkdir -p -- "${RLCH_CIS_4_2_2_STATE_DIR}" || ! : > "${temporary_state}"; then
        error_message "Unable to initialize CIS 4.2.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    for scope in permanent runtime; do
        for item in interface ipv4 ipv6; do
            if ! state="$(cis_4_2_2_item_state "${scope}" "${item}")" ||
               ! printf '%s=%s\n' "${scope}_${item}" "${state}" >> "${temporary_state}"; then
                rm -f -- "${temporary_state}"
                error_message "Unable to capture CIS 4.2.2 ${scope} ${item} state."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        done
    done

    if ! mv -- "${temporary_state}" "${RLCH_CIS_4_2_2_STATE_FILE}"; then
        rm -f -- "${temporary_state}"
        error_message "Unable to finalize CIS 4.2.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_4_2_2_ensure_present() {
    local item="${2:-}"
    local scope="${1:-}"
    local result=0

    if cis_4_2_2_query "${scope}" "${item}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    else
        result=$?
    fi
    if [[ "${result}" -ne 1 ]] || ! cis_4_2_2_firewall_args add "${scope}" "${item}" >/dev/null; then
        error_message "Unable to configure CIS 4.2.2 ${scope} ${item} state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_4_2_2_restore_item() {
    local desired_state="${3:-}"
    local item="${2:-}"
    local scope="${1:-}"
    local action result=0

    if cis_4_2_2_query "${scope}" "${item}"; then
        result=0
    else
        result=$?
    fi
    [[ "${result}" -le 1 ]] || return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ "${desired_state}" == "present" && "${result}" -eq 1 ]]; then
        action=add
    elif [[ "${desired_state}" == "absent" && "${result}" -eq 0 ]]; then
        action=remove
    else
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_4_2_2_firewall_args "${action}" "${scope}" "${item}" >/dev/null || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    local item scope result=0
    local non_compliant="false"

    for scope in permanent runtime; do
        for item in interface ipv4 ipv6; do
            if cis_4_2_2_query "${scope}" "${item}"; then
                continue
            else
                result=$?
            fi
            if [[ "${result}" -eq 1 ]]; then
                non_compliant="true"
            else
                error_message "Unable to inspect CIS 4.2.2 ${scope} ${item} state."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        done
    done

    [[ "${non_compliant}" == "false" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local item scope result=0

    check || result=$?
    case "${result}" in
        "${RLCH_MODULE_RESULT_SUCCESS}")
            return "${RLCH_MODULE_RESULT_SUCCESS}"
            ;;
        "${RLCH_MODULE_RESULT_NON_COMPLIANT}")
            ;;
        *)
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac

    cis_4_2_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_4_2_2_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    for scope in permanent runtime; do
        for item in interface ipv4 ipv6; do
            result=0
            cis_4_2_2_ensure_present "${scope}" "${item}" >/dev/null || result=$?
            if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" &&
                  "${result}" -ne "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        done
    done

    if ! check; then
        error_message "CIS 4.2.2 validation failed after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local entry expected_key item scope state
    local result=0
    local -a entries=()
    local -a expected_keys=(permanent_interface permanent_ipv4 permanent_ipv6 runtime_interface runtime_ipv4 runtime_ipv6)

    [[ -e "${RLCH_CIS_4_2_2_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_4_2_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mapfile -t entries < "${RLCH_CIS_4_2_2_STATE_FILE}"
    if [[ "${#entries[@]}" -ne "${#expected_keys[@]}" ]]; then
        error_message "Invalid CIS 4.2.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    for entry in "${!entries[@]}"; do
        expected_key="${expected_keys[entry]}"
        if [[ "${entries[entry]}" != "${expected_key}=present" &&
              "${entries[entry]}" != "${expected_key}=absent" ]]; then
            error_message "Invalid CIS 4.2.2 rollback state."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done

    for entry in "${entries[@]}"; do
        scope="${entry%%_*}"
        item="${entry#*_}"
        item="${item%%=*}"
        state="${entry#*=}"
        result=0
        cis_4_2_2_restore_item "${scope}" "${item}" "${state}" >/dev/null || result=$?
        if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" &&
              "${result}" -ne "${RLCH_MODULE_RESULT_CHANGED}" ]]; then
            error_message "Unable to restore CIS 4.2.2 ${scope} ${item} state."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done

    if ! rm -f -- "${RLCH_CIS_4_2_2_STATE_FILE}"; then
        error_message "Unable to remove CIS 4.2.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rmdir "${RLCH_CIS_4_2_2_STATE_DIR}" >/dev/null 2>&1 || true
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
