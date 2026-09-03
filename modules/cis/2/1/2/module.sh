#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.2 - Ensure avahi daemon services are not in use.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_2_PACKAGE="${RLCH_CIS_2_1_2_PACKAGE:-avahi}"
RLCH_CIS_2_1_2_SERVICE="${RLCH_CIS_2_1_2_SERVICE:-avahi-daemon.service}"
RLCH_CIS_2_1_2_SOCKET="${RLCH_CIS_2_1_2_SOCKET:-avahi-daemon.socket}"
RLCH_CIS_2_1_2_STATE_DIR="${RLCH_CIS_2_1_2_STATE_DIR:-/var/lib/rlch/cis/2.1.2}"

cis_2_1_2_package_installed() {
    rpm -q "${RLCH_CIS_2_1_2_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_2_unit_active() {
    local unit="${1:-}"

    systemctl is-active --quiet "${unit}"
}

cis_2_1_2_unit_masked() {
    local unit="${1:-}"
    local state=""

    state="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"

    [[ "${state}" == "masked" || "${state}" == "masked-runtime" ]]
}

cis_2_1_2_unit_compliant() {
    local unit="${1:-}"

    if cis_2_1_2_unit_active "${unit}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! cis_2_1_2_unit_masked "${unit}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_2_capture_unit_state() {
    local label="${1:-}"
    local unit="${2:-}"
    local enabled_state
    local active_state

    enabled_state="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    active_state="$(systemctl is-active "${unit}" 2>/dev/null || true)"

    if ! printf '%s\n' "${enabled_state}" > "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.enabled"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${active_state}" > "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.active"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_2_capture_state() {
    if [[ -e "${RLCH_CIS_2_1_2_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_2_1_2_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_2_capture_unit_state service "${RLCH_CIS_2_1_2_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_2_capture_unit_state socket "${RLCH_CIS_2_1_2_SOCKET}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_2_1_2_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_2_1_2_harden_unit() {
    local unit="${1:-}"

    if ! systemctl stop "${unit}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! systemctl disable "${unit}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! systemctl mask "${unit}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local result

    if ! cis_2_1_2_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_1_2_unit_compliant "${RLCH_CIS_2_1_2_SERVICE}"
    result=$?

    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${result}"
    fi

    cis_2_1_2_unit_compliant "${RLCH_CIS_2_1_2_SOCKET}"
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_1_2_capture_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_2_harden_unit "${RLCH_CIS_2_1_2_SOCKET}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_2_harden_unit "${RLCH_CIS_2_1_2_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

cis_2_1_2_restore_unit() {
    local label="${1:-}"
    local unit="${2:-}"
    local enabled_state
    local active_state

    if [[ ! -f "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.enabled" ||
          ! -f "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.active" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    enabled_state="$(cat -- "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.enabled")"
    active_state="$(cat -- "${RLCH_CIS_2_1_2_STATE_DIR}/${label}.active")"

    if ! systemctl unmask "${unit}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${enabled_state}" == "enabled" ]]; then
        if ! systemctl enable "${unit}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! systemctl disable "${unit}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if [[ "${active_state}" == "active" ]]; then
        if ! systemctl start "${unit}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! systemctl stop "${unit}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if [[ "${enabled_state}" == "masked" || "${enabled_state}" == "masked-runtime" ]]; then
        if ! systemctl mask "${unit}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

rollback() {
    if [[ ! -e "${RLCH_CIS_2_1_2_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cis_2_1_2_restore_unit service "${RLCH_CIS_2_1_2_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_2_restore_unit socket "${RLCH_CIS_2_1_2_SOCKET}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -rf -- "${RLCH_CIS_2_1_2_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
