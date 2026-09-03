#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.1 - Ensure autofs services are not in use.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_1_PACKAGE="${RLCH_CIS_2_1_1_PACKAGE:-autofs}"
RLCH_CIS_2_1_1_SERVICE="${RLCH_CIS_2_1_1_SERVICE:-autofs.service}"
RLCH_CIS_2_1_1_STATE_DIR="${RLCH_CIS_2_1_1_STATE_DIR:-/var/lib/rlch/cis/2.1.1}"

cis_2_1_1_package_installed() {
    rpm -q "${RLCH_CIS_2_1_1_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_1_service_active() {
    systemctl is-active --quiet "${RLCH_CIS_2_1_1_SERVICE}"
}

cis_2_1_1_service_enabled() {
    systemctl is-enabled --quiet "${RLCH_CIS_2_1_1_SERVICE}"
}

cis_2_1_1_service_masked() {
    local state

    if ! state="$(systemctl is-enabled "${RLCH_CIS_2_1_1_SERVICE}" 2>/dev/null)"; then
        if [[ "${state}" == "masked" || "${state}" == "masked-runtime" ]]; then
            return "${RLCH_MODULE_RESULT_SUCCESS}"
        fi
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ "${state}" == "masked" || "${state}" == "masked-runtime" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cis_2_1_1_capture_state() {
    local enabled_state
    local active_state

    if [[ -e "${RLCH_CIS_2_1_1_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_2_1_1_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    enabled_state="$(systemctl is-enabled "${RLCH_CIS_2_1_1_SERVICE}" 2>/dev/null || true)"
    active_state="$(systemctl is-active "${RLCH_CIS_2_1_1_SERVICE}" 2>/dev/null || true)"

    if ! printf '%s\n' "${enabled_state}" > "${RLCH_CIS_2_1_1_STATE_DIR}/enabled"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${active_state}" > "${RLCH_CIS_2_1_1_STATE_DIR}/active"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_2_1_1_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    if ! cis_2_1_1_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if cis_2_1_1_service_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if cis_2_1_1_service_enabled; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    cis_2_1_1_service_masked
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

    cis_2_1_1_capture_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! systemctl stop "${RLCH_CIS_2_1_1_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! systemctl disable "${RLCH_CIS_2_1_1_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! systemctl mask "${RLCH_CIS_2_1_1_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local enabled_state
    local active_state

    if [[ ! -e "${RLCH_CIS_2_1_1_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${RLCH_CIS_2_1_1_STATE_DIR}/enabled" ||
          ! -f "${RLCH_CIS_2_1_1_STATE_DIR}/active" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    enabled_state="$(cat -- "${RLCH_CIS_2_1_1_STATE_DIR}/enabled")"
    active_state="$(cat -- "${RLCH_CIS_2_1_1_STATE_DIR}/active")"

    if ! systemctl unmask "${RLCH_CIS_2_1_1_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${enabled_state}" == "enabled" ]]; then
        if ! systemctl enable "${RLCH_CIS_2_1_1_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! systemctl disable "${RLCH_CIS_2_1_1_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if [[ "${active_state}" == "active" ]]; then
        if ! systemctl start "${RLCH_CIS_2_1_1_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! systemctl stop "${RLCH_CIS_2_1_1_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if [[ "${enabled_state}" == "masked" || "${enabled_state}" == "masked-runtime" ]]; then
        if ! systemctl mask "${RLCH_CIS_2_1_1_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_2_1_1_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
