#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 2.1.9 - Ensure network file system services are not in use.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_9_PACKAGE="${RLCH_CIS_2_1_9_PACKAGE:-nfs-utils}"
RLCH_CIS_2_1_9_SERVICE="${RLCH_CIS_2_1_9_SERVICE:-nfs-server.service}"
RLCH_CIS_2_1_9_RPM_COMMAND="${RLCH_CIS_2_1_9_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND="${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_2_1_9_STATE_DIR="${RLCH_CIS_2_1_9_STATE_DIR:-/var/lib/rlch/cis/2.1.9}"

cis_2_1_9_package_installed() {
    "${RLCH_CIS_2_1_9_RPM_COMMAND}" -q "${RLCH_CIS_2_1_9_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_9_service_active() {
    "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" is-active --quiet "${RLCH_CIS_2_1_9_SERVICE}"
}

cis_2_1_9_service_masked() {
    local enabled_state

    enabled_state="$(
        "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" is-enabled \
            "${RLCH_CIS_2_1_9_SERVICE}" 2>/dev/null
    )" || true

    [[ "${enabled_state}" == "masked" ]]
}

cis_2_1_9_service_enabled_state() {
    "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" is-enabled \
        "${RLCH_CIS_2_1_9_SERVICE}" 2>/dev/null || true
}

cis_2_1_9_service_active_state() {
    if cis_2_1_9_service_active; then
        printf '%s\n' "active"
    else
        printf '%s\n' "inactive"
    fi
}

cis_2_1_9_capture_state() {
    local enabled_state
    local active_state

    if [[ -e "${RLCH_CIS_2_1_9_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    enabled_state="$(cis_2_1_9_service_enabled_state)"
    active_state="$(cis_2_1_9_service_active_state)"

    if ! mkdir -p -- "${RLCH_CIS_2_1_9_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${enabled_state}" \
        > "${RLCH_CIS_2_1_9_STATE_DIR}/enabled-state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${active_state}" \
        > "${RLCH_CIS_2_1_9_STATE_DIR}/active-state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_2_1_9_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    if ! cis_2_1_9_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if cis_2_1_9_service_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! cis_2_1_9_service_masked; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
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

    cis_2_1_9_capture_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_1_9_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_1_9_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_2_1_9_SERVICE}"; then
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

    if [[ ! -e "${RLCH_CIS_2_1_9_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${RLCH_CIS_2_1_9_STATE_DIR}/enabled-state" ]] ||
        [[ ! -f "${RLCH_CIS_2_1_9_STATE_DIR}/active-state" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    enabled_state="$(cat -- "${RLCH_CIS_2_1_9_STATE_DIR}/enabled-state")"
    active_state="$(cat -- "${RLCH_CIS_2_1_9_STATE_DIR}/active-state")"

    if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_2_1_9_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case "${enabled_state}" in
        enabled)
            if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_2_1_9_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        masked)
            if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_2_1_9_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        *)
            if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_1_9_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
    esac

    if [[ "${active_state}" == "active" ]]; then
        if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_2_1_9_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! "${RLCH_CIS_2_1_9_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_1_9_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_2_1_9_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
