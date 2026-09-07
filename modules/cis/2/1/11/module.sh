#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.1.11 - Ensure print server services are not in use.
#

RLCH_CIS_2_1_11_PACKAGE="${RLCH_CIS_2_1_11_PACKAGE:-cups}"
RLCH_CIS_2_1_11_SERVICE="${RLCH_CIS_2_1_11_SERVICE:-cups.service}"
RLCH_CIS_2_1_11_RPM_COMMAND="${RLCH_CIS_2_1_11_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND="${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_2_1_11_STATE_DIR="${RLCH_CIS_2_1_11_STATE_DIR:-/var/lib/rlch/cis/2.1.11}"

cis_2_1_11_package_installed() {
    "${RLCH_CIS_2_1_11_RPM_COMMAND}" -q "${RLCH_CIS_2_1_11_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_11_service_active() {
    "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" is-active --quiet "${RLCH_CIS_2_1_11_SERVICE}"
}

cis_2_1_11_service_enabled_state() {
    "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" is-enabled "${RLCH_CIS_2_1_11_SERVICE}" 2>/dev/null || true
}

cis_2_1_11_service_masked() {
    [[ "$(cis_2_1_11_service_enabled_state)" == "masked" ]]
}

cis_2_1_11_capture_state() {
    local enabled_state
    local active_state="inactive"

    if [[ -e "${RLCH_CIS_2_1_11_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    enabled_state="$(cis_2_1_11_service_enabled_state)"
    if cis_2_1_11_service_active; then
        active_state="active"
    fi

    if ! mkdir -p -- "${RLCH_CIS_2_1_11_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${enabled_state}" > "${RLCH_CIS_2_1_11_STATE_DIR}/enabled-state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "${active_state}" > "${RLCH_CIS_2_1_11_STATE_DIR}/active-state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${RLCH_CIS_2_1_11_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    if ! cis_2_1_11_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if cis_2_1_11_service_active; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! cis_2_1_11_service_masked; then
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

    cis_2_1_11_capture_state
    result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_1_11_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_1_11_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_2_1_11_SERVICE}"; then
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

    if [[ ! -e "${RLCH_CIS_2_1_11_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${RLCH_CIS_2_1_11_STATE_DIR}/enabled-state" ]] ||
       [[ ! -f "${RLCH_CIS_2_1_11_STATE_DIR}/active-state" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    enabled_state="$(cat -- "${RLCH_CIS_2_1_11_STATE_DIR}/enabled-state")"
    active_state="$(cat -- "${RLCH_CIS_2_1_11_STATE_DIR}/active-state")"

    if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" unmask "${RLCH_CIS_2_1_11_SERVICE}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case "${enabled_state}" in
        enabled)
            if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" enable "${RLCH_CIS_2_1_11_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        masked)
            if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" mask "${RLCH_CIS_2_1_11_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        *)
            if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" disable "${RLCH_CIS_2_1_11_SERVICE}"; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
    esac

    if [[ "${active_state}" == "active" ]]; then
        if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" start "${RLCH_CIS_2_1_11_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! "${RLCH_CIS_2_1_11_SYSTEMCTL_COMMAND}" stop "${RLCH_CIS_2_1_11_SERVICE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_2_1_11_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
