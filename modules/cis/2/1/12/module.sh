#!/usr/bin/env bash
RLCH_CIS_2_1_12_PACKAGE="${RLCH_CIS_2_1_12_PACKAGE:-rpcbind}"
RLCH_CIS_2_1_12_RPM_COMMAND="${RLCH_CIS_2_1_12_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND="${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_2_1_12_STATE_DIR="${RLCH_CIS_2_1_12_STATE_DIR:-/var/lib/rlch/cis/2.1.12}"
RLCH_CIS_2_1_12_UNITS="${RLCH_CIS_2_1_12_UNITS:-rpcbind.service rpcbind.socket}"

cis_2_1_12_package_installed() {
    "${RLCH_CIS_2_1_12_RPM_COMMAND}" -q "${RLCH_CIS_2_1_12_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_12_unit_active() {
    "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" is-active --quiet "${1:?Unit required}"
}

cis_2_1_12_enabled_state() {
    "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" is-enabled "${1:?Unit required}" 2>/dev/null || true
}

cis_2_1_12_state_name() {
    local unit="${1:?Unit required}"
    printf '%s\n' "${unit//./_}"
}

cis_2_1_12_capture_state() {
    local unit name enabled active
    if [[ -e "${RLCH_CIS_2_1_12_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if ! mkdir -p -- "${RLCH_CIS_2_1_12_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for unit in ${RLCH_CIS_2_1_12_UNITS}; do
        name="$(cis_2_1_12_state_name "${unit}")"
        enabled="$(cis_2_1_12_enabled_state "${unit}")"
        active="inactive"
        if cis_2_1_12_unit_active "${unit}"; then active="active"; fi
        if ! printf '%s\n' "${enabled}" > "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.enabled"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if ! printf '%s\n' "${active}" > "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.active"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    if ! : > "${RLCH_CIS_2_1_12_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

check() {
    local unit
    if ! cis_2_1_12_package_installed; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    for unit in ${RLCH_CIS_2_1_12_UNITS}; do
        if cis_2_1_12_unit_active "${unit}"; then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
        if [[ "$(cis_2_1_12_enabled_state "${unit}")" != "masked" ]]; then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
    done
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result unit
    check
    result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    cis_2_1_12_capture_state
    result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for unit in ${RLCH_CIS_2_1_12_UNITS}; do
        if ! "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" stop "${unit}"; then return "${RLCH_MODULE_RESULT_ERROR}"; fi
        if ! "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" disable "${unit}"; then return "${RLCH_MODULE_RESULT_ERROR}"; fi
        if ! "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" mask "${unit}"; then return "${RLCH_MODULE_RESULT_ERROR}"; fi
    done
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    local unit name enabled active
    if [[ ! -e "${RLCH_CIS_2_1_12_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    for unit in ${RLCH_CIS_2_1_12_UNITS}; do
        name="$(cis_2_1_12_state_name "${unit}")"
        if [[ ! -f "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.enabled" ]] ||
           [[ ! -f "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.active" ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        enabled="$(cat -- "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.enabled")"
        active="$(cat -- "${RLCH_CIS_2_1_12_STATE_DIR}/${name}.active")"
        if ! "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" unmask "${unit}"; then return "${RLCH_MODULE_RESULT_ERROR}"; fi
        case "${enabled}" in
            enabled) "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" enable "${unit}" || return "${RLCH_MODULE_RESULT_ERROR}" ;;
            masked) "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" mask "${unit}" || return "${RLCH_MODULE_RESULT_ERROR}" ;;
            *) "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" disable "${unit}" || return "${RLCH_MODULE_RESULT_ERROR}" ;;
        esac
        if [[ "${active}" == "active" ]]; then
            "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" start "${unit}" || return "${RLCH_MODULE_RESULT_ERROR}"
        else
            "${RLCH_CIS_2_1_12_SYSTEMCTL_COMMAND}" stop "${unit}" || return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    rm -rf -- "${RLCH_CIS_2_1_12_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
