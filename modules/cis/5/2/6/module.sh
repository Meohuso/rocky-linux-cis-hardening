#!/usr/bin/env bash
# CIS 5.2.6 - Ensure sudo authentication timeout is configured correctly.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_2_6_TIMEOUT="${RLCH_CIS_5_2_6_TIMEOUT:-15}"
RLCH_CIS_5_2_6_DROPIN="${RLCH_CIS_5_2_6_DROPIN:-/etc/sudoers.d/99-rlch-cis-5-2-6}"
RLCH_CIS_5_2_6_STATE_FILE="${RLCH_CIS_5_2_6_STATE_FILE:-/var/lib/rlch/cis/5.2.6/dropin.state}"

check() { sudoers_global_value_equals timestamp_timeout "${RLCH_CIS_5_2_6_TIMEOUT}"; }

apply() {
    local content result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    printf -v content 'Defaults timestamp_timeout=%s' "${RLCH_CIS_5_2_6_TIMEOUT}"
    sudoers_write_managed_file "${RLCH_CIS_5_2_6_DROPIN}" "${RLCH_CIS_5_2_6_STATE_FILE}" "${content}" || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! check; then
        sudoers_rollback_managed_file "${RLCH_CIS_5_2_6_DROPIN}" "${RLCH_CIS_5_2_6_STATE_FILE}" >/dev/null 2>&1 || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sudoers_rollback_managed_file "${RLCH_CIS_5_2_6_DROPIN}" "${RLCH_CIS_5_2_6_STATE_FILE}"; }
