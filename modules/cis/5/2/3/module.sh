#!/usr/bin/env bash
# CIS 5.2.3 - Ensure sudo log file exists.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_2_3_LOGFILE="${RLCH_CIS_5_2_3_LOGFILE:-/var/log/sudo.log}"
RLCH_CIS_5_2_3_DROPIN="${RLCH_CIS_5_2_3_DROPIN:-/etc/sudoers.d/00-rlch-cis-5-2-3}"
RLCH_CIS_5_2_3_STATE_FILE="${RLCH_CIS_5_2_3_STATE_FILE:-/var/lib/rlch/cis/5.2.3/dropin.state}"

check() { sudoers_global_value_equals logfile "${RLCH_CIS_5_2_3_LOGFILE}"; }

apply() {
    local content result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    printf -v content 'Defaults logfile="%s"' "${RLCH_CIS_5_2_3_LOGFILE}"
    sudoers_write_managed_file "${RLCH_CIS_5_2_3_DROPIN}" "${RLCH_CIS_5_2_3_STATE_FILE}" "${content}" || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sudoers_rollback_managed_file "${RLCH_CIS_5_2_3_DROPIN}" "${RLCH_CIS_5_2_3_STATE_FILE}"; }
