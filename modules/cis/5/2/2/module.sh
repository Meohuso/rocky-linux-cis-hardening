#!/usr/bin/env bash
# CIS 5.2.2 - Ensure sudo commands use pty.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_2_2_DROPIN="${RLCH_CIS_5_2_2_DROPIN:-/etc/sudoers.d/00-rlch-cis-5-2-2}"
RLCH_CIS_5_2_2_STATE_FILE="${RLCH_CIS_5_2_2_STATE_FILE:-/var/lib/rlch/cis/5.2.2/dropin.state}"

check() { sudoers_global_boolean_enabled use_pty; }

apply() {
    local result=0
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_write_managed_file "${RLCH_CIS_5_2_2_DROPIN}" "${RLCH_CIS_5_2_2_STATE_FILE}" 'Defaults use_pty' || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sudoers_rollback_managed_file "${RLCH_CIS_5_2_2_DROPIN}" "${RLCH_CIS_5_2_2_STATE_FILE}"; }
