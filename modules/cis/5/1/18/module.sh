#!/usr/bin/env bash
# CIS 5.1.18 - Ensure sshd MaxSessions is configured.
# SPDX-License-Identifier: MIT
RLCH_CIS_5_1_18_VALUE="${RLCH_CIS_5_1_18_VALUE:-10}"
RLCH_CIS_5_1_18_DROPIN="${RLCH_CIS_5_1_18_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.18.conf}"
RLCH_CIS_5_1_18_STATE_FILE="${RLCH_CIS_5_1_18_STATE_FILE:-/var/lib/rlch/cis/5.1.18/dropin.state}"
check() {
 local value result=0; value="$(sshd_effective_value maxsessions)" || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" && "${value}" == "${RLCH_CIS_5_1_18_VALUE}" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
 return "${RLCH_MODULE_RESULT_SUCCESS}"
}
apply() {
 local result=0; check || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 sshd_write_dropin "${RLCH_CIS_5_1_18_DROPIN}" "${RLCH_CIS_5_1_18_STATE_FILE}" MaxSessions "${RLCH_CIS_5_1_18_VALUE}" || result=$?
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 check || return "${RLCH_MODULE_RESULT_ERROR}"; return "${RLCH_MODULE_RESULT_CHANGED}"
}
validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_18_DROPIN}" "${RLCH_CIS_5_1_18_STATE_FILE}"; }
