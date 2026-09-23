#!/usr/bin/env bash
# CIS 5.1.17 - Ensure sshd MaxStartups is configured.
# SPDX-License-Identifier: MIT
RLCH_CIS_5_1_17_VALUE="${RLCH_CIS_5_1_17_VALUE:-10:30:60}"
RLCH_CIS_5_1_17_DROPIN="${RLCH_CIS_5_1_17_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.17.conf}"
RLCH_CIS_5_1_17_STATE_FILE="${RLCH_CIS_5_1_17_STATE_FILE:-/var/lib/rlch/cis/5.1.17/dropin.state}"
check() {
 local value result=0; value="$(sshd_effective_value maxstartups)" || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" && "${value}" == "${RLCH_CIS_5_1_17_VALUE}" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
 return "${RLCH_MODULE_RESULT_SUCCESS}"
}
apply() {
 local result=0; check || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 sshd_write_dropin "${RLCH_CIS_5_1_17_DROPIN}" "${RLCH_CIS_5_1_17_STATE_FILE}" MaxStartups "${RLCH_CIS_5_1_17_VALUE}" || result=$?
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 check || return "${RLCH_MODULE_RESULT_ERROR}"; return "${RLCH_MODULE_RESULT_CHANGED}"
}
validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_17_DROPIN}" "${RLCH_CIS_5_1_17_STATE_FILE}"; }
