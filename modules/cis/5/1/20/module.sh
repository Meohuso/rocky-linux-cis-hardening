#!/usr/bin/env bash
# CIS 5.1.20 - Ensure sshd PermitRootLogin is disabled.
# SPDX-License-Identifier: MIT
RLCH_CIS_5_1_20_DROPIN="${RLCH_CIS_5_1_20_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.20.conf}"
RLCH_CIS_5_1_20_STATE_FILE="${RLCH_CIS_5_1_20_STATE_FILE:-/var/lib/rlch/cis/5.1.20/dropin.state}"
check() {
 local value result=0; value="$(sshd_effective_value permitrootlogin)" || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" && "${value,,}" == no ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
 return "${RLCH_MODULE_RESULT_SUCCESS}"
}
apply() {
 local result=0; check || result=$?
 [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 sshd_write_dropin "${RLCH_CIS_5_1_20_DROPIN}" "${RLCH_CIS_5_1_20_STATE_FILE}" PermitRootLogin no || result=$?
 [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
 check || return "${RLCH_MODULE_RESULT_ERROR}"; return "${RLCH_MODULE_RESULT_CHANGED}"
}
validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_20_DROPIN}" "${RLCH_CIS_5_1_20_STATE_FILE}"; }
