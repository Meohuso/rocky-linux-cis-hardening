#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.8 - Ensure sshd Banner is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_8_VALUE="${RLCH_CIS_5_1_8_VALUE:-/etc/issue.net}"
RLCH_CIS_5_1_8_DROPIN="${RLCH_CIS_5_1_8_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.8.conf}"
RLCH_CIS_5_1_8_STATE_DIR="${RLCH_CIS_5_1_8_STATE_DIR:-/var/lib/rlch/cis/5.1.8}"
RLCH_CIS_5_1_8_STATE_FILE="${RLCH_CIS_5_1_8_STATE_FILE:-${RLCH_CIS_5_1_8_STATE_DIR}/dropin.state}"

check() {
    local value result=0

    value="$(sshd_effective_value banner)" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" && "${value}" == "${RLCH_CIS_5_1_8_VALUE}" ]] ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sshd_write_dropin "${RLCH_CIS_5_1_8_DROPIN}" "${RLCH_CIS_5_1_8_STATE_FILE}" Banner "${RLCH_CIS_5_1_8_VALUE}" || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_8_DROPIN}" "${RLCH_CIS_5_1_8_STATE_FILE}"; }
