#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.12 - Ensure sshd HostbasedAuthentication is disabled.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_12_VALUE="${RLCH_CIS_5_1_12_VALUE:-no}"
RLCH_CIS_5_1_12_DROPIN="${RLCH_CIS_5_1_12_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.12.conf}"
RLCH_CIS_5_1_12_STATE_DIR="${RLCH_CIS_5_1_12_STATE_DIR:-/var/lib/rlch/cis/5.1.12}"
RLCH_CIS_5_1_12_STATE_FILE="${RLCH_CIS_5_1_12_STATE_FILE:-${RLCH_CIS_5_1_12_STATE_DIR}/dropin.state}"

check() {
    local value result=0

    value="$(sshd_effective_value hostbasedauthentication)" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" && "${value,,}" == "${RLCH_CIS_5_1_12_VALUE}" ]] ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sshd_write_dropin "${RLCH_CIS_5_1_12_DROPIN}" "${RLCH_CIS_5_1_12_STATE_FILE}" HostbasedAuthentication "${RLCH_CIS_5_1_12_VALUE}" || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_12_DROPIN}" "${RLCH_CIS_5_1_12_STATE_FILE}"; }
