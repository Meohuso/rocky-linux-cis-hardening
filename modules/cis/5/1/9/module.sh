#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 5.1.9 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_5_1_9_INTERVAL="${RLCH_CIS_5_1_9_INTERVAL:-300}"
RLCH_CIS_5_1_9_COUNT_MAX="${RLCH_CIS_5_1_9_COUNT_MAX:-1}"
RLCH_CIS_5_1_9_DROPIN="${RLCH_CIS_5_1_9_DROPIN:-/etc/ssh/sshd_config.d/00-rlch-cis-5.1.9.conf}"
RLCH_CIS_5_1_9_STATE_DIR="${RLCH_CIS_5_1_9_STATE_DIR:-/var/lib/rlch/cis/5.1.9}"
RLCH_CIS_5_1_9_STATE_FILE="${RLCH_CIS_5_1_9_STATE_FILE:-${RLCH_CIS_5_1_9_STATE_DIR}/dropin.state}"

check() {
    local count interval result=0

    interval="$(sshd_effective_value clientaliveinterval)" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    result=0
    count="$(sshd_effective_value clientalivecountmax)" || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    [[ "${interval}" == "${RLCH_CIS_5_1_9_INTERVAL}" && "${count}" == "${RLCH_CIS_5_1_9_COUNT_MAX}" ]] ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local result=0

    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sshd_write_dropin \
        "${RLCH_CIS_5_1_9_DROPIN}" "${RLCH_CIS_5_1_9_STATE_FILE}" \
        ClientAliveInterval "${RLCH_CIS_5_1_9_INTERVAL}" \
        ClientAliveCountMax "${RLCH_CIS_5_1_9_COUNT_MAX}" || result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_CHANGED}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    check || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }
rollback() { sshd_rollback_dropin "${RLCH_CIS_5_1_9_DROPIN}" "${RLCH_CIS_5_1_9_STATE_FILE}"; }
