#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.8.3 - Ensure noexec option is set on /dev/shm partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_8_3_MOUNT_TARGET="/dev/shm"
readonly RLCH_CIS_1_1_8_3_MOUNT_OPTION="noexec"

RLCH_CIS_1_1_8_3_FSTAB="${RLCH_CIS_1_1_8_3_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}}"

check() {
    local result

    mount_check_option \
        "${RLCH_CIS_1_1_8_3_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_3_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_8_3_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

apply() {
    local result

    mount_apply_option \
        "${RLCH_CIS_1_1_8_3_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_3_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_8_3_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

validate() {
    check
}

rollback() {
    local result

    mount_rollback \
        "${RLCH_CIS_1_1_8_3_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_3_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}
