#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.8.2 - Ensure nodev option is set on /dev/shm partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_8_2_MOUNT_TARGET="/dev/shm"
readonly RLCH_CIS_1_1_8_2_MOUNT_OPTION="nodev"

RLCH_CIS_1_1_8_2_FSTAB="${RLCH_CIS_1_1_8_2_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}}"

check() {
    local result

    mount_check_option \
        "${RLCH_CIS_1_1_8_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_2_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_8_2_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

apply() {
    local result

    mount_apply_option \
        "${RLCH_CIS_1_1_8_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_2_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_8_2_FSTAB}"
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
        "${RLCH_CIS_1_1_8_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_2_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}
