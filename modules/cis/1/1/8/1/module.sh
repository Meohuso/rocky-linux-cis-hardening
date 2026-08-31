#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.8.1 - Ensure /dev/shm is a separate partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_8_1_MOUNT_TARGET="/dev/shm"

RLCH_CIS_1_1_8_1_FSTAB="${RLCH_CIS_1_1_8_1_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}}"

check() {
    local result

    mount_check_partition \
        "${RLCH_CIS_1_1_8_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_1_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

apply() {
    mount_apply_partition
}

validate() {
    check
}

rollback() {
    local result

    mount_rollback \
        "${RLCH_CIS_1_1_8_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_8_1_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}
