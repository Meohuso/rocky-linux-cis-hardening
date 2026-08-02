#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.2.2 - Ensure nodev option is set on /tmp partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_2_2_MOUNT_TARGET="/tmp"
readonly RLCH_CIS_1_1_2_2_MOUNT_OPTION="nodev"

RLCH_CIS_1_1_2_2_FSTAB="${RLCH_CIS_1_1_2_2_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}}"

##
# Check whether nodev is configured persistently and active on /tmp.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when compliant.
#   RLCH_MODULE_RESULT_NON_COMPLIANT when nodev is missing.
#   RLCH_MODULE_RESULT_ERROR when the check cannot be completed.
##
check() {
    local result

    mount_check_option \
        "${RLCH_CIS_1_1_2_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_2_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_2_2_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

##
# Apply CIS control 1.1.2.2.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when already compliant.
#   RLCH_MODULE_RESULT_CHANGED when nodev is added successfully.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
apply() {
    local result

    mount_apply_option \
        "${RLCH_CIS_1_1_2_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_2_MOUNT_OPTION}" \
        "${RLCH_CIS_1_1_2_2_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

##
# Validate CIS control 1.1.2.2 after remediation.
#
# Returns:
#   The result returned by check.
##
validate() {
    check
}

##
# Restore the framework-managed fstab backup, when present.
#
# Returns:
#   RLCH_MODULE_RESULT_CHANGED when a backup is restored.
#   RLCH_MODULE_RESULT_SUCCESS when no backup exists.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
rollback() {
    local result

    mount_rollback \
        "${RLCH_CIS_1_1_2_2_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_2_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}
