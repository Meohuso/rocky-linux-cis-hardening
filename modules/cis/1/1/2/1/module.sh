#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.2.1 - Ensure /tmp is a separate partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_2_1_MOUNT_TARGET="/tmp"

RLCH_CIS_1_1_2_1_FSTAB="${
    RLCH_CIS_1_1_2_1_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}
}"

##
# Check whether /tmp has its own persistent and runtime mount.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when compliant.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
##
check() {
    local result

    mount_check_partition \
        "${RLCH_CIS_1_1_2_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_1_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}

##
# Apply CIS control 1.1.2.1.
#
# Automatic partition creation, resizing, formatting, and data migration are
# intentionally unsupported. The required partition must be provisioned during
# installation or through an approved storage migration procedure.
#
# Returns:
#   RLCH_MODULE_RESULT_ERROR.
##
apply() {
    mount_apply_partition
}

##
# Validate CIS control 1.1.2.1 after remediation.
#
# Returns:
#   The result returned by check.
##
validate() {
    check
}

##
# Restore a framework-managed fstab backup, when present.
#
# Returns:
#   RLCH_MODULE_RESULT_CHANGED when a backup is restored.
#   RLCH_MODULE_RESULT_SUCCESS when no backup exists.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
rollback() {
    local result

    mount_rollback \
        "${RLCH_CIS_1_1_2_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_1_FSTAB}"
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${result}"
}
