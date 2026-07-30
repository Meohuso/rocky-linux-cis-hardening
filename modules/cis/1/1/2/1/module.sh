#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.2.1 - Ensure /tmp is a separate partition.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_2_1_CONTROL_ID="1.1.2.1"
readonly RLCH_CIS_1_1_2_1_MOUNT_TARGET="/tmp"

RLCH_CIS_1_1_2_1_FSTAB="${RLCH_CIS_1_1_2_1_FSTAB:-${RLCH_MOUNT_FSTAB:-/etc/fstab}}"

##
# Check CIS control 1.1.2.1.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when /tmp has an exact persistent and runtime
#   mount entry.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
##
check() {
    mount_check_partition \
        "${RLCH_CIS_1_1_2_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_1_FSTAB}"
}

##
# Apply CIS control 1.1.2.1.
#
# Automatic partition creation, formatting, resizing, and data migration are
# intentionally unsupported by the framework.
#
# Returns:
#   RLCH_MODULE_RESULT_ERROR.
##
apply() {
    mount_apply_partition
}

##
# Validate CIS control 1.1.2.1 after remediation.
##
validate() {
    check
}

##
# Roll back framework-managed configuration.
#
# The control does not provision storage automatically. The mount library
# restores an existing framework-managed fstab backup when one is present.
#
# Returns:
#   RLCH_MODULE_RESULT_CHANGED when an fstab backup is restored.
#   RLCH_MODULE_RESULT_COMPLIANT when no backup exists.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
rollback() {
    mount_rollback \
        "${RLCH_CIS_1_1_2_1_MOUNT_TARGET}" \
        "${RLCH_CIS_1_1_2_1_FSTAB}"
}