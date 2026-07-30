#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.1.6 - Ensure squashfs kernel module is not available.
#
# SPDX-License-Identifier: MIT
#
readonly RLCH_CIS_1_1_1_6_MODULE_NAME="squashfs"
readonly RLCH_CIS_1_1_1_6_CONTROL_ID="1.1.1.6"
RLCH_CIS_1_1_1_6_MODPROBE_DIRECTORY="${RLCH_CIS_1_1_1_6_MODPROBE_DIRECTORY:-/etc/modprobe.d}"
RLCH_CIS_1_1_1_6_CONFIGURATION_FILE="${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE:-${RLCH_CIS_1_1_1_6_MODPROBE_DIRECTORY}/rlch-cis-1.1.1.6-squashfs.conf}"
RLCH_CIS_1_1_1_6_EFFECTIVE_UID="${RLCH_CIS_1_1_1_6_EFFECTIVE_UID:-${EUID}}"
##
# Check CIS control 1.1.1.6.
##
check() {
    kernel_module_check "${RLCH_CIS_1_1_1_6_MODULE_NAME}"
}

##
# Apply CIS control 1.1.1.6.
##
apply() {
    kernel_module_apply \
        "${RLCH_CIS_1_1_1_6_CONTROL_ID}" \
        "${RLCH_CIS_1_1_1_6_MODULE_NAME}" \
        "${RLCH_CIS_1_1_1_6_MODPROBE_DIRECTORY}" \
        "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}" \
        "${RLCH_CIS_1_1_1_6_EFFECTIVE_UID}"
}

##
# Validate CIS control 1.1.1.6 after remediation.
##
validate() {
    check
}
##
# Roll back the framework-managed configuration.
##
rollback() {
    kernel_module_rollback \
        "${RLCH_CIS_1_1_1_6_CONTROL_ID}" \
        "${RLCH_CIS_1_1_1_6_CONFIGURATION_FILE}" \
        "${RLCH_CIS_1_1_1_6_EFFECTIVE_UID}"
}
