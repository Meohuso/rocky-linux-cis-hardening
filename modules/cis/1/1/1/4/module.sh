#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.1.4 - Ensure hfsplus kernel module is not available.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_1_4_MODULE_NAME="hfsplus"
readonly RLCH_CIS_1_1_1_4_CONTROL_ID="1.1.1.4"
RLCH_CIS_1_1_1_4_MODPROBE_DIRECTORY="${RLCH_CIS_1_1_1_4_MODPROBE_DIRECTORY:-/etc/modprobe.d}"
RLCH_CIS_1_1_1_4_CONFIGURATION_FILE="${RLCH_CIS_1_1_1_4_CONFIGURATION_FILE:-${RLCH_CIS_1_1_1_4_MODPROBE_DIRECTORY}/rlch-cis-1.1.1.4-hfsplus.conf}"
RLCH_CIS_1_1_1_4_EFFECTIVE_UID="${RLCH_CIS_1_1_1_4_EFFECTIVE_UID:-${EUID}}"
##
# Check CIS control 1.1.1.4.
##
check() {
    kernel_module_check "${RLCH_CIS_1_1_1_4_MODULE_NAME}"
}

##
# Apply CIS control 1.1.1.4.
##
apply() {
    kernel_module_apply \
        "${RLCH_CIS_1_1_1_4_CONTROL_ID}" \
        "${RLCH_CIS_1_1_1_4_MODULE_NAME}" \
        "${RLCH_CIS_1_1_1_4_MODPROBE_DIRECTORY}" \
        "${RLCH_CIS_1_1_1_4_CONFIGURATION_FILE}" \
        "${RLCH_CIS_1_1_1_4_EFFECTIVE_UID}"
}

##
# Validate CIS control 1.1.1.4 after remediation.
##
validate() {
    check
}
##
# Roll back the framework-managed configuration.
##
rollback() {
    kernel_module_rollback \
        "${RLCH_CIS_1_1_1_4_CONTROL_ID}" \
        "${RLCH_CIS_1_1_1_4_CONFIGURATION_FILE}" \
        "${RLCH_CIS_1_1_1_4_EFFECTIVE_UID}"
}
