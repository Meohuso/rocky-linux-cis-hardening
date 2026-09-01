#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.4.1 - Ensure bootloader password is set.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_4_1_USER_CONFIG="${RLCH_CIS_1_4_1_USER_CONFIG:-${RLCH_GRUB_USER_CONFIG:-/boot/grub2/user.cfg}}"

check() {
    grub_password_is_configured "${RLCH_CIS_1_4_1_USER_CONFIG}"
}

apply() {
    error_message "CIS 1.4.1 requires a site-specific GRUB2 bootloader password."
    error_message "Automatic bootloader password generation or storage is intentionally unsupported."
    error_message "Configure the password securely with grub2-setpassword, then run validation again."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
