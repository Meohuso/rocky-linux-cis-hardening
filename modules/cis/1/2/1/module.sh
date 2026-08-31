#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.1 - Ensure GPG keys are configured.
#
# SPDX-License-Identifier: MIT
#

check() {
    rpm_has_gpg_keys
}

apply() {
    log_warn "CIS 1.2.1 requires manual validation of trusted RPM GPG keys."
    error_message "Automatic GPG key import is intentionally unsupported."

    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    log_info "CIS 1.2.1 does not modify the system; no rollback action is required."

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
