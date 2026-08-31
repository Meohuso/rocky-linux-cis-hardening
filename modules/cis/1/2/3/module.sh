#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.3 - Ensure package manager repositories are configured.
#
# SPDX-License-Identifier: MIT
#

check() {
    dnf_has_enabled_repositories
}

apply() {
    error_message "CIS 1.2.3 requires manual validation of approved package manager repositories."
    error_message "Automatic repository creation or modification is intentionally unsupported."

    return "${RLCH_MODULE_RESULT_ERROR}"
}

validate() {
    check
}

rollback() {
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
