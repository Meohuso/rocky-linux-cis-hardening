#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.3.2 - Ensure filesystem integrity is regularly checked.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_3_2_CRONTAB="${RLCH_CIS_1_3_2_CRONTAB:-/etc/crontab}"
readonly RLCH_CIS_1_3_2_CRON_ENTRY="05 4 * * 0 root /usr/sbin/aide --check"
readonly RLCH_CIS_1_3_2_CRON_PATTERN='^[[:space:]]*[^#].*[[:space:]]/usr/sbin/aide[[:space:]]+--check([[:space:]]|$)'

check() {
    if ! rpm_package_is_installed "aide"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    cron_file_has_entry \
        "${RLCH_CIS_1_3_2_CRONTAB}" \
        "${RLCH_CIS_1_3_2_CRON_ENTRY}"
}

apply() {
    if ! rpm_package_is_installed "aide"; then
        error_message "AIDE must be installed before configuring periodic integrity checks."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cron_ensure_entry \
        "${RLCH_CIS_1_3_2_CRONTAB}" \
        "${RLCH_CIS_1_3_2_CRON_ENTRY}" \
        "${RLCH_CIS_1_3_2_CRON_PATTERN}"
}

validate() {
    check
}

rollback() {
    cron_rollback_file "${RLCH_CIS_1_3_2_CRONTAB}"
}
