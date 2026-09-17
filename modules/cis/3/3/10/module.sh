#!/usr/bin/env bash
# CIS 3.3.10 - Ensure TCP SYN cookies are enabled.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_10_CONFIG="${RLCH_CIS_3_3_10_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.10.conf}"
RLCH_CIS_3_3_10_STATE_DIR="${RLCH_CIS_3_3_10_STATE_DIR:-/var/lib/rlch/cis/3.3.10}"
RLCH_CIS_3_3_10_PARAMETERS=(net.ipv4.tcp_syncookies)
RLCH_CIS_3_3_10_VALUES=(1)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_10_CONFIG}" RLCH_CIS_3_3_10_PARAMETERS RLCH_CIS_3_3_10_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_10_CONFIG}" "${RLCH_CIS_3_3_10_STATE_DIR}" RLCH_CIS_3_3_10_PARAMETERS RLCH_CIS_3_3_10_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_10_CONFIG}" "${RLCH_CIS_3_3_10_STATE_DIR}" RLCH_CIS_3_3_10_PARAMETERS
}
