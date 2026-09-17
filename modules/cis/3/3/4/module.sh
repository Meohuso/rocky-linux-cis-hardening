#!/usr/bin/env bash
# CIS 3.3.4 - Ensure broadcast ICMP requests are ignored.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_4_CONFIG="${RLCH_CIS_3_3_4_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.4.conf}"
RLCH_CIS_3_3_4_STATE_DIR="${RLCH_CIS_3_3_4_STATE_DIR:-/var/lib/rlch/cis/3.3.4}"
RLCH_CIS_3_3_4_PARAMETERS=(net.ipv4.icmp_echo_ignore_broadcasts)
RLCH_CIS_3_3_4_VALUES=(1)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_4_CONFIG}" RLCH_CIS_3_3_4_PARAMETERS RLCH_CIS_3_3_4_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_4_CONFIG}" "${RLCH_CIS_3_3_4_STATE_DIR}" RLCH_CIS_3_3_4_PARAMETERS RLCH_CIS_3_3_4_VALUES
}

validate() {
    check
}

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_4_CONFIG}" "${RLCH_CIS_3_3_4_STATE_DIR}" RLCH_CIS_3_3_4_PARAMETERS
}
