#!/usr/bin/env bash
# CIS 3.3.7 - Ensure reverse path filtering is enabled.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_7_CONFIG="${RLCH_CIS_3_3_7_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.7.conf}"
RLCH_CIS_3_3_7_STATE_DIR="${RLCH_CIS_3_3_7_STATE_DIR:-/var/lib/rlch/cis/3.3.7}"
RLCH_CIS_3_3_7_PARAMETERS=(net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter)
RLCH_CIS_3_3_7_VALUES=(1 1)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_7_CONFIG}" RLCH_CIS_3_3_7_PARAMETERS RLCH_CIS_3_3_7_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_7_CONFIG}" "${RLCH_CIS_3_3_7_STATE_DIR}" RLCH_CIS_3_3_7_PARAMETERS RLCH_CIS_3_3_7_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_7_CONFIG}" "${RLCH_CIS_3_3_7_STATE_DIR}" RLCH_CIS_3_3_7_PARAMETERS
}
