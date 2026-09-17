#!/usr/bin/env bash
# CIS 3.3.9 - Ensure suspicious packets are logged.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_9_CONFIG="${RLCH_CIS_3_3_9_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.9.conf}"
RLCH_CIS_3_3_9_STATE_DIR="${RLCH_CIS_3_3_9_STATE_DIR:-/var/lib/rlch/cis/3.3.9}"
RLCH_CIS_3_3_9_PARAMETERS=(net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians)
RLCH_CIS_3_3_9_VALUES=(1 1)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_9_CONFIG}" RLCH_CIS_3_3_9_PARAMETERS RLCH_CIS_3_3_9_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_9_CONFIG}" "${RLCH_CIS_3_3_9_STATE_DIR}" RLCH_CIS_3_3_9_PARAMETERS RLCH_CIS_3_3_9_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_9_CONFIG}" "${RLCH_CIS_3_3_9_STATE_DIR}" RLCH_CIS_3_3_9_PARAMETERS
}
