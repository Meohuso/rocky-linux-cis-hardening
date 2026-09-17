#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.3.2 - Ensure packet redirect sending is disabled.
# SPDX-License-Identifier: MIT
#

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.

RLCH_CIS_3_3_2_CONFIG="${RLCH_CIS_3_3_2_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.2.conf}"
RLCH_CIS_3_3_2_STATE_DIR="${RLCH_CIS_3_3_2_STATE_DIR:-/var/lib/rlch/cis/3.3.2}"
RLCH_CIS_3_3_2_PARAMETERS=(
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.default.send_redirects
)
RLCH_CIS_3_3_2_VALUES=(0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_2_CONFIG}" RLCH_CIS_3_3_2_PARAMETERS RLCH_CIS_3_3_2_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_2_CONFIG}" "${RLCH_CIS_3_3_2_STATE_DIR}" RLCH_CIS_3_3_2_PARAMETERS RLCH_CIS_3_3_2_VALUES
}

validate() {
    check
}

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_2_CONFIG}" "${RLCH_CIS_3_3_2_STATE_DIR}" RLCH_CIS_3_3_2_PARAMETERS
}
