#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.3.1 - Ensure IP forwarding is disabled.
# SPDX-License-Identifier: MIT
#

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.

RLCH_CIS_3_3_1_CONFIG="${RLCH_CIS_3_3_1_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.1.conf}"
RLCH_CIS_3_3_1_STATE_DIR="${RLCH_CIS_3_3_1_STATE_DIR:-/var/lib/rlch/cis/3.3.1}"
RLCH_CIS_3_3_1_PARAMETERS=(
    net.ipv4.ip_forward
    net.ipv6.conf.all.forwarding
)
RLCH_CIS_3_3_1_VALUES=(0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_1_CONFIG}" RLCH_CIS_3_3_1_PARAMETERS RLCH_CIS_3_3_1_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_1_CONFIG}" "${RLCH_CIS_3_3_1_STATE_DIR}" RLCH_CIS_3_3_1_PARAMETERS RLCH_CIS_3_3_1_VALUES
}

validate() {
    check
}

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_1_CONFIG}" "${RLCH_CIS_3_3_1_STATE_DIR}" RLCH_CIS_3_3_1_PARAMETERS
}
