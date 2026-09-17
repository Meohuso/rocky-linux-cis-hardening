#!/usr/bin/env bash
# CIS 3.3.6 - Ensure secure ICMP redirects are not accepted.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_6_CONFIG="${RLCH_CIS_3_3_6_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.6.conf}"
RLCH_CIS_3_3_6_STATE_DIR="${RLCH_CIS_3_3_6_STATE_DIR:-/var/lib/rlch/cis/3.3.6}"
RLCH_CIS_3_3_6_PARAMETERS=(net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects)
RLCH_CIS_3_3_6_VALUES=(0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_6_CONFIG}" RLCH_CIS_3_3_6_PARAMETERS RLCH_CIS_3_3_6_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_6_CONFIG}" "${RLCH_CIS_3_3_6_STATE_DIR}" RLCH_CIS_3_3_6_PARAMETERS RLCH_CIS_3_3_6_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_6_CONFIG}" "${RLCH_CIS_3_3_6_STATE_DIR}" RLCH_CIS_3_3_6_PARAMETERS
}
