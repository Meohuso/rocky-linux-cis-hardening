#!/usr/bin/env bash
# CIS 3.3.11 - Ensure IPv6 router advertisements are not accepted.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_11_CONFIG="${RLCH_CIS_3_3_11_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.11.conf}"
RLCH_CIS_3_3_11_STATE_DIR="${RLCH_CIS_3_3_11_STATE_DIR:-/var/lib/rlch/cis/3.3.11}"
RLCH_CIS_3_3_11_PARAMETERS=(net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra)
RLCH_CIS_3_3_11_VALUES=(0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_11_CONFIG}" RLCH_CIS_3_3_11_PARAMETERS RLCH_CIS_3_3_11_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_11_CONFIG}" "${RLCH_CIS_3_3_11_STATE_DIR}" RLCH_CIS_3_3_11_PARAMETERS RLCH_CIS_3_3_11_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_11_CONFIG}" "${RLCH_CIS_3_3_11_STATE_DIR}" RLCH_CIS_3_3_11_PARAMETERS
}
