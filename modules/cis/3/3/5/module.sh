#!/usr/bin/env bash
# CIS 3.3.5 - Ensure ICMP redirects are not accepted.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_5_CONFIG="${RLCH_CIS_3_3_5_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.5.conf}"
RLCH_CIS_3_3_5_STATE_DIR="${RLCH_CIS_3_3_5_STATE_DIR:-/var/lib/rlch/cis/3.3.5}"
RLCH_CIS_3_3_5_PARAMETERS=(
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.default.accept_redirects
)
RLCH_CIS_3_3_5_VALUES=(0 0 0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_5_CONFIG}" RLCH_CIS_3_3_5_PARAMETERS RLCH_CIS_3_3_5_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_5_CONFIG}" "${RLCH_CIS_3_3_5_STATE_DIR}" RLCH_CIS_3_3_5_PARAMETERS RLCH_CIS_3_3_5_VALUES
}

validate() {
    check
}

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_5_CONFIG}" "${RLCH_CIS_3_3_5_STATE_DIR}" RLCH_CIS_3_3_5_PARAMETERS
}
