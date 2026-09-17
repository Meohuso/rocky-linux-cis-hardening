#!/usr/bin/env bash
# CIS 3.3.8 - Ensure source routed packets are not accepted.
# SPDX-License-Identifier: MIT

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.
RLCH_CIS_3_3_8_CONFIG="${RLCH_CIS_3_3_8_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.8.conf}"
RLCH_CIS_3_3_8_STATE_DIR="${RLCH_CIS_3_3_8_STATE_DIR:-/var/lib/rlch/cis/3.3.8}"
RLCH_CIS_3_3_8_PARAMETERS=(
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.default.accept_source_route
    net.ipv6.conf.all.accept_source_route
    net.ipv6.conf.default.accept_source_route
)
RLCH_CIS_3_3_8_VALUES=(0 0 0 0)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_8_CONFIG}" RLCH_CIS_3_3_8_PARAMETERS RLCH_CIS_3_3_8_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_8_CONFIG}" "${RLCH_CIS_3_3_8_STATE_DIR}" RLCH_CIS_3_3_8_PARAMETERS RLCH_CIS_3_3_8_VALUES
}

validate() { check; }

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_8_CONFIG}" "${RLCH_CIS_3_3_8_STATE_DIR}" RLCH_CIS_3_3_8_PARAMETERS
}
