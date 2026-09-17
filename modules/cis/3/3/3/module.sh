#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 3.3.3 - Ensure bogus ICMP responses are ignored.
# SPDX-License-Identifier: MIT
#

# shellcheck disable=SC2034 # Policy arrays are consumed through helper namerefs.

RLCH_CIS_3_3_3_CONFIG="${RLCH_CIS_3_3_3_CONFIG:-/etc/sysctl.d/60-rlch-cis-3.3.3.conf}"
RLCH_CIS_3_3_3_STATE_DIR="${RLCH_CIS_3_3_3_STATE_DIR:-/var/lib/rlch/cis/3.3.3}"
RLCH_CIS_3_3_3_PARAMETERS=(net.ipv4.icmp_ignore_bogus_error_responses)
RLCH_CIS_3_3_3_VALUES=(1)

check() {
    sysctl_control_check "${RLCH_CIS_3_3_3_CONFIG}" RLCH_CIS_3_3_3_PARAMETERS RLCH_CIS_3_3_3_VALUES
}

apply() {
    sysctl_control_apply "${RLCH_CIS_3_3_3_CONFIG}" "${RLCH_CIS_3_3_3_STATE_DIR}" RLCH_CIS_3_3_3_PARAMETERS RLCH_CIS_3_3_3_VALUES
}

validate() {
    check
}

rollback() {
    sysctl_control_rollback "${RLCH_CIS_3_3_3_CONFIG}" "${RLCH_CIS_3_3_3_STATE_DIR}" RLCH_CIS_3_3_3_PARAMETERS
}
