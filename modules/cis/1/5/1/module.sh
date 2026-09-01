#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.1 - Ensure address space layout randomization is enabled.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_5_1_PARAMETER="${RLCH_CIS_1_5_1_PARAMETER:-kernel.randomize_va_space}"
RLCH_CIS_1_5_1_VALUE="${RLCH_CIS_1_5_1_VALUE:-2}"
RLCH_CIS_1_5_1_CONFIG="${RLCH_CIS_1_5_1_CONFIG:-${RLCH_SYSCTL_CONFIG_DIR:-/etc/sysctl.d}/60-rlch-aslr.conf}"

check() {
    sysctl_parameter_is_configured \
        "${RLCH_CIS_1_5_1_CONFIG}" \
        "${RLCH_CIS_1_5_1_PARAMETER}" \
        "${RLCH_CIS_1_5_1_VALUE}"
}

apply() {
    sysctl_set_parameter \
        "${RLCH_CIS_1_5_1_CONFIG}" \
        "${RLCH_CIS_1_5_1_PARAMETER}" \
        "${RLCH_CIS_1_5_1_VALUE}"
}

validate() {
    check
}

rollback() {
    sysctl_rollback_parameter \
        "${RLCH_CIS_1_5_1_CONFIG}" \
        "${RLCH_CIS_1_5_1_PARAMETER}"
}
