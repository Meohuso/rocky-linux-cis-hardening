#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.2 - Ensure ptrace_scope is restricted.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_5_2_PARAMETER="${RLCH_CIS_1_5_2_PARAMETER:-kernel.yama.ptrace_scope}"
RLCH_CIS_1_5_2_VALUE="${RLCH_CIS_1_5_2_VALUE:-1}"
RLCH_CIS_1_5_2_CONFIG="${RLCH_CIS_1_5_2_CONFIG:-${RLCH_SYSCTL_CONFIG_DIR:-/etc/sysctl.d}/60-rlch-ptrace.conf}"

check() {
    sysctl_parameter_is_configured         "${RLCH_CIS_1_5_2_CONFIG}"         "${RLCH_CIS_1_5_2_PARAMETER}"         "${RLCH_CIS_1_5_2_VALUE}"
}

apply() {
    sysctl_set_parameter         "${RLCH_CIS_1_5_2_CONFIG}"         "${RLCH_CIS_1_5_2_PARAMETER}"         "${RLCH_CIS_1_5_2_VALUE}"
}

validate() {
    check
}

rollback() {
    sysctl_rollback_parameter         "${RLCH_CIS_1_5_2_CONFIG}"         "${RLCH_CIS_1_5_2_PARAMETER}"
}
