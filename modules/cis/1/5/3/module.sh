#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.3 - Ensure core dump backtraces are disabled.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_5_3_CONFIG="${RLCH_CIS_1_5_3_CONFIG:-${RLCH_COREDUMP_CONFIG_DIR:-/etc/systemd/coredump.conf.d}/60-rlch-coredump.conf}"
RLCH_CIS_1_5_3_OPTION="${RLCH_CIS_1_5_3_OPTION:-ProcessSizeMax}"
RLCH_CIS_1_5_3_VALUE="${RLCH_CIS_1_5_3_VALUE:-0}"

check() {
    coredump_option_is_configured \
        "${RLCH_CIS_1_5_3_CONFIG}" \
        "${RLCH_CIS_1_5_3_OPTION}" \
        "${RLCH_CIS_1_5_3_VALUE}"
}

apply() {
    coredump_set_option \
        "${RLCH_CIS_1_5_3_CONFIG}" \
        "${RLCH_CIS_1_5_3_OPTION}" \
        "${RLCH_CIS_1_5_3_VALUE}"
}

validate() {
    check
}

rollback() {
    coredump_rollback_config "${RLCH_CIS_1_5_3_CONFIG}"
}
