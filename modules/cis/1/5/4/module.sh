#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.5.4 - Ensure core dump storage is disabled.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_5_4_CONFIG="${RLCH_CIS_1_5_4_CONFIG:-${RLCH_COREDUMP_CONFIG_DIR:-/etc/systemd/coredump.conf.d}/60-rlch-coredump-storage.conf}"
RLCH_CIS_1_5_4_OPTION="${RLCH_CIS_1_5_4_OPTION:-Storage}"
RLCH_CIS_1_5_4_VALUE="${RLCH_CIS_1_5_4_VALUE:-none}"

check() {
    coredump_option_is_configured \
        "${RLCH_CIS_1_5_4_CONFIG}" \
        "${RLCH_CIS_1_5_4_OPTION}" \
        "${RLCH_CIS_1_5_4_VALUE}"
}

apply() {
    coredump_set_option \
        "${RLCH_CIS_1_5_4_CONFIG}" \
        "${RLCH_CIS_1_5_4_OPTION}" \
        "${RLCH_CIS_1_5_4_VALUE}"
}

validate() {
    check
}

rollback() {
    coredump_rollback_config "${RLCH_CIS_1_5_4_CONFIG}"
}
