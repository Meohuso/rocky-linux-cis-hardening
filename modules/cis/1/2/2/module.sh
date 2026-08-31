#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.2.2 - Ensure gpgcheck is globally activated.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_2_2_DNF_OPTION="gpgcheck"
readonly RLCH_CIS_1_2_2_DNF_VALUE="1"
RLCH_CIS_1_2_2_DNF_CONFIG="${RLCH_CIS_1_2_2_DNF_CONFIG:-${RLCH_DNF_CONFIG:-/etc/dnf/dnf.conf}}"

check() {
    dnf_main_option_is_enabled \
        "${RLCH_CIS_1_2_2_DNF_OPTION}" \
        "${RLCH_CIS_1_2_2_DNF_CONFIG}"
}

apply() {
    dnf_set_main_option \
        "${RLCH_CIS_1_2_2_DNF_OPTION}" \
        "${RLCH_CIS_1_2_2_DNF_VALUE}" \
        "${RLCH_CIS_1_2_2_DNF_CONFIG}"
}

validate() {
    check
}

rollback() {
    dnf_rollback_config "${RLCH_CIS_1_2_2_DNF_CONFIG}"
}
