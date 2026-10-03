#!/usr/bin/env bash
# CIS 6.2.2.1.1 - exact RPM-name existence, pinned RHEL9 package template.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../../lib/rpm_observation.sh"
RLCH_CIS_6_2_2_1_1_RPM="${RLCH_CIS_6_2_2_1_1_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"

check() {
    local result=0
    rlch_rpm_package_status "$RLCH_CIS_6_2_2_1_1_RPM" systemd-journal-remote || result=$?
    case "$result" in
        1) printf 'CIS 6.2.2.1.1: the exact systemd-journal-remote RPM package is absent\n' >&2;;
        2) printf 'CIS 6.2.2.1.1: RPM unavailable, unsafe inventory or concurrent package change; manual review required\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.2.1.1: manual remediation required; install systemd-journal-remote through approved package management after repository, dependency and change-policy review; exact transaction rollback is not guaranteed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No installation, removal, transaction, backup or persistent state is created.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
