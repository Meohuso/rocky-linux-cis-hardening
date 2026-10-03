#!/usr/bin/env bash
# CIS 6.2.3.1 - exact RPM-name installation observation; no official CAS rule.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/rpm_observation.sh"
RLCH_CIS_6_2_3_1_RPM="${RLCH_CIS_6_2_3_1_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"

check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_rpm_package_status "$RLCH_CIS_6_2_3_1_RPM" rsyslog || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") return "$RLCH_MODULE_RESULT_SUCCESS";;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT")
            printf 'CIS 6.2.3.1: the exact rsyslog RPM package is absent\n' >&2
            return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *)
            printf 'CIS 6.2.3.1: RPM unavailable, unsafe inventory or concurrent package change; manual review required\n' >&2
            return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.3.1: manual remediation required; install rsyslog through approved package management after repository, dependency, scriptlet and logging-architecture review; exact transaction rollback is not guaranteed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No installation, removal, service action, backup or persistent state.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
