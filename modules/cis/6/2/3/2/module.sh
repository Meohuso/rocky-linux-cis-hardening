#!/usr/bin/env bash
# CIS 6.2.3.2 - stable rsyslog service enablement and activity.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_observation.sh"
RLCH_CIS_6_2_3_2_SYSTEMCTL="${RLCH_CIS_6_2_3_2_SYSTEMCTL:-/usr/bin/systemctl}"

rlch_6_2_3_2_check() {
    local before after id load active file timestamp
    before="$(rlch_systemd_properties "$RLCH_CIS_6_2_3_2_SYSTEMCTL" rsyslog.service runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_systemd_properties "$RLCH_CIS_6_2_3_2_SYSTEMCTL" rsyslog.service runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r id load active file timestamp <<< "$before"
    # A different primary unit Id is not proof about this exact service.
    [[ "$id" == rsyslog.service && -n "$timestamp" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$load" == loaded && "$file" == enabled && "$active" == active ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_6_2_3_2_check 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 6.2.3.2: rsyslog.service must be persistently enabled and active\n' >&2;;
        "$RLCH_MODULE_RESULT_ERROR") printf 'CIS 6.2.3.2: unavailable, ambiguous, unsupported or unstable system manager observation; manual review required\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.3.2: manual remediation required; review the approved logging architecture, rsyslog configuration, journald coexistence, dependencies and SELinux, then enable and start rsyslog through approved change management; processed records, queues and service side effects cannot be exactly rolled back\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No service/package/configuration action, transaction, backup or state file.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
