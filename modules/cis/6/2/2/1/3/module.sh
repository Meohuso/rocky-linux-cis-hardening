#!/usr/bin/env bash
# CIS 6.2.2.1.3 - stable journal-upload service enablement and activity.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../../lib/systemd_observation.sh"
RLCH_CIS_6_2_2_1_3_SYSTEMCTL="${RLCH_CIS_6_2_2_1_3_SYSTEMCTL:-/usr/bin/systemctl}"

rlch_6_2_2_1_3_check() {
    local before after id load active file timestamp
    before="$(rlch_systemd_properties "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" systemd-journal-upload.service runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_systemd_properties "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" systemd-journal-upload.service runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r id load active file timestamp <<< "$before"
    # A different primary unit Id is not proof about this exact service.
    [[ "$id" == systemd-journal-upload.service && -n "$timestamp" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$load" == loaded && "$file" == enabled && "$active" == active ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_6_2_2_1_3_check 2>/dev/null || result=$?
    case "$result" in
        1) printf 'CIS 6.2.2.1.3: systemd-journal-upload.service must be persistently enabled and active\n' >&2;;
        2) printf 'CIS 6.2.2.1.3: unavailable, ambiguous, unsupported or unstable system manager observation; manual review required\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.2.1.3: manual remediation required; review approved upload configuration and authentication, then enable and start the service through approved change management; log transfer and service side effects are not exactly reversible\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No service/package/configuration action, transaction, backup or state file.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
