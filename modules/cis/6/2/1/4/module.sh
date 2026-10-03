#!/usr/bin/env bash
# CIS 6.2.1.4 - exactly one active logging service, pinned RHEL9 OVAL.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_observation.sh"
RLCH_CIS_6_2_1_4_SYSTEMCTL="${RLCH_CIS_6_2_1_4_SYSTEMCTL:-/usr/bin/systemctl}"

rlch_6_2_1_4_snapshot() {
    local unit row
    for unit in rsyslog.service systemd-journald.service; do
        row="$(rlch_systemd_properties "$RLCH_CIS_6_2_1_4_SYSTEMCTL" "$unit" runtime)" || return 2
        # The OVAL names two distinct units. An unexpected alias cannot prove
        # that these observations represent two distinct logging services.
        [[ "${row%%|*}" == "$unit" ]] || return 2
        printf '%s\n' "$row"
    done
}
rlch_6_2_1_4_check() {
    local before after row id load active file timestamp count=0
    before="$(rlch_6_2_1_4_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_6_2_1_4_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS= read -r row; do
        IFS='|' read -r id load active file timestamp <<< "$row"
        if [[ "$active" == active ]]; then count=$((count + 1)); fi
    done <<< "$before"
    [[ "$count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_6_2_1_4_check || result=$?
    case "$result" in
        1) printf 'CIS 6.2.1.4: exactly one of rsyslog.service and systemd-journald.service must be active\n' >&2;;
        2) printf 'CIS 6.2.1.4: system manager unavailable, ambiguous properties or observed state change; manual review required\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.1.4: manual architectural decision required; if both are active choose the organization-approved logging system; if neither is active activate the approved logging system; resolve observation errors before changes\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# Observation only: no backup, transaction, state file or runtime mutation.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
