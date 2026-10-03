#!/usr/bin/env bash
# CIS 6.2.2.1.4 - pinned CAS socket LoadState masking predicate.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../../lib/systemd_observation.sh"
RLCH_CIS_6_2_2_1_4_SYSTEMCTL="${RLCH_CIS_6_2_2_1_4_SYSTEMCTL:-/usr/bin/systemctl}"

rlch_6_2_2_1_4_check() {
    local before after load row active file
    before="$(rlch_systemd_properties "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" systemd-journal-remote.socket runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_systemd_properties "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" systemd-journal-remote.socket runtime)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" && "${before%%|*}" == systemd-journal-remote.socket ]] || return "$RLCH_MODULE_RESULT_ERROR"
    row="${before#*|}"; load="${row%%|*}"
    row="${row#*|}"; active="${row%%|*}"
    row="${row#*|}"; file="${row%%|*}"
    # Absence handling differs between the OVAL probe and OCIL guidance.
    [[ "$load" != not-found ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$load" == masked ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    # OVAL alone does not ensure inactivity/persistence. Respect the broader
    # OCIL/SCE review rather than certifying these discordant observations.
    [[ "$active" == inactive && "$file" == masked ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_6_2_2_1_4_check 2>/dev/null || result=$?
    case "$result" in
        1) printf 'CIS 6.2.2.1.4: the mapped systemd-journal-remote.socket LoadState is not masked\n' >&2;;
        2) printf 'CIS 6.2.2.1.4: unavailable, ambiguous, unsupported, unstable or discordant socket observation; manual review required\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.2.1.4: manual remediation required; review receiver role and dependencies, then stop and mask the receiver socket through approved change management; interrupted reception and pending connections cannot be exactly restored\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# Observation only: no unit action, configuration, backup, state or transaction.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
