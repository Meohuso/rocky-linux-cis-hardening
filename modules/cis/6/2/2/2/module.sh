#!/usr/bin/env bash
# CIS 6.2.2.2 - pending CAS mapping; observe explicit forwarding policy only.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_config.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_config.sh"
RLCH_CIS_6_2_2_2_ROOT="${RLCH_CIS_6_2_2_2_ROOT:-/}"
RLCH_CIS_6_2_2_2_ANALYZE="${RLCH_CIS_6_2_2_2_ANALYZE:-/usr/bin/systemd-analyze}"

rlch_6_2_2_2_value() {
    local rows="$1" key origin line value
    # The generic scalar observer emits exactly one requested key.
    [[ "$rows" != *$'\n'* ]] || return 2
    IFS='|' read -r key origin line value <<< "$rows"
    [[ "$key" == ForwardToSyslog ]] || return 2
    [[ -n "$origin" ]] || return 1
    [[ -n "$line" && -n "$value" ]] || return 2
    case "${value,,}" in
        no|n|false|f|off|0) return 0;;
        yes|y|true|t|on|1) return 1;;
        *) return 2;;
    esac
}
rlch_6_2_2_2_observe() {
    local before after rows first_result=0 last_result=0
    before="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_2_ROOT" "$RLCH_CIS_6_2_2_2_ANALYZE" systemd/journald.conf)" || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_2_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$before")" || return 2
    rlch_6_2_2_2_value "$rows" || first_result=$?
    [[ "$first_result" -ne 2 ]] || return 2
    after="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_2_ROOT" "$RLCH_CIS_6_2_2_2_ANALYZE" systemd/journald.conf)" || return 2
    [[ "$before" == "$after" ]] || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_2_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$after")" || return 2
    rlch_6_2_2_2_value "$rows" || last_result=$?
    [[ "$first_result" == "$last_result" ]] || return 2
    return "$first_result"
}
check() {
    local result=0
    rlch_6_2_2_2_observe 2>/dev/null || result=$?
    case "$result" in
        0) printf 'CIS 6.2.2.2: explicit disabled forwarding configuration observed; pending CAS logging-method conflict, loaded daemon state and kernel overrides require manual review\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
        1) printf 'CIS 6.2.2.2: explicit disabled ForwardToSyslog setting absent or forwarding explicitly enabled; configuration deficit\n' >&2; return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *) printf 'CIS 6.2.2.2: unsafe, inaccessible, malformed, unsupported or unstable configuration; manual review required\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    check || :
    printf 'CIS 6.2.2.2: manual remediation required; reconcile the approved journald/syslog collection method and pending CAS conflict, review overrides and effective daemon behavior before configuring disabled forwarding; no configuration or service changes performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No configuration, service, backup, transaction or state mutation.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
