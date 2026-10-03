#!/usr/bin/env bash
# CIS 6.2.3.3 - unmapped supported CAS entry; observe forwarding configuration only.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_config.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_config.sh"
RLCH_CIS_6_2_3_3_ROOT="${RLCH_CIS_6_2_3_3_ROOT:-/}"
RLCH_CIS_6_2_3_3_ANALYZE="${RLCH_CIS_6_2_3_3_ANALYZE:-/usr/bin/systemd-analyze}"

rlch_6_2_3_3_value() {
    local rows="$1" key origin line value
    # The generic scalar observer emits exactly one requested key.
    [[ "$rows" != *$'\n'* ]] || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r key origin line value <<< "$rows"
    [[ "$key" == ForwardToSyslog ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -n "$origin" ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    [[ -n "$line" && -n "$value" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    case "${value,,}" in
        no|n|false|f|off|0) return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        yes|y|true|t|on|1) return "$RLCH_MODULE_RESULT_SUCCESS";;
        *) return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
rlch_6_2_3_3_observe() {
    local before after rows first_result="$RLCH_MODULE_RESULT_SUCCESS" last_result="$RLCH_MODULE_RESULT_SUCCESS"
    before="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_3_3_ROOT" "$RLCH_CIS_6_2_3_3_ANALYZE" systemd/journald.conf)" || return "$RLCH_MODULE_RESULT_ERROR"
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_3_3_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$before")" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_3_3_value "$rows" || first_result=$?
    [[ "$first_result" -ne "$RLCH_MODULE_RESULT_ERROR" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_3_3_ROOT" "$RLCH_CIS_6_2_3_3_ANALYZE" systemd/journald.conf)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_3_3_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$after")" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_6_2_3_3_value "$rows" || last_result=$?
    [[ "$first_result" == "$last_result" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$first_result"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_6_2_3_3_observe 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") printf 'CIS 6.2.3.3: explicit enabled forwarding configuration observed; loaded daemon state, kernel overrides, namespaces and rsyslog reception require manual review\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 6.2.3.3: explicit enabled ForwardToSyslog setting absent or forwarding explicitly disabled; disk configuration deficit; alternate collection requires manual review\n' >&2; return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *) printf 'CIS 6.2.3.3: unsafe, inaccessible, malformed, unsupported or unstable configuration; manual review required\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    check || :
    printf 'CIS 6.2.3.3: manual remediation required; reconcile the approved logging method with CIS 6.2.2.2, review selected Journal configuration, kernel and namespace overrides, imuxsock/imjournal inputs and rsyslog reception before approved forwarding changes; activation and message side effects have no exact rollback; no configuration or service changes performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No configuration, service, backup, transaction or state mutation.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
