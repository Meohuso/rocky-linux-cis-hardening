#!/usr/bin/env bash
# CIS 6.2.2.4 - explicit persistent storage configuration, mapped pinned journald_storage rule.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_config.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_config.sh"
RLCH_CIS_6_2_2_4_ROOT="${RLCH_CIS_6_2_2_4_ROOT:-/}"
RLCH_CIS_6_2_2_4_ANALYZE="${RLCH_CIS_6_2_2_4_ANALYZE:-/usr/bin/systemd-analyze}"

rlch_6_2_2_4_value() {
    local rows="$1" key origin line value
    # The generic scalar observer emits exactly one requested key.
    [[ "$rows" != *$'\n'* ]] || return 2
    IFS='|' read -r key origin line value <<< "$rows"
    [[ "$key" == Storage ]] || return 2
    [[ -n "$origin" ]] || return 1
    [[ -n "$line" && -n "$value" ]] || return 2
    [[ "$value" != persistent ]] || return 0
    case "$value" in
        auto|volatile|none) return 1;;
        *) return 2;;
    esac
}
rlch_6_2_2_4_observe() {
    local before after rows first_result=0 last_result=0
    before="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_4_ROOT" "$RLCH_CIS_6_2_2_4_ANALYZE" systemd/journald.conf)" || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_4_ROOT" systemd/journald.conf Journal Storage <<< "$before")" || return 2
    rlch_6_2_2_4_value "$rows" || first_result=$?
    [[ "$first_result" -ne 2 ]] || return 2
    after="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_4_ROOT" "$RLCH_CIS_6_2_2_4_ANALYZE" systemd/journald.conf)" || return 2
    [[ "$before" == "$after" ]] || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_2_4_ROOT" systemd/journald.conf Journal Storage <<< "$after")" || return 2
    rlch_6_2_2_4_value "$rows" || last_result=$?
    [[ "$first_result" == "$last_result" ]] || return 2
    return "$first_result"
}
check() {
    local result=0
    rlch_6_2_2_4_observe 2>/dev/null || result=$?
    case "$result" in
        0) return "$RLCH_MODULE_RESULT_SUCCESS";;
        1) printf 'CIS 6.2.2.4: explicit Storage=persistent absent or storage not persistent; configuration deficit\n' >&2; return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *) printf 'CIS 6.2.2.4: unsafe, inaccessible, malformed, unsupported, discordant or unstable storage configuration; manual review required\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.2.4: manual remediation required; review selected Journal configuration and installed systemd storage, writable disk, flush and loaded-daemon behavior before setting unquoted Storage=persistent through approved change management; no configuration, service or journal changes performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No configuration, service, backup, transaction or state mutation.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
