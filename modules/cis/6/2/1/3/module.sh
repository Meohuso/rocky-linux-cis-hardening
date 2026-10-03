#!/usr/bin/env bash
# CIS 6.2.1.3 - no organization-supplied rotation policy exists.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/systemd_config.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/systemd_config.sh"
RLCH_CIS_6_2_1_3_ROOT="${RLCH_CIS_6_2_1_3_ROOT:-/}"
RLCH_CIS_6_2_1_3_ANALYZE="${RLCH_CIS_6_2_1_3_ANALYZE:-/usr/bin/systemd-analyze}"
rlch_6_2_1_3_values() {
    local rows="$1" key origin line value number missing=0
    while IFS='|' read -r key origin line value; do
        if [[ -z "$origin" ]]; then
            printf '%s=implicit-default-not-explicit\n' "$key";missing=1;continue
        fi
        [[ -n "$line" && -n "$value" ]] || return 2
        if [[ "$key" == MaxFileSec ]]; then
            number="$(rlch_sdconf_duration "$RLCH_CIS_6_2_1_3_ANALYZE" "$value")" || return 2
            case "$number" in
                0) printf '%s=0us(time-rotation-disabled)\n' "$key";;
                18446744073709551615) printf '%s=infinity(no-finite-time-limit)\n' "$key";;
                *) printf '%s=%sus\n' "$key" "$number";;
            esac
        else
            number="$(rlch_sdconf_size "$value")" || return 2
            if [[ "$number" == 18446744073709551615 ]]; then
                printf '%s=uint64-default-sentinel(review-installed-version)\n' "$key"
            else printf '%s=%sB(configured-not-runtime-computed)\n' "$key" "$number"; fi
        fi
    done <<< "$rows"
    return "$missing"
}
rlch_6_2_1_3_observe() {
    local before after first last rows result=0 final_result=0
    local names='SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec'
    before="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_1_3_ROOT" "$RLCH_CIS_6_2_1_3_ANALYZE" systemd/journald.conf)" || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_1_3_ROOT" systemd/journald.conf Journal "$names" <<< "$before")" || return 2
    first="$(rlch_6_2_1_3_values "$rows")" || result=$?
    [[ "$result" -ne 2 ]] || return 2
    after="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_1_3_ROOT" "$RLCH_CIS_6_2_1_3_ANALYZE" systemd/journald.conf)" || return 2
    [[ "$before" == "$after" ]] || return 2
    rows="$(rlch_sdconf_scalars "$RLCH_CIS_6_2_1_3_ROOT" systemd/journald.conf Journal "$names" <<< "$after")" || return 2
    last="$(rlch_6_2_1_3_values "$rows")" || final_result=$?
    [[ "$result" == "$final_result" && "$first" == "$last" ]] || return 2
    printf '%s\n' "$first" >&2
    return "$result"
}
check() {
    local result=0
    rlch_6_2_1_3_observe || result=$?
    case "$result" in
        0) printf 'CIS 6.2.1.3: five explicit technically valid settings; no supplied site policy, manual organizational review required\n' >&2;return "$RLCH_MODULE_RESULT_ERROR";;
        1) printf 'CIS 6.2.1.3: expected explicit rotation setting(s) absent; implicit systemd defaults are not explicit site configuration\n' >&2;return "$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        *) printf 'CIS 6.2.1.3: unsafe/inaccessible/unstable or unsupported configuration/value; manual review required\n' >&2;return "$RLCH_MODULE_RESULT_ERROR";;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'CIS 6.2.1.3: manual remediation; supply an approved site rotation policy, inspect selected main/drop-ins and actual installed systemd behavior; no configuration or journal mutation performed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
