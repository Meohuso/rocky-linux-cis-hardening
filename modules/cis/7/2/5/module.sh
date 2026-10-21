#!/usr/bin/env bash
# CIS 7.2.5 - Pinned textfilecontent54 captures from /etc/group, not NSS IDs.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_5_GROUP="${RLCH_CIS_7_2_5_GROUP:-/etc/group}"
RLCH_CIS_7_2_5_RPM="${RLCH_CIS_7_2_5_RPM:-/usr/bin/rpm}"

rlch_7_2_5_observe() {
    local applicable=0 after_applicable=0 before after first second
    local row name_field password_field _uid_kind gid total=0 selected=0 distinct=0
    local -A seen=()
    rlch_rpm_package_status "$RLCH_CIS_7_2_5_RPM" kernel-core 2>/dev/null || applicable=$?
    case "$applicable" in
        0) : ;;
        1) return "$RLCH_MODULE_RESULT_NOT_APPLICABLE" ;;
        *) return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_5_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    first="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_5_GROUP" group 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    second="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_5_GROUP" group 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_5_GROUP" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_rpm_package_status "$RLCH_CIS_7_2_5_RPM" kernel-core 2>/dev/null || after_applicable=$?
    [[ "$after_applicable" -eq 0 && -n "$first" && "$first" == "$second" && "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    (( ${#first} <= 6291456 )) || return "$RLCH_MODULE_RESULT_ERROR"
    while IFS= read -r row; do
        total=$((total + 1))
        (( total <= 65536 && ${#row} <= 16480 )) || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$row" =~ ^(EMPTY|PRESENT)\|(EMPTY|PRESENT)\|NA\|(NONE|[0-9]+)$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
        IFS='|' read -r name_field password_field _uid_kind gid <<< "$row"
        # For supported four-field rows, ^.+:.+:(\d+):.*$ selects exactly
        # nonempty first/second fields and an ASCII decimal third field.
        # NONE is a nonmatching field, not a numeric conversion failure.
        if [[ "$name_field" == PRESENT && "$password_field" == PRESENT && "$gid" != NONE ]]; then
            selected=$((selected + 1))
            # Prefix keys and retain every digit: 42 and 0042 are distinct.
            # No numeric bound, arithmetic expansion or GID normalization.
            if [[ -z "${seen[gid:$gid]+present}" ]]; then
                seen["gid:$gid"]=1
                distinct=$((distinct + 1))
            fi
        fi
    done <<< "$first"
    # An empty capture domain is not certified as vacuous conformity. Its
    # scanner collection/variable flags require real OpenSCAP qualification.
    (( selected > 0 )) || return "$RLCH_MODULE_RESULT_ERROR"
    if (( selected != distinct )); then
        printf 'CIS 7.2.5: %s selected local group entries have %s distinct GID captures; identities and GIDs withheld\n' "$selected" "$distinct" >&2
        return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_7_2_5_observe || result=$?
    case "$result" in
        0|1|3) return "$result" ;;
        *) printf 'CIS 7.2.5: cannot reliably evaluate local GID uniqueness; applicability or complete stable supported captures unproven\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.5: manual remediation required; review group access and protected ownership restoration before changing GIDs\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
