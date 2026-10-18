#!/usr/bin/env bash
# CIS 7.2.3 - Pinned local textfilecontent54 string captures, not numeric NSS IDs.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
RLCH_CIS_7_2_3_PASSWD="${RLCH_CIS_7_2_3_PASSWD:-/etc/passwd}"
RLCH_CIS_7_2_3_GROUP="${RLCH_CIS_7_2_3_GROUP:-/etc/group}"

rlch_7_2_3_observe() {
    local before_p before_g after_p after_g first_p first_g second_p second_g
    local row name_field password_field uid_kind gid total=0 selected=0 group_count=0 missing=0
    local -A group_gids=()
    before_p="$(rlch_identity_stamp "$RLCH_CIS_7_2_3_PASSWD" 2>/dev/null)" || return 2
    before_g="$(rlch_identity_stamp "$RLCH_CIS_7_2_3_GROUP" 2>/dev/null)" || return 2
    first_p="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_3_PASSWD" passwd 2>/dev/null)" || return 2
    first_g="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_3_GROUP" group 2>/dev/null)" || return 2
    second_p="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_3_PASSWD" passwd 2>/dev/null)" || return 2
    second_g="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_3_GROUP" group 2>/dev/null)" || return 2
    after_p="$(rlch_identity_stamp "$RLCH_CIS_7_2_3_PASSWD" 2>/dev/null)" || return 2
    after_g="$(rlch_identity_stamp "$RLCH_CIS_7_2_3_GROUP" 2>/dev/null)" || return 2
    [[ -n "$first_p" && -n "$first_g" && "$first_p" == "$second_p" && "$first_g" == "$second_g" &&
       "$before_p" == "$after_p" && "$before_g" == "$after_g" ]] || return 2
    # Bound defensive decoding as well as the underlying reader's input size.
    (( ${#first_p} <= 6291456 && ${#first_g} <= 6291456 )) || return 2
    while IFS= read -r row; do
        total=$((total + 1)); (( total <= 65536 && ${#row} <= 16480 )) || return 2
        [[ "$row" =~ ^(EMPTY|PRESENT)\|(EMPTY|PRESENT)\|NA\|(NONE|[0-9]+)$ ]] || return 2
        IFS='|' read -r name_field password_field uid_kind gid <<< "$row"
        if [[ "$name_field" == PRESENT && "$password_field" == PRESENT && "$gid" != NONE ]]; then
            # Prefix avoids numeric interpretation; no arithmetic expansion or
            # normalization of the captured spelling, including leading zeros.
            group_gids["gid:$gid"]=1; group_count=$((group_count + 1))
        fi
    done <<< "$first_g"
    total=0
    while IFS= read -r row; do
        total=$((total + 1)); (( total <= 65536 && ${#row} <= 16480 )) || return 2
        [[ "$row" =~ ^(EMPTY|PRESENT)\|(EMPTY|PRESENT)\|(DECIMAL|OTHER)\|(NONE|[0-9]+)$ ]] || return 2
        IFS='|' read -r name_field password_field uid_kind gid <<< "$row"
        if [[ "$name_field" == PRESENT && "$password_field" == PRESENT && "$uid_kind" == DECIMAL && "$gid" != NONE ]]; then
            selected=$((selected + 1))
            [[ -n "${group_gids[gid:$gid]+present}" ]] || missing=$((missing + 1))
        fi
    done <<< "$first_p"
    if (( selected == 0 )); then
        printf 'CIS 7.2.3: no local passwd entry satisfies the pinned capture; all_exist is not satisfied\n' >&2
        return 1
    fi
    # OVAL state var_ref cannot be evaluated when the group variable has no
    # values. Do not silently turn that missing state evidence into a finding.
    (( group_count > 0 )) || return 2
    if (( missing > 0 )); then
        printf 'CIS 7.2.3: %s of %s selected local primary group references have no exact group capture; identities and GIDs withheld\n' "$missing" "$selected" >&2
        return 1
    fi
    return 0
}
check() {
    local result=0
    rlch_7_2_3_observe || result=$?
    case "$result" in
        0|1) return "$result" ;;
        *) printf 'CIS 7.2.3: cannot reliably evaluate both local identity files; evidence invalid, incomplete, unstable or unavailable\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 7.2.3: manual remediation required; review identity policy and protected restoration before changing group references\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
