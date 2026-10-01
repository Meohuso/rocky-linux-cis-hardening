#!/usr/bin/env bash
# CIS 5.4.2.7 - Independent CAS password and shell populations.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/account_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/account_observation.sh"
RLCH_CIS_5_4_2_7_PASSWD="${RLCH_CIS_5_4_2_7_PASSWD:-/etc/passwd}"
RLCH_CIS_5_4_2_7_SHADOW="${RLCH_CIS_5_4_2_7_SHADOW:-/etc/shadow}"
RLCH_CIS_5_4_2_7_LOGIN_DEFS="${RLCH_CIS_5_4_2_7_LOGIN_DEFS:-/etc/login.defs}"

rlch_5_4_2_7_check() {
    local before after accounts locks settings account uid marker shell state key value
    local uid_min=unset sys_min=unset sys_max=unset shell_limit finding=0
    local -A lock_states=() account_names=()
    before="$(rlch_accounts_fingerprint "$RLCH_CIS_5_4_2_7_PASSWD" "$RLCH_CIS_5_4_2_7_SHADOW" "$RLCH_CIS_5_4_2_7_LOGIN_DEFS")" || return 2
    accounts="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_7_PASSWD" passwd)" || return 2
    locks="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_7_SHADOW" shadow)" || return 2
    settings="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_7_LOGIN_DEFS" login_defs)" || return 2
    while IFS='|' read -r key value; do
        case "$key" in
            UID_MIN) uid_min="$value" ;;
            SYS_UID_MIN) sys_min="$value" ;;
            SYS_UID_MAX) sys_max="$value" ;;
        esac
    done <<< "$settings"
    if [[ "$sys_min" == unset && "$sys_max" == unset ]]; then
        [[ "$uid_min" != unset ]] || return 2
        shell_limit="$uid_min"
    elif [[ "$sys_min" != unset && "$sys_max" != unset ]]; then
        (( sys_min <= sys_max )) || return 2
        # Reserved [0,MIN) union dynamic [MIN,MAX) is [0,MAX).
        shell_limit="$sys_max"
    else
        printf 'CIS 5.4.2.7: both SYS_UID_MIN and SYS_UID_MAX must be defined or both absent\n' >&2
        finding=1
        shell_limit=0
    fi
    while IFS='|' read -r account state; do lock_states["$account"]="$state"; done <<< "$locks"
    while IFS='|' read -r account uid marker shell; do
        account_names["$account"]=1
        if (( uid < 1000 )); then
            # CAS create_system_accounts_list_object uses compiled uid_min=1000;
            # it does not read runtime UID_MIN/SYS_UID_* for this sub-rule.
            case "$account" in
                root|halt|sync|shutdown|nfsnobody) ;;
                *)
                    [[ -n "${lock_states[$account]+present}" ]] || return 2
                    if [[ "${lock_states[$account]}" != locked ]]; then
                        printf 'CIS 5.4.2.7: %s password authentication is not locked\n' "$account" >&2
                        finding=1
                    fi
                    ;;
            esac
        fi
        if [[ "$marker" == shadow ]]; then
            [[ -n "${lock_states[$account]+present}" ]] || return 2
        fi
        # Reproduce the RHEL OVAL root-name and allowed-shell prefix filters.
        if [[ "$marker" == shadow && "$account" != root* ]] && (( uid < shell_limit )); then
            case "$shell" in
                /usr/sbin/nologin*|/sbin/nologin*|/bin/sync*|/sbin/shutdown*|/sbin/halt*) ;;
                *) printf 'CIS 5.4.2.7: %s has a disallowed system-account login shell\n' "$account" >&2
                   finding=1 ;;
            esac
        fi
    done <<< "$accounts"
    for account in "${!lock_states[@]}"; do
        [[ -n "${account_names[$account]+present}" ]] || return 2
    done
    after="$(rlch_accounts_fingerprint "$RLCH_CIS_5_4_2_7_PASSWD" "$RLCH_CIS_5_4_2_7_SHADOW" "$RLCH_CIS_5_4_2_7_LOGIN_DEFS")" || return 2
    [[ "$before" == "$after" ]] || return 2
    [[ "$finding" -eq 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_5_4_2_7_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.2.7: cannot safely analyze identity files or UID policy\n' >&2
    fi
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 5.4.2.7: manual remediation required; review reported accounts and service dependencies before changing password locks or login shells\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
