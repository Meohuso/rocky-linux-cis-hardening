#!/usr/bin/env bash
# CIS 5.4.2.8 - Literal RHEL CAS invalid-shell/lock observation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/account_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/account_observation.sh"
RLCH_CIS_5_4_2_8_PASSWD="${RLCH_CIS_5_4_2_8_PASSWD:-/etc/passwd}"
RLCH_CIS_5_4_2_8_SHADOW="${RLCH_CIS_5_4_2_8_SHADOW:-/etc/shadow}"
RLCH_CIS_5_4_2_8_SHELLS="${RLCH_CIS_5_4_2_8_SHELLS:-/etc/shells}"

rlch_5_4_2_8_check() {
    local before after accounts locks shells account uid marker shell state finding=0
    local -A lock_states=() account_names=() valid_shells=()
    before="$(rlch_accounts_fingerprint "$RLCH_CIS_5_4_2_8_PASSWD" "$RLCH_CIS_5_4_2_8_SHADOW" "$RLCH_CIS_5_4_2_8_SHELLS")" || return 2
    accounts="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_8_PASSWD" passwd)" || return 2
    locks="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_8_SHADOW" shadow_shells)" || return 2
    shells="$(rlch_accounts_rows "$RLCH_CIS_5_4_2_8_SHELLS" shells)" || return 2
    while IFS='|' read -r account state; do lock_states["$account"]="$state"; done <<< "$locks"
    # The upstream nologin state targets the collected pattern entity rather
    # than text. Its fixed slash-line collector pattern has no word nologin;
    # follow literal OVAL entity semantics instead of silently fixing the filter.
    while IFS= read -r shell; do valid_shells["$shell"]=1; done <<< "$shells"
    while IFS='|' read -r account uid marker shell; do
        account_names["$account"]=1
        if [[ "$marker" == shadow ]]; then
            [[ -n "${lock_states[$account]+present}" ]] || return 2
        fi
        case "$account" in root|nobody|nfsnobody) continue ;; esac
        # The local-interactive-users OVAL already excludes these prefixes.
        case "$shell" in /sbin/nologin*|/usr/sbin/nologin*|/bin/false*|/usr/bin/false*) continue ;; esac
        # The later passwd shell capture requires a nonempty shell.
        [[ -n "$shell" ]] || continue
        [[ -n "${lock_states[$account]+present}" ]] || return 2
        [[ "${lock_states[$account]}" != locked ]] || continue
        if [[ -z "${valid_shells[$shell]+present}" ]]; then
            printf 'CIS 5.4.2.8: %s has an unlisted login shell and is not locked by the CAS motif\n' "$account" >&2
            finding=1
        fi
    done <<< "$accounts"
    for account in "${!lock_states[@]}"; do
        [[ -n "${account_names[$account]+present}" ]] || return 2
    done
    after="$(rlch_accounts_fingerprint "$RLCH_CIS_5_4_2_8_PASSWD" "$RLCH_CIS_5_4_2_8_SHADOW" "$RLCH_CIS_5_4_2_8_SHELLS")" || return 2
    [[ "$before" == "$after" ]] || return 2
    [[ "$finding" -eq 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_5_4_2_8_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.2.8: cannot safely analyze identity files or the shell list\n' >&2
    fi
    return "$result"
}
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 5.4.2.8: manual remediation required; review reported accounts and dependencies before locking accounts or changing their login shell\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
