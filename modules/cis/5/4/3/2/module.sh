#!/usr/bin/env bash
# CIS 5.4.3.2 - RHEL9 default shell timeout, with create-only remediation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/shell_timeout.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/shell_timeout.sh"
RLCH_CIS_5_4_3_2_PROFILE="${RLCH_CIS_5_4_3_2_PROFILE:-/etc/profile}"
RLCH_CIS_5_4_3_2_PROFILE_D="${RLCH_CIS_5_4_3_2_PROFILE_D:-/etc/profile.d}"
RLCH_CIS_5_4_3_2_STATE="${RLCH_CIS_5_4_3_2_STATE:-${RLCH_CIS_5_4_3_2_PROFILE_D}/.rlch-5.4.3.2}"
RLCH_CIS_5_4_3_2_ID_COMMAND="${RLCH_CIS_5_4_3_2_ID_COMMAND:-/usr/bin/id}"

rlch_5_4_3_2_check() {
    local before after file rows count finding active total=0 failed=0 index=0
    RLCH_TMOUT_ACTIVE=0
    before="$(rlch_tmout_fingerprint "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_PROFILE_D")" || return 2
    rlch_tmout_inventory "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_PROFILE_D" || return 2
    for file in "${RLCH_TMOUT_FILES[@]}"; do
        index=$((index + 1))
        rows="$(rlch_tmout_scan_file "$file" 900)" || return 2
        IFS='|' read -r count finding active <<< "$rows"
        total=$((total + count)); RLCH_TMOUT_ACTIVE=$((RLCH_TMOUT_ACTIVE + active))
        if [[ "$finding" -ne 0 ]]; then
            printf 'CIS 5.4.3.2: configuration file %s has a timeout or attribute violation\n' "$index" >&2
            failed=1
        fi
    done
    after="$(rlch_tmout_fingerprint "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_PROFILE_D")" || return 2
    [[ "$before" == "$after" ]] || return 2
    RLCH_TMOUT_SNAPSHOT="$after"
    if [[ "$total" -eq 0 ]]; then
        printf 'CIS 5.4.3.2: no recognized exported readonly timeout definition\n' >&2
        failed=1
    fi
    [[ "$failed" -eq 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_5_4_3_2_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.3.2: unsafe input, ambiguous TMOUT syntax or concurrent change; manual review required\n' >&2
    fi
    return "$result"
}

rlch_5_4_3_2_apply() {
    local result=0 target state lock_fd current
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    if [[ "$result" -ne 1 || "$RLCH_TMOUT_ACTIVE" -ne 0 ]]; then
        printf 'CIS 5.4.3.2: manual remediation required for existing or ambiguous TMOUT declarations\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$("$RLCH_CIS_5_4_3_2_ID_COMMAND" -u)" == 0 ]] || return 2
    target="$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; state="$RLCH_CIS_5_4_3_2_STATE"
    [[ -f "$RLCH_CIS_5_4_3_2_PROFILE" && ! -e "$target" && ! -L "$target" ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_5_4_3_2_PROFILE_D" || return 2
    # Keep the private journal on the same filesystem, outside the *.sh set.
    [[ "$state" == "$RLCH_CIS_5_4_3_2_PROFILE_D/"* && "${state##*/}" != *.sh && "${state%/*}" == "$RLCH_CIS_5_4_3_2_PROFILE_D" ]] || return 2
    [[ ! -e "$state" && ! -L "$state" ]] || return 2
    (umask 077; /usr/bin/mkdir -- "$state") || return 2
    if ! { exec {lock_fd}<"$state"; } 2>/dev/null; then
        /usr/bin/rmdir -- "$state" || true
        return 2
    fi
    if ! /usr/bin/flock -n -x "$lock_fd"; then
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    current="$(rlch_tmout_fingerprint "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_PROFILE_D")" || current=''
    if [[ "$current" != "$RLCH_TMOUT_SNAPSHOT" ]]; then
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    if ! (set -o noclobber; printf '# CIS 5.4.3.2 managed default timeout\ntypeset -xr TMOUT=900\n' > "$state/payload") ||
       ! /usr/bin/chmod 0644 -- "$state/payload" ||
       ! (set -o noclobber; rlch_tmout_payload_identity "$state/payload" > "$state/identity"); then
        /usr/bin/rm -f -- "$state/payload" "$state/identity"
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    if ! rlch_tmout_link "$state/payload" "$target"; then
        if [[ "$target" -ef "$state/payload" ]]; then
            rlch_tmout_restore_created "$state" "$target" || true
        else
            /usr/bin/rm -f -- "$state/payload" "$state/identity"
            /usr/bin/rmdir -- "$state" || true
        fi
        exec {lock_fd}<&-
        return 2
    fi
    if ! (set -o noclobber; rlch_tmout_file_stamp "$target" > "$state/installed"); then
        /usr/bin/rm -f -- "$state/installed"
        rlch_tmout_restore_created "$state" "$target" || true
        exec {lock_fd}<&-
        return 2
    fi
    if ! validate || ! rlch_tmout_created_matches "$state" "$target"; then
        if ! rlch_tmout_restore_created "$state" "$target"; then
            printf 'CIS 5.4.3.2: restoration failed; retain isolated state for manual recovery\n' >&2
        fi
        exec {lock_fd}<&-
        return 2
    fi
    exec {lock_fd}<&-
    return "$RLCH_MODULE_RESULT_CHANGED"
}
validate() { check; }
rlch_5_4_3_2_rollback() {
    local state="$RLCH_CIS_5_4_3_2_STATE" target="$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" lock_fd result=0
    [[ -e "$state" || -L "$state" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$("$RLCH_CIS_5_4_3_2_ID_COMMAND" -u)" == 0 ]] || return 2
    [[ "${state%/*}" == "$RLCH_CIS_5_4_3_2_PROFILE_D" && "${state##*/}" != *.sh ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_5_4_3_2_PROFILE_D" || return 2
    rlch_tmout_writable_directory "$state" || return 2
    [[ "$(/usr/bin/stat -Lc '%a' -- "$state")" == 700 ]] || return 2
    { exec {lock_fd}<"$state"; } 2>/dev/null || return 2
    if ! /usr/bin/flock -n -x "$lock_fd"; then exec {lock_fd}<&-; return 2; fi
    rlch_tmout_restore_created "$state" "$target" || result=2
    exec {lock_fd}<&-
    [[ "$result" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_CHANGED"
}

apply() {
    local result=0
    rlch_5_4_3_2_apply || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.3.2: no safe automatic correction completed; review configuration, paths and any retained isolated state\n' >&2
    fi
    return "$result"
}
rollback() {
    local result=0
    rlch_5_4_3_2_rollback || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.3.2: rollback refused or failed; preserve concurrent changes and review isolated state\n' >&2
    fi
    return "$result"
}
