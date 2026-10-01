#!/usr/bin/env bash
# CIS 5.4.3.3 - Three independent default-user umask dimensions.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/user_umask.sh
source "${BASH_SOURCE[0]%/*}/../../../../../../lib/user_umask.sh"
RLCH_CIS_5_4_3_3_BASHRC="${RLCH_CIS_5_4_3_3_BASHRC:-/etc/bashrc}"
RLCH_CIS_5_4_3_3_LOGIN_DEFS="${RLCH_CIS_5_4_3_3_LOGIN_DEFS:-/etc/login.defs}"
RLCH_CIS_5_4_3_3_PROFILE="${RLCH_CIS_5_4_3_3_PROFILE:-/etc/profile}"
RLCH_CIS_5_4_3_3_PROFILE_D="${RLCH_CIS_5_4_3_3_PROFILE_D:-/etc/profile.d}"
RLCH_CIS_5_4_3_3_STATE="${RLCH_CIS_5_4_3_3_STATE:-${RLCH_CIS_5_4_3_3_PROFILE_D}/.rlch-5.4.3.3}"
RLCH_CIS_5_4_3_3_ID_COMMAND="${RLCH_CIS_5_4_3_3_ID_COMMAND:-/usr/bin/id}"

rlch_5_4_3_3_dimension() {
    local kind="$1" file rows value recognized mask count=0 finding=0
    shift
    RLCH_UMASK_DIM_ACTIVE=0
    for file in "$@"; do
        rows="$(rlch_umask_scan "$file" "$kind")" || return 2
        while IFS='|' read -r value recognized; do
            [[ -n "$value" ]] || continue
            RLCH_UMASK_DIM_ACTIVE=$((RLCH_UMASK_DIM_ACTIVE + 1))
            [[ "$recognized" -eq 0 ]] || count=$((count + 1))
            mask=$((8#$value))
            if (( (mask & 0027) != 0027 )) || [[ "$recognized" -eq 0 ]]; then finding=1; fi
        done <<< "$rows"
    done
    if [[ "$count" -eq 0 || "$finding" -ne 0 ]]; then
        printf 'CIS 5.4.3.3: %s has a missing or insufficient recognized umask\n' "$kind" >&2
        return 1
    fi
}
rlch_5_4_3_3_check() {
    local before after first=0 second=0 third=0
    RLCH_UMASK_FIXED_OK=0; RLCH_UMASK_ACTIVE=0
    before="$(rlch_umask_fingerprint "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_PROFILE_D")" || return 2
    rlch_umask_inventory "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_PROFILE_D" || return 2
    rlch_5_4_3_3_dimension bashrc "$RLCH_CIS_5_4_3_3_BASHRC" || first=$?
    rlch_5_4_3_3_dimension defs "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" || second=$?
    rlch_5_4_3_3_dimension profile "${RLCH_UMASK_PROFILE_FILES[@]}" || third=$?
    RLCH_UMASK_ACTIVE="$RLCH_UMASK_DIM_ACTIVE"
    if [[ "$first" -eq 0 && "$second" -eq 0 ]]; then RLCH_UMASK_FIXED_OK=1; fi
    after="$(rlch_umask_fingerprint "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_PROFILE_D")" || return 2
    [[ "$before" == "$after" ]] || return 2
    RLCH_UMASK_SNAPSHOT="$after"
    [[ "$first" -ne 2 && "$second" -ne 2 && "$third" -ne 2 ]] || return 2
    [[ "$first" -eq 0 && "$second" -eq 0 && "$third" -eq 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_5_4_3_3_check || result=$?
    if [[ "$result" -eq 2 ]]; then printf 'CIS 5.4.3.3: unsafe input, ambiguous syntax or observed concurrent change; manual review required\n' >&2; fi
    return "$result"
}
rlch_5_4_3_3_apply() {
    local result=0 target state lock_fd current
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    if [[ "$result" -ne 1 || "$RLCH_UMASK_ACTIVE" -ne 0 || "$RLCH_UMASK_FIXED_OK" -ne 1 ]]; then
        printf 'CIS 5.4.3.3: manual remediation required for existing or ambiguous UMASK declarations\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$("$RLCH_CIS_5_4_3_3_ID_COMMAND" -u)" == 0 ]] || return 2
    target="$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; state="$RLCH_CIS_5_4_3_3_STATE"
    [[ -f "$RLCH_CIS_5_4_3_3_PROFILE" && ! -e "$target" && ! -L "$target" ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_5_4_3_3_PROFILE_D" || return 2
    # Keep the private journal on the same filesystem, outside the *.sh set.
    [[ "$state" == "$RLCH_CIS_5_4_3_3_PROFILE_D/"* && "${state##*/}" != *.sh && "${state%/*}" == "$RLCH_CIS_5_4_3_3_PROFILE_D" ]] || return 2
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
    current="$(rlch_umask_fingerprint "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_PROFILE_D")" || current=''
    if [[ "$current" != "$RLCH_UMASK_SNAPSHOT" ]]; then
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    if ! (set -o noclobber; printf '# CIS 5.4.3.3 managed default umask\numask 027\n' > "$state/payload") ||
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
            printf 'CIS 5.4.3.3: restoration failed; retain isolated state for manual recovery\n' >&2
        fi
        exec {lock_fd}<&-
        return 2
    fi
    exec {lock_fd}<&-
    return "$RLCH_MODULE_RESULT_CHANGED"
}
validate() { check; }
rlch_5_4_3_3_rollback() {
    local state="$RLCH_CIS_5_4_3_3_STATE" target="$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" lock_fd result=0
    [[ -e "$state" || -L "$state" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$("$RLCH_CIS_5_4_3_3_ID_COMMAND" -u)" == 0 ]] || return 2
    [[ "${state%/*}" == "$RLCH_CIS_5_4_3_3_PROFILE_D" && "${state##*/}" != *.sh ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_5_4_3_3_PROFILE_D" || return 2
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
    rlch_5_4_3_3_apply || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.3.3: no safe automatic correction completed; review configuration, paths and any retained isolated state\n' >&2
    fi
    return "$result"
}
rollback() {
    local result=0
    rlch_5_4_3_3_rollback || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 5.4.3.3: rollback refused or failed; preserve concurrent changes and review isolated state\n' >&2
    fi
    return "$result"
}
