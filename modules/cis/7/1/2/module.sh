#!/usr/bin/env bash
# CIS 7.1.2 - optional /etc/passwd- attributes, no content or mutation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/journal_access.sh"
RLCH_CIS_7_1_2_ROOT="${RLCH_CIS_7_1_2_ROOT:-/}"

# Private stat boundary: no dereference, NSS, content read or atime update.
rlch_7_1_2_stat() {
    LC_ALL=C /usr/bin/stat -c '%d|%i|%h|%u|%g|%a|%f|%z' -- "$1"
}
rlch_7_1_2_evidence() (
    local file="$1" type="$2" stamp dev inode links uid gid mode raw ctime
    set -o pipefail
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    # Check output before Bash substitution so a NUL cannot disappear unnoticed.
    stamp="$(rlch_7_1_2_stat "$file" | LC_ALL=C /usr/bin/awk -v error="$RLCH_MODULE_RESULT_ERROR" '
        {bytes+=length($0)+1
         if(NR>1 || bytes>1024 || index($0,sprintf("%c",0)) || $0 ~ /[[:cntrl:]]/) exit error
         print}
        END {if(NR!=1) exit error}
    ')" || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r dev inode links uid gid mode raw ctime <<< "$stamp"
    [[ "$dev" =~ ^(0|[1-9][0-9]{0,19})$ && "$inode" =~ ^[1-9][0-9]{0,19}$ && "$links" =~ ^[1-9][0-9]{0,19}$ &&
       "$uid" =~ ^(0|[1-9][0-9]{0,9})$ && "$gid" =~ ^(0|[1-9][0-9]{0,9})$ &&
       "$mode" =~ ^[0-7]{1,4}$ && "$raw" =~ ^[0-9a-f]{1,8}$ &&
       "$ctime" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}\ [+-][0-9]{4}$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    (( uid<=4294967294 && gid<=4294967294 && (16#$raw & 0170000) == type &&
       (16#$raw & 07777) == 8#$mode )) || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$type" == 0100000 ]]; then
        [[ "$links" == 1 && -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    else
        [[ -d "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$stamp"
)
# Missing backup is allowed by CAS, but false -e alone also hides EACCES.
# Require a real observable /etc and stable parent identity/metadata. Never
# traverse unrelated account files, create a backup, or print its contents.
rlch_7_1_2_snapshot() (
    local file="${RLCH_CIS_7_1_2_ROOT%/}/etc/passwd-" parent before after stamp
    local -a matches=()
    parent="${file%/*}"
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$file" || -L "$file" ]]; then
        [[ -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        stamp="$(rlch_7_1_2_evidence "$file" 0100000)" || return "$RLCH_MODULE_RESULT_ERROR"
        printf 'present:%s\n' "$stamp"
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    rlch_tmout_directory "$parent" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    before="$(rlch_7_1_2_evidence "$parent" 0040000)" || return "$RLCH_MODULE_RESULT_ERROR"
    # Glob only the exact backup name; isolate caller glob options/ignores.
    unset GLOBIGNORE
    set +f
    shopt -u failglob
    shopt -s nullglob
    matches=("$parent"/passwd[-])
    [[ ${#matches[@]} -eq 0 && ! -e "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_tmout_directory "$parent" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_7_1_2_evidence "$parent" 0040000)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" && ! -e "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'absent:%s\n' "$after"
)
rlch_7_1_2_observe() {
    local before after dev inode links uid gid mode raw ctime result="$RLCH_MODULE_RESULT_SUCCESS"
    before="$(rlch_7_1_2_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_7_1_2_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$after" == absent:* ]]; then return "$RLCH_MODULE_RESULT_SUCCESS"; fi
    after="${after#present:}"
    # These fields were validated in snapshot; classification happens only
    # after the entire tuple, including inode/type/nlink/ctime, agrees twice.
    IFS='|' read -r dev inode links uid gid mode raw ctime <<< "$after"
    if [[ "$uid" != 0 || "$gid" != 0 ]]; then result="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
    printf -v mode '%04o' "$((8#$mode))"
    if ! rlch_journal_mode "$mode" 0644; then result="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
    return "$result"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_7_1_2_observe 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") printf 'CIS 7.1.2: stable absence of /etc/passwd-, or stable regular single-link backup with UID/GID 0 and POSIX mode 0644 or more restrictive; extended ACL, xattr and SELinux are not assessed\n' >&2 ;;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 7.1.2: stable /etc/passwd- has an incorrect numeric UID/GID or a forbidden POSIX permission bit; manual remediation required\n' >&2 ;;
        *) result="$RLCH_MODULE_RESULT_ERROR"; printf 'CIS 7.1.2: manual review required; backup or parent is unsafe, non-regular, multiply linked, inaccessible or unstable, a present/absent transition occurred, or stat evidence is invalid\n' >&2 ;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_7_1_2_observe 2>/dev/null || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 7.1.2: stable absence or compliant observed POSIX attributes; no mutation; extended ACL/xattr/SELinux require separate review\n' >&2
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    printf 'CIS 7.1.2: manual remediation required; never create a missing /etc/passwd-; for a present backup confirm its exact regular single-link inode, UID/GID 0 and remove only bits forbidden by 0644; preserve content, more restrictive modes, ACL/xattr/SELinux and exact original attributes, coordinate account-file replacement and verify rollback in an isolated environment; no automatic chmod/chown/chgrp, creation, backup or state\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No attributes or content changed, no transaction state to restore.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
