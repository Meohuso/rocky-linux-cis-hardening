#!/usr/bin/env bash
# CIS 7.1.1 - current /etc/passwd attributes only, no content or mutation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/journal_access.sh"
RLCH_CIS_7_1_1_ROOT="${RLCH_CIS_7_1_1_ROOT:-/}"

# Private stat boundary: no dereference, NSS, content read or atime update.
rlch_7_1_1_stat() {
    LC_ALL=C /usr/bin/stat -c '%d|%i|%h|%u|%g|%a|%f|%z' -- "$1"
}
rlch_7_1_1_snapshot() (
    local file="${RLCH_CIS_7_1_1_ROOT%/}/etc/passwd" stamp dev inode links uid gid mode raw ctime
    set -o pipefail
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    # Check output before Bash substitution so a NUL cannot disappear unnoticed.
    stamp="$(rlch_7_1_1_stat "$file" | LC_ALL=C /usr/bin/awk -v error="$RLCH_MODULE_RESULT_ERROR" '
        {bytes+=length($0)+1
         if(NR>1 || bytes>1024 || index($0,sprintf("%c",0)) || $0 ~ /[[:cntrl:]]/) exit error
         print}
        END {if(NR!=1) exit error}
    ')" || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r dev inode links uid gid mode raw ctime <<< "$stamp"
    [[ "$dev" =~ ^(0|[1-9][0-9]{0,19})$ && "$inode" =~ ^[1-9][0-9]{0,19}$ && "$links" == 1 &&
       "$uid" =~ ^(0|[1-9][0-9]{0,9})$ && "$gid" =~ ^(0|[1-9][0-9]{0,9})$ &&
       "$mode" =~ ^[0-7]{1,4}$ && "$raw" =~ ^[0-9a-f]{1,8}$ &&
       "$ctime" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}\ [+-][0-9]{4}$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    (( uid<=4294967294 && gid<=4294967294 && (16#$raw & 0170000) == 0100000 &&
       (16#$raw & 07777) == 8#$mode )) || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$stamp"
)
rlch_7_1_1_observe() {
    local before after dev inode links uid gid mode raw ctime result="$RLCH_MODULE_RESULT_SUCCESS"
    before="$(rlch_7_1_1_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_7_1_1_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
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
    rlch_7_1_1_observe 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") printf 'CIS 7.1.1: stable regular single-link /etc/passwd has UID/GID 0 and POSIX mode 0644 or more restrictive; extended ACL, xattr and SELinux are not assessed\n' >&2 ;;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 7.1.1: stable /etc/passwd has an incorrect numeric UID/GID or a forbidden POSIX permission bit; manual remediation required\n' >&2 ;;
        *) result="$RLCH_MODULE_RESULT_ERROR"; printf 'CIS 7.1.1: manual review required; /etc/passwd is absent, unsafe, non-regular, multiply linked, inaccessible or unstable, or stat evidence is invalid\n' >&2 ;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_7_1_1_observe 2>/dev/null || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 7.1.1: observed POSIX attributes already satisfy the criterion; no mutation; extended ACL/xattr/SELinux require separate review\n' >&2
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    printf 'CIS 7.1.1: manual remediation required; confirm the exact regular single-link /etc/passwd inode, UID/GID 0 and remove only bits forbidden by 0644; preserve content, more restrictive modes, ACL/xattr/SELinux and exact original attributes, coordinate account-file replacement and verify rollback in an isolated environment; no automatic chmod/chown/chgrp, creation, backup or state\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# No attributes or content changed, no transaction state to restore.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
