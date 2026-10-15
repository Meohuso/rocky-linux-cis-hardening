#!/usr/bin/env bash
# CIS 7.1.10 - pinned CAS partial scope: opasswd only, never secret content.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/journal_access.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/journal_access.sh"
RLCH_CIS_7_1_10_ROOT="${RLCH_CIS_7_1_10_ROOT:-/}"
RLCH_CIS_7_1_10_RPM="${RLCH_CIS_7_1_10_RPM:-rpm}"
RLCH_CIS_7_1_10_GETFACL="${RLCH_CIS_7_1_10_GETFACL:-getfacl}"

# The package[pam] precondition must be established, never guessed from a file.
# Missing package/tool or ambiguous query => ERROR, not an inferred applicability.
rlch_7_1_10_platform() (
    local evidence
    set -o pipefail
    evidence="$(LC_ALL=C "$RLCH_CIS_7_1_10_RPM" -q --qf '%{NAME}\n' pam 2>/dev/null |
        LC_ALL=C /usr/bin/awk '{if(NR!=1 || $0!="pam") exit 2; print} END {if(NR!=1) exit 2}')" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$evidence" == pam ]] || return "$RLCH_MODULE_RESULT_ERROR"
)
# stat and getfacl inspect metadata, without opening password history contents.
rlch_7_1_10_stat() {
    LC_ALL=C /usr/bin/stat -c '%d|%i|%h|%u|%g|%a|%f|%z' -- "$1"
}
rlch_7_1_10_evidence() (
    local file="$1" type="$2" stamp dev inode links uid gid mode raw ctime
    set -o pipefail
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    # Check output before Bash substitution so a NUL cannot disappear unnoticed.
    stamp="$(rlch_7_1_10_stat "$file" | LC_ALL=C /usr/bin/awk -v error="$RLCH_MODULE_RESULT_ERROR" '
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
    (( uid<=4294967294 && gid<=4294967294 && (16#$raw & ~0177777) == 0 &&
       (16#$raw & 0170000) == type &&
       (16#$raw & 07777) == 8#$mode )) || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$type" == 0100000 ]]; then
        [[ "$links" == 1 && -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    else
        [[ -d "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$stamp"
)
rlch_7_1_10_getfacl() {
    LC_ALL=C "$RLCH_CIS_7_1_10_GETFACL" -c -n -E -P -- "$1"
}
# Unlike the general journal ACL helper, CAS forbids ALL extended ACLs,
# including masked/zero grants. Validate base entries against POSIX stat bits.
# The canonical metadata stream is compared, not just the compliant/deficit flag.
rlch_7_1_10_acl() (
    local file="$1" mode="$2"
    set -o pipefail
    rlch_7_1_10_getfacl "$file" | LC_ALL=C /usr/bin/awk -F: -v mode="$((8#$mode))" '
        function bits(s,i,n) {n=0;for(i=1;i<=3;i++) if(substr(s,i,1)!="-") n+=2^(3-i);return n}
        function invalid() {bad=1;exit 2}
        {
            bytes+=length($0)+1
            if(bytes>65536 || NR>1024 || index($0,sprintf("%c",0)) || $0 ~ /[[:cntrl:]]/) invalid()
            if($0=="") next
            if(NF!=3 || $1 !~ /^(user|group|mask|other)$/ || $3 !~ /^[r-][w-][x-]$/) invalid()
            if($2!="" && ($1 !~ /^(user|group)$/ || $2 !~ /^(0|[1-9][0-9]*)$/ || length($2)>10 || $2+0>4294967294)) invalid()
            key=$1 ":" $2; if(seen[key]++) invalid()
            if($2!="") {named=1;extended=1}
            else {p[$1]=bits($3); if($1=="mask") extended=1}
            stream=stream $0 ";"
        }
        END {
            if(bad || !seen["user:"] || !seen["group:"] || !seen["other:"] || (named && !seen["mask:"])) exit 2
            group=(seen["mask:"] ? p["mask"] : p["group"])
            if(p["user"]!=int(mode/64)%8 || group!=int(mode/8)%8 || p["other"]!=mode%8) exit 2
            print "acl:" (extended ? "extended:" : "basic:") stream
        }
    ' || return "$RLCH_MODULE_RESULT_ERROR"
)
rlch_7_1_10_snapshot() (
    local file="${RLCH_CIS_7_1_10_ROOT%/}/etc/security/opasswd" parent before after acl mode
    local -a matches=() fields=()
    parent="${file%/*}"
    rlch_7_1_10_platform || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_journal_path "$file" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_tmout_directory "$parent" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$file" || -L "$file" ]]; then
        [[ -f "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        before="$(rlch_7_1_10_evidence "$file" 0100000)" || return "$RLCH_MODULE_RESULT_ERROR"
        IFS='|' read -r -a fields <<< "$before"; mode="${fields[5]}"
        acl="$(rlch_7_1_10_acl "$file" "$mode")" || return "$RLCH_MODULE_RESULT_ERROR"
        after="$(rlch_7_1_10_evidence "$file" 0100000)" || return "$RLCH_MODULE_RESULT_ERROR"
        rlch_tmout_directory "$parent" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        printf 'present:%s\n%s\n' "$after" "$acl"
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    # all_exist requires presence. Prove absence through a stable observable
    # parent and exact-name glob, never infer it solely from a false -e.
    before="$(rlch_7_1_10_evidence "$parent" 0040000)" || return "$RLCH_MODULE_RESULT_ERROR"
    unset GLOBIGNORE
    set +f
    shopt -u failglob
    shopt -s nullglob
    matches=("$parent"/opassw[d])
    [[ ${#matches[@]} -eq 0 && ! -e "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_tmout_directory "$parent" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_7_1_10_evidence "$parent" 0040000)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" && ! -e "$file" && ! -L "$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    printf 'absent:%s\n' "$after"
)
rlch_7_1_10_observe() {
    local before after stamp dev inode links uid gid mode raw ctime
    before="$(rlch_7_1_10_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_7_1_10_snapshot)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    # Both complete snapshots must be reliable before any deficit is classified.
    [[ "$after" != absent:* ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    stamp="${after%%$'\n'*}"; stamp="${stamp#present:}"
    IFS='|' read -r dev inode links uid gid mode raw ctime <<< "$stamp"
    [[ "$uid" == 0 && "$gid" == 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    (( 8#$mode == 0600 )) || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    [[ "$after" == *$'\nacl:basic:'* ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_7_1_10_observe 2>/dev/null || result=$?
    case "$result" in
        "$RLCH_MODULE_RESULT_SUCCESS") printf 'CIS 7.1.10: CAS partial scope only; stable regular single-link /etc/security/opasswd has UID/GID 0, exact mode 0600 and no extended ACL; opasswd.old is not assessed, full CIS coverage is not demonstrated\n' >&2 ;;
        "$RLCH_MODULE_RESULT_NON_COMPLIANT") printf 'CIS 7.1.10: CAS partial scope only; proven stable absence or incorrect UID/GID, exact mode 0600 or extended ACL on /etc/security/opasswd; manual remediation required; opasswd.old is not assessed\n' >&2 ;;
        *) result="$RLCH_MODULE_RESULT_ERROR"; printf 'CIS 7.1.10: CAS partial scope only; manual review required for unsafe or unstable target/parent, ambiguous absence, invalid stat/ACL evidence or unproven PAM applicability/tools; opasswd.old is not assessed\n' >&2 ;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result="$RLCH_MODULE_RESULT_SUCCESS"
    rlch_7_1_10_observe 2>/dev/null || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 7.1.10: CAS partial scope only; opasswd attributes already conform; no mutation; opasswd.old is not assessed and full CIS coverage is not demonstrated\n' >&2
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    printf 'CIS 7.1.10: CAS partial scope only; manual remediation required; establish PAM applicability, safe exact regular single-link opasswd inode, UID/GID 0, exact mode 0600 and no extended ACL; preserve secret content, xattr/SELinux/capabilities and original ACL/attributes, coordinate PAM history rotation and test exact rollback in isolation; no automatic mutation, creation, backup or state; opasswd.old is not assessed\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
# Observation-only: no secret copies or transaction state to restore.
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
