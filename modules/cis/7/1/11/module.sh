#!/usr/bin/env bash
# CIS 7.1.11 - complete pinned OVAL eligible-mount metadata audit; no mutation.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/mount.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/mount.sh"
RLCH_CIS_7_1_11_ROOT="${RLCH_CIS_7_1_11_ROOT:-/}"
RLCH_CIS_7_1_11_MOUNTINFO="${RLCH_CIS_7_1_11_MOUNTINFO:-/proc/self/mountinfo}"

rlch_7_1_11_canonical() {
    local fd pid result=0
    local -a paths=()
    exec {fd}< <(LC_ALL=C /usr/bin/realpath -z -e -- "$1" 2>/dev/null); pid=$!
    mapfile -d '' -t paths <&"$fd" || result=2
    exec {fd}<&-
    wait "$pid" || result=2
    [[ "$result" == 0 && ${#paths[@]} == 1 && "${paths[0]}" == "$1" ]]
}
rlch_7_1_11_root_stat() {
    LC_ALL=C /usr/bin/stat -c '%d|%f' -- "$1"
}
rlch_7_1_11_mount_device() {
    local evidence dev raw
    [[ -d "$1" && ! -L "$1" && -r "$1" && -x "$1" ]] || return 2
    rlch_7_1_11_canonical "$1" || return 2
    evidence="$(set -o pipefail; rlch_7_1_11_root_stat "$1" | LC_ALL=C /usr/bin/awk '
        {if(NR!=1 || length($0)>128 || index($0,sprintf("%c",0)) || $0 ~ /[[:cntrl:]]/) exit 2; print}
        END {if(NR!=1) exit 2}
    ')" || return 2
    [[ "$evidence" =~ ^(0|[1-9][0-9]{0,18})\|[0-9a-f]{1,8}$ ]] || return 2
    IFS='|' read -r dev raw <<< "$evidence"
    (( (16#$raw & ~0177777)==0 && (16#$raw & 0170000)==0040000 &&
       (16#$raw & 0444)!=0 && (16#$raw & 0111)!=0 )) || return 2
    printf '%s:%s\n' "$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) ))" "$(( (dev & 255) | (dev>>12 & 4294967040) ))"
}
# Escape GNU find -path patterns, so literal mount names never become globs.
rlch_7_1_11_pattern() {
    local p="$1"
    p="${p//\\/\\\\}";p="${p//\*/\\*}";p="${p//\?/\\?}";p="${p//\[/\\[}"
    printf -v RLCH_7111_PATTERN '%s' "$p"
}
rlch_7_1_11_find() {
    LC_ALL=C /usr/bin/find "$@"
}
# NUL field protocol, complete producer status retained by caller. Limit is
# 100000 objects / 64 MiB per mount / depth 1024. Exceeding it is ERROR.
rlch_7_1_11_frame() (
    set -o pipefail
    rlch_7_1_11_find "$@" | LC_ALL=C /usr/bin/awk -v RS='\0' '
        {bytes+=length($0)+1;if(bytes>67108864 || NR>1000000 || length($0)>4096) exit 2
         printf "%s%c",$0,0}
        END {if(NR%10!=0) exit 2}
    '
)
rlch_7_1_11_walk() {
    local root="$1" index="$2" prefix="$3" fd pid result=0 i p type dev ino links uid gid mode ctime depth logical
    local RLCH_7111_PATTERN
    local -n inventory="$4" walk_result="$5"
    local -a args=(-P "$root" -xdev) prunes=() fields=()
    local -A seen=()
    for ((i=0;i<${#inventory[@]};i+=10)); do
        p="${inventory[i+4]}"
        [[ "$p" != "${inventory[index+4]}" ]] || continue
        if [[ "${inventory[index+4]}" == / || "$p" == "${inventory[index+4]}/"* ]]; then
            p="${prefix}${p}"; rlch_7_1_11_pattern "$p"
            if (( ${#prunes[@]} )); then prunes+=(-o); fi
            prunes+=(-path "$RLCH_7111_PATTERN")
        fi
    done
    if (( ${#prunes[@]} )); then args+=(\( "${prunes[@]}" \) -prune -o); fi
    args+=(-printf '%p\0%y\0%D\0%i\0%n\0%U\0%G\0%m\0%C@\0%d\0')
    exec {fd}< <(rlch_7_1_11_frame "${args[@]}" 2>/dev/null); pid=$!
    mapfile -d '' -t fields <&"$fd" || result=2
    exec {fd}<&-
    wait "$pid" || result=2
    [[ "$result" == 0 ]] || return 2
    (( ${#fields[@]}>0 && ${#fields[@]}%10==0 )) || return 2
    RLCH_7111_OBJECTS=$((RLCH_7111_OBJECTS+${#fields[@]}/10))
    (( RLCH_7111_OBJECTS<=200000 )) || return 2
    for ((i=0;i<${#fields[@]};i+=10)); do
        p="${fields[i]}";type="${fields[i+1]}";dev="${fields[i+2]}";ino="${fields[i+3]}";links="${fields[i+4]}"
        uid="${fields[i+5]}";gid="${fields[i+6]}";mode="${fields[i+7]}";ctime="${fields[i+8]}";depth="${fields[i+9]}"
        [[ "$p" == "$root" || "$p" == "$root/"* || ( "$root" == / && "$p" == /* ) ]] || return 2
        [[ "$p" != *'/../'* && "$p" != *'/./'* && "$p" != *'//'* && "$p" != */.. && "$p" != */. ]] || return 2
        [[ ! ${seen["$p"]+present} ]] || return 2
        seen["$p"]=1
        [[ "$type" =~ ^[bcdflps]$ && "$dev" =~ ^(0|[1-9][0-9]{0,18})$ && "$ino" =~ ^[1-9][0-9]{0,19}$ &&
           "$links" =~ ^[1-9][0-9]{0,19}$ && "$uid" =~ ^(0|[1-9][0-9]{0,9})$ && "$gid" =~ ^(0|[1-9][0-9]{0,9})$ &&
           "$mode" =~ ^[0-7]{1,4}$ && "$ctime" =~ ^-?[0-9]{1,19}\.[0-9]{1,10}$ && "$depth" =~ ^(0|[1-9][0-9]{0,3})$ ]] || return 2
        (( uid<=4294967294 && gid<=4294967294 && depth<=1024 )) || return 2
        [[ "$dev" == "${fields[2]}" ]] || return 2
        if [[ "$i" == 0 ]]; then [[ "$p" == "$root" && "$type" == d && "$depth" == 0 ]] || return 2; fi
        if [[ "$type" == d ]]; then
            [[ -r "$p" && -x "$p" ]] || return 2
            (( (8#$mode & 0444)!=0 && (8#$mode & 0111)!=0 )) || return 2
        fi
        logical="${p#"$prefix"}"
        if [[ "$type" == f ]] && (( (8#$mode & 2)!=0 )); then
            # Literal CAS regex anchors with newline-bearing exception paths
            # need probe-engine semantics beyond shell patterns: fail closed.
            if [[ "$logical" == *$'\n'* && ( "$logical" == /sysroot/* || "$logical" == /selinux/* ) ]]; then return 2; fi
            case "$logical" in /sysroot/*|/selinux/member|/selinux/user|/selinux/relabel|/selinux/create|/selinux/access|/selinux/context) :;;
                *) RLCH_7111_DEFICIT=1;;
            esac
        elif [[ "$type" == d ]]; then
            if (( (8#$mode & 2)!=0 && (8#$mode & 01000)==0 )); then RLCH_7111_DEFICIT=1; fi
        fi
    done
    # shellcheck disable=SC2034 # Writes through the caller-owned nameref.
    walk_result=("${fields[@]}")
}
rlch_7_1_11_observe() {
    local prefix="${RLCH_CIS_7_1_11_ROOT%/}" i j root device selected=0 RLCH_7111_DEFICIT=0 RLCH_7111_OBJECTS=0
    local -a mounts=() middle=() final=() first=() second=()
    [[ -z "$prefix" || "$prefix" == /* ]] || return 2
    rlch_7_1_11_canonical "${prefix:-/}" || return 2
    mount_inventory mounts "$RLCH_CIS_7_1_11_MOUNTINFO" || return 2
    for ((i=0;i<${#mounts[@]};i+=10)); do
        [[ "${mounts[i+5]}" == /dev/* ]] || continue
        # PCRE device pattern with embedded newlines is not safely equivalent
        # to a shell glob. Do not silently widen the pinned OVAL selection.
        [[ "${mounts[i+5]}" != *$'\n'* ]] || return 2
        selected=$((selected+1)); root="${prefix}${mounts[i+4]}"
        [[ "$root" == / ]] || root="${root%/}"
        device="$(rlch_7_1_11_mount_device "$root")" || return 2
        [[ "$device" == "${mounts[i+2]}" ]] || return 2
        rlch_7_1_11_walk "$root" "$i" "$prefix" mounts first || return 2
        mount_inventory middle "$RLCH_CIS_7_1_11_MOUNTINFO" || return 2
        [[ ${#mounts[@]} == "${#middle[@]}" ]] || return 2
        for ((j=0;j<${#mounts[@]};j++)); do [[ "${mounts[j]}" == "${middle[j]}" ]] || return 2; done
        rlch_7_1_11_walk "$root" "$i" "$prefix" mounts second || return 2
        [[ ${#first[@]} == "${#second[@]}" ]] || return 2
        for ((j=0;j<${#first[@]};j++)); do [[ "${first[j]}" == "${second[j]}" ]] || return 2; done
        device="$(rlch_7_1_11_mount_device "$root")" || return 2
        [[ "$device" == "${mounts[i+2]}" ]] || return 2
    done
    # No vacuous global conformity for a container with no eligible device.
    (( selected>0 )) || return 2
    mount_inventory final "$RLCH_CIS_7_1_11_MOUNTINFO" || return 2
    [[ ${#mounts[@]} == "${#final[@]}" ]] || return 2
    for ((j=0;j<${#mounts[@]};j++)); do [[ "${mounts[j]}" == "${final[j]}" ]] || return 2; done
    (( RLCH_7111_DEFICIT==0 )) || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_7_1_11_observe 2>/dev/null || result=$?
    case "$result" in
        0) printf 'CIS 7.1.11: complete stable pinned RHEL9 OVAL eligible-mount scan; no world-writable regular files outside CAS exceptions or world-writable directories lacking sticky bit; excluded filesystems and independent ACL grants are not assessed\n' >&2;;
        1) printf 'CIS 7.1.11: complete stable pinned RHEL9 OVAL eligible-mount scan found forbidden other-write file permissions or directories lacking sticky bit; manual review required\n' >&2;;
        *) result=2; printf 'CIS 7.1.11: ERROR; mount selection, traversal completeness or metadata stability is unproven, invalid, inaccessible, interrupted or over resource limits; no conformity conclusion\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    rlch_7_1_11_observe 2>/dev/null || result=$?
    if [[ "$result" == 0 ]]; then
        printf 'CIS 7.1.11: pinned OVAL eligible-mount criteria satisfied; observation only, no mutation\n' >&2
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    printf 'CIS 7.1.11: manual review required; establish complete stable mount scope, review application needs before removing other-write or setting directory sticky bit; preserve inode identity, original permissions and ACL/xattr/SELinux/capabilities, coordinate concurrent changes and isolated exact rollback; no automatic mutation or state\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
