#!/usr/bin/env bash
# Read-only bounded metadata traversal. No CIS selection or ownership policy.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/mount.sh
source "${BASH_SOURCE[0]%/*}/mount.sh"

# Public API: rlch_fs_observe ROOT MOUNTINFO SELECTOR VISITOR
# SELECTOR ARRAY INDEX: 0 include, 1 exclude, other error. VISITOR ARRAY PREFIX
# receives complete stable ten-field tuples for each included mount (same
# fields as GNU find below). Both callbacks execute in the caller shell.
# Returns 0/2, no stdout; RLCH_FS_OBSERVATION_ERROR is a bounded category.
# Callbacks are trusted code, must not mutate evidence/inventory or scan state.
# Limits: 100000 tuples/64 MiB per pass, 200000 tuples total, depth 1024.
# A two-pass comparison detects observed changes, not transient ABA changes.

rlch_fs_canonical() {
    local fd pid result=0
    local -a values=()
    exec {fd}< <(LC_ALL=C /usr/bin/realpath -ez -- "$1" 2>/dev/null); pid=$!
    mapfile -d '' -t values <&"$fd" || result=2
    exec {fd}<&-
    wait "$pid" || result=2
    [[ "$result" == 0 && ${#values[@]} == 1 && "${values[0]}" == "$1" ]]
}
rlch_fs_root_stat() { LC_ALL=C /usr/bin/stat -c '%d|%f' -- "$1"; }
rlch_fs_device() {
    local evidence dev raw
    [[ -d "$1" && ! -L "$1" && -r "$1" && -x "$1" ]] || return 2
    rlch_fs_canonical "$1" || return 2
    evidence="$(set -o pipefail; rlch_fs_root_stat "$1" 2>/dev/null | LC_ALL=C /usr/bin/awk '
      {if(NR!=1 || length($0)>128 || index($0,sprintf("%c",0)) || /[[:cntrl:]]/) exit 2;print}
      END {if(NR!=1) exit 2}')" || return 2
    [[ "$evidence" =~ ^(0|[1-9][0-9]{0,18})\|[0-9a-f]{1,8}$ ]] || return 2
    IFS='|' read -r dev raw <<< "$evidence"
    [[ ${#dev} -lt 19 || "x$dev" < x9223372036854775808 ]] || return 2
    (( (16#$raw & ~0177777)==0 && (16#$raw & 0170000)==0040000 &&
       (16#$raw & 0444)!=0 && (16#$raw & 0111)!=0 )) || return 2
    printf '%s:%s\n' "$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) ))" "$(( (dev & 255) | (dev>>12 & 4294967040) ))"
}
rlch_fs_find() { LC_ALL=C /usr/bin/find "$@"; }
rlch_fs_frame() (
    set -o pipefail
    {
        # Any stderr, even with status zero, invalidates this observation.
        { rlch_fs_find "$@" 2>&1 1>&3 | /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'; } 3>&1 || exit 2
        printf 'RLCH-FS-END\0'
    } | /usr/bin/head -c 67108865 | LC_ALL=C /usr/bin/awk -v RS='\0' '
      {bytes+=length($0)+1
       if(bytes>67108864 || length($0)>4096 || ended) {bad=1;exit 2}
       if($0=="RLCH-FS-END") {if((NR-1)%10 || NR==1) {bad=1;exit 2};ended=1;next}
       if(NR>1000000) {bad=1;exit 2};printf "%s%c",$0,0}
      END {if(bad || !ended) exit 2}'
)
rlch_fs_equal() {
    local -n _rfe_left="$1" _rfe_right="$2"
    local _rfe_i
    [[ ${#_rfe_left[@]} == "${#_rfe_right[@]}" ]] || return 2
    for ((_rfe_i=0;_rfe_i<${#_rfe_left[@]};_rfe_i++)); do
        [[ "${_rfe_left[_rfe_i]}" == "${_rfe_right[_rfe_i]}" ]] || return 2
    done
}
rlch_fs_walk() {
    local _rfw_root="$1" _rfw_index="$2" _rfw_prefix="$3" _rfw_fd _rfw_pid _rfw_result=0 _rfw_i _rfw_p
    local _rfw_type _rfw_dev _rfw_ino _rfw_links _rfw_uid _rfw_gid _rfw_mode _rfw_ctime _rfw_depth
    local -n _rfw_inventory="$4" _rfw_output="$5"
    local -a _rfw_args=(-P "$_rfw_root" -xdev) _rfw_prunes=() _rfw_fields=()
    local -A _rfw_seen=()
    _rfw_output=()
    for ((_rfw_i=0;_rfw_i<${#_rfw_inventory[@]};_rfw_i+=10)); do
        _rfw_p="${_rfw_inventory[_rfw_i+4]}"
        [[ "$_rfw_p" != "${_rfw_inventory[_rfw_index+4]}" ]] || continue
        if [[ "${_rfw_inventory[_rfw_index+4]}" == / || "$_rfw_p" == "${_rfw_inventory[_rfw_index+4]}/"* ]]; then
            _rfw_p="${_rfw_prefix}${_rfw_p}"
            _rfw_p="${_rfw_p//\\/\\\\}"; _rfw_p="${_rfw_p//\*/\\*}"
            _rfw_p="${_rfw_p//\?/\\?}"; _rfw_p="${_rfw_p//\[/\\[}"
            if (( ${#_rfw_prunes[@]} )); then _rfw_prunes+=(-o); fi
            _rfw_prunes+=(-path "$_rfw_p")
        fi
    done
    if (( ${#_rfw_prunes[@]} )); then _rfw_args+=(\( "${_rfw_prunes[@]}" \) -prune -o); fi
    _rfw_args+=(-printf '%p\0%y\0%D\0%i\0%n\0%U\0%G\0%m\0%C@\0%d\0')
    exec {_rfw_fd}< <(rlch_fs_frame "${_rfw_args[@]}" 2>/dev/null); _rfw_pid=$!
    mapfile -d '' -t _rfw_fields <&"$_rfw_fd" || _rfw_result=2
    exec {_rfw_fd}<&-
    wait "$_rfw_pid" || _rfw_result=2
    [[ "$_rfw_result" == 0 ]] || return 2
    (( ${#_rfw_fields[@]}>0 && ${#_rfw_fields[@]}%10==0 )) || return 2
    _rfo_objects=$((_rfo_objects+${#_rfw_fields[@]}/10))
    (( _rfo_objects<=200000 )) || return 2
    for ((_rfw_i=0;_rfw_i<${#_rfw_fields[@]};_rfw_i+=10)); do
        _rfw_p="${_rfw_fields[_rfw_i]}"; _rfw_type="${_rfw_fields[_rfw_i+1]}"; _rfw_dev="${_rfw_fields[_rfw_i+2]}"
        _rfw_ino="${_rfw_fields[_rfw_i+3]}"; _rfw_links="${_rfw_fields[_rfw_i+4]}"; _rfw_uid="${_rfw_fields[_rfw_i+5]}"
        _rfw_gid="${_rfw_fields[_rfw_i+6]}"; _rfw_mode="${_rfw_fields[_rfw_i+7]}"; _rfw_ctime="${_rfw_fields[_rfw_i+8]}"; _rfw_depth="${_rfw_fields[_rfw_i+9]}"
        [[ "$_rfw_p" == "$_rfw_root" || "$_rfw_p" == "$_rfw_root/"* || ( "$_rfw_root" == / && "$_rfw_p" == /* ) ]] || return 2
        [[ "$_rfw_p" != *'/../'* && "$_rfw_p" != *'/./'* && "$_rfw_p" != *'//'* && "$_rfw_p" != */.. && "$_rfw_p" != */. ]] || return 2
        [[ ! ${_rfw_seen["$_rfw_p"]+present} ]] || return 2
        _rfw_seen["$_rfw_p"]=1
        [[ "$_rfw_type" =~ ^[bcdflps]$ && "$_rfw_dev" =~ ^(0|[1-9][0-9]{0,18})$ &&
           "$_rfw_ino" =~ ^[1-9][0-9]{0,19}$ && "$_rfw_links" =~ ^[1-9][0-9]{0,19}$ &&
           "$_rfw_uid" =~ ^(0|[1-9][0-9]{0,9})$ && "$_rfw_gid" =~ ^(0|[1-9][0-9]{0,9})$ &&
           "$_rfw_mode" =~ ^[0-7]{1,4}$ && "$_rfw_ctime" =~ ^-?[0-9]{1,19}\.[0-9]{1,10}$ &&
           "$_rfw_depth" =~ ^(0|[1-9][0-9]{0,3})$ ]] || return 2
        (( _rfw_uid<=4294967294 && _rfw_gid<=4294967294 && _rfw_depth<=1024 )) || return 2
        [[ ${#_rfw_dev} -lt 19 || "x$_rfw_dev" < x9223372036854775808 ]] || return 2
        [[ ${#_rfw_ino} -lt 20 || "x$_rfw_ino" < x18446744073709551616 ]] || return 2
        [[ ${#_rfw_links} -lt 20 || "x$_rfw_links" < x18446744073709551616 ]] || return 2
        [[ "$_rfw_dev" == "${_rfw_fields[2]}" ]] || return 2
        if (( _rfw_i==0 )); then
            # dev_t must agree with independently checked mount inventory.
            [[ "$(( (_rfw_dev>>8 & 4095) | (_rfw_dev>>32 & 4294963200) )):$(( (_rfw_dev & 255) | (_rfw_dev>>12 & 4294967040) ))" == "${_rfw_inventory[_rfw_index+2]}" ]] || return 2
        fi
        if (( _rfw_i==0 )); then [[ "$_rfw_p" == "$_rfw_root" && "$_rfw_type" == d && "$_rfw_depth" == 0 ]] || return 2; fi
        if [[ "$_rfw_type" == d ]]; then
            [[ -r "$_rfw_p" && -x "$_rfw_p" ]] || return 2
            (( (8#$_rfw_mode & 0444)!=0 && (8#$_rfw_mode & 0111)!=0 )) || return 2
        fi
    done
    # shellcheck disable=SC2034 # Caller-owned output nameref.
    _rfw_output=("${_rfw_fields[@]}")
}
rlch_fs_observe() {
    local _rfo_prefix="${1%/}" _rfo_info="$2" _rfo_selector="$3" _rfo_visitor="$4"
    local _rfo_i _rfo_root _rfo_device _rfo_result _rfo_objects=0
    local -a _rfo_mounts=() _rfo_middle=() _rfo_final=() _rfo_first=() _rfo_second=() _rfo_selected=()
    RLCH_FS_OBSERVATION_ERROR=root
    [[ -z "$_rfo_prefix" || "$_rfo_prefix" == /* ]] || return 2
    rlch_fs_canonical "${_rfo_prefix:-/}" || return 2
    declare -F "$_rfo_selector" >/dev/null && declare -F "$_rfo_visitor" >/dev/null || return 2
    RLCH_FS_OBSERVATION_ERROR=inventory
    mount_inventory _rfo_mounts "$_rfo_info" || return 2
    for ((_rfo_i=0;_rfo_i<${#_rfo_mounts[@]};_rfo_i+=10)); do
        _rfo_result=0; "$_rfo_selector" _rfo_mounts "$_rfo_i" || _rfo_result=$?
        case "$_rfo_result" in 0) _rfo_selected+=("$_rfo_i");; 1) :;; *) RLCH_FS_OBSERVATION_ERROR=selection; return 2;; esac
    done
    (( ${#_rfo_selected[@]}>0 )) || { RLCH_FS_OBSERVATION_ERROR=empty_selection; return 2; }
    for _rfo_i in "${_rfo_selected[@]}"; do
        _rfo_root="${_rfo_prefix}${_rfo_mounts[_rfo_i+4]}"
        [[ "$_rfo_root" == / ]] || _rfo_root="${_rfo_root%/}"
        RLCH_FS_OBSERVATION_ERROR=device
        _rfo_device="$(rlch_fs_device "$_rfo_root")" || return 2
        [[ "$_rfo_device" == "${_rfo_mounts[_rfo_i+2]}" ]] || return 2
        RLCH_FS_OBSERVATION_ERROR=traversal
        rlch_fs_walk "$_rfo_root" "$_rfo_i" "$_rfo_prefix" _rfo_mounts _rfo_first || return 2
        RLCH_FS_OBSERVATION_ERROR=inventory_changed
        mount_inventory _rfo_middle "$_rfo_info" || return 2
        rlch_fs_equal _rfo_mounts _rfo_middle || return 2
        RLCH_FS_OBSERVATION_ERROR=traversal
        rlch_fs_walk "$_rfo_root" "$_rfo_i" "$_rfo_prefix" _rfo_mounts _rfo_second || return 2
        RLCH_FS_OBSERVATION_ERROR=metadata_changed
        rlch_fs_equal _rfo_first _rfo_second || return 2
        RLCH_FS_OBSERVATION_ERROR=device
        _rfo_device="$(rlch_fs_device "$_rfo_root")" || return 2
        [[ "$_rfo_device" == "${_rfo_mounts[_rfo_i+2]}" ]] || return 2
        RLCH_FS_OBSERVATION_ERROR=visitor
        "$_rfo_visitor" _rfo_first "$_rfo_prefix" || return 2
    done
    RLCH_FS_OBSERVATION_ERROR=inventory_changed
    mount_inventory _rfo_final "$_rfo_info" || return 2
    rlch_fs_equal _rfo_mounts _rfo_final || return 2
    # shellcheck disable=SC2034 # Public error category consumed by callers.
    RLCH_FS_OBSERVATION_ERROR=''
    return 0
}
