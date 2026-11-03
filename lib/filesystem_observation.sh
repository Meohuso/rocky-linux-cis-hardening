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

# Additive API: rlch_fs_snapshot PATH CHILD_DEPTH all|local MOUNTINFO
# Controlled INTERNAL stdout: NUL fields, twelve per record:
# PATH TYPE DEV INO NLINK UID GID MODE SIZE MTIME CTIME CHILD_DEPTH.
# TYPE=a is reliably absent (remaining metadata identifies its existing parent).
# Other types: f d l b c p s. No contents or symlink targets are read.
# Return 0 only for a complete stable snapshot, 2 otherwise. Caller MUST check
# status before consuming stdout; output-device failure is not transactional.
# No diagnostics. A private subshell disables tracing and bounds VM to 256 MiB.
# Limits: depth 0..8, 16384 records, 4096 bytes/path, 8 MiB projection, 64 distinct
# mount IDs encountered, 64 path components. Mount inventory retains its own
# existing 4096-record/4-MiB limits. No historical API is changed.
# Local accepts proven-local ext2/3/4 xfs btrfs tmpfs overlay ramfs only; other
# filesystems return ERROR, never an incomplete successful traversal. `all`
# allows mounted filesystems except autofs (which could trigger a mutation).
# Every directory is pinned by an FD before enumeration, with lstat/opened-FD
# identity comparison. Independent Bash glob census detects a producer silently
# truncating even on a complete NUL boundary. Missing final NUL, producer stderr,
# nonzero status, changed census/metadata/inventory or exceeded bounds fail.
# Two entire passes plus ancestor guards detect observable changes, not atomic
# transactions, transient ABA, a hostile kernel/runtime, or elapsed-time bounds.
# Ancestor opening can race, but an unexpected FD is rejected BEFORE listing.
# No symlink ancestor is accepted; leaf symlinks are reported without following.

_rlch_fs_snapshot_stat() {
    LC_ALL=C /usr/bin/stat -c '%d|%i|%h|%u|%g|%a|%s|%y|%z|%f' -- "$1"
}
_rlch_fs_snapshot_meta() {
    local data raw dev ino links uid gid mode size mt ct extra
    data="$(_rlch_fs_snapshot_stat "$1" 2>&1)" || return 2
    (( ${#data}<=512 )) || return 2
    [[ "$data" =~ ^[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-7]{1,4}\|[0-9]+\|[0-9:.+\ -]+\|[0-9:.+\ -]+\|[0-9a-f]{4,8}$ ]] || return 2
    IFS='|' read -r dev ino links uid gid mode size mt ct raw extra <<< "$data"
    [[ -z "$extra" && "$dev" =~ ^(0|[1-9][0-9]{0,18})$ && "$ino" =~ ^[1-9][0-9]{0,19}$ &&
       "$links" =~ ^[1-9][0-9]{0,19}$ && "$uid" =~ ^(0|[1-9][0-9]{0,9})$ &&
       "$gid" =~ ^(0|[1-9][0-9]{0,9})$ && "$size" =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 2
    [[ ${#dev} -lt 19 || "x$dev" < x9223372036854775808 ]] || return 2
    [[ ${#size} -lt 19 || "x$size" < x9223372036854775808 ]] || return 2
    [[ ${#ino} -lt 20 || "x$ino" < x18446744073709551616 ]] || return 2
    [[ ${#links} -lt 20 || "x$links" < x18446744073709551616 ]] || return 2
    (( uid<=4294967294 && gid<=4294967294 && (16#$raw & ~0177777)==0 && (16#$raw & 07777)==8#$mode )) || return 2
    printf '%s\n' "$data"
}
_rlch_fs_snapshot_open_meta() {
    LC_ALL=C /usr/bin/stat -Lc '%d|%i|%h|%u|%g|%a|%s|%y|%z|%f' -- "/proc/self/fd/$1"
}
_rlch_fs_snapshot_guard() {
    local dev ino links uid gid mode size mt ct raw
    IFS='|' read -r dev ino links uid gid mode size mt ct raw <<< "$1"
    # Existing ancestors only: sibling creation must not invalidate an intact
    # path. Observed target directories/absence parents keep their FULL stamps.
    printf '%s|%s|%s|%s|%s|%s\n' "$dev" "$ino" "$uid" "$gid" "$mode" "$raw"
}
_rlch_fs_snapshot_names_stream() {
    LC_ALL=C /usr/bin/find -P "$1/." -mindepth 1 -maxdepth 1 -printf '%f\0'
}
_rlch_fs_snapshot_names() {
    local base="$1" output="$2" fd pid rc=0 value='' bytes=0 n
    local -n _rfs_names_out="$output"
    local -a found=() census=()
    # Bound before mapfile/glob allocation too, through the API's VM limit.
    census=("$base"/*)
    (( ${#census[@]}<=16384 && ${#census[@]}+${#_rfs_rows[@]}/12<=16384 )) || return 2
    exec {fd}< <(
        set -o pipefail
        { { _rlch_fs_snapshot_names_stream "$base" 2>&1 1>&3 | /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'; } 3>&1 && printf 'RLCH-SNAPSHOT-END\0'; } |
            /usr/bin/head -c 8388609
    ); pid=$!
    while IFS= read -r -d '' value <&"$fd"; do
        bytes=$((bytes+${#value}+1))
        if (( bytes>8388608 || ${#value}>4096 || ${#found[@]}>16384 )); then rc=2; break; fi
        found+=("$value")
    done
    [[ -z "$value" ]] || rc=2
    exec {fd}<&-
    wait "$pid" || rc=2
    [[ "$rc" == 0 && ${#found[@]} -eq $((${#census[@]}+1)) && "${found[-1]:-}" == RLCH-SNAPSHOT-END ]] || return 2
    unset 'found[-1]'
    # Compare the complete unordered producer population against independent
    # glob entries without interpreting a file name as an array subscript.
    local -A seen=()
    for value in "${found[@]}"; do
        [[ -n "$value" && "$value" != . && "$value" != .. && "$value" != */* && ! ${seen["n:$value"]+yes} ]] || return 2
        seen["n:$value"]=1
    done
    for ((n=0;n<${#census[@]};n++)); do
        value="${census[n]##*/}"
        [[ ${seen["n:$value"]+yes} ]] || return 2
        census[n]="$value"
    done
    _rfs_names_out=("${census[@]}")
}
_rlch_fs_snapshot_scope() {
    local path="$1" evidence="$2" i best=-1 length=0 target dev pair fs id
    dev="${evidence%%|*}"
    pair="$(( (dev>>8 & 4095) | (dev>>32 & 4294963200) )):$(( (dev & 255) | (dev>>12 & 4294967040) ))"
    for ((i=0;i<${#_rfs_mounts[@]};i+=10)); do
        target="${_rfs_mounts[i+4]}"
        if [[ "$target" == / || "$path" == "$target" || "$path" == "$target/"* ]]; then
            if (( ${#target}>length )); then best=$i; length=${#target}; fi
        fi
    done
    (( best>=0 )) || return 2
    [[ "${_rfs_mounts[best+2]}" == "$pair" ]] || return 2
    fs="${_rfs_mounts[best+6]}"; id="${_rfs_mounts[best]}"
    [[ "$fs" != autofs ]] || return 2
    if [[ "$_rfs_policy" == local ]]; then
        case "$fs" in ext2|ext3|ext4|xfs|btrfs|tmpfs|overlay|ramfs) :;; *) return 2;; esac
    fi
    _rfs_seen_mounts["m:$id"]=1
    (( ${#_rfs_seen_mounts[@]}<=64 ))
}
_rlch_fs_snapshot_append() {
    local path="$1" evidence="$2" depth="$3" type="${4:-}" raw dev ino links uid gid mode size mt ct
    IFS='|' read -r dev ino links uid gid mode size mt ct raw <<< "$evidence"
    if [[ -z "$type" ]]; then
        case "$((16#$raw & 0170000))" in
            32768) type=f;; 16384) type=d;; 40960) type=l;; 24576) type=b;; 8192) type=c;; 4096) type=p;; 49152) type=s;; *) return 2;;
        esac
    fi
    _rfs_bytes=$((_rfs_bytes+${#path}+${#evidence}+24))
    (( ${#_rfs_rows[@]}<196608 && _rfs_bytes<=8388608 && ${#path}<=4096 )) || return 2
    _rfs_rows+=("$path" "$type" "$dev" "$ino" "$links" "$uid" "$gid" "$mode" "$size" "$mt" "$ct" "$depth")
}
_rlch_fs_snapshot_walk() {
    local path="$1" anchor="$2" evidence="$3" depth="$4" fd opened after name child data raw
    # shellcheck disable=SC2034 # Arrays consumed through namerefs.
    local -a names=() second=()
    _rlch_fs_snapshot_scope "$path" "$evidence" || return 2
    _rlch_fs_snapshot_append "$path" "$evidence" "$depth" || return 2
    raw="${evidence##*|}"
    (( (16#$raw & 0170000)==0040000 && depth<_rfs_depth )) || return 0
    [[ -r "$anchor" && -x "$anchor" ]] || return 2
    (( (16#$raw & 0444)!=0 && (16#$raw & 0111)!=0 )) || return 2
    { exec {fd}<"$anchor"; } 2>/dev/null || return 2
    opened="$(_rlch_fs_snapshot_open_meta "$fd")" || return 2
    [[ "$opened" == "$evidence" ]] || return 2
    _rlch_fs_snapshot_names "/proc/self/fd/$fd" names || return 2
    for name in "${names[@]}"; do
        child="${path%/}/$name"
        (( ${#child}<=4096 )) || return 2
        data="$(_rlch_fs_snapshot_meta "/proc/self/fd/$fd/$name")" || return 2
        _rlch_fs_snapshot_walk "$child" "/proc/self/fd/$fd/$name" "$data" "$((depth+1))" || return 2
    done
    _rlch_fs_snapshot_names "/proc/self/fd/$fd" second || return 2
    rlch_fs_equal names second || return 2
    after="$(_rlch_fs_snapshot_open_meta "$fd")" || return 2
    [[ "$after" == "$opened" && "$after" == "$(_rlch_fs_snapshot_meta "$anchor")" ]] || return 2
    exec {fd}<&-
}
_rlch_fs_snapshot_pass() {
    local rest="${_rfs_path#/}" part path='' fd next=0 data opened after raw components=0 missing=0
    local -a names=() parents=() parent_data=() parent_paths=()
    _rfs_rows=(); _rfs_bytes=0; _rfs_guards=()
    { exec {fd}</; } 2>/dev/null || return 2
    parents+=("$fd"); parent_paths+=(/)
    data="$(_rlch_fs_snapshot_meta /)" || return 2
    [[ "$data" == "$(_rlch_fs_snapshot_open_meta "$fd")" ]] || return 2
    parent_data+=("$data")
    if [[ "$_rfs_path" == / ]]; then
        _rlch_fs_snapshot_walk / "/proc/self/fd/$fd/." "$data" 0 || return 2
    else
        while [[ -n "$rest" ]]; do
            components=$((components+1)); (( components<=64 )) || return 2
            part="${rest%%/*}"; if [[ "$rest" == */* ]]; then rest="${rest#*/}"; else rest=''; fi
            path+="/$part"
            # Inspect the mounted path before opening it (autofs is rejected).
            local i target
            for ((i=0;i<${#_rfs_mounts[@]};i+=10)); do
                target="${_rfs_mounts[i+4]}"
                [[ "$target" != "$path" || "${_rfs_mounts[i+6]}" != autofs ]] || return 2
            done
            if ! data="$(_rlch_fs_snapshot_meta "/proc/self/fd/$fd/$part")"; then
                _rlch_fs_snapshot_names "/proc/self/fd/$fd" names || return 2
                for opened in "${names[@]}"; do [[ "$opened" != "$part" ]] || return 2; done
                opened="$(_rlch_fs_snapshot_open_meta "$fd")" || return 2
                [[ "$opened" == "${parent_data[-1]}" ]] || return 2
                _rlch_fs_snapshot_append "$_rfs_path" "$opened" 0 a || return 2
                missing=1; break
            fi
            if [[ -z "$rest" ]]; then
                _rlch_fs_snapshot_walk "$path" "/proc/self/fd/$fd/$part" "$data" 0 || return 2
                break
            fi
            raw="${data##*|}"
            (( (16#$raw & 0170000)==0040000 && (16#$raw & 0444)!=0 && (16#$raw & 0111)!=0 )) || return 2
            [[ -r "/proc/self/fd/$fd/$part" && -x "/proc/self/fd/$fd/$part" ]] || return 2
            { exec {next}<"/proc/self/fd/$fd/$part"; } 2>/dev/null || return 2
            opened="$(_rlch_fs_snapshot_open_meta "$next")" || return 2
            [[ "$(_rlch_fs_snapshot_guard "$data")" == "$(_rlch_fs_snapshot_guard "$opened")" ]] || return 2
            fd="$next"; parents+=("$fd"); parent_data+=("$data"); parent_paths+=("$path")
        done
    fi
    for ((next=0;next<${#parents[@]};next++)); do
        fd="${parents[next]}"
        after="$(_rlch_fs_snapshot_open_meta "$fd")" || return 2
        after="$(_rlch_fs_snapshot_guard "$after")"
        [[ "$after" == "$(_rlch_fs_snapshot_guard "${parent_data[next]}")" && "$after" == "$(_rlch_fs_snapshot_guard "$(_rlch_fs_snapshot_meta "${parent_paths[next]}")")" ]] || return 2
        _rfs_guards+=("$after")
        exec {fd}<&-
    done
    (( ${#_rfs_rows[@]}>0 && missing<=1 ))
}
rlch_fs_snapshot() (
    set +x
    export LC_ALL=C
    ulimit -v 262144 || return 2
    [[ $# -eq 4 && "$1" == /* && ${#1} -le 4096 && "$2" =~ ^[0-8]$ && ( "$3" == all || "$3" == local ) ]] || return 2
    [[ "$1" == / || ( "$1" != */ && "$1" != *//* && "$1" != */./* && "$1" != */../* && "$1" != */. && "$1" != */.. ) ]] || return 2
    unset GLOBIGNORE
    shopt -s nullglob dotglob
    shopt -u failglob
    local _rfs_path="$1" _rfs_depth="$2" _rfs_policy="$3" _rfs_bytes=0
    # shellcheck disable=SC2034 # Arrays consumed through namerefs.
    local -a _rfs_mounts=() middle=() final=() _rfs_rows=() first=() _rfs_guards=() guards=()
    local -A _rfs_seen_mounts=()
    mount_inventory _rfs_mounts "$4" || return 2
    local i target
    for ((i=0;i<${#_rfs_mounts[@]};i+=10)); do
        target="${_rfs_mounts[i+4]}"
        if [[ "${_rfs_mounts[i+6]}" == autofs && ( "$target" == / || "$_rfs_path" == "$target" || "$_rfs_path" == "$target/"* || "$target" == "${_rfs_path%/}/"* ) ]]; then return 2; fi
    done
    _rlch_fs_snapshot_pass || return 2
    # shellcheck disable=SC2034 # Guards compared through namerefs.
    first=("${_rfs_rows[@]}")
    # shellcheck disable=SC2034 # Compared through a nameref.
    guards=("${_rfs_guards[@]}")
    mount_inventory middle "$4" || return 2
    rlch_fs_equal _rfs_mounts middle || return 2
    _rlch_fs_snapshot_pass || return 2
    rlch_fs_equal first _rfs_rows && rlch_fs_equal guards _rfs_guards || return 2
    mount_inventory final "$4" || return 2
    rlch_fs_equal _rfs_mounts final || return 2
    printf '%s\0' "${first[@]}" || return 2
) 2>/dev/null
