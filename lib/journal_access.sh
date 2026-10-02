#!/usr/bin/env bash
# Bounded tmpfiles/access observations, not a full tmpfiles interpreter.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/shell_timeout.sh
source "${BASH_SOURCE[0]%/*}/shell_timeout.sh"

rlch_journal_mode() {
    local mode="$1" allowed="$2"
    [[ "$mode" =~ ^[0-7]{3,4}$ && "$allowed" =~ ^[0-7]{3,4}$ ]] || return 2
    (( (8#$mode & ~8#$allowed) == 0 )) || return 1
}
rlch_journal_path() {
    local path="$1" parent
    [[ "$path" == /* && "$path" != *[[:cntrl:]]* && "$path" != *'|'* ]] || return 2
    [[ "$(/usr/bin/realpath -m -s -- "$path")" == "$path" ]] || return 2
    if [[ -e "$path" || -L "$path" ]]; then
        [[ ! -L "$path" && "$(/usr/bin/realpath -e -- "$path")" == "$path" ]] || return 2
    else
        parent="${path%/*}"
        while [[ ! -e "$parent" && ! -L "$parent" ]]; do parent="${parent%/*}"; [[ -n "$parent" ]] || parent=/; done
        rlch_tmout_directory "$parent" >/dev/null || return 2
    fi
}
# Configuration needs readable content. Hash via an identity-checked descriptor.
rlch_journal_config_file() (
    local file="$1" before after fd hash size
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    size="$(/usr/bin/stat -Lc '%s' -- "$file")" || return 2
    [[ "$size" -le 1048576 ]] || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || return 2
    [[ "$before" == "$after" ]] || return 2
    hash="$(/usr/bin/sha256sum <&"$fd")" || return 2
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf '%s|%s\n' "$before" "$hash"
)
rlch_journal_config_snapshot() (
    local root="$1" command="$2" directory file stamp content before after
    local -a directories=(etc/tmpfiles.d run/tmpfiles.d usr/local/lib/tmpfiles.d usr/lib/tmpfiles.d) args=()
    [[ "$root" == / ]] || args+=("--root=$root")
    shopt -s nullglob dotglob
    for directory in "${directories[@]}"; do
        directory="${root%/}/$directory"; rlch_journal_path "$directory" || return 2
        if [[ ! -e "$directory" ]]; then printf 'absent:%s\n' "$directory"; continue; fi
        stamp="$(rlch_tmout_directory "$directory")" || return 2
        printf 'directory:%s|%s\n' "$directory" "$stamp"
        for file in "$directory"/*.conf; do
            [[ "$file" != *[[:cntrl:]]* && "$file" != *'|'* ]] || return 2
            # /dev/null mask is the one documented intentional config symlink.
            if [[ -L "$file" ]]; then
                [[ "$(/usr/bin/readlink -- "$file")" == /dev/null ]] || return 2
                stamp="$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%s:%y:%z' -- "$file")" || return 2
            else stamp="$(rlch_journal_config_file "$file")" || return 2; fi
            printf 'config:%s|%s\n' "$file" "$stamp"
        done
    done
    file="${root%/}/etc/machine-id"
    before="$(rlch_journal_config_file "$file")" || return 2
    content="$(cat -- "$file")" || return 2
    [[ "$content" =~ ^[a-f0-9]{32}$ && "$content" != 00000000000000000000000000000000 ]] || return 2
    after="$(rlch_journal_config_file "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf 'machine:%s|%s\n===program===\n' "$content" "$before"
    set -o pipefail
    LC_ALL=C SYSTEMD_PAGER=cat "$command" --cat-config --no-pager "${args[@]}" 2>/dev/null | LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1; clean=$0; gsub(/\t/,"",clean)
         if(bytes>4194304 || length($0)>8192 || index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) exit 2; print}
    ' || return 2
)

# Numeric ACLs from getfacl -c -n -E -P. Additional effective named grants are
# organizational decisions: ERROR, never an invented CIS violation. Base ACL
# group permissions may be masked; POSIX stat evaluates that group-class mask.
rlch_journal_acl_review() {
    LC_ALL=C /usr/bin/awk -F: '
        function bits(s,n,i) {n=0;for(i=1;i<=3;i++) {c=substr(s,i,1); if(c!="-") n+=2^(3-i)} return n}
        /^[ \t]*$/ {next}
        {
            if($0 ~ /[[:cntrl:]]/) {bad=1; next}
            default_acl=($1=="default"); if(default_acl) {k=$2;name=$3;p=$4; if(NF!=4) bad=1} else {k=$1;name=$2;p=$3;if(NF!=3) bad=1}
            if(k !~ /^(user|group|mask|other)$/ || p !~ /^[r-][w-][x-]$/) {bad=1; next}
            key=default_acl ":" k ":" name; if(seen[key]++) bad=1
            if(name!="" && name !~ /^[0-9]+$/) bad=1
            if(name!="" && k !~ /^(user|group)$/) bad=1
            if(name!="") grants[default_acl ":" name ":" k]=bits(p)
            if(k=="mask") mask[default_acl]=bits(p)
            if(default_acl) has_default=1
        }
        END {
            if(!seen["0:user:"] || !seen["0:group:"] || !seen["0:other:"]) bad=1
            if(has_default && (!seen["1:user:"] || !seen["1:group:"] || !seen["1:other:"])) bad=1
            for(key in grants) {split(key,a,":");m=(a[1] in mask ? mask[a[1]] : 7); for(i=0;i<3;i++) if(int(grants[key]/2^i)%2 && int(m/2^i)%2) bad=1}
            if(bad) exit 2
        }
    '
}
rlch_journal_object_stamp() {
    rlch_journal_path "$1" || return 2
    # Deliberately omit size/mtime/ctime: appending records is normal and does
    # not change access. Mode 0000 is observable without reading journal data.
    /usr/bin/stat -c '%d:%i:%f:%u:%g:%a' -- "$1"
}
rlch_journal_tree_snapshot() (
    local root="$1" acl_command="$2" path stamp after acl name count=0 index=0
    local -a queue=("${root%/}/run/log/journal" "${root%/}/var/log/journal") children=()
    shopt -s nullglob dotglob
    while [[ "$index" -lt ${#queue[@]} ]]; do
        path="${queue[$index]}"; index=$((index+1)); count=$((count+1)); [[ "$count" -le 16384 ]] || return 2
        rlch_journal_path "$path" || return 2
        if [[ ! -e "$path" ]]; then printf 'absent:%s\n' "$path"; continue; fi
        stamp="$(rlch_journal_object_stamp "$path")" || return 2
        if [[ -d "$path" ]]; then
            rlch_tmout_directory "$path" >/dev/null || return 2
            children=("$path"/*); queue+=("${children[@]}")
            [[ ${#queue[@]} -le 16384 ]] || return 2
        elif [[ ! -f "$path" ]]; then return 2; fi
        name="${path##*/}"
        if [[ -d "$path" || "$name" == *.journal || "$name" == *.journal~ ]]; then
            # Physical traversal plus identity checks: never read journal body.
            set -o pipefail
            acl="$(LC_ALL=C "$acl_command" -c -n -E -P -- "$path" 2>/dev/null | LC_ALL=C /usr/bin/awk '
                {bytes+=length($0)+1; if(bytes>65536 || index($0,sprintf("%c",0))) exit 2; print}
            ')" || return 2
            [[ ${#acl} -le 65536 ]] || return 2
            rlch_journal_acl_review <<< "$acl" || return 2
            printf 'acl:%s|%s\n' "$path" "$(/usr/bin/sha256sum <<< "$acl")"
        fi
        after="$(rlch_journal_object_stamp "$path")" || return 2
        [[ "$stamp" == "$after" ]] || return 2
        if [[ -f "$path" && ( "$name" == *.journal || "$name" == *.journal~ ) ]]; then
            printf 'journal:%s|%s\n' "$path" "$stamp"
        else printf 'object:%s|%s\n' "$path" "$stamp"; fi
    done
)
