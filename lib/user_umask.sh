#!/usr/bin/env bash
# Default-user umask observation; file helpers only are shared with TMOUT.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/shell_timeout.sh
source "${BASH_SOURCE[0]%/*}/shell_timeout.sh"

rlch_umask_walk() {
    local directory="$1" root="$2" entry
    rlch_tmout_directory "$directory" >/dev/null || return 2
    RLCH_UMASK_DIRS+=("$directory")
    for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        [[ "$entry" != *[[:cntrl:]]* && ! -L "$entry" ]] || return 2
        if [[ -d "$entry" ]]; then
            [[ "$entry" != *.sh && "$entry" != "$root/sh.local" ]] || return 2
            # Isolated transaction state is not a profile configuration tree.
            [[ "$entry" != "$root/.rlch-5.4.3.3" && "$entry" != "$root/.rlch-5.4.3.2" ]] || continue
            rlch_umask_walk "$entry" "$root" || return 2
        elif [[ "$entry" == *.sh || "$entry" == "$root/sh.local" ]]; then
            rlch_tmout_file_stamp "$entry" >/dev/null || return 2
            RLCH_UMASK_PROFILE_FILES+=("$entry")
        fi
    done
}
rlch_umask_inventory() {
    local bashrc="$1" defs="$2" profile="$3" directory="$4" file
    RLCH_UMASK_PROFILE_FILES=(); RLCH_UMASK_DIRS=()
    for file in "$bashrc" "$defs" "$profile"; do
        if [[ -e "$file" || -L "$file" ]]; then
            rlch_tmout_file_stamp "$file" >/dev/null || return 2
        else
            rlch_tmout_directory "${file%/*}" >/dev/null || return 2
        fi
    done
    if [[ -e "$profile" ]]; then RLCH_UMASK_PROFILE_FILES+=("$profile"); fi
    if [[ -e "$directory" || -L "$directory" ]]; then
        rlch_umask_walk "$directory" "$directory" || return 2
    else
        rlch_tmout_directory "${directory%/*}" >/dev/null || return 2
    fi
}
rlch_umask_fingerprint() {
    local bashrc="$1" defs="$2" profile="$3" directory="$4" file dir
    rlch_umask_inventory "$@" || return 2
    for dir in "${RLCH_UMASK_DIRS[@]}"; do
        printf '%s\n' "$dir"; rlch_tmout_directory "$dir" || return 2
    done
    [[ -e "$directory" ]] || printf 'profile directory absent\n'
    for file in "$bashrc" "$defs" "${RLCH_UMASK_PROFILE_FILES[@]}"; do
        printf '%s\n' "$file"
        if [[ -e "$file" ]]; then rlch_tmout_file_stamp "$file" || return 2; else printf 'absent\n'; fi
    done
    [[ -e "$profile" ]] || printf 'profile absent\n'
}

# Sanitized octal values and whether the exact RHEL OVAL form recognizes them.
# Empty output means no active declaration. Scripts are never executed.
rlch_umask_scan() {
    local file="$1" kind="$2" before after fd rows result=0
    [[ -e "$file" || -L "$file" ]] || return 0
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || after=''
    if [[ "$before" != "$after" ]]; then exec {fd}<&-; return 2; fi
    rows="$(LC_ALL=C /usr/bin/awk -v kind="$kind" '
        {clean=$0; gsub(/\t/, "", clean); if (index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) {bad=1; next}}
        /^[[:space:]]*(#|$)/ {next}
        {raw=$0; sub(/[[:space:]]+#.*$/, "", $0)}
        kind!="defs" && (/^[[:space:]]*(if|elif|for|while|until|case|select|function)([[:space:]]|$)/ || /[{}]/ || /\\[[:space:]]*$/) {dynamic=1}
        (kind=="defs" && /^[[:space:]]*UMASK([[:space:]=]|$)/) || (kind!="defs" && /(^|[^a-zA-Z0-9_])umask([^a-zA-Z0-9_]|$)/) {
            active++; line=$0; sub(/[[:space:]]+$/, "", line)
            if ((kind=="defs" && line !~ /^[[:space:]]*UMASK[[:space:]]+[0-7][0-7][0-7]$/) || (kind!="defs" && line !~ /^[[:space:]]*umask[[:space:]]+[0-7][0-7][0-7]$/)) {bad=1; next}
            sub(/^.*[[:space:]]/, "", line)
            recognized=(kind!="bashrc" || raw ~ /^[[:space:]]*umask[[:space:]]+[0-7][0-7][0-7][[:space:]]*$/)
            out[++n]=line "|" recognized
        }
        END {if (bad || (active && dynamic)) exit 2; for (i=1;i<=n;i++) print out[i]}
    ' <&"$fd" 2>/dev/null)" || result=2
    exec {fd}<&-
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$result" -eq 0 && "$before" == "$after" ]] || return 2
    [[ -z "$rows" ]] || printf '%s\n' "$rows"
}
