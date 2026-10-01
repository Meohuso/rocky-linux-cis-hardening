#!/usr/bin/env bash
# Read-only shell-policy observation and isolated create-only transactions.
# SPDX-License-Identifier: MIT

rlch_tmout_directory() {
    local path="$1" canonical mode
    [[ -d "$path" && -r "$path" && -x "$path" && ! -L "$path" ]] || return 2
    canonical="$(/usr/bin/realpath -e -- "$path" 2>/dev/null)" || return 2
    [[ "$canonical" == "$path" ]] || return 2
    mode="$(/usr/bin/stat -Lc '%a' -- "$path")" || return 2
    (( (8#$mode & 0444) != 0 && (8#$mode & 0111) != 0 )) || return 2
    /usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "$path"
}

rlch_tmout_file_stamp() {
    local file="$1" canonical mode
    [[ -f "$file" && -r "$file" && ! -L "$file" ]] || return 2
    canonical="$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" || return 2
    [[ "$canonical" == "$file" ]] || return 2
    mode="$(/usr/bin/stat -Lc '%a' -- "$file")" || return 2
    (( (8#$mode & 0444) != 0 )) || return 2
    /usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "$file"
}

# Includes hidden .sh files, matching the OVAL filename expression. No symlinks
# are followed, and all inspection errors remain errors rather than empty sets.
rlch_tmout_inventory() {
    local profile="$1" directory="$2" file parent
    RLCH_TMOUT_FILES=()
    if [[ -e "$profile" || -L "$profile" ]]; then
        rlch_tmout_file_stamp "$profile" >/dev/null || return 2
        RLCH_TMOUT_FILES+=("$profile")
    else
        parent="${profile%/*}"
        rlch_tmout_directory "$parent" >/dev/null || return 2
    fi
    if [[ -e "$directory" || -L "$directory" ]]; then
        rlch_tmout_directory "$directory" >/dev/null || return 2
        for file in "$directory"/*.sh "$directory"/.*.sh; do
            [[ -e "$file" || -L "$file" ]] || continue
            [[ "$file" != *[[:cntrl:]]* ]] || return 2
            rlch_tmout_file_stamp "$file" >/dev/null || return 2
            RLCH_TMOUT_FILES+=("$file")
        done
    else
        rlch_tmout_directory "${directory%/*}" >/dev/null || return 2
    fi
}

rlch_tmout_fingerprint() {
    local profile="$1" directory="$2" file
    rlch_tmout_inventory "$profile" "$directory" || return 2
    if [[ -d "$directory" ]]; then rlch_tmout_directory "$directory" || return 2; else printf 'directory absent\n'; fi
    if [[ ! -e "$profile" ]]; then printf 'profile absent\n'; fi
    for file in "${RLCH_TMOUT_FILES[@]}"; do
        printf '%s\n' "$file"
        rlch_tmout_file_stamp "$file" || return 2
    done
}

# Print only count|finding|active. No script contents are emitted or executed.
rlch_tmout_scan_file() {
    local file="$1" limit="$2" before after fd result=0 rows
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || after=''
    if [[ "$before" != "$after" ]]; then exec {fd}<&-; return 2; fi
    rows="$(LC_ALL=C /usr/bin/awk -v limit="$limit" '
        {clean=$0; gsub(/\t/, "", clean)
         if (index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) {bad=1; next}}
        /^[[:space:]]*(#|$)/ {next}
        {sub(/[[:space:]]+#.*$/, "", $0)}
        /^[[:space:]]*(if|elif|for|while|until|case|select|function)([[:space:]]|$)/ || /[{}]/ || /\\[[:space:]]*$/ {dynamic=1}
        /TMOUT/ {
            line=$0; active++
            # Only complete literal standalone statements are safely classified.
            sub(/[[:space:]]+#.*$/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line ~ /^[[:space:]]*(typeset|declare)[[:space:]]+-xr[[:space:]]+TMOUT=[0-9]+$/) {
                sub(/^.*TMOUT=/, "", line)
                if (length(line)>10) {bad=1; next}
                # Reject leading-zero ambiguity instead of assuming every shell
                # interprets the integer exactly like OVAL.
                if (line ~ /^0[0-9]+$/) {bad=1; next}
                count++; if (line+0<1 || line+0>limit) finding=1
            } else if (line ~ /^[[:space:]]*((typeset|declare)[[:space:]]+-[a-zA-Z]+[[:space:]]+|export[[:space:]]+|readonly[[:space:]]+)?TMOUT[[:space:]]*=[[:space:]]*-?[0-9]+$/ || line ~ /^[[:space:]]*(readonly|export)[[:space:]]+TMOUT$/) {
                finding=1
            } else bad=1
        }
        END {if (bad || (active && dynamic)) exit 2; print count+0 "|" finding+0 "|" active+0}
    ' <&"$fd" 2>/dev/null)" || result=2
    exec {fd}<&-
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$result" -eq 0 && "$before" == "$after" ]] || return 2
    printf '%s\n' "$rows"
}

# Mutations require a canonical directory owned by the invoking privileged UID,
# with no group/other write bits. Privilege is checked by the module separately.
rlch_tmout_writable_directory() {
    local path="$1" owner mode
    rlch_tmout_directory "$path" >/dev/null || return 2
    owner="$(/usr/bin/stat -Lc '%u' -- "$path")" || return 2
    mode="$(/usr/bin/stat -Lc '%a' -- "$path")" || return 2
    if [[ "$owner" != "$EUID" ]] || (( (8#$mode & 0022) != 0 )); then return 2; fi
    # Ancestors must also be trusted. Root-owned sticky directories (e.g. the
    # test runner's /tmp) protect already-owned child names from other users.
    while [[ "$path" != / ]]; do
        path="${path%/*}"; [[ -n "$path" ]] || path=/
        owner="$(/usr/bin/stat -Lc '%u' -- "$path")" || return 2
        mode="$(/usr/bin/stat -Lc '%a' -- "$path")" || return 2
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 2
        if (( (8#$mode & 0022) != 0 )); then
            if [[ "$owner" != 0 ]] || (( (8#$mode & 01000) == 0 )); then return 2; fi
        fi
    done
}

rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; }
rlch_tmout_remove() { /usr/bin/rm -- "$1"; }

rlch_tmout_payload_identity() {
    rlch_tmout_file_stamp "$1" >/dev/null || return 2
    /usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "$1" || return 2
    /usr/bin/sha256sum < "$1" || return 2
}

# Called with the transaction-directory flock held. A hard link to the retained
# payload proves the created inode; a separate identity/hash detects edits to
# both hard links. Final timestamps additionally reject edit-and-restore cases.
rlch_tmout_created_matches() {
    local state="$1" target="$2" expected current
    [[ -f "$state/identity" && ! -L "$state/identity" && -f "$state/payload" && ! -L "$state/payload" ]] || return 2
    [[ -f "$target" && ! -L "$target" && "$target" -ef "$state/payload" ]] || return 2
    expected="$(cat -- "$state/identity")" || return 2
    current="$(rlch_tmout_payload_identity "$target")" || return 2
    [[ "$current" == "$expected" ]] || return 2
    if [[ -e "$state/installed" || -L "$state/installed" ]]; then
        [[ -f "$state/installed" && ! -L "$state/installed" ]] || return 2
        expected="$(cat -- "$state/installed")" || return 2
        current="$(rlch_tmout_file_stamp "$target")" || return 2
        [[ "$current" == "$expected" ]] || return 2
    fi
}

rlch_tmout_restore_created() {
    local state="$1" target="$2"
    [[ -f "$state/identity" && ! -L "$state/identity" && -f "$state/payload" && ! -L "$state/payload" ]] || return 2
    if [[ -e "$target" || -L "$target" ]]; then
        rlch_tmout_created_matches "$state" "$target" || return 2
        rlch_tmout_remove "$target" || return 2
    else
        # An absent file after a completed transaction is an administrator edit.
        [[ ! -e "$state/installed" && ! -L "$state/installed" ]] || return 2
    fi
    /usr/bin/rm -f -- "$state/installed" "$state/identity" "$state/payload" || return 2
    /usr/bin/rmdir -- "$state" || return 2
}
