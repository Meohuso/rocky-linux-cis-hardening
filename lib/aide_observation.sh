#!/usr/bin/env bash
# Strict RPM and AIDE configuration observation; no installation or init.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/shell_timeout.sh
source "${BASH_SOURCE[0]%/*}/shell_timeout.sh"

# The generic boolean RPM helper conflates absent packages and query failures.
rlch_aide_package_status() {
    local command="$1" output result=0 line
    output="$(LC_ALL=C "$command" -q --qf '%{NAME}\n' aide 2>&1)" || result=$?
    if [[ "$result" -eq 0 && -n "$output" ]]; then
        while IFS= read -r line; do [[ "$line" == aide ]] || return 2; done <<< "$output"
        return 0
    fi
    if [[ "$result" -eq 1 && "$output" == 'package aide is not installed' ]]; then return 1; fi
    return 2
}

# Observe a safely absent path from its nearest existing ancestor. No guessed
# backend or directory is created and no pathname is printed in diagnostics.
rlch_aide_absent_stamp() {
    local file="$1" parent="${1%/*}" stamp
    [[ "$file" == /* && ! -e "$file" && ! -L "$file" ]] || return 2
    while [[ ! -e "$parent" && ! -L "$parent" ]]; do
        [[ "$parent" != / ]] || return 2
        parent="${parent%/*}"; [[ -n "$parent" ]] || parent=/
    done
    stamp="$(rlch_tmout_directory "$parent")" || return 2
    printf 'absent:%s\n' "$stamp"
}
rlch_aide_config_stamp() {
    if [[ -e "$1" || -L "$1" ]]; then rlch_tmout_file_stamp "$1"; else rlch_aide_absent_stamp "$1"; fi
}

# Print only first DBDIR|first operational URI. Reject conflicting definitions
# instead of assuming the database_out comment also defines input precedence.
rlch_aide_config_rows() {
    local file="$1" before after fd rows result=0
    [[ -e "$file" || -L "$file" ]] || return 1
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || after=''
    if [[ "$before" != "$after" ]]; then exec {fd}<&-; return 2; fi
    rows="$(LC_ALL=C /usr/bin/awk '
        {clean=$0; gsub(/\t/, "", clean); if (index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/ || /\|/) {bad=1; next}}
        /^[[:space:]]*(#|$)/ {next}
        /^[[:space:]]*@@/ && $0 !~ /^[[:space:]]*@@define[[:space:]]/ {bad=1; next}
        /^[[:space:]]*@@define[[:space:]]+DBDIR([[:space:]]|$)/ {
            if ($0 !~ /^@@define[ \t]DBDIR[ \t]+\/[^[:space:]#@]+$/) {bad=1; next}
            value=$0; sub(/^@@define[ \t]DBDIR[ \t]+/, "", value)
            if (dir!="" && dir!=value) bad=1
            if (dir=="") dir=value
            next
        }
        /^[[:space:]]*database(_in)?([[:space:]=]|$)/ {
            if ($0 !~ /^database(_in)?=file:(@@\{DBDIR\})?\/([a-z.]+\/)*[a-z.]+$/) {bad=1; next}
            value=$0; sub(/^database(_in)?=file:/, "", value)
            if (uri!="" && uri!=value) bad=1
            if (uri=="") uri=value
        }
        END {if (bad) exit 2; print (dir=="" ? "missing" : dir) "|" (uri=="" ? "missing" : uri)}
    ' <&"$fd" 2>/dev/null)" || result=2
    exec {fd}<&-
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$result" -eq 0 && "$before" == "$after" ]] || return 2
    printf '%s\n' "$rows"
}

# A present artifact must be regular, safely readable, stable and nonempty.
# No --check, format decode or filesystem scan is performed.
rlch_aide_database_stamp() {
    local file="$1" before after fd size
    if [[ ! -e "$file" && ! -L "$file" ]]; then
        rlch_aide_absent_stamp "$file" || return 2
        return 1
    fi
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || after=''
    exec {fd}<&-
    [[ "$before" == "$after" ]] || return 2
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    size="$(/usr/bin/stat -Lc '%s' -- "$file")" || return 2
    printf '%s\n' "$after"
    [[ "$size" -gt 0 ]] || return 1
    return 0
}
