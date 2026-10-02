#!/usr/bin/env bash
# Static direct-line AIDE observation; deliberately not an AIDE interpreter.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/aide_observation.sh
source "${BASH_SOURCE[0]%/*}/aide_observation.sh"

# Trust existing ancestors without requiring write access. Root-owned sticky
# ancestors permit private Bats directories below /tmp, never the file parent.
rlch_aide_tools_trust() {
    local file="$1" path="${1%/*}" owner mode first=1
    [[ "$file" == /* && "$(/usr/bin/realpath -m -s -- "$file")" == "$file" ]] || return 2
    if [[ -e "$file" || -L "$file" ]]; then
        rlch_tmout_file_stamp "$file" >/dev/null || return 2
        owner="$(/usr/bin/stat -Lc '%u' -- "$file")" || return 2
        mode="$(/usr/bin/stat -Lc '%a' -- "$file")" || return 2
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 2
        (( (8#$mode & 0022) == 0 )) || return 2
    fi
    while [[ ! -e "$path" && ! -L "$path" ]]; do
        [[ "$path" != / ]] || return 2
        path="${path%/*}"; [[ -n "$path" ]] || path=/
    done
    while :; do
        rlch_tmout_directory "$path" >/dev/null || return 2
        owner="$(/usr/bin/stat -Lc '%u' -- "$path")" || return 2
        mode="$(/usr/bin/stat -Lc '%a' -- "$path")" || return 2
        [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 2
        if (( (8#$mode & 0022) != 0 )); then
            [[ "$first" -eq 0 && "$owner" == 0 ]] || return 2
            (( (8#$mode & 01000) != 0 )) || return 2
        fi
        [[ "$path" != / ]] || break
        first=0; path="${path%/*}"; [[ -n "$path" ]] || path=/
    done
}

# Snapshot includes metadata and content. Open-descriptor identity is compared
# with the canonical pathname before/after reads; neither hash nor content is
# printed by the module. Bounded input prevents unbounded parser allocation.
rlch_aide_tools_snapshot() (
    local file="$1" before after fd hash size
    rlch_aide_tools_trust "$file" || return 2
    if [[ ! -e "$file" && ! -L "$file" ]]; then
        rlch_aide_absent_stamp "$file" || return 2
        return 0
    fi
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

# Arguments: config, space-separated tool inventory, exact accepted attribute
# lists. Policy values live in the CIS module. First matching direct occurrence
# is authoritative, as in OVAL instance=1. A later nonconforming occurrence
# following a conforming first occurrence is an ambiguity (ERROR).
rlch_aide_tools_rows() (
    local file="$1" tools="$2" attrs="$3" richer="$4" before after stamp fd result=0
    before="$(rlch_aide_tools_snapshot "$file")" || return 2
    [[ -e "$file" || -L "$file" ]] || return 1
    stamp="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || return 2
    [[ "$stamp" == "$after" ]] || return 2
    LC_ALL=C /usr/bin/awk -v tools="$tools" -v attrs="$attrs" -v richer="$richer" '
        BEGIN {count=split(tools,names," "); }
        {
            clean=$0; gsub(/\t/,"",clean)
            if(length($0)>8192 || index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) {unsafe=1; next}
        }
        /^[ \t]*(#|$)/ {next}
        /^[ \t]*@@/ {
            # Only inert static definitions are supported. Includes, conditions,
            # substitutions and executable expansion cannot be audited here.
            if($0 !~ /^@@define[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]+[^@]+$/) unsafe=1
            next
        }
        # Known inert database/report settings do not select audit tools.
        /^(database|database_in|database_out|report_url)[ \t]*=/ {next}
        /@@\{|@@\(/ {unsafe=1; next}
        {
            for(i=1;i<=count;i++) {
                tool=names[i]
                pattern="^(/usr)?/sbin/" tool "[ \t]+[^\n]+$"
                if($0 ~ pattern) {
                    value=$0; sub("^(/usr)?/sbin/" tool "[ \t]+","",value)
                    good=(value==attrs || value==richer)
                    # A named group is not statically expanded or executed.
                    if(value ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && value !~ /^(sha[0-9]+|md5)$/) unsafe=1
                    if(!seen[tool]++) first[tool]=good
                    else if(first[tool] && !good) unsafe=1
                } else if($0 ~ "^[ \t]*[!=-](/usr)?/sbin/" tool "([ \t$]|$)") unsafe=1
            }
        }
        END {
            if(unsafe) exit 2
            for(i=1;i<=count;i++) if(!seen[names[i]] || !first[names[i]]) exit 1
            exit 0
        }
    ' <&"$fd" 2>/dev/null || result=$?
    after="$(rlch_aide_tools_snapshot "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    return "$result"
)
