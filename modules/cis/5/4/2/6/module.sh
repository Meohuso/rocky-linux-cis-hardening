#!/usr/bin/env bash
# CIS 5.4.2.6 - Restricted static root-file audit; never execute root scripts.
# SPDX-License-Identifier: MIT
RLCH_CIS_5_4_2_6_BASH_PROFILE="${RLCH_CIS_5_4_2_6_BASH_PROFILE:-/root/.bash_profile}"
RLCH_CIS_5_4_2_6_BASHRC="${RLCH_CIS_5_4_2_6_BASHRC:-/root/.bashrc}"

rlch_5_4_2_6_mask() {
    local argument="$1" clause who permissions group_seen=0 user_seen=0 other_seen=0
    local allowed=0 bits shift
    # Quotes are accepted only around an otherwise complete literal argument.
    if [[ "$argument" == \"*\" || "$argument" == \'*\' ]]; then
        argument="${argument:1:${#argument}-2}"
    fi
    if [[ "$argument" =~ ^[0-7]{1,4}$ ]]; then
        printf '%s\n' "$((8#$argument & 0777))"
        return 0
    fi
    # Only complete absolute symbolic assignments are independent of inherited
    # umask. Relative operations, variables, substitutions and partial forms
    # cannot be safely evaluated statically.
    [[ "$argument" =~ ^[ugo]=[rwx]*(,[ugo]=[rwx]*){2}$ ]] || return 2
    while :; do
        clause="${argument%%,*}"
        who="${clause%%=*}"
        permissions="${clause#*=}"
        case "$who" in
            u) user_seen=$((user_seen + 1)); shift=6 ;;
            g) group_seen=$((group_seen + 1)); shift=3 ;;
            o) other_seen=$((other_seen + 1)); shift=0 ;;
            *) return 2 ;;
        esac
        bits=0
        [[ "$permissions" != *r* ]] || bits=$((bits | 4))
        [[ "$permissions" != *w* ]] || bits=$((bits | 2))
        [[ "$permissions" != *x* ]] || bits=$((bits | 1))
        allowed=$((allowed | (bits << shift)))
        [[ "$argument" == *,* ]] || break
        argument="${argument#*,}"
    done
    [[ "$user_seen" -eq 1 && "$group_seen" -eq 1 && "$other_seen" -eq 1 ]] || return 2
    printf '%s\n' "$((0777 ^ allowed))"
}

rlch_5_4_2_6_file() {
    local file="$1" label="$2" parent canonical before after mode fd line argument
    local mask='' result=0 number=0
    local statement='^[[:space:]]*umask[[:space:]]+([^[:space:]]+)([[:space:]]+#.*)?[[:space:]]*$'
    if [[ ! -e "$file" && ! -L "$file" ]]; then
        parent="${file%/*}"
        [[ -d "$parent" && -x "$parent" ]] || return 2
        canonical="$(/usr/bin/realpath -e -- "$parent" 2>/dev/null)" || return 2
        [[ "$canonical" == "$parent" ]] || return 2
        # No root-specific overriding declaration; inherited policy is separate.
        return 0
    fi
    [[ -f "$file" && -r "$file" && ! -L "$file" ]] || return 2
    canonical="$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" || return 2
    [[ "$canonical" == "$file" ]] || return 2
    before="$(/usr/bin/stat -Lc '%d:%i:%s:%y:%z:%a' -- "$file" 2>/dev/null)" || return 2
    mode="${before##*:}"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 2
    (( (8#$mode & 0444) != 0 )) || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%s:%y:%z:%a' -- "/proc/self/fd/$fd" 2>/dev/null)" || after=''
    if [[ "$before" != "$after" ]]; then
        exec {fd}<&-
        return 2
    fi
    # Bash read silently drops NUL bytes; reject them before parsing.
    if ! LC_ALL=C /usr/bin/awk 'index($0, sprintf("%c",0)) {exit 2} {line=$0; gsub(/\t/, "", line); if (line ~ /[[:cntrl:]]/) exit 2}' "/proc/self/fd/$fd" 2>/dev/null; then
        result=2
    fi
    # awk uses its own file description through /proc, preserving fd position.
    while IFS= read -r line <&"$fd" || [[ -n "$line" ]]; do
        number=$((number + 1))
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*:[[:space:]]*(#.*)?$ ]] && continue
        if [[ "$line" =~ $statement ]]; then
            argument="${BASH_REMATCH[1]}"
            mask="$(rlch_5_4_2_6_mask "$argument")" || result=2
        else
            printf 'CIS 5.4.2.6: %s line %s requires manual shell-semantics review\n' "$label" "$number" >&2
            result=2
        fi
    done
    exec {fd}<&-
    after="$(/usr/bin/stat -Lc '%d:%i:%s:%y:%z:%a' -- "$file" 2>/dev/null)" || return 2
    canonical="$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" || return 2
    [[ "$before" == "$after" && "$canonical" == "$file" && ! -L "$file" ]] || return 2
    [[ "$result" -eq 0 ]] || return 2
    # 027 or more restrictive means all required denial bits, not a numeric >=.
    if [[ -n "$mask" ]] && (( (mask & 0027) != 0027 )); then
        printf 'CIS 5.4.2.6: %s last literal umask permits access forbidden by 027\n' "$label" >&2
        return 1
    fi
    return 0
}

check() {
    local first=0 second=0
    rlch_5_4_2_6_file "$RLCH_CIS_5_4_2_6_BASH_PROFILE" .bash_profile || first=$?
    rlch_5_4_2_6_file "$RLCH_CIS_5_4_2_6_BASHRC" .bashrc || second=$?
    if [[ "$first" -eq 2 || "$second" -eq 2 ]]; then
        printf 'CIS 5.4.2.6: root umask configuration cannot be safely interpreted\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$first" -eq 0 && "$second" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]]; then
        printf 'CIS 5.4.2.6: manual remediation required; review root startup ordering and configure umask 027 or a stricter bitmask at the appropriate source\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
