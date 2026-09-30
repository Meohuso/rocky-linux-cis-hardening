#!/usr/bin/env bash
# CIS 5.4.2.5 - Observe the evaluating root process environment, as CAS does.
# SPDX-License-Identifier: MIT

# Never resolve inspection utilities using the PATH that is under assessment.
rlch_5_4_2_5_uid() { /usr/bin/id -u; }
rlch_5_4_2_5_stat() { /usr/bin/stat -L -c '%d:%i:%u:%a:%f:%y:%z' -- "$1" 2>/dev/null; }
rlch_5_4_2_5_realpath() { /usr/bin/realpath -e -- "$1" 2>/dev/null; }
rlch_5_4_2_5_finding() { printf 'CIS 5.4.2.5: PATH entry %s: %s\n' "$1" "$2" >&2; }

# Confirm that a nonexistent entry has a searchable, inspectable ancestor.
# Otherwise absence and inability to inspect cannot safely be distinguished.
rlch_5_4_2_5_missing() {
    local ancestor="${1%/*}"
    [[ -n "$ancestor" ]] || ancestor=/
    while [[ ! -e "$ancestor" && ! -L "$ancestor" ]]; do
        ancestor="${ancestor%/*}"
        [[ -n "$ancestor" ]] || ancestor=/
    done
    [[ -d "$ancestor" && -x "$ancestor" ]] || return 2
    rlch_5_4_2_5_stat "$ancestor" >/dev/null || return 2
    return 0
}

check() {
    local uid root_path remaining component more index=0 finding=0 unsafe=0
    local before after resolved resolved_after device inode owner mode kind rest
    uid="$(rlch_5_4_2_5_uid)" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$uid" != 0 || "${PATH+x}" != x ]]; then
        printf 'CIS 5.4.2.5: evaluation requires root and its effective PATH environment\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    root_path="$PATH"
    remaining="$root_path"
    while :; do
        more=0
        if [[ "$remaining" == *:* ]]; then
            component="${remaining%%:*}"
            remaining="${remaining#*:}"
            more=1
        else
            component="$remaining"
        fi
        index=$((index + 1))
        if [[ -z "$component" ]]; then
            rlch_5_4_2_5_finding "$index" 'empty component denotes the current directory'
            finding=1
        elif [[ "$component" == . ]]; then
            rlch_5_4_2_5_finding "$index" 'dot denotes the current directory'
            finding=1
        elif [[ "$component" != /* ]]; then
            rlch_5_4_2_5_finding "$index" 'relative path'
            finding=1
        elif [[ "$component" == *..* || ( "$more" -eq 0 && "$component" == *. ) ]]; then
            rlch_5_4_2_5_finding "$index" 'period pattern rejected by CAS root_path_no_dot'
            finding=1
        elif [[ ! -e "$component" ]]; then
            if [[ -L "$component" ]]; then
                rlch_5_4_2_5_finding "$index" 'symlink has no accessible directory target'
                finding=1
            elif rlch_5_4_2_5_missing "$component"; then
                rlch_5_4_2_5_finding "$index" 'directory does not exist'
                finding=1
            else
                rlch_5_4_2_5_finding "$index" 'cannot safely establish directory existence'
                unsafe=1
            fi
        else
            before="$(rlch_5_4_2_5_stat "$component")" || before=''
            resolved="$(rlch_5_4_2_5_realpath "$component")" || resolved=''
            IFS=: read -r device inode owner mode kind rest <<< "$before"
            if [[ ! "$device" =~ ^[0-9]+$ || ! "$inode" =~ ^[0-9]+$ || ! "$owner" =~ ^[0-9]+$ || ! "$mode" =~ ^[0-7]{3,4}$ || ! "$kind" =~ ^[0-9a-fA-F]+$ || -z "$resolved" || -z "$rest" ]]; then
                rlch_5_4_2_5_finding "$index" 'cannot safely inspect directory metadata'
                unsafe=1
            else
                if (( (16#$kind & 0170000) != 0040000 )); then
                    rlch_5_4_2_5_finding "$index" 'entry is not a directory'
                    finding=1
                else
                    if [[ "$owner" != 0 ]]; then
                        rlch_5_4_2_5_finding "$index" 'directory target is not owned by root'
                        finding=1
                    fi
                    if (( (8#$mode & 0020) != 0 )); then
                        rlch_5_4_2_5_finding "$index" 'directory target is group-writable'
                        finding=1
                    fi
                    if (( (8#$mode & 0002) != 0 )); then
                        rlch_5_4_2_5_finding "$index" 'directory target is world-writable'
                        finding=1
                    fi
                fi
                after="$(rlch_5_4_2_5_stat "$component")" || after=''
                resolved_after="$(rlch_5_4_2_5_realpath "$component")" || resolved_after=''
                if [[ "$before" != "$after" || "$resolved" != "$resolved_after" ]]; then
                    rlch_5_4_2_5_finding "$index" 'directory changed during inspection'
                    unsafe=1
                fi
            fi
        fi
        [[ "$more" -eq 1 ]] || break
    done
    [[ "$unsafe" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
apply() {
    local result=0
    check || result=$?
    if [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]]; then
        printf 'CIS 5.4.2.5: manual remediation required; identify each reported entry and its exact environment source or directory target before changing profiles, ownership or permissions\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$result"
}
validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
