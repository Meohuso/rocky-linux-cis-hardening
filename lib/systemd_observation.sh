#!/usr/bin/env bash
# Bounded machine-property observations, without systemd mutations.
# SPDX-License-Identifier: MIT

# The existing boolean RPM helper conflates absence with query failure.
# Generalize the strict observation used by AIDE without refactoring 6.1.
rlch_systemd_package_status() {
    local command="$1" package="$2" output result=0 line
    [[ "$package" =~ ^[a-zA-Z0-9][a-zA-Z0-9.+_-]*$ ]] || return 2
    output="$(LC_ALL=C "$command" -q --qf '%{NAME}\n' "$package" 2>&1)" || result=$?
    if [[ "$result" -eq 0 && -n "$output" ]]; then
        while IFS= read -r line; do [[ "$line" == "$package" ]] || return 2; done <<< "$output"
        return 0
    fi
    [[ "$result" -eq 1 && "$output" == "package $package is not installed" ]] || return 2
    return 1
}
rlch_systemd_unit_name() {
    [[ ${#1} -le 255 && "$1" =~ ^[a-zA-Z0-9_:@.\\-]+\.[a-z]+$ ]]
}

# Reject NUL/control bytes before Bash command substitution can discard them.
rlch_systemd_show() (
    local command="$1" unit="$2" properties="$3"
    set -o pipefail
    LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_PAGER=cat "$command" --system --no-pager show \
        --property="$properties" -- "$unit" 2>/dev/null | LC_ALL=C /usr/bin/awk '
        {total+=length($0)+1; if(total>131072 || index($0,sprintf("%c",0)) || /[[:cntrl:]]/) exit 2; print}
    '
)

# Keys are machine-readable, independently of property ordering. Fail closed on
# missing/duplicate/unknown keys and command errors; never evaluate values.
# Output: Id|LoadState|ActiveState|UnitFileState|timestamp for runtime;
# Id|LoadState|Requires|Wants for targets. Arrays are normalized as sets.
rlch_systemd_properties() {
    local command="$1" unit="$2" kind="$3" output line key value property deps token
    local -a tokens=()
    local -A fields=()
    rlch_systemd_unit_name "$unit" || return 2
    if [[ "$kind" == runtime ]]; then
        output="$(rlch_systemd_show "$command" "$unit" Id,LoadState,ActiveState,UnitFileState,StateChangeTimestampMonotonic)" || return 2
    elif [[ "$kind" == target ]]; then
        output="$(rlch_systemd_show "$command" "$unit" Id,LoadState,Requires,Wants)" || return 2
    else return 2; fi
    [[ -n "$output" && ${#output} -le 131072 ]] || return 2
    while IFS= read -r line; do
        [[ "$line" != *[[:cntrl:]]* && "$line" == *=* ]] || return 2
        key="${line%%=*}"; value="${line#*=}"
        [[ -n "$key" ]] || return 2
        [[ -z "${fields[$key]+set}" ]] || return 2
        case "$kind:$key" in
            runtime:Id|runtime:LoadState|runtime:ActiveState|runtime:UnitFileState|runtime:StateChangeTimestampMonotonic|target:Id|target:LoadState|target:Requires|target:Wants) ;;
            *) return 2;;
        esac
        fields["$key"]="$value"
    done <<< "$output"
    [[ -n "${fields[Id]+set}" && -n "${fields[LoadState]+set}" ]] || return 2
    # Alias names are allowed; primary Id and requested suffix must agree.
    rlch_systemd_unit_name "${fields[Id]}" || return 2
    [[ "${fields[Id]##*.}" == "${unit##*.}" ]] || return 2
    case "${fields[LoadState]}" in loaded|masked|not-found) ;; *) return 2;; esac
    if [[ "$kind" == runtime ]]; then
        for property in ActiveState UnitFileState StateChangeTimestampMonotonic; do [[ -n "${fields[$property]+set}" ]] || return 2; done
        case "${fields[ActiveState]}" in active|inactive|failed) ;; *) return 2;; esac
        case "${fields[UnitFileState]}" in enabled|enabled-runtime|disabled|static|indirect|generated|transient|alias|linked|linked-runtime|masked|masked-runtime|'') ;; *) return 2;; esac
        [[ "${fields[StateChangeTimestampMonotonic]}" =~ ^[0-9]+$ ]] || return 2
        if [[ "${fields[LoadState]}" == not-found ]]; then
            [[ "${fields[ActiveState]}" == inactive && -z "${fields[UnitFileState]}" ]] || return 2
        elif [[ "${fields[LoadState]}" == loaded ]]; then
            [[ -n "${fields[UnitFileState]}" && "${fields[UnitFileState]}" != masked* ]] || return 2
        else
            [[ "${fields[UnitFileState]}" == masked || "${fields[UnitFileState]}" == masked-runtime ]] || return 2
        fi
        printf '%s|%s|%s|%s|%s\n' "${fields[Id]}" "${fields[LoadState]}" "${fields[ActiveState]}" "${fields[UnitFileState]}" "${fields[StateChangeTimestampMonotonic]}"
    else
        [[ -n "${fields[Requires]+set}" && -n "${fields[Wants]+set}" && "${fields[LoadState]}" == loaded ]] || return 2
        for property in Requires Wants; do
            deps="${fields[$property]}"
            [[ "$deps" != *$'\t'* ]] || return 2
            IFS=' ' read -r -a tokens <<< "$deps"
            for token in "${tokens[@]}"; do rlch_systemd_unit_name "$token" || return 2; done
            deps="$(printf '%s\n' "${tokens[@]}" | LC_ALL=C /usr/bin/sort -u)" || return 2
            fields["$property"]="${deps//$'\n'/ }"
        done
        printf '%s|%s|%s|%s\n' "${fields[Id]}" "${fields[LoadState]}" "${fields[Requires]}" "${fields[Wants]}"
    fi
}

# OpenSCAP dependency probe: collect Wants/Requires, recurse only into targets.
# Preserve every observed target property, including edges, for comparison.
# Bounds and a visited set prevent unbounded traversal and target cycles.
rlch_systemd_target_graph() {
    local command="$1" root="$2" unit row id load requires wants dependency count=0
    local -a queue=("$root") rows=() dependencies=()
    local -A visited=()
    while [[ ${#queue[@]} -gt 0 ]]; do
        unit="${queue[0]}"; queue=("${queue[@]:1}")
        [[ -z "${visited[$unit]+set}" ]] || continue
        visited["$unit"]=1; count=$((count + 1)); [[ "$count" -le 256 ]] || return 2
        row="$(rlch_systemd_properties "$command" "$unit" target)" || return 2
        IFS='|' read -r id load requires wants <<< "$row"
        [[ "$id" == *.target && "$load" == loaded ]] || return 2
        rows+=("target:$unit|$row")
        IFS=' ' read -r -a dependencies <<< "$requires $wants"
        for dependency in "${dependencies[@]}"; do
            rows+=("dependency:$dependency")
            if [[ "$dependency" == *.target ]]; then queue+=("$dependency"); fi
            [[ ${#rows[@]} -le 16384 && ${#queue[@]} -le 4096 ]] || return 2
        done
    done
    printf '%s\n' "${rows[@]}" | LC_ALL=C /usr/bin/sort -u
}
