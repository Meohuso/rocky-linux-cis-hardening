#!/usr/bin/env bash
# Reusable helpers for validated, isolated sudoers configuration.
# SPDX-License-Identifier: MIT

if [[ -n "${RLCH_SUDOERS_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_SUDOERS_LOADED=1

RLCH_SUDOERS_VISUDO_COMMAND="${RLCH_SUDOERS_VISUDO_COMMAND:-visudo}"
RLCH_SUDOERS_ID_COMMAND="${RLCH_SUDOERS_ID_COMMAND:-id}"
RLCH_SUDOERS_MAIN_FILE="${RLCH_SUDOERS_MAIN_FILE:-/etc/sudoers}"
RLCH_SUDOERS_INCLUDE_DIR="${RLCH_SUDOERS_INCLUDE_DIR:-/etc/sudoers.d}"

sudoers_require_root() {
    local uid
    uid="$("${RLCH_SUDOERS_ID_COMMAND}" -u 2>/dev/null)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${uid}" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
}

sudoers_validate() {
    "${RLCH_SUDOERS_VISUDO_COMMAND}" -c >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
}

sudoers_configuration_files() {
    [[ -f "${RLCH_SUDOERS_MAIN_FILE}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    printf '%s\0' "${RLCH_SUDOERS_MAIN_FILE}"
    if [[ -d "${RLCH_SUDOERS_INCLUDE_DIR}" ]]; then
        find "${RLCH_SUDOERS_INCLUDE_DIR}" -maxdepth 1 -type f \
            ! -name '*.*' ! -name '*~' -print0 | sort -z
    fi
}

sudoers_global_boolean_enabled() {
    local option="${1:-}" files_file result

    [[ "${option}" =~ ^[a-z][a-z0-9_]*$ ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    files_file="$(mktemp)" || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! sudoers_configuration_files > "${files_file}"; then
        rm -f -- "${files_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    result=0
    # shellcheck disable=SC2016 # The single-quoted program is evaluated by awk.
    xargs -0 awk -v wanted="${option}" '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            return value
        }
        function evaluate(line, body, count, global, idx, item, items, scoped) {
            line = trim(line)
            if (line == "" || line ~ /^#/) return
            if (line !~ /^Defaults([[:space:]]|:|@|>|!)/) return
            global = (line ~ /^Defaults[[:space:]]/)
            scoped = !global
            body = line
            sub(/^Defaults[^[:space:]]*/, "", body)
            body = trim(body)
            count = split(body, items, ",")
            for (idx = 1; idx <= count; idx++) {
                item = trim(items[idx])
                if (global && item == wanted) global_state = 1
                if (global && item == "!" wanted) global_state = -1
                if (scoped && item == "!" wanted) scoped_disabled = 1
            }
        }
        {
            current = $0
            sub(/[[:space:]]*#.*/, "", current)
            if (continued != "") current = continued current
            if (current ~ /\\[[:space:]]*$/) {
                sub(/\\[[:space:]]*$/, "", current)
                continued = current
                next
            }
            continued = ""
            evaluate(current)
        }
        END {
            if (continued != "") evaluate(continued)
            exit !(global_state == 1 && scoped_disabled != 1)
        }
    ' < "${files_file}" || result=$?
    rm -f -- "${files_file}"
    [[ "${result}" -eq 0 ]] && return "${RLCH_MODULE_RESULT_SUCCESS}"
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

sudoers_global_value_equals() {
    local option="${1:-}" expected="${2:-}" files_file result

    [[ "${option}" =~ ^[a-z][a-z0-9_]*$ && -n "${expected}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    files_file="$(mktemp)" || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! sudoers_configuration_files > "${files_file}"; then
        rm -f -- "${files_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    result=0
    # shellcheck disable=SC2016 # The single-quoted program is evaluated by awk.
    xargs -0 awk -v wanted="${option}" -v expected="${expected}" '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value
        }
        function unquote(value) {
            if (value ~ /^".*"$/) { sub(/^"/, "", value); sub(/"$/, "", value) }
            return value
        }
        function evaluate(line, body, count, global, idx, item, items, scoped, value) {
            line = trim(line)
            if (line == "" || line ~ /^#/ || line !~ /^Defaults([[:space:]]|:|@|>|!)/) return
            global = (line ~ /^Defaults[[:space:]]/); scoped = !global
            body = line; sub(/^Defaults[^[:space:]]*/, "", body); body = trim(body)
            count = split(body, items, ",")
            for (idx = 1; idx <= count; idx++) {
                item = trim(items[idx])
                if (item !~ ("^" wanted "[[:space:]]*=")) continue
                value = item; sub("^" wanted "[[:space:]]*=[[:space:]]*", "", value)
                value = unquote(trim(value))
                if (global) global_matches = (value == expected ? 1 : -1)
                if (scoped && value != expected) scoped_conflict = 1
            }
        }
        {
            current = $0; sub(/[[:space:]]*#.*/, "", current)
            if (continued != "") current = continued current
            if (current ~ /\\[[:space:]]*$/) { sub(/\\[[:space:]]*$/, "", current); continued = current; next }
            continued = ""; evaluate(current)
        }
        END {
            if (continued != "") evaluate(continued)
            exit !(global_matches == 1 && scoped_conflict != 1)
        }
    ' < "${files_file}" || result=$?
    rm -f -- "${files_file}"
    [[ "${result}" -eq 0 ]] && return "${RLCH_MODULE_RESULT_SUCCESS}"
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

sudoers_restore_managed_file() {
    local file="${1:-}" state_file="${2:-}" backup directory state temporary
    backup="${state_file}.original"
    IFS= read -r state < "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    case "${state}" in
        present)
            [[ -f "${backup}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
            directory="$(dirname -- "${file}")"
            temporary="$(mktemp "${directory}/.rlch-sudoers-restore.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
            rm -f -- "${temporary}"
            if ! cp -a -- "${backup}" "${temporary}" || ! mv -f -- "${temporary}" "${file}"; then
                rm -f -- "${temporary}"
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        absent) rm -f -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}" ;;
        *) return "${RLCH_MODULE_RESULT_ERROR}" ;;
    esac
}

sudoers_write_managed_file() {
    local file="${1:-}" state_file="${2:-}" content="${3:-}"
    local backup directory state_directory temporary

    [[ -n "${file}" && -n "${state_file}" && -n "${content}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    directory="$(dirname -- "${file}")"; state_directory="$(dirname -- "${state_file}")"; backup="${state_file}.original"
    mkdir -p -- "${state_directory}" "${directory}" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ ! -e "${state_file}" ]]; then
        if [[ -e "${file}" ]]; then
            [[ -f "${file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
            cp -a -- "${file}" "${backup}" || return "${RLCH_MODULE_RESULT_ERROR}"
            printf 'present\n' > "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        else
            printf 'absent\n' > "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        chmod 0600 -- "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    temporary="$(mktemp "${directory}/.rlch-sudoers.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! printf '%s\n' "${content}" > "${temporary}" || ! chmod 0440 -- "${temporary}" ||
       ! chown 0:0 -- "${temporary}" || ! mv -f -- "${temporary}" "${file}"; then
        rm -f -- "${temporary}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! sudoers_validate; then
        sudoers_restore_managed_file "${file}" "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        rm -f -- "${state_file}" "${backup}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

sudoers_rollback_managed_file() {
    local file="${1:-}" state_file="${2:-}" backup
    [[ -e "${state_file}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    sudoers_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    backup="${state_file}.original"
    sudoers_restore_managed_file "${file}" "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    rm -f -- "${state_file}" "${backup}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
