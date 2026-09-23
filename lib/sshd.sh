#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Reusable helpers for effective sshd settings and isolated drop-in files.
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_SSHD_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_SSHD_LOADED=1

RLCH_SSHD_COMMAND="${RLCH_SSHD_COMMAND:-sshd}"
RLCH_SSHD_ID_COMMAND="${RLCH_SSHD_ID_COMMAND:-id}"

sshd_effective_value() {
    local keyword="${1:-}" output

    [[ "${keyword}" =~ ^[a-z][a-z0-9]*$ ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! output="$("${RLCH_SSHD_COMMAND}" -T -C user=root -C host=localhost -C addr=127.0.0.1 2>/dev/null)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    awk -v key="${keyword}" '
        tolower($1) == key {
            $1 = ""
            sub(/^[[:space:]]+/, "")
            print
            found = 1
            exit
        }
        END { if (!found) exit 1 }
    ' <<< "${output}" || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

sshd_require_root() {
    local uid
    uid="$("${RLCH_SSHD_ID_COMMAND}" -u 2>/dev/null)" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${uid}" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
}

sshd_validate_configuration() {
    "${RLCH_SSHD_COMMAND}" -t >/dev/null 2>&1 || return "${RLCH_MODULE_RESULT_ERROR}"
}

sshd_write_dropin() {
    local file="${1:-}" state_file="${2:-}"
    local backup directory index state_directory temporary
    local -a settings=("${@:3}")

    [[ -n "${file}" && -n "${state_file}" && "${#settings[@]}" -ge 2 &&
       $(( ${#settings[@]} % 2 )) -eq 0 ]] ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    for ((index = 0; index < ${#settings[@]}; index += 2)); do
        [[ "${settings[index]}" =~ ^[A-Za-z][A-Za-z0-9]*$ &&
           -n "${settings[index + 1]}" && "${settings[index + 1]}" != *$'\n'* ]] ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    done
    sshd_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    directory="$(dirname -- "${file}")"
    state_directory="$(dirname -- "${state_file}")"
    backup="${state_file}.original"
    if [[ ! -e "${state_file}" ]]; then
        mkdir -p -- "${state_directory}" || return "${RLCH_MODULE_RESULT_ERROR}"
        if [[ -e "${file}" ]]; then
            [[ -f "${file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
            cp -a -- "${file}" "${backup}" || return "${RLCH_MODULE_RESULT_ERROR}"
            printf 'present\n' > "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        else
            printf 'absent\n' > "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        chmod 0600 -- "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    mkdir -p -- "${directory}" || return "${RLCH_MODULE_RESULT_ERROR}"
    temporary="$(mktemp "${directory}/.rlch-sshd.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! : > "${temporary}"; then
        rm -f -- "${temporary}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for ((index = 0; index < ${#settings[@]}; index += 2)); do
        if ! printf '%s %s\n' "${settings[index]}" "${settings[index + 1]}" >> "${temporary}"; then
            rm -f -- "${temporary}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    if ! chmod 0600 -- "${temporary}" || ! chown 0:0 -- "${temporary}" ||
       ! mv -f -- "${temporary}" "${file}"; then
        rm -f -- "${temporary}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    sshd_validate_configuration || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

sshd_rollback_dropin() {
    local file="${1:-}" state_file="${2:-}" backup state

    [[ -n "${file}" && -n "${state_file}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ -e "${state_file}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    sshd_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    backup="${state_file}.original"
    IFS= read -r state < "${state_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    case "${state}" in
        present)
            [[ -f "${backup}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
            cp -a -- "${backup}" "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
        absent)
            [[ ! -e "${backup}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
            rm -f -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
        *) return "${RLCH_MODULE_RESULT_ERROR}" ;;
    esac
    sshd_validate_configuration || return "${RLCH_MODULE_RESULT_ERROR}"
    rm -f -- "${state_file}" "${backup}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
