#!/usr/bin/env bash
# CIS 5.2.5 - Ensure re-authentication is not disabled globally.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_2_5_STATE_DIR="${RLCH_CIS_5_2_5_STATE_DIR:-/var/lib/rlch/cis/5.2.5}"
RLCH_CIS_5_2_5_MANIFEST="${RLCH_CIS_5_2_5_MANIFEST:-${RLCH_CIS_5_2_5_STATE_DIR}/manifest}"

cis_5_2_5_file_status() {
    local file="${1:-}"
    awk '
        /^[[:space:]]*#/ { next }
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            was_continued = continued
            if (continued) line = logical line
            if (line ~ /\\[[:space:]]*$/) {
                sub(/\\[[:space:]]*$/, "", line); logical = line; continued = 1; next
            }
            continued = 0; logical = ""
            if (was_continued && line ~ /(^|[[:space:],])!authenticate([[:space:],]|$)/) ambiguous = 1
            if (line ~ /^[[:space:]]*Defaults([[:space:]]|:|@|>|!)/ &&
                line ~ /(^|[[:space:],])!authenticate([[:space:],]|$)/) found = 1
        }
        END {
            if (continued && logical ~ /(^|[[:space:],])!authenticate([[:space:],]|$)/) ambiguous = 1
            if (ambiguous) exit 2
            exit(found ? 1 : 0)
        }
    ' "${file}"
}

cis_5_2_5_transform_file() {
    local file="${1:-}" temporary
    temporary="$(mktemp "$(dirname -- "${file}")/.rlch-sudoers.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
    if ! awk '
        function trim(value) { sub(/^[[:space:]]+/, "", value); sub(/[[:space:]]+$/, "", value); return value }
        {
            original = $0
            if (original ~ /^[[:space:]]*#/ || original !~ /^[[:space:]]*Defaults([[:space:]]|:|@|>|!)/ ||
                original !~ /(^|[[:space:],])!authenticate([[:space:],]|$)/) { print original; next }
            comment = ""; code = original
            marker = index(code, "#")
            if (marker > 0) { comment = substr(code, marker); code = substr(code, 1, marker - 1) }
            match(code, /^[[:space:]]*Defaults[^[:space:]]*[[:space:]]*/)
            prefix = substr(code, 1, RLENGTH); body = substr(code, RLENGTH + 1)
            count = split(body, options, ","); rebuilt = ""
            for (idx = 1; idx <= count; idx++) {
                option = trim(options[idx])
                if (option == "!authenticate" || option == "") continue
                rebuilt = (rebuilt == "" ? option : rebuilt "," option)
            }
            if (rebuilt == "") print "# RLCH CIS 5.2.5 removed: " original
            else print prefix rebuilt (comment == "" ? "" : " " comment)
        }
    ' "${file}" > "${temporary}"; then
        rm -f -- "${temporary}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! chmod --reference="${file}" "${temporary}" ||
       ! chown --reference="${file}" "${temporary}" ||
       ! mv -f -- "${temporary}" "${file}"; then
        rm -f -- "${temporary}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
}

cis_5_2_5_restore_state() {
    local backup index path
    [[ -f "${RLCH_CIS_5_2_5_MANIFEST}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    exec 9< "${RLCH_CIS_5_2_5_MANIFEST}"
    while IFS= read -r -d '' index <&9; do
        IFS= read -r -d '' path <&9 || { exec 9<&-; return "${RLCH_MODULE_RESULT_ERROR}"; }
        backup="${RLCH_CIS_5_2_5_STATE_DIR}/backup/${index}"
        [[ -f "${backup}" ]] || { exec 9<&-; return "${RLCH_MODULE_RESULT_ERROR}"; }
        if ! cp -a -- "${backup}" "${path}.rlch-restore" ||
           ! mv -f -- "${path}.rlch-restore" "${path}"; then
            exec 9<&-
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    exec 9<&-
}

check() {
    local file result
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    while IFS= read -r -d '' file; do
        result=0; cis_5_2_5_file_status "${file}" || result=$?
        [[ "${result}" -ne 2 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
        [[ "${result}" -ne 1 ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    done < <(sudoers_configuration_files)
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local backup file index=0 result=0 status
    local -a affected=()
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    while IFS= read -r -d '' file; do
        status=0; cis_5_2_5_file_status "${file}" || status=$?
        [[ "${status}" -ne 2 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
        [[ "${status}" -ne 1 ]] || affected+=("${file}")
    done < <(sudoers_configuration_files)
    [[ "${#affected[@]}" -gt 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    mkdir -p -- "${RLCH_CIS_5_2_5_STATE_DIR}/backup" || return "${RLCH_MODULE_RESULT_ERROR}"
    : > "${RLCH_CIS_5_2_5_MANIFEST}" || return "${RLCH_MODULE_RESULT_ERROR}"
    for file in "${affected[@]}"; do
        printf -v backup '%s/backup/%06d' "${RLCH_CIS_5_2_5_STATE_DIR}" "${index}"
        cp -a -- "${file}" "${backup}" || return "${RLCH_MODULE_RESULT_ERROR}"
        printf '%06d\0%s\0' "${index}" "${file}" >> "${RLCH_CIS_5_2_5_MANIFEST}" || return "${RLCH_MODULE_RESULT_ERROR}"
        index=$((index + 1))
    done
    chmod 0600 -- "${RLCH_CIS_5_2_5_MANIFEST}" || return "${RLCH_MODULE_RESULT_ERROR}"
    for file in "${affected[@]}"; do cis_5_2_5_transform_file "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"; done
    if ! sudoers_validate || ! check; then
        cis_5_2_5_restore_state || return "${RLCH_MODULE_RESULT_ERROR}"
        rm -rf -- "${RLCH_CIS_5_2_5_STATE_DIR}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    [[ -e "${RLCH_CIS_5_2_5_MANIFEST}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    sudoers_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_5_2_5_restore_state || return "${RLCH_MODULE_RESULT_ERROR}"
    sudoers_validate || return "${RLCH_MODULE_RESULT_ERROR}"
    rm -rf -- "${RLCH_CIS_5_2_5_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
