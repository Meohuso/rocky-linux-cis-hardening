#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.3.3 - Ensure chrony is not run as the root user.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_3_3_CONFIG="${RLCH_CIS_2_3_3_CONFIG:-/etc/sysconfig/chronyd}"
RLCH_CIS_2_3_3_ID_COMMAND="${RLCH_CIS_2_3_3_ID_COMMAND:-id}"
RLCH_CIS_2_3_3_STATE_DIR="${RLCH_CIS_2_3_3_STATE_DIR:-/var/lib/rlch/cis/2.3.3}"
RLCH_CIS_2_3_3_STATE_FILE="${RLCH_CIS_2_3_3_STATE_FILE:-${RLCH_CIS_2_3_3_STATE_DIR}/original-state}"
RLCH_CIS_2_3_3_BACKUP_FILE="${RLCH_CIS_2_3_3_BACKUP_FILE:-${RLCH_CIS_2_3_3_STATE_DIR}/chronyd}"

cis_2_3_3_options_are_compliant() {
    [[ -f "${RLCH_CIS_2_3_3_CONFIG}" ]] || return 0

    awk '
        /^[[:space:]]*#/ {
            next
        }
        /^[[:space:]]*OPTIONS[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=/, "", value)
            count = split(value, fields, /[[:space:]]+/)

            for (position = 1; position <= count; position++) {
                token = fields[position]
                gsub(/["\047]/, "", token)

                if (token == "" || substr(token, 1, 1) == "#") {
                    if (substr(token, 1, 1) == "#") {
                        break
                    }
                    continue
                }

                if (token == "-u") {
                    position++
                    user = fields[position]
                    gsub(/["\047]/, "", user)
                    if (user != "chrony") {
                        non_compliant = 1
                    }
                } else if (substr(token, 1, 2) == "-u" && substr(token, 3) != "chrony") {
                    non_compliant = 1
                }
            }
        }
        END {
            exit non_compliant ? 1 : 0
        }
    ' "${RLCH_CIS_2_3_3_CONFIG}"
}

cis_2_3_3_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_2_3_3_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 2.3.3."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 2.3.3 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_3_3_capture_state() {
    if [[ -e "${RLCH_CIS_2_3_3_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p "${RLCH_CIS_2_3_3_STATE_DIR}"; then
        error_message "Unable to create CIS 2.3.3 state directory."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cp -p "${RLCH_CIS_2_3_3_CONFIG}" "${RLCH_CIS_2_3_3_BACKUP_FILE}"; then
        error_message "Unable to back up ${RLCH_CIS_2_3_3_CONFIG}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! printf '%s\n' "existing" > "${RLCH_CIS_2_3_3_STATE_FILE}"; then
        error_message "Unable to record CIS 2.3.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_3_3_remove_user_overrides() {
    local config_directory
    local temporary_file

    config_directory="$(dirname "${RLCH_CIS_2_3_3_CONFIG}")"
    if ! temporary_file="$(mktemp "${config_directory}/.rlch-chronyd.XXXXXX")"; then
        error_message "Unable to create a temporary chronyd configuration."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! awk '
        function remove_user_options(value,    pattern, matched, replacement, single_quote) {
            single_quote = sprintf("%c", 39)
            pattern = "(^|[[:space:]\"" single_quote "])-u([[:space:]]*[^[:space:]\"" single_quote "]+)?"

            while (match(value, pattern)) {
                matched = substr(value, RSTART, RLENGTH)
                replacement = matched ~ /^-u/ ? "" : substr(matched, 1, 1)
                value = substr(value, 1, RSTART - 1) replacement substr(value, RSTART + RLENGTH)
            }

            return value
        }

        /^[[:space:]]*OPTIONS[[:space:]]*=/ {
            separator = index($0, "=")
            prefix = substr($0, 1, separator)
            value = substr($0, separator + 1)
            comment_at = index(value, "#")

            if (comment_at > 0) {
                comment = substr(value, comment_at)
                value = substr(value, 1, comment_at - 1)
            } else {
                comment = ""
            }

            print prefix remove_user_options(value) comment
            next
        }

        {
            print
        }
    ' "${RLCH_CIS_2_3_3_CONFIG}" > "${temporary_file}"; then
        rm -f "${temporary_file}"
        error_message "Unable to update ${RLCH_CIS_2_3_3_CONFIG}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod --reference="${RLCH_CIS_2_3_3_CONFIG}" "${temporary_file}" ||
       ! chown --reference="${RLCH_CIS_2_3_3_CONFIG}" "${temporary_file}" ||
       ! mv -f "${temporary_file}" "${RLCH_CIS_2_3_3_CONFIG}"; then
        rm -f "${temporary_file}"
        error_message "Unable to replace ${RLCH_CIS_2_3_3_CONFIG}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if cis_2_3_3_options_are_compliant; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    if cis_2_3_3_options_are_compliant; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_3_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_2_3_3_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_2_3_3_remove_user_overrides || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_2_3_3_options_are_compliant; then
        error_message "Chronyd still has an invalid user override after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local original_state

    if [[ ! -e "${RLCH_CIS_2_3_3_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_3_3_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! IFS= read -r original_state < "${RLCH_CIS_2_3_3_STATE_FILE}"; then
        error_message "Unable to read CIS 2.3.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${original_state}" != "existing" ]] ||
       [[ ! -f "${RLCH_CIS_2_3_3_BACKUP_FILE}" ]] ||
       ! cp -p "${RLCH_CIS_2_3_3_BACKUP_FILE}" "${RLCH_CIS_2_3_3_CONFIG}"; then
        error_message "Unable to restore ${RLCH_CIS_2_3_3_CONFIG}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -rf "${RLCH_CIS_2_3_3_STATE_DIR}"; then
        error_message "Unable to remove CIS 2.3.3 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
