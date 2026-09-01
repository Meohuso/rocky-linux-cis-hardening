#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable sysctl helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_SYSCTL_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_SYSCTL_LOADED=1

RLCH_SYSCTL_CONFIG_DIR="${RLCH_SYSCTL_CONFIG_DIR:-/etc/sysctl.d}"
RLCH_SYSCTL_BACKUP_SUFFIX="${RLCH_SYSCTL_BACKUP_SUFFIX:-.rlch.bak}"

sysctl_runtime_value() {
    local parameter="${1:-}"

    if [[ -z "${parameter}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! sysctl -n "${parameter}" 2>/dev/null; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
}

sysctl_runtime_value_is() {
    local parameter="${1:-}"
    local expected_value="${2:-}"
    local current_value

    if [[ -z "${parameter}" || -z "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! current_value="$(sysctl_runtime_value "${parameter}")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${current_value}" == "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

sysctl_config_value_is() {
    local file="${1:-}"
    local parameter="${2:-}"
    local expected_value="${3:-}"

    if [[ -z "${file}" || -z "${parameter}" || -z "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if awk \
        -v parameter="${parameter}" \
        -v expected="${expected_value}" \
        '
        /^[[:space:]]*#/ {
            next
        }

        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)

            split(line, fields, "=")
            if (length(fields) != 2) {
                next
            }

            key = fields[1]
            value = fields[2]

            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

            if (key == parameter && value == expected) {
                found = 1
            }
        }

        END {
            exit(found ? 0 : 1)
        }
        ' "${file}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

sysctl_parameter_is_configured() {
    local file="${1:-}"
    local parameter="${2:-}"
    local expected_value="${3:-}"

    if ! sysctl_config_value_is "${file}" "${parameter}" "${expected_value}"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    sysctl_runtime_value_is "${parameter}" "${expected_value}"
}

sysctl_set_parameter() {
    local file="${1:-}"
    local parameter="${2:-}"
    local expected_value="${3:-}"
    local backup_file
    local directory
    local temporary_file
    local changed="false"

    if [[ -z "${file}" || -z "${parameter}" || -z "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if sysctl_parameter_is_configured "${file}" "${parameter}" "${expected_value}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    directory="$(dirname -- "${file}")"
    if [[ ! -d "${directory}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_SYSCTL_BACKUP_SUFFIX}"

    if [[ -f "${file}" && ! -e "${backup_file}" ]]; then
        if ! cp -a -- "${file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    temporary_file="$(mktemp "${directory}/.rlch-sysctl.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ -f "${file}" ]]; then
        if ! awk \
            -v parameter="${parameter}" \
            '
            {
                line = $0

                if (line ~ /^[[:space:]]*#/) {
                    print
                    next
                }

                split(line, fields, "=")
                key = fields[1]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)

                if (key == parameter) {
                    next
                }

                print
            }
            ' "${file}" > "${temporary_file}"; then
            rm -f -- "${temporary_file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! printf '%s = %s\n' "${parameter}" "${expected_value}" >> "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0644 -- "${temporary_file}" ||
       ! chown 0:0 -- "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    changed="true"

    if ! sysctl -w "${parameter}=${expected_value}" >/dev/null 2>&1; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

sysctl_rollback_parameter() {
    local file="${1:-}"
    local parameter="${2:-}"
    local backup_file
    local previous_value=""

    if [[ -z "${file}" || -z "${parameter}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_SYSCTL_BACKUP_SUFFIX}"

    if [[ -f "${backup_file}" ]]; then
        previous_value="$(awk \
            -v parameter="${parameter}" \
            '
            /^[[:space:]]*#/ {
                next
            }

            {
                line = $0
                sub(/[[:space:]]*#.*/, "", line)
                split(line, fields, "=")

                key = fields[1]
                value = fields[2]

                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

                if (key == parameter) {
                    result = value
                }
            }

            END {
                if (result != "") {
                    print result
                }
            }
            ' "${backup_file}")"

        if ! cp -a -- "${backup_file}" "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if [[ -n "${previous_value}" ]]; then
            if ! sysctl -w "${parameter}=${previous_value}" >/dev/null 2>&1; then
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
        fi

        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    if [[ -f "${file}" ]]; then
        if ! rm -f -- "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}
