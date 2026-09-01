#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable systemd-coredump configuration helpers.
#
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_COREDUMP_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_COREDUMP_LOADED=1

RLCH_COREDUMP_CONFIG_DIR="${RLCH_COREDUMP_CONFIG_DIR:-/etc/systemd/coredump.conf.d}"
RLCH_COREDUMP_BACKUP_SUFFIX="${RLCH_COREDUMP_BACKUP_SUFFIX:-.rlch.bak}"

coredump_option_is_configured() {
    local file="${1:-}"
    local option="${2:-}"
    local expected_value="${3:-}"

    if [[ -z "${file}" || -z "${option}" || -z "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if awk \
        -v option="${option}" \
        -v expected="${expected_value}" \
        '
        BEGIN {
            in_coredump = 0
            found = 0
        }

        /^[[:space:]]*[#;]/ {
            next
        }

        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[[[:space:]]*|[[:space:]]*\][[:space:]]*$/, "", section)
            in_coredump = (section == "Coredump")
            next
        }

        in_coredump {
            line = $0
            sub(/[[:space:]]*[#;].*$/, "", line)

            split(line, fields, "=")
            if (length(fields) != 2) {
                next
            }

            key = fields[1]
            value = fields[2]

            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

            if (key == option && value == expected) {
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

coredump_set_option() {
    local file="${1:-}"
    local option="${2:-}"
    local expected_value="${3:-}"
    local directory
    local backup_file
    local temporary_file

    if [[ -z "${file}" || -z "${option}" || -z "${expected_value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if coredump_option_is_configured "${file}" "${option}" "${expected_value}"; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    directory="$(dirname -- "${file}")"
    backup_file="${file}${RLCH_COREDUMP_BACKUP_SUFFIX}"

    if ! mkdir -p -- "${directory}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -f "${file}" && ! -e "${backup_file}" ]]; then
        if ! cp -a -- "${file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    temporary_file="$(mktemp "${directory}/.rlch-coredump.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ -f "${file}" ]]; then
        if ! awk \
            -v option="${option}" \
            '
            BEGIN {
                in_coredump = 0
            }

            /^[[:space:]]*\[/ {
                section = $0
                gsub(/^[[:space:]]*\[[[:space:]]*|[[:space:]]*\][[:space:]]*$/, "", section)
                in_coredump = (section == "Coredump")
                print
                next
            }

            {
                if (in_coredump && $0 !~ /^[[:space:]]*[#;]/) {
                    line = $0
                    split(line, fields, "=")
                    key = fields[1]
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)

                    if (key == option) {
                        next
                    }
                }

                print
            }
            ' "${file}" > "${temporary_file}"; then
            rm -f -- "${temporary_file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! grep -Eq '^[[:space:]]*\[[[:space:]]*Coredump[[:space:]]*\][[:space:]]*$' "${temporary_file}"; then
        if [[ -s "${temporary_file}" ]]; then
            printf '\n' >> "${temporary_file}"
        fi
        printf '%s\n' "[Coredump]" >> "${temporary_file}"
    fi

    if ! printf '%s=%s\n' "${option}" "${expected_value}" >> "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0644 -- "${temporary_file}" ||
       ! chown 0:0 -- "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

coredump_rollback_config() {
    local file="${1:-}"
    local backup_file

    if [[ -z "${file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    backup_file="${file}${RLCH_COREDUMP_BACKUP_SUFFIX}"

    if [[ -f "${backup_file}" ]]; then
        if ! cp -a -- "${backup_file}" "${file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
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
