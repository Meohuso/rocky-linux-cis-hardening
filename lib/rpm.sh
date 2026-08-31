#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Reusable RPM package and DNF configuration helpers.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_RPM_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_RPM_LOADED=1

RLCH_RPM_COMMAND="${RLCH_RPM_COMMAND:-rpm}"
RLCH_DNF_COMMAND="${RLCH_DNF_COMMAND:-dnf}"
RLCH_DNF_CONFIG="${RLCH_DNF_CONFIG:-/etc/dnf/dnf.conf}"
RLCH_DNF_CONFIG_BACKUP_SUFFIX="${RLCH_DNF_CONFIG_BACKUP_SUFFIX:-.rlch.bak}"

rpm_list_gpg_keys() {
    "${RLCH_RPM_COMMAND}" -q gpg-pubkey 2>/dev/null
}

rpm_has_gpg_keys() {
    local output

    if ! output="$(rpm_list_gpg_keys)"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ -z "${output}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

dnf_main_option_value() {
    local option="${1:-}"
    local config_file="${2:-${RLCH_DNF_CONFIG}}"

    if [[ -z "${option}" || ! -f "${config_file}" ]]; then
        return 1
    fi

    awk -v option="${option}" '
        BEGIN {
            in_main = 0
            found = 0
        }

        /^[[:space:]]*\[/ {
            in_main = ($0 ~ /^[[:space:]]*\[[[:space:]]*main[[:space:]]*\][[:space:]]*$/)
            next
        }

        in_main && $0 !~ /^[[:space:]]*[#;]/ {
            line = $0
            sub(/^[[:space:]]*/, "", line)

            separator = index(line, "=")
            if (separator == 0) {
                next
            }

            key = substr(line, 1, separator - 1)
            value = substr(line, separator + 1)

            gsub(/[[:space:]]/, "", key)
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)

            if (key == option) {
                result = value
                found = 1
            }
        }

        END {
            if (found) {
                print result
                exit 0
            }

            exit 1
        }
    ' "${config_file}"
}

dnf_main_option_is_enabled() {
    local option="${1:-}"
    local config_file="${2:-${RLCH_DNF_CONFIG}}"
    local value

    if ! value="$(dnf_main_option_value "${option}" "${config_file}")"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if [[ "${value}" == "1" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

dnf_set_main_option() {
    local option="${1:-}"
    local value="${2:-}"
    local config_file="${3:-${RLCH_DNF_CONFIG}}"
    local backup_file="${config_file}${RLCH_DNF_CONFIG_BACKUP_SUFFIX}"
    local temporary_file

    if [[ -z "${option}" || -z "${value}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${config_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "$(dnf_main_option_value "${option}" "${config_file}" 2>/dev/null || true)" == "${value}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -e "${backup_file}" ]]; then
        if ! cp -p -- "${config_file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    temporary_file="$(mktemp "${config_file}.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! awk -v option="${option}" -v value="${value}" '
        BEGIN {
            in_main = 0
            main_found = 0
            option_written = 0
        }

        /^[[:space:]]*\[/ {
            if (in_main && !option_written) {
                print option "=" value
                option_written = 1
            }

            if ($0 ~ /^[[:space:]]*\[[[:space:]]*main[[:space:]]*\][[:space:]]*$/) {
                in_main = 1
                main_found = 1
            } else {
                in_main = 0
            }

            print
            next
        }

        in_main && $0 !~ /^[[:space:]]*[#;]/ {
            line = $0
            sub(/^[[:space:]]*/, "", line)

            separator = index(line, "=")
            if (separator > 0) {
                key = substr(line, 1, separator - 1)
                gsub(/[[:space:]]/, "", key)

                if (key == option) {
                    if (!option_written) {
                        print option "=" value
                        option_written = 1
                    }
                    next
                }
            }
        }

        {
            print
        }

        END {
            if (in_main && !option_written) {
                print option "=" value
                option_written = 1
            }

            if (!main_found) {
                print ""
                print "[main]"
                print option "=" value
            }
        }
    ' "${config_file}" > "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod --reference="${config_file}" "${temporary_file}" ||
       ! chown --reference="${config_file}" "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${config_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

dnf_rollback_config() {
    local config_file="${1:-${RLCH_DNF_CONFIG}}"
    local backup_file="${config_file}${RLCH_DNF_CONFIG_BACKUP_SUFFIX}"

    if [[ "$(id -u)" -ne 0 ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${backup_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cp -p -- "${backup_file}" "${config_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

dnf_list_enabled_repositories() {
    "${RLCH_DNF_COMMAND}" -q repolist --enabled 2>/dev/null
}

dnf_has_enabled_repositories() {
    local output
    local repository_count

    if ! output="$(dnf_list_enabled_repositories)"; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    repository_count="$(
        awk '
            /^[[:space:]]*repo id[[:space:]]+repo name[[:space:]]*$/ {
                next
            }

            /^[[:space:]]*$/ {
                next
            }

            {
                count++
            }

            END {
                print count + 0
            }
        ' <<< "${output}"
    )"

    if [[ "${repository_count}" -gt 0 ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}
