#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.1.21 - Ensure mail transfer agents are configured for local-only mode.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_1_21_POSTFIX_PACKAGE="${RLCH_CIS_2_1_21_POSTFIX_PACKAGE:-postfix}"
RLCH_CIS_2_1_21_POSTFIX_CONFIG="${RLCH_CIS_2_1_21_POSTFIX_CONFIG:-/etc/postfix/main.cf}"
RLCH_CIS_2_1_21_RPM_COMMAND="${RLCH_CIS_2_1_21_RPM_COMMAND:-rpm}"
RLCH_CIS_2_1_21_SS_COMMAND="${RLCH_CIS_2_1_21_SS_COMMAND:-ss}"
RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND="${RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND:-systemctl}"
RLCH_CIS_2_1_21_ID_COMMAND="${RLCH_CIS_2_1_21_ID_COMMAND:-id}"
RLCH_CIS_2_1_21_STATE_DIR="${RLCH_CIS_2_1_21_STATE_DIR:-/var/lib/rlch/cis/2.1.21}"
RLCH_CIS_2_1_21_STATE_FILE="${RLCH_CIS_2_1_21_STATE_FILE:-${RLCH_CIS_2_1_21_STATE_DIR}/state}"
RLCH_CIS_2_1_21_BACKUP_FILE="${RLCH_CIS_2_1_21_BACKUP_FILE:-${RLCH_CIS_2_1_21_STATE_DIR}/main.cf.backup}"

cis_2_1_21_postfix_installed() {
    "${RLCH_CIS_2_1_21_RPM_COMMAND}" -q "${RLCH_CIS_2_1_21_POSTFIX_PACKAGE}" >/dev/null 2>&1
}

cis_2_1_21_postfix_active() {
    "${RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND}" is-active --quiet postfix >/dev/null 2>&1
}

cis_2_1_21_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_2_1_21_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 2.1.21."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 2.1.21 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_21_postfix_config_compliant() {
    local matching_lines

    [[ -f "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" ]] || return 1

    if ! matching_lines="$(awk '
        /^[[:space:]]*#/ { next }
        {
            line = tolower($0)
            if (line ~ /^[[:space:]]*inet_interfaces[[:space:]]*=/) {
                sub(/^[^=]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]*#.*/, "", line)
                gsub(/[[:space:]]/, "", line)
                print line
            }
        }
    ' "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}")"; then
        return 2
    fi

    [[ "${matching_lines}" == "loopback-only" ]]
}

cis_2_1_21_has_nonlocal_listener() {
    local listener_output
    local line
    local local_endpoint
    local address
    local port

    if ! listener_output="$("${RLCH_CIS_2_1_21_SS_COMMAND}" -H -lnt 2>/dev/null)"; then
        return 2
    fi

    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        read -r _ _ _ local_endpoint _ <<< "${line}"

        if [[ "${local_endpoint}" =~ ^(.*):([0-9]+)$ ]]; then
            address="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        else
            continue
        fi

        case "${port}" in
            25|465|587)
                ;;
            *)
                continue
                ;;
        esac

        case "${address}" in
            127.0.0.1|\[::1\]|::1)
                ;;
            *)
                return 0
                ;;
        esac
    done <<< "${listener_output}"

    return 1
}

cis_2_1_21_create_state() {
    local file_existed="false"
    local service_active="false"

    if [[ -e "${RLCH_CIS_2_1_21_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p "${RLCH_CIS_2_1_21_STATE_DIR}"; then
        error_message "Unable to create CIS 2.1.21 state directory: ${RLCH_CIS_2_1_21_STATE_DIR}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" ]]; then
        file_existed="true"
        if ! cp -a "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" "${RLCH_CIS_2_1_21_BACKUP_FILE}"; then
            error_message "Unable to back up Postfix configuration for CIS 2.1.21."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if cis_2_1_21_postfix_active; then
        service_active="true"
    fi

    if ! printf 'file_existed=%s\nservice_active=%s\n' "${file_existed}" "${service_active}" > "${RLCH_CIS_2_1_21_STATE_FILE}"; then
        error_message "Unable to write CIS 2.1.21 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_21_write_postfix_config() {
    local config_directory
    local temporary_file

    config_directory="$(dirname "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}")"
    if ! mkdir -p "${config_directory}"; then
        error_message "Unable to create Postfix configuration directory: ${config_directory}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! temporary_file="$(mktemp "${config_directory}/.rlch-main.cf.XXXXXX")"; then
        error_message "Unable to create a temporary Postfix configuration file."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -f "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" ]]; then
        if ! awk '
            BEGIN { written = 0 }
            {
                line = tolower($0)
                if (line !~ /^[[:space:]]*#/ && line ~ /^[[:space:]]*inet_interfaces[[:space:]]*=/) {
                    if (!written) {
                        print "inet_interfaces = loopback-only"
                        written = 1
                    }
                    next
                }
                print
            }
            END {
                if (!written) {
                    print "inet_interfaces = loopback-only"
                }
            }
        ' "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" > "${temporary_file}"; then
            rm -f "${temporary_file}"
            error_message "Unable to update Postfix configuration for CIS 2.1.21."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        chmod --reference="${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" "${temporary_file}" || {
            rm -f "${temporary_file}"
            error_message "Unable to preserve Postfix configuration permissions."
            return "${RLCH_MODULE_RESULT_ERROR}"
        }
        chown --reference="${RLCH_CIS_2_1_21_POSTFIX_CONFIG}" "${temporary_file}" || {
            rm -f "${temporary_file}"
            error_message "Unable to preserve Postfix configuration ownership."
            return "${RLCH_MODULE_RESULT_ERROR}"
        }
    else
        if ! printf '%s\n' "inet_interfaces = loopback-only" > "${temporary_file}"; then
            rm -f "${temporary_file}"
            error_message "Unable to write Postfix configuration for CIS 2.1.21."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        chmod 0644 "${temporary_file}" || {
            rm -f "${temporary_file}"
            return "${RLCH_MODULE_RESULT_ERROR}"
        }
    fi

    if ! mv -f "${temporary_file}" "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"; then
        rm -f "${temporary_file}"
        error_message "Unable to install Postfix configuration for CIS 2.1.21."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_1_21_remove_state() {
    if ! rm -f "${RLCH_CIS_2_1_21_STATE_FILE}" "${RLCH_CIS_2_1_21_BACKUP_FILE}"; then
        error_message "Unable to remove CIS 2.1.21 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rmdir "${RLCH_CIS_2_1_21_STATE_DIR}" >/dev/null 2>&1 || true
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    local listener_result=0
    local config_result=0

    cis_2_1_21_has_nonlocal_listener || listener_result=$?
    if [[ "${listener_result}" -eq 2 ]]; then
        error_message "Unable to inspect listening TCP sockets for CIS 2.1.21."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${listener_result}" -eq 0 ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if cis_2_1_21_postfix_installed; then
        cis_2_1_21_postfix_config_compliant || config_result=$?
        if [[ "${config_result}" -eq 2 ]]; then
            error_message "Unable to inspect Postfix configuration for CIS 2.1.21."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if [[ "${config_result}" -ne 0 ]]; then
            return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
        fi
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

apply() {
    local check_result=0
    local listener_result=0
    local postfix_active="false"

    check || check_result=$?
    if [[ "${check_result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ "${check_result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_1_21_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_2_1_21_postfix_installed; then
        error_message "A non-local MTA listener exists, but Postfix is not installed; manual remediation is required."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_1_21_create_state || return "${RLCH_MODULE_RESULT_ERROR}"
    if cis_2_1_21_postfix_active; then
        postfix_active="true"
    fi

    cis_2_1_21_write_postfix_config || return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ "${postfix_active}" == "true" ]]; then
        if ! "${RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND}" restart postfix; then
            error_message "Unable to restart Postfix after CIS 2.1.21 remediation."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    cis_2_1_21_has_nonlocal_listener || listener_result=$?
    if [[ "${listener_result}" -eq 2 ]]; then
        error_message "Unable to verify listening TCP sockets after CIS 2.1.21 remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${listener_result}" -eq 0 ]]; then
        error_message "An MTA is still listening on a non-loopback address after Postfix remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_1_21_postfix_config_compliant; then
        error_message "Postfix configuration is not compliant after CIS 2.1.21 remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local file_existed
    local service_active

    [[ -e "${RLCH_CIS_2_1_21_STATE_FILE}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"

    cis_2_1_21_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    file_existed="$(awk -F= '$1 == "file_existed" { print $2 }' "${RLCH_CIS_2_1_21_STATE_FILE}")"
    service_active="$(awk -F= '$1 == "service_active" { print $2 }' "${RLCH_CIS_2_1_21_STATE_FILE}")"

    case "${file_existed}" in
        true)
            if [[ ! -f "${RLCH_CIS_2_1_21_BACKUP_FILE}" ]]; then
                error_message "CIS 2.1.21 rollback backup is missing."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            if ! cp -a "${RLCH_CIS_2_1_21_BACKUP_FILE}" "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"; then
                error_message "Unable to restore Postfix configuration for CIS 2.1.21."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        false)
            if ! rm -f "${RLCH_CIS_2_1_21_POSTFIX_CONFIG}"; then
                error_message "Unable to remove Postfix configuration created by CIS 2.1.21."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        *)
            error_message "CIS 2.1.21 rollback state is invalid."
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac

    if [[ "${service_active}" == "true" ]]; then
        if ! "${RLCH_CIS_2_1_21_SYSTEMCTL_COMMAND}" restart postfix; then
            error_message "Unable to restart Postfix after CIS 2.1.21 rollback."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif [[ "${service_active}" != "false" ]]; then
        error_message "CIS 2.1.21 rollback service state is invalid."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_2_1_21_remove_state || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
