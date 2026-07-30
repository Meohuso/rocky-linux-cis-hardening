#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Generic mount hardening helpers.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_MOUNT_LIBRARY_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_MOUNT_LIBRARY_LOADED=1

RLCH_MOUNT_FSTAB_FILE="${RLCH_MOUNT_FSTAB_FILE:-/etc/fstab}"

mount_option_list_contains() {
    local option_list="${1:-}"
    local required_option="${2:-}"
    local option

    [[ -n "${option_list}" && -n "${required_option}" ]] || return 1

    IFS=',' read -r -a options <<<"${option_list}"
    for option in "${options[@]}"; do
        if [[ "${option}" == "${required_option}" ]]; then
            return 0
        fi
    done

    return 1
}

mount_runtime_target() {
    local mount_point="${1:-}"

    [[ -n "${mount_point}" ]] || return 1

    findmnt --kernel --noheadings --output TARGET --target "${mount_point}" 2>/dev/null |
        awk 'NF { print $1; exit }'
}

mount_runtime_options() {
    local mount_point="${1:-}"

    [[ -n "${mount_point}" ]] || return 1

    findmnt --kernel --noheadings --output OPTIONS --target "${mount_point}" 2>/dev/null |
        awk 'NF { print $1; exit }'
}

mount_is_separate_partition() {
    local mount_point="${1:-}"
    local runtime_target

    [[ -n "${mount_point}" ]] || return 1

    if ! runtime_target="$(mount_runtime_target "${mount_point}")"; then
        return 1
    fi

    [[ "${runtime_target}" == "${mount_point}" ]]
}

mount_has_runtime_option() {
    local mount_point="${1:-}"
    local required_option="${2:-}"
    local runtime_target
    local runtime_options

    [[ -n "${mount_point}" && -n "${required_option}" ]] || return 1

    if ! runtime_target="$(mount_runtime_target "${mount_point}")"; then
        return 1
    fi

    [[ "${runtime_target}" == "${mount_point}" ]] || return 1

    if ! runtime_options="$(mount_runtime_options "${mount_point}")"; then
        return 1
    fi

    mount_option_list_contains "${runtime_options}" "${required_option}"
}

mount_fstab_entry_exists() {
    local mount_point="${1:-}"
    local fstab_file="${2:-${RLCH_MOUNT_FSTAB_FILE}}"

    [[ -n "${mount_point}" && -r "${fstab_file}" ]] || return 1

    awk -v mount_point="${mount_point}" '
        /^[[:space:]]*#/ || NF == 0 { next }
        $2 == mount_point { found = 1 }
        END { exit !found }
    ' "${fstab_file}"
}

mount_fstab_options() {
    local mount_point="${1:-}"
    local fstab_file="${2:-${RLCH_MOUNT_FSTAB_FILE}}"

    [[ -n "${mount_point}" && -r "${fstab_file}" ]] || return 1

    awk -v mount_point="${mount_point}" '
        /^[[:space:]]*#/ || NF == 0 { next }
        $2 == mount_point { print $4; found = 1; exit }
        END { exit !found }
    ' "${fstab_file}"
}

mount_fstab_has_option() {
    local mount_point="${1:-}"
    local required_option="${2:-}"
    local fstab_file="${3:-${RLCH_MOUNT_FSTAB_FILE}}"
    local fstab_options

    [[ -n "${mount_point}" && -n "${required_option}" ]] || return 1

    if ! fstab_options="$(mount_fstab_options "${mount_point}" "${fstab_file}")"; then
        return 1
    fi

    mount_option_list_contains "${fstab_options}" "${required_option}"
}

mount_check_partition() {
    local mount_point="${1:-}"
    local fstab_file="${2:-${RLCH_MOUNT_FSTAB_FILE}}"

    if [[ -z "${mount_point}" || -z "${fstab_file}" ]]; then
        error_message "Mount partition check arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v findmnt >/dev/null 2>&1; then
        error_message "Required command is unavailable: findmnt"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_fstab_entry_exists "${mount_point}" "${fstab_file}"; then
        log_warning "Mount point ${mount_point} has no persistent fstab entry."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! mount_is_separate_partition "${mount_point}"; then
        log_warning "Mount point ${mount_point} is not mounted separately."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

mount_check_option() {
    local mount_point="${1:-}"
    local required_option="${2:-}"
    local fstab_file="${3:-${RLCH_MOUNT_FSTAB_FILE}}"

    if [[ -z "${mount_point}" || -z "${required_option}" || -z "${fstab_file}" ]]; then
        error_message "Mount option check arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v findmnt >/dev/null 2>&1; then
        error_message "Required command is unavailable: findmnt"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_fstab_has_option "${mount_point}" "${required_option}" "${fstab_file}"; then
        log_warning "Mount option ${required_option} is not persistent on ${mount_point}."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! mount_has_runtime_option "${mount_point}" "${required_option}"; then
        log_warning "Mount option ${required_option} is not active on ${mount_point}."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

mount_write_fstab_option() {
    local mount_point="${1:-}"
    local required_option="${2:-}"
    local fstab_file="${3:-${RLCH_MOUNT_FSTAB_FILE}}"
    local fstab_directory
    local temporary_file
    local awk_status

    if [[ -z "${mount_point}" || -z "${required_option}" || -z "${fstab_file}" ]]; then
        error_message "Mount fstab update arguments must not be empty."
        return 1
    fi

    [[ -f "${fstab_file}" ]] || {
        error_message "Fstab file does not exist: ${fstab_file}"
        return 1
    }

    fstab_directory="$(dirname "${fstab_file}")"
    if ! temporary_file="$(mktemp "${fstab_directory}/.rlch-fstab.XXXXXX")"; then
        error_message "Unable to create temporary fstab file."
        return 1
    fi

    awk -v mount_point="${mount_point}" -v required_option="${required_option}" '
        function has_option(options, required, count, values, index) {
            count = split(options, values, ",")
            for (index = 1; index <= count; index++) {
                if (values[index] == required) {
                    return 1
                }
            }
            return 0
        }
        /^[[:space:]]*#/ || NF == 0 { print; next }
        $2 == mount_point {
            found = 1
            if (!has_option($4, required_option)) {
                $4 = ($4 == "defaults" ? "defaults," required_option : $4 "," required_option)
            }
        }
        { print }
        END { if (!found) exit 42 }
    ' "${fstab_file}" >"${temporary_file}"
    awk_status=$?
    if [[ "${awk_status}" -ne 0 ]]; then
        rm -f "${temporary_file}"
        if [[ "${awk_status}" -eq 42 ]]; then
            error_message "Mount point ${mount_point} has no fstab entry."
        else
            error_message "Unable to update fstab entry for ${mount_point}."
        fi
        return 1
    fi

    if ! chmod --reference="${fstab_file}" "${temporary_file}" 2>/dev/null; then
        chmod 0644 "${temporary_file}" || {
            rm -f "${temporary_file}"
            error_message "Unable to set permissions on temporary fstab file."
            return 1
        }
    fi

    if ! mv -f "${temporary_file}" "${fstab_file}"; then
        rm -f "${temporary_file}"
        error_message "Unable to replace fstab file: ${fstab_file}"
        return 1
    fi

    return 0
}

mount_create_backup() {
    local source_file="${1:-}"
    local backup_file="${2:-}"
    local backup_directory

    if [[ -z "${source_file}" || -z "${backup_file}" ]]; then
        error_message "Mount backup arguments must not be empty."
        return 1
    fi

    [[ -f "${source_file}" ]] || {
        error_message "Backup source does not exist: ${source_file}"
        return 1
    }

    if [[ -e "${backup_file}" ]]; then
        return 0
    fi

    backup_directory="$(dirname "${backup_file}")"
    mkdir -p "${backup_directory}" || {
        error_message "Unable to create backup directory: ${backup_directory}"
        return 1
    }

    cp -p "${source_file}" "${backup_file}" || {
        error_message "Unable to create mount backup: ${backup_file}"
        return 1
    }
}

mount_remount_with_option() {
    local mount_point="${1:-}"
    local required_option="${2:-}"

    [[ -n "${mount_point}" && -n "${required_option}" ]] || return 1

    mount -o "remount,${required_option}" "${mount_point}"
}

mount_apply_partition() {
    local control_identifier="${1:-}"
    local mount_point="${2:-}"
    local fstab_file="${3:-${RLCH_MOUNT_FSTAB_FILE}}"
    local effective_uid="${4:-}"
    local check_status

    if [[ -z "${control_identifier}" || -z "${mount_point}" || -z "${fstab_file}" || -z "${effective_uid}" ]]; then
        error_message "Mount partition remediation arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" -ne 0 ]]; then
        error_message "Root privileges are required to remediate CIS control ${control_identifier}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    mount_check_partition "${mount_point}" "${fstab_file}"
    check_status=$?
    if [[ "${check_status}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    error_message "Automatic partition creation is not supported for ${mount_point}."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

mount_apply_option() {
    local control_identifier="${1:-}"
    local mount_point="${2:-}"
    local required_option="${3:-}"
    local fstab_file="${4:-${RLCH_MOUNT_FSTAB_FILE}}"
    local backup_file="${5:-}"
    local effective_uid="${6:-}"
    local persistent_changed="false"
    local runtime_changed="false"

    if [[ -z "${control_identifier}" || -z "${mount_point}" || -z "${required_option}" || -z "${fstab_file}" || -z "${backup_file}" || -z "${effective_uid}" ]]; then
        error_message "Mount option remediation arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" -ne 0 ]]; then
        error_message "Root privileges are required to remediate CIS control ${control_identifier}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v findmnt >/dev/null 2>&1 || ! command -v mount >/dev/null 2>&1; then
        error_message "Required mount commands are unavailable."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_fstab_entry_exists "${mount_point}" "${fstab_file}"; then
        error_message "Mount point ${mount_point} has no fstab entry."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_fstab_has_option "${mount_point}" "${required_option}" "${fstab_file}"; then
        if ! mount_create_backup "${fstab_file}" "${backup_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if ! mount_write_fstab_option "${mount_point}" "${required_option}" "${fstab_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        persistent_changed="true"
    fi

    if ! mount_has_runtime_option "${mount_point}" "${required_option}"; then
        if ! mount_remount_with_option "${mount_point}" "${required_option}"; then
            error_message "Unable to remount ${mount_point} with option ${required_option}."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        runtime_changed="true"
    fi

    if [[ "${persistent_changed}" == "true" || "${runtime_changed}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

mount_validate_partition() {
    mount_check_partition "$@"
}

mount_validate_option() {
    mount_check_option "$@"
}

mount_rollback() {
    local control_identifier="${1:-}"
    local mount_point="${2:-}"
    local fstab_file="${3:-${RLCH_MOUNT_FSTAB_FILE}}"
    local backup_file="${4:-}"
    local effective_uid="${5:-}"

    if [[ -z "${control_identifier}" || -z "${mount_point}" || -z "${fstab_file}" || -z "${backup_file}" || -z "${effective_uid}" ]]; then
        error_message "Mount rollback arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" -ne 0 ]]; then
        error_message "Root privileges are required to roll back CIS control ${control_identifier}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -f "${backup_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! cp -p "${backup_file}" "${fstab_file}"; then
        error_message "Unable to restore fstab backup: ${backup_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if mount_is_separate_partition "${mount_point}"; then
        if ! mount -o remount "${mount_point}"; then
            error_message "Unable to remount ${mount_point} after rollback."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -f "${backup_file}"; then
        error_message "Unable to remove mount backup: ${backup_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
