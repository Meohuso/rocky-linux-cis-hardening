#!/usr/bin/env bash

# Rocky Linux CIS Hardening Framework
# Mount management library.
#
# This library centralizes persistent and runtime mount inspection and
# remediation. CIS modules must consume the public functions exposed here
# instead of invoking findmnt, mount, or editing /etc/fstab directly.

if [[ -n "${RLCH_MOUNT_LIBRARY_LOADED:-}" ]]; then
    return 0 2>/dev/null || exit 0
fi
readonly RLCH_MOUNT_LIBRARY_LOADED=1

: "${RLCH_MOUNT_FSTAB:=/etc/fstab}"
: "${RLCH_MOUNT_BACKUP_SUFFIX:=.rlch.bak}"
: "${RLCH_MOUNT_FINDMNT_COMMAND:=findmnt}"
: "${RLCH_MOUNT_COMMAND:=mount}"

# Framework result fallbacks. Existing constants remain authoritative.
: "${RLCH_MODULE_RESULT_COMPLIANT:=0}"
: "${RLCH_MODULE_RESULT_NON_COMPLIANT:=1}"
: "${RLCH_MODULE_RESULT_CHANGED:=2}"
: "${RLCH_MODULE_RESULT_ERROR:=3}"

##
# Print a mount-library error.
#
# Arguments:
#   $1 Error message.
#
# Returns:
#   0.
##
_mount_error() {
    printf 'mount: %s\n' "${1:-Unknown error.}" >&2
}

##
# Validate a mount target.
#
# Arguments:
#   $1 Absolute mount target.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_is_valid_target() {
    local target="${1:-}"

    [[ -n "${target}" ]] || return 1
    [[ "${target}" == /* ]] || return 1
    [[ "${target}" != *$'\n'* ]] || return 1
    [[ "${target}" != *$'\r'* ]] || return 1
    [[ "${target}" != *$'\t'* ]] || return 1

    return 0
}

##
# Validate a single mount option.
#
# Arguments:
#   $1 Mount option.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_is_valid_option() {
    local option="${1:-}"

    [[ -n "${option}" ]] || return 1
    [[ "${option}" != *,* ]] || return 1
    [[ "${option}" != *[[:space:]]* ]] || return 1
    [[ "${option}" =~ ^[A-Za-z0-9._:+@=-]+$ ]] || return 1

    return 0
}

##
# Normalize a mount target for exact comparisons.
#
# Root remains "/". Other trailing slashes are removed.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Normalized target.
#
# Returns:
#   0 when valid.
#   1 otherwise.
##
mount_normalize_target() {
    local target="${1:-}"

    mount_is_valid_target "${target}" || return 1

    while [[ "${target}" != "/" && "${target}" == */ ]]; do
        target="${target%/}"
    done

    printf '%s\n' "${target}"
}

##
# Decode fstab escape sequences used in source and target fields.
#
# Arguments:
#   $1 Encoded field.
#
# Outputs:
#   Decoded field.
#
# Returns:
#   0.
##
_mount_decode_fstab_field() {
    local value="${1:-}"

    value="${value//\\040/ }"
    value="${value//\\011/$'\t'}"
    value="${value//\\012/$'\n'}"
    value="${value//\\134/\\}"

    printf '%s\n' "${value}"
}

##
# Encode a field for fstab.
#
# Arguments:
#   $1 Plain field.
#
# Outputs:
#   Encoded field.
#
# Returns:
#   0.
##
_mount_encode_fstab_field() {
    local value="${1:-}"

    value="${value//\\/\\134}"
    value="${value//$'\t'/\\011}"
    value="${value//$'\n'/\\012}"
    value="${value// /\\040}"

    printf '%s\n' "${value}"
}

##
# Test whether a comma-separated option list contains an exact option.
#
# Arguments:
#   $1 Comma-separated option list.
#   $2 Required option.
#
# Returns:
#   0 when present.
#   1 otherwise.
##
mount_option_list_contains() {
    local option_list="${1:-}"
    local required_option="${2:-}"
    local option
    local -a options=()

    mount_is_valid_option "${required_option}" || return 1

    IFS=',' read -r -a options <<< "${option_list}"
    for option in "${options[@]}"; do
        [[ "${option}" == "${required_option}" ]] && return 0
    done

    return 1
}

##
# Add an option to a comma-separated list without duplicates.
#
# Arguments:
#   $1 Existing option list.
#   $2 Required option.
#
# Outputs:
#   Updated option list.
#
# Returns:
#   0 on success.
#   1 for invalid input.
##
mount_option_list_add() {
    local option_list="${1:-}"
    local required_option="${2:-}"

    mount_is_valid_option "${required_option}" || return 1

    if mount_option_list_contains "${option_list}" "${required_option}"; then
        printf '%s\n' "${option_list}"
    elif [[ -z "${option_list}" ]]; then
        printf '%s\n' "${required_option}"
    else
        printf '%s,%s\n' "${option_list}" "${required_option}"
    fi
}

##
# Print the first active fstab entry for an exact target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path. Defaults to RLCH_MOUNT_FSTAB.
#
# Outputs:
#   Six tab-separated fields:
#   source, target, filesystem, options, dump, pass.
#
# Returns:
#   0 when found.
#   1 when absent or invalid.
##
mount_fstab_entry() {
    local requested_target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"
    local normalized_target
    local line
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value
    local extra
    local decoded_target

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1
    [[ -r "${fstab_path}" ]] || return 1

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue

        source=""
        target=""
        filesystem=""
        options=""
        dump_value=""
        pass_value=""
        extra=""

        read -r source target filesystem options dump_value pass_value extra <<< "${line}"

        [[ -n "${source}" && -n "${target}" && -n "${filesystem}" && -n "${options}" ]] || continue
        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || continue

        if [[ "${decoded_target}" == "${normalized_target}" ]]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${source}" \
                "${target}" \
                "${filesystem}" \
                "${options}" \
                "${dump_value:-0}" \
                "${pass_value:-0}"
            return 0
        fi
    done < "${fstab_path}"

    return 1
}

##
# Print the persistent option list for an exact target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Outputs:
#   Comma-separated option list.
#
# Returns:
#   0 when the target exists in fstab.
#   1 otherwise.
##
mount_fstab_options() {
    local entry
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value

    entry="$(mount_fstab_entry "${1:-}" "${2:-${RLCH_MOUNT_FSTAB}}")" || return 1
    IFS=$'\t' read -r source target filesystem options dump_value pass_value <<< "${entry}"
    printf '%s\n' "${options}"
}

##
# Print runtime mount data for an exact target.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Four tab-separated fields:
#   source, target, filesystem, options.
#
# Returns:
#   0 when the exact target is mounted.
#   1 otherwise.
##
mount_runtime_entry() {
    local requested_target="${1:-}"
    local normalized_target
    local output
    local source
    local target
    local filesystem
    local options
    local decoded_target

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1

    command -v "${RLCH_MOUNT_FINDMNT_COMMAND}" >/dev/null 2>&1 || return 1

    output="$(
        "${RLCH_MOUNT_FINDMNT_COMMAND}" \
            --raw \
            --noheadings \
            --output SOURCE,TARGET,FSTYPE,OPTIONS \
            --target "${normalized_target}" 2>/dev/null
    )" || return 1

    [[ -n "${output}" ]] || return 1

    while IFS= read -r output; do
        read -r source target filesystem options <<< "${output}"
        [[ -n "${target}" ]] || continue

        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || continue

        if [[ "${decoded_target}" == "${normalized_target}" ]]; then
            printf '%s\t%s\t%s\t%s\n' \
                "${source}" \
                "${target}" \
                "${filesystem}" \
                "${options}"
            return 0
        fi
    done <<< "${output}"

    return 1
}

##
# Print runtime options for an exact mount target.
#
# Arguments:
#   $1 Mount target.
#
# Outputs:
#   Comma-separated option list.
#
# Returns:
#   0 when mounted.
#   1 otherwise.
##
mount_runtime_options() {
    local entry
    local source
    local target
    local filesystem
    local options

    entry="$(mount_runtime_entry "${1:-}")" || return 1
    IFS=$'\t' read -r source target filesystem options <<< "${entry}"
    printf '%s\n' "${options}"
}

##
# Check whether a target has its own persistent and runtime mount.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when both exact entries exist.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
##
mount_check_partition() {
    local target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"

    if ! mount_fstab_entry "${target}" "${fstab_path}" >/dev/null; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! mount_runtime_entry "${target}" >/dev/null; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_COMPLIANT}"
}

##
# Check whether a mount option is configured persistently and active.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when persistent and runtime states comply.
#   RLCH_MODULE_RESULT_NON_COMPLIANT otherwise.
#   RLCH_MODULE_RESULT_ERROR for invalid arguments.
##
mount_check_option() {
    local target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local persistent_options
    local runtime_options

    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_option "${required_option}" || return "${RLCH_MODULE_RESULT_ERROR}"

    persistent_options="$(mount_fstab_options "${target}" "${fstab_path}")" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    mount_option_list_contains "${persistent_options}" "${required_option}" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    runtime_options="$(mount_runtime_options "${target}")" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    mount_option_list_contains "${runtime_options}" "${required_option}" ||
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"

    return "${RLCH_MODULE_RESULT_COMPLIANT}"
}

##
# Return the backup path associated with an fstab file.
#
# Arguments:
#   $1 Optional fstab path.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0.
##
mount_backup_path() {
    local fstab_path="${1:-${RLCH_MOUNT_FSTAB}}"

    printf '%s%s\n' "${fstab_path}" "${RLCH_MOUNT_BACKUP_SUFFIX}"
}

##
# Create the persistent backup once.
#
# Existing backups are preserved to retain the original pre-remediation state.
#
# Arguments:
#   $1 Optional fstab path.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0 on success.
#   1 on failure.
##
mount_backup_fstab() {
    local fstab_path="${1:-${RLCH_MOUNT_FSTAB}}"
    local backup_path

    [[ -f "${fstab_path}" ]] || return 1
    backup_path="$(mount_backup_path "${fstab_path}")"

    if [[ ! -e "${backup_path}" ]]; then
        cp --preserve=mode,ownership,timestamps -- "${fstab_path}" "${backup_path}" || return 1
    fi

    printf '%s\n' "${backup_path}"
}

##
# Require effective root privileges.
#
# Returns:
#   0 for root.
#   1 otherwise.
##
_mount_require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        _mount_error "Root privileges are required."
        return 1
    fi

    return 0
}

##
# Add an option to the exact target entry using an atomic replacement.
#
# Comments, blank lines, unrelated entries, source, filesystem, dump, and pass
# values are preserved. The matching entry is normalized to tab-separated
# fields when changed.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   0 on success, including idempotent success.
#   1 on failure.
##
mount_write_fstab_option() {
    local requested_target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local normalized_target
    local directory
    local temporary_path
    local line
    local source
    local target
    local filesystem
    local options
    local dump_value
    local pass_value
    local extra
    local decoded_target
    local updated_options
    local found=0
    local changed=0

    normalized_target="$(mount_normalize_target "${requested_target}")" || return 1
    mount_is_valid_option "${required_option}" || return 1
    [[ -f "${fstab_path}" && -r "${fstab_path}" && -w "${fstab_path}" ]] || return 1

    directory="$(dirname -- "${fstab_path}")"
    temporary_path="$(mktemp "${directory}/.rlch-fstab.XXXXXX")" || return 1

    if ! chmod --reference="${fstab_path}" "${temporary_path}" ||
        ! chown --reference="${fstab_path}" "${temporary_path}" 2>/dev/null; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" =~ ^[[:space:]]*$ || "${line}" =~ ^[[:space:]]*# ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        source=""
        target=""
        filesystem=""
        options=""
        dump_value=""
        pass_value=""
        extra=""

        read -r source target filesystem options dump_value pass_value extra <<< "${line}"

        if [[ -z "${source}" || -z "${target}" || -z "${filesystem}" || -z "${options}" ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        decoded_target="$(_mount_decode_fstab_field "${target}")"
        decoded_target="$(mount_normalize_target "${decoded_target}")" || decoded_target=""

        if [[ "${decoded_target}" != "${normalized_target}" ]]; then
            printf '%s\n' "${line}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
            continue
        fi

        found=1
        updated_options="$(mount_option_list_add "${options}" "${required_option}")" || {
            rm -f -- "${temporary_path}"
            return 1
        }

        if [[ "${updated_options}" != "${options}" ]]; then
            changed=1
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${source}" \
            "${target}" \
            "${filesystem}" \
            "${updated_options}" \
            "${dump_value:-0}" \
            "${pass_value:-0}" >> "${temporary_path}" || {
                rm -f -- "${temporary_path}"
                return 1
            }
    done < "${fstab_path}"

    if [[ "${found}" -eq 0 ]]; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    if [[ "${changed}" -eq 0 ]]; then
        rm -f -- "${temporary_path}"
        return 0
    fi

    sync "${temporary_path}" 2>/dev/null || true

    if ! mv -f -- "${temporary_path}" "${fstab_path}"; then
        rm -f -- "${temporary_path}"
        return 1
    fi

    return 0
}

##
# Remount an exact target using its fstab configuration.
#
# Arguments:
#   $1 Mount target.
#
# Returns:
#   0 on success.
#   1 on failure.
##
mount_remount_target() {
    local target="${1:-}"
    local normalized_target

    normalized_target="$(mount_normalize_target "${target}")" || return 1
    command -v "${RLCH_MOUNT_COMMAND}" >/dev/null 2>&1 || return 1

    "${RLCH_MOUNT_COMMAND}" -o remount "${normalized_target}"
}

##
# Apply a persistent and runtime mount option.
#
# Arguments:
#   $1 Mount target.
#   $2 Required option.
#   $3 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_COMPLIANT when already compliant.
#   RLCH_MODULE_RESULT_CHANGED when changed successfully.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
mount_apply_option() {
    local target="${1:-}"
    local required_option="${2:-}"
    local fstab_path="${3:-${RLCH_MOUNT_FSTAB}}"
    local check_status
    local backup_path

    _mount_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_option "${required_option}" || return "${RLCH_MODULE_RESULT_ERROR}"

    mount_check_option "${target}" "${required_option}" "${fstab_path}"
    check_status=$?

    if [[ "${check_status}" -eq "${RLCH_MODULE_RESULT_COMPLIANT}" ]]; then
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    fi

    backup_path="$(mount_backup_fstab "${fstab_path}")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! mount_write_fstab_option "${target}" "${required_option}" "${fstab_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_remount_target "${target}"; then
        cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}" 2>/dev/null || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mount_check_option "${target}" "${required_option}" "${fstab_path}"; then
        cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}" 2>/dev/null || true
        mount_remount_target "${target}" >/dev/null 2>&1 || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

##
# Refuse automatic storage provisioning.
#
# The framework validates partition requirements but does not create,
# resize, format, or migrate filesystems automatically.
#
# Returns:
#   RLCH_MODULE_RESULT_ERROR.
##
mount_apply_partition() {
    _mount_error "Automatic partition creation is intentionally unsupported."
    return "${RLCH_MODULE_RESULT_ERROR}"
}

##
# Restore the original fstab backup and remount the target.
#
# Arguments:
#   $1 Mount target.
#   $2 Optional fstab path.
#
# Returns:
#   RLCH_MODULE_RESULT_CHANGED when restored.
#   RLCH_MODULE_RESULT_COMPLIANT when no backup exists.
#   RLCH_MODULE_RESULT_ERROR on failure.
##
mount_rollback() {
    local target="${1:-}"
    local fstab_path="${2:-${RLCH_MOUNT_FSTAB}}"
    local backup_path

    _mount_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    mount_is_valid_target "${target}" || return "${RLCH_MODULE_RESULT_ERROR}"

    backup_path="$(mount_backup_path "${fstab_path}")"

    if [[ ! -e "${backup_path}" ]]; then
        return "${RLCH_MODULE_RESULT_COMPLIANT}"
    fi

    [[ -f "${backup_path}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cp --preserve=mode,ownership,timestamps -- "${backup_path}" "${fstab_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if mount_runtime_entry "${target}" >/dev/null 2>&1; then
        if ! mount_remount_target "${target}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -f -- "${backup_path}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
