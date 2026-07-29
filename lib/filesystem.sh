#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_FILESYSTEM_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_FILESYSTEM_LOADED=1

readonly RLCH_FILESYSTEM_DEFAULT_DIRECTORY_MODE="0755"
readonly RLCH_FILESYSTEM_DEFAULT_FILE_MODE="0644"
readonly RLCH_FILESYSTEM_DEFAULT_BACKUP_SUFFIX=".rlch.bak"

##
# Determine whether a filesystem path exists.
#
# Symbolic links are considered to exist even when their target is missing.
#
# Arguments:
#   $1 Filesystem path.
#
# Returns:
#   0 when the path exists.
#   1 otherwise.
##
filesystem_exists() {
    local path="${1:-}"

    [[ -n "${path}" && ( -e "${path}" || -L "${path}" ) ]]
}

##
# Determine whether a regular file exists.
#
# Arguments:
#   $1 File path.
#
# Returns:
#   0 when the path is a regular file.
#   1 otherwise.
##
filesystem_file_exists() {
    local file_path="${1:-}"

    [[ -n "${file_path}" && -f "${file_path}" ]]
}

##
# Determine whether a directory exists.
#
# Arguments:
#   $1 Directory path.
#
# Returns:
#   0 when the path is a directory.
#   1 otherwise.
##
filesystem_directory_exists() {
    local directory_path="${1:-}"

    [[ -n "${directory_path}" && -d "${directory_path}" ]]
}

##
# Determine whether a symbolic link exists.
#
# Arguments:
#   $1 Symbolic link path.
#
# Returns:
#   0 when the path is a symbolic link.
#   1 otherwise.
##
filesystem_symlink_exists() {
    local symlink_path="${1:-}"

    [[ -n "${symlink_path}" && -L "${symlink_path}" ]]
}

##
# Determine whether a path is readable.
#
# Arguments:
#   $1 Filesystem path.
#
# Returns:
#   0 when the path exists and is readable.
#   1 otherwise.
##
filesystem_is_readable() {
    local path="${1:-}"

    filesystem_exists "${path}" && [[ -r "${path}" ]]
}

##
# Determine whether a path is writable.
#
# Arguments:
#   $1 Filesystem path.
#
# Returns:
#   0 when the path exists and is writable.
#   1 otherwise.
##
filesystem_is_writable() {
    local path="${1:-}"

    filesystem_exists "${path}" && [[ -w "${path}" ]]
}

##
# Determine whether a path is executable.
#
# Arguments:
#   $1 Filesystem path.
#
# Returns:
#   0 when the path exists and is executable.
#   1 otherwise.
##
filesystem_is_executable() {
    local path="${1:-}"

    filesystem_exists "${path}" && [[ -x "${path}" ]]
}

##
# Validate a Unix file mode.
#
# Arguments:
#   $1 File mode.
#
# Returns:
#   0 when the mode is valid.
#   1 otherwise.
##
_filesystem_mode_is_valid() {
    local mode="${1:-}"

    [[ "${mode}" =~ ^0?[0-7]{3,4}$ ]]
}

##
# Return a temporary file path located beside the destination.
#
# Arguments:
#   $1 Destination file path.
#
# Outputs:
#   Temporary file path.
#
# Returns:
#   0 on success.
#   1 when the destination path is invalid.
##
_filesystem_temporary_path() {
    local destination_path="${1:-}"
    local destination_directory
    local destination_name

    if [[ -z "${destination_path}" ]]; then
        return 1
    fi

    destination_directory="$(dirname -- "${destination_path}")"
    destination_name="$(basename -- "${destination_path}")"

    printf '%s/.%s.rlch.XXXXXX\n' \
        "${destination_directory}" \
        "${destination_name}"
}

##
# Create a directory and its missing parents.
#
# Arguments:
#   $1 Directory path.
#   $2 Optional directory mode. Defaults to 0755.
#
# Returns:
#   0 when the directory exists with the requested mode.
#   1 on failure.
##
filesystem_create_directory() {
    local directory_path="${1:-}"
    local mode="${2:-${RLCH_FILESYSTEM_DEFAULT_DIRECTORY_MODE}}"

    if [[ -z "${directory_path}" ]]; then
        error_message "A directory path is required."
        return 1
    fi

    if ! _filesystem_mode_is_valid "${mode}"; then
        error_message "Invalid directory mode: ${mode}"
        return 1
    fi

    if filesystem_exists "${directory_path}" &&
        ! filesystem_directory_exists "${directory_path}"; then
        error_message \
            "Cannot create directory because the path already exists: ${directory_path}"
        return 1
    fi

    if ! mkdir -p -- "${directory_path}"; then
        error_message "Unable to create directory: ${directory_path}"
        return 1
    fi

    if ! chmod -- "${mode}" "${directory_path}"; then
        error_message \
            "Unable to set directory mode ${mode}: ${directory_path}"
        return 1
    fi

    return 0
}

##
# Remove a regular file or symbolic link.
#
# Missing paths are treated as already compliant.
#
# Arguments:
#   $1 File or symbolic link path.
#
# Returns:
#   0 when the path does not exist.
#   1 on failure.
##
filesystem_remove_file() {
    local file_path="${1:-}"

    if [[ -z "${file_path}" ]]; then
        error_message "A file path is required."
        return 1
    fi

    if ! filesystem_exists "${file_path}"; then
        return 0
    fi

    if filesystem_directory_exists "${file_path}" &&
        ! filesystem_symlink_exists "${file_path}"; then
        error_message "Path is a directory: ${file_path}"
        return 1
    fi

    if ! rm -f -- "${file_path}"; then
        error_message "Unable to remove file: ${file_path}"
        return 1
    fi

    return 0
}

##
# Remove a directory.
#
# Missing directories are treated as already compliant.
#
# Arguments:
#   $1 Directory path.
#   $2 Optional recursive boolean. Defaults to false.
#
# Returns:
#   0 when the directory does not exist.
#   1 on failure.
##
filesystem_remove_directory() {
    local directory_path="${1:-}"
    local recursive="${2:-false}"

    if [[ -z "${directory_path}" ]]; then
        error_message "A directory path is required."
        return 1
    fi

    if ! is_boolean "${recursive}"; then
        error_message "Invalid recursive value: ${recursive}"
        return 1
    fi

    if ! filesystem_exists "${directory_path}"; then
        return 0
    fi

    if ! filesystem_directory_exists "${directory_path}" ||
        filesystem_symlink_exists "${directory_path}"; then
        error_message "Path is not a directory: ${directory_path}"
        return 1
    fi

    if is_true "${recursive}"; then
        if ! rm -rf -- "${directory_path}"; then
            error_message "Unable to remove directory: ${directory_path}"
            return 1
        fi
    elif ! rmdir -- "${directory_path}"; then
        error_message \
            "Unable to remove non-empty directory: ${directory_path}"
        return 1
    fi

    return 0
}

##
# Copy a file or directory.
#
# Arguments:
#   $1 Source path.
#   $2 Destination path.
#   $3 Optional overwrite boolean. Defaults to false.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_copy() {
    local source_path="${1:-}"
    local destination_path="${2:-}"
    local overwrite="${3:-false}"
    local -a copy_options=(-a)

    if [[ -z "${source_path}" || -z "${destination_path}" ]]; then
        error_message "Source and destination paths are required."
        return 1
    fi

    if ! is_boolean "${overwrite}"; then
        error_message "Invalid overwrite value: ${overwrite}"
        return 1
    fi

    if ! filesystem_exists "${source_path}"; then
        error_message "Source path does not exist: ${source_path}"
        return 1
    fi

    if filesystem_exists "${destination_path}" && ! is_true "${overwrite}"; then
        error_message "Destination path already exists: ${destination_path}"
        return 1
    fi

    if is_true "${overwrite}"; then
        copy_options+=(-f)
    else
        copy_options+=(-n)
    fi

    if ! cp "${copy_options[@]}" -- "${source_path}" "${destination_path}"; then
        error_message \
            "Unable to copy ${source_path} to ${destination_path}"
        return 1
    fi

    return 0
}

##
# Move a file or directory.
#
# Arguments:
#   $1 Source path.
#   $2 Destination path.
#   $3 Optional overwrite boolean. Defaults to false.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_move() {
    local source_path="${1:-}"
    local destination_path="${2:-}"
    local overwrite="${3:-false}"
    local -a move_options=()

    if [[ -z "${source_path}" || -z "${destination_path}" ]]; then
        error_message "Source and destination paths are required."
        return 1
    fi

    if ! is_boolean "${overwrite}"; then
        error_message "Invalid overwrite value: ${overwrite}"
        return 1
    fi

    if ! filesystem_exists "${source_path}"; then
        error_message "Source path does not exist: ${source_path}"
        return 1
    fi

    if filesystem_exists "${destination_path}" && ! is_true "${overwrite}"; then
        error_message "Destination path already exists: ${destination_path}"
        return 1
    fi

    if is_true "${overwrite}"; then
        move_options+=(-f)
    else
        move_options+=(-n)
    fi

    if ! mv "${move_options[@]}" -- "${source_path}" "${destination_path}"; then
        error_message \
            "Unable to move ${source_path} to ${destination_path}"
        return 1
    fi

    return 0
}

##
# Print a regular file.
#
# Arguments:
#   $1 File path.
#
# Outputs:
#   File content.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_read_file() {
    local file_path="${1:-}"

    if [[ -z "${file_path}" ]]; then
        error_message "A file path is required."
        return 1
    fi

    if ! filesystem_file_exists "${file_path}"; then
        error_message "File does not exist: ${file_path}"
        return 1
    fi

    if ! filesystem_is_readable "${file_path}"; then
        error_message "File is not readable: ${file_path}"
        return 1
    fi

    cat -- "${file_path}"
}

##
# Replace a file atomically with supplied content.
#
# Arguments:
#   $1 File path.
#   $2 Content.
#   $3 Optional mode used when creating a new file. Defaults to 0644.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_write_file() {
    local file_path="${1:-}"
    local content="${2-}"
    local mode="${3:-${RLCH_FILESYSTEM_DEFAULT_FILE_MODE}}"
    local directory_path
    local temporary_template
    local temporary_path
    local existing_mode=""

    if [[ -z "${file_path}" ]]; then
        error_message "A file path is required."
        return 1
    fi

    if ! _filesystem_mode_is_valid "${mode}"; then
        error_message "Invalid file mode: ${mode}"
        return 1
    fi

    if filesystem_exists "${file_path}" &&
        ! filesystem_file_exists "${file_path}"; then
        error_message "Path is not a regular file: ${file_path}"
        return 1
    fi

    directory_path="$(dirname -- "${file_path}")"

    if ! filesystem_directory_exists "${directory_path}"; then
        error_message "Parent directory does not exist: ${directory_path}"
        return 1
    fi

    if filesystem_file_exists "${file_path}"; then
        existing_mode="$(filesystem_mode "${file_path}")" || return 1
    fi

    temporary_template="$(_filesystem_temporary_path "${file_path}")" ||
        return 1

    if ! temporary_path="$(mktemp "${temporary_template}")"; then
        error_message "Unable to create temporary file for: ${file_path}"
        return 1
    fi

    if ! printf '%s' "${content}" >"${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to write temporary file for: ${file_path}"
        return 1
    fi

    if [[ -n "${existing_mode}" ]]; then
        mode="${existing_mode}"
    fi

    if ! chmod -- "${mode}" "${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to set file mode ${mode}: ${temporary_path}"
        return 1
    fi

    if ! mv -f -- "${temporary_path}" "${file_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to replace file: ${file_path}"
        return 1
    fi

    return 0
}

##
# Append content to a file.
#
# Arguments:
#   $1 File path.
#   $2 Content.
#   $3 Optional mode used when creating a new file. Defaults to 0644.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_append_file() {
    local file_path="${1:-}"
    local content="${2-}"
    local mode="${3:-${RLCH_FILESYSTEM_DEFAULT_FILE_MODE}}"
    local directory_path
    local file_created=false

    if [[ -z "${file_path}" ]]; then
        error_message "A file path is required."
        return 1
    fi

    if ! _filesystem_mode_is_valid "${mode}"; then
        error_message "Invalid file mode: ${mode}"
        return 1
    fi

    if filesystem_exists "${file_path}" &&
        ! filesystem_file_exists "${file_path}"; then
        error_message "Path is not a regular file: ${file_path}"
        return 1
    fi

    directory_path="$(dirname -- "${file_path}")"

    if ! filesystem_directory_exists "${directory_path}"; then
        error_message "Parent directory does not exist: ${directory_path}"
        return 1
    fi

    if ! filesystem_file_exists "${file_path}"; then
        file_created=true
    fi

    if ! printf '%s' "${content}" >>"${file_path}"; then
        error_message "Unable to append to file: ${file_path}"
        return 1
    fi

    if is_true "${file_created}" && ! chmod -- "${mode}" "${file_path}"; then
        error_message "Unable to set file mode ${mode}: ${file_path}"
        return 1
    fi

    return 0
}

##
# Replace matching lines or append a replacement line.
#
# All lines matching the extended regular expression are removed. The
# replacement line is inserted at the position of the first match. When no
# match exists, the replacement line is appended.
#
# Arguments:
#   $1 File path.
#   $2 Extended regular expression.
#   $3 Replacement line.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_replace_line() {
    local file_path="${1:-}"
    local pattern="${2:-}"
    local replacement="${3-}"
    local temporary_template
    local temporary_path
    local current_mode
    local current_owner
    local current_group

    if [[ -z "${file_path}" || -z "${pattern}" ]]; then
        error_message "A file path and matching pattern are required."
        return 1
    fi

    if ! filesystem_file_exists "${file_path}"; then
        error_message "File does not exist: ${file_path}"
        return 1
    fi

    if ! filesystem_is_readable "${file_path}" ||
        ! filesystem_is_writable "${file_path}"; then
        error_message "File must be readable and writable: ${file_path}"
        return 1
    fi

    current_mode="$(filesystem_mode "${file_path}")" || return 1
    current_owner="$(filesystem_owner "${file_path}")" || return 1
    current_group="$(filesystem_group "${file_path}")" || return 1

    temporary_template="$(_filesystem_temporary_path "${file_path}")" ||
        return 1

    if ! temporary_path="$(mktemp "${temporary_template}")"; then
        error_message "Unable to create temporary file for: ${file_path}"
        return 1
    fi

    if ! awk \
        -v pattern="${pattern}" \
        -v replacement="${replacement}" \
        '
        BEGIN {
            replaced = 0
        }

        $0 ~ pattern {
            if (replaced == 0) {
                print replacement
                replaced = 1
            }
            next
        }

        {
            print
        }

        END {
            if (replaced == 0) {
                print replacement
            }
        }
        ' "${file_path}" >"${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to replace matching lines in: ${file_path}"
        return 1
    fi

    if ! chmod -- "${current_mode}" "${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to preserve file mode: ${file_path}"
        return 1
    fi

    if ! chown -- "${current_owner}:${current_group}" "${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to preserve file ownership: ${file_path}"
        return 1
    fi

    if ! mv -f -- "${temporary_path}" "${file_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to replace file: ${file_path}"
        return 1
    fi

    return 0
}

##
# Remove lines matching an extended regular expression.
#
# Arguments:
#   $1 File path.
#   $2 Extended regular expression.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_remove_matching_lines() {
    local file_path="${1:-}"
    local pattern="${2:-}"
    local temporary_template
    local temporary_path
    local current_mode
    local current_owner
    local current_group

    if [[ -z "${file_path}" || -z "${pattern}" ]]; then
        error_message "A file path and matching pattern are required."
        return 1
    fi

    if ! filesystem_file_exists "${file_path}"; then
        error_message "File does not exist: ${file_path}"
        return 1
    fi

    if ! filesystem_is_readable "${file_path}" ||
        ! filesystem_is_writable "${file_path}"; then
        error_message "File must be readable and writable: ${file_path}"
        return 1
    fi

    current_mode="$(filesystem_mode "${file_path}")" || return 1
    current_owner="$(filesystem_owner "${file_path}")" || return 1
    current_group="$(filesystem_group "${file_path}")" || return 1

    temporary_template="$(_filesystem_temporary_path "${file_path}")" ||
        return 1

    if ! temporary_path="$(mktemp "${temporary_template}")"; then
        error_message "Unable to create temporary file for: ${file_path}"
        return 1
    fi

    if ! awk \
        -v pattern="${pattern}" \
        '$0 !~ pattern { print }' \
        "${file_path}" >"${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to remove matching lines from: ${file_path}"
        return 1
    fi

    if ! chmod -- "${current_mode}" "${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to preserve file mode: ${file_path}"
        return 1
    fi

    if ! chown -- "${current_owner}:${current_group}" "${temporary_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to preserve file ownership: ${file_path}"
        return 1
    fi

    if ! mv -f -- "${temporary_path}" "${file_path}"; then
        rm -f -- "${temporary_path}"
        error_message "Unable to replace file: ${file_path}"
        return 1
    fi

    return 0
}

##
# Return the default backup path for a file.
#
# Arguments:
#   $1 Original path.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0 on success.
#   1 when the original path is invalid.
##
filesystem_backup_path() {
    local source_path="${1:-}"

    if [[ -z "${source_path}" ]]; then
        return 1
    fi

    printf '%s%s\n' \
        "${source_path}" \
        "${RLCH_FILESYSTEM_BACKUP_SUFFIX:-${RLCH_FILESYSTEM_DEFAULT_BACKUP_SUFFIX}}"
}

##
# Create a backup copy.
#
# Existing backups are preserved unless overwrite is enabled.
#
# Arguments:
#   $1 Source path.
#   $2 Optional backup path.
#   $3 Optional overwrite boolean. Defaults to false.
#
# Outputs:
#   Backup path.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_backup() {
    local source_path="${1:-}"
    local backup_path="${2:-}"
    local overwrite="${3:-false}"

    if [[ -z "${source_path}" ]]; then
        error_message "A source path is required."
        return 1
    fi

    if ! is_boolean "${overwrite}"; then
        error_message "Invalid overwrite value: ${overwrite}"
        return 1
    fi

    if ! filesystem_exists "${source_path}"; then
        error_message "Source path does not exist: ${source_path}"
        return 1
    fi

    if [[ -z "${backup_path}" ]]; then
        backup_path="$(filesystem_backup_path "${source_path}")" ||
            return 1
    fi

    if filesystem_exists "${backup_path}" && ! is_true "${overwrite}"; then
        printf '%s\n' "${backup_path}"
        return 0
    fi

    if ! filesystem_copy \
        "${source_path}" \
        "${backup_path}" \
        "${overwrite}" \
        >/dev/null; then
        return 1
    fi

    printf '%s\n' "${backup_path}"
}

##
# Restore a path from a backup.
#
# Arguments:
#   $1 Backup path.
#   $2 Destination path.
#   $3 Optional overwrite boolean. Defaults to true.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_restore() {
    local backup_path="${1:-}"
    local destination_path="${2:-}"
    local overwrite="${3:-true}"

    if [[ -z "${backup_path}" || -z "${destination_path}" ]]; then
        error_message "Backup and destination paths are required."
        return 1
    fi

    if ! is_boolean "${overwrite}"; then
        error_message "Invalid overwrite value: ${overwrite}"
        return 1
    fi

    if ! filesystem_exists "${backup_path}"; then
        error_message "Backup path does not exist: ${backup_path}"
        return 1
    fi

    filesystem_copy "${backup_path}" "${destination_path}" "${overwrite}"
}

##
# Return the SHA-256 checksum of a regular file.
#
# Arguments:
#   $1 File path.
#
# Outputs:
#   SHA-256 checksum.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_sha256() {
    local file_path="${1:-}"
    local checksum

    if [[ -z "${file_path}" ]]; then
        error_message "A file path is required."
        return 1
    fi

    if ! filesystem_file_exists "${file_path}"; then
        error_message "File does not exist: ${file_path}"
        return 1
    fi

    if ! command_exists "sha256sum"; then
        error_message "Required command is unavailable: sha256sum"
        return 1
    fi

    if ! checksum="$(sha256sum -- "${file_path}")"; then
        error_message "Unable to calculate SHA-256 checksum: ${file_path}"
        return 1
    fi

    printf '%s\n' "${checksum%% *}"
}

##
# Return the numeric owner identifier of a path.
#
# Arguments:
#   $1 Filesystem path.
#
# Outputs:
#   Numeric user identifier.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_owner() {
    local path="${1:-}"

    if ! filesystem_exists "${path}"; then
        return 1
    fi

    stat -c '%u' -- "${path}"
}

##
# Return the numeric group identifier of a path.
#
# Arguments:
#   $1 Filesystem path.
#
# Outputs:
#   Numeric group identifier.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_group() {
    local path="${1:-}"

    if ! filesystem_exists "${path}"; then
        return 1
    fi

    stat -c '%g' -- "${path}"
}

##
# Return the numeric mode of a path.
#
# Arguments:
#   $1 Filesystem path.
#
# Outputs:
#   Numeric mode without a leading zero.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_mode() {
    local path="${1:-}"

    if ! filesystem_exists "${path}"; then
        return 1
    fi

    stat -c '%a' -- "${path}"
}

##
# Set the owner of a filesystem path.
#
# Arguments:
#   $1 Filesystem path.
#   $2 User name or numeric user identifier.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_set_owner() {
    local path="${1:-}"
    local owner="${2:-}"

    if [[ -z "${path}" || -z "${owner}" ]]; then
        error_message "A path and owner are required."
        return 1
    fi

    if ! filesystem_exists "${path}"; then
        error_message "Path does not exist: ${path}"
        return 1
    fi

    if ! chown -- "${owner}" "${path}"; then
        error_message "Unable to set owner ${owner}: ${path}"
        return 1
    fi

    return 0
}

##
# Set the group of a filesystem path.
#
# Arguments:
#   $1 Filesystem path.
#   $2 Group name or numeric group identifier.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_set_group() {
    local path="${1:-}"
    local group="${2:-}"

    if [[ -z "${path}" || -z "${group}" ]]; then
        error_message "A path and group are required."
        return 1
    fi

    if ! filesystem_exists "${path}"; then
        error_message "Path does not exist: ${path}"
        return 1
    fi

    if ! chgrp -- "${group}" "${path}"; then
        error_message "Unable to set group ${group}: ${path}"
        return 1
    fi

    return 0
}

##
# Set the mode of a filesystem path.
#
# Arguments:
#   $1 Filesystem path.
#   $2 Numeric file mode.
#
# Returns:
#   0 on success.
#   1 on failure.
##
filesystem_set_mode() {
    local path="${1:-}"
    local mode="${2:-}"

    if [[ -z "${path}" || -z "${mode}" ]]; then
        error_message "A path and mode are required."
        return 1
    fi

    if ! _filesystem_mode_is_valid "${mode}"; then
        error_message "Invalid file mode: ${mode}"
        return 1
    fi

    if ! filesystem_exists "${path}"; then
        error_message "Path does not exist: ${path}"
        return 1
    fi

    if ! chmod -- "${mode}" "${path}"; then
        error_message "Unable to set mode ${mode}: ${path}"
        return 1
    fi

    return 0
}