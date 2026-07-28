#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_COMMON_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_COMMON_LOADED=1

##
# Determine whether a command is available.
#
# Arguments:
#   $1 Command name.
#
# Returns:
#   0 when the command exists.
#   1 otherwise.
##
command_exists() {
    local command_name="${1:-}"

    if [[ -z "${command_name}" ]]; then
        return 1
    fi

    command -v -- "${command_name}" >/dev/null 2>&1
}

##
# Determine whether a regular file exists.
#
# Arguments:
#   $1 File path.
#
# Returns:
#   0 when the file exists.
#   1 otherwise.
##
file_exists() {
    local file_path="${1:-}"

    [[ -n "${file_path}" && -f "${file_path}" ]]
}

##
# Determine whether a readable regular file exists.
#
# Arguments:
#   $1 File path.
#
# Returns:
#   0 when the file exists and is readable.
#   1 otherwise.
##
readable_file_exists() {
    local file_path="${1:-}"

    [[ -n "${file_path}" && -f "${file_path}" && -r "${file_path}" ]]
}

##
# Determine whether a directory exists.
#
# Arguments:
#   $1 Directory path.
#
# Returns:
#   0 when the directory exists.
#   1 otherwise.
##
directory_exists() {
    local directory_path="${1:-}"

    [[ -n "${directory_path}" && -d "${directory_path}" ]]
}

##
# Determine whether a value represents true.
#
# Accepted values:
#   true
#   yes
#   1
#   on
#
# Arguments:
#   $1 Value.
#
# Returns:
#   0 when the value represents true.
#   1 otherwise.
##
is_true() {
    local value="${1:-}"

    value="${value,,}"

    case "${value}" in
        true | yes | 1 | on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Determine whether a value represents false.
#
# Accepted values:
#   false
#   no
#   0
#   off
#
# Arguments:
#   $1 Value.
#
# Returns:
#   0 when the value represents false.
#   1 otherwise.
##
is_false() {
    local value="${1:-}"

    value="${value,,}"

    case "${value}" in
        false | no | 0 | off)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Determine whether a value is a supported boolean.
#
# Arguments:
#   $1 Value.
#
# Returns:
#   0 when the value is a supported boolean.
#   1 otherwise.
##
is_boolean() {
    local value="${1:-}"

    is_true "${value}" || is_false "${value}"
}

##
# Remove leading and trailing whitespace from a string.
#
# Arguments:
#   $1 Value.
#
# Outputs:
#   Trimmed value.
#
# Returns:
#   0 on success.
##
trim() {
    local value="${1:-}"

    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    printf '%s' "${value}"
}

##
# Determine whether the current process runs as root.
#
# Returns:
#   0 when running as root.
#   1 otherwise.
##
is_root() {
    ((EUID == 0))
}

##
# Require root privileges.
#
# Outputs:
#   An error message to standard error when root privileges are missing.
#
# Returns:
#   0 when running as root.
#   1 otherwise.
##
require_root() {
    if is_root; then
        return 0
    fi

    printf 'Root privileges are required.\n' >&2
    return 1
}