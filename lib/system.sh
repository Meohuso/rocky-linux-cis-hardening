#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# System information and operating system detection library.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_SYSTEM_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_SYSTEM_LOADED=1

readonly RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE="/etc/os-release"
readonly RLCH_SYSTEM_DEFAULT_BOOT_ID_FILE="/proc/sys/kernel/random/boot_id"
readonly RLCH_SYSTEM_DEFAULT_UPTIME_FILE="/proc/uptime"

##
# Determine whether a system command is available.
#
# Arguments:
#   $1 Command name.
#
# Returns:
#   0 when the command exists.
#   1 otherwise.
##
system_command_exists() {
    local command_name="${1:-}"

    if [[ -z "${command_name}" ]]; then
        return 1
    fi

    command_exists "${command_name}"
}

##
# Require a system command.
#
# Arguments:
#   $1 Command name.
#
# Outputs:
#   An error message when the command is unavailable.
#
# Returns:
#   0 when the command exists.
#   1 otherwise.
##
system_require_command() {
    local command_name="${1:-}"

    if [[ -z "${command_name}" ]]; then
        error_message "A command name is required."
        return 1
    fi

    if system_command_exists "${command_name}"; then
        return 0
    fi

    error_message "Required system command is unavailable: ${command_name}"
    return 1
}

##
# Read a value from an os-release compatible file.
#
# The first matching key is returned. Surrounding single or double quotes are
# removed from the value.
#
# Arguments:
#   $1 Key name.
#   $2 Optional os-release file path.
#
# Outputs:
#   Value associated with the requested key.
#
# Returns:
#   0 when the key exists.
#   1 when the argument, file, or key is invalid.
##
system_os_release_value() {
    local key_name="${1:-}"
    local os_release_file="${
        2:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"
    local line
    local value

    if [[ -z "${key_name}" ]] ||
        [[ ! "${key_name}" =~ ^[A-Z0-9_]+$ ]]; then
        return 1
    fi

    if ! readable_file_exists "${os_release_file}"; then
        return 1
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" != "${key_name}="* ]]; then
            continue
        fi

        value="${line#"${key_name}="}"

        if [[ "${value}" == \"*\" ]] &&
            [[ "${value}" == *\" ]] &&
            ((${#value} >= 2)); then
            value="${value:1:${#value}-2}"
        elif [[ "${value}" == \'*\' ]] &&
            [[ "${value}" == *\' ]] &&
            ((${#value} >= 2)); then
            value="${value:1:${#value}-2}"
        fi

        printf '%s\n' "${value}"
        return 0
    done <"${os_release_file}"

    return 1
}

##
# Return the operating system identifier.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Outputs:
#   Operating system identifier.
#
# Returns:
#   0 when the identifier is available.
#   1 otherwise.
##
system_operating_system_id() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"

    system_os_release_value "ID" "${os_release_file}"
}

##
# Return the operating system name.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Outputs:
#   Operating system display name.
#
# Returns:
#   0 when the name is available.
#   1 otherwise.
##
system_operating_system_name() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"

    system_os_release_value "NAME" "${os_release_file}"
}

##
# Return the operating system version identifier.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Outputs:
#   Operating system version identifier.
#
# Returns:
#   0 when the version identifier is available.
#   1 otherwise.
##
system_operating_system_version_id() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"

    system_os_release_value "VERSION_ID" "${os_release_file}"
}

##
# Return the operating system major version.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Outputs:
#   Numeric major version.
#
# Returns:
#   0 when the major version can be determined.
#   1 otherwise.
##
system_operating_system_major_version() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"
    local version_id
    local major_version

    if ! version_id="$(
        system_operating_system_version_id "${os_release_file}"
    )"; then
        return 1
    fi

    major_version="${version_id%%.*}"

    if [[ ! "${major_version}" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    printf '%s\n' "${major_version}"
}

##
# Determine whether the operating system is Rocky Linux.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Returns:
#   0 when the operating system identifier is rocky.
#   1 otherwise.
##
system_is_rocky_linux() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"
    local operating_system_id

    if ! operating_system_id="$(
        system_operating_system_id "${os_release_file}"
    )"; then
        return 1
    fi

    [[ "${operating_system_id,,}" == "rocky" ]]
}

##
# Determine whether the operating system is Rocky Linux 10.
#
# Arguments:
#   $1 Optional os-release file path.
#
# Returns:
#   0 when the operating system is Rocky Linux 10.
#   1 otherwise.
##
system_is_rocky_linux_10() {
    local os_release_file="${
        1:-${RLCH_SYSTEM_OS_RELEASE_FILE:-${RLCH_SYSTEM_DEFAULT_OS_RELEASE_FILE}}
    }"
    local major_version

    if ! system_is_rocky_linux "${os_release_file}"; then
        return 1
    fi

    if ! major_version="$(
        system_operating_system_major_version "${os_release_file}"
    )"; then
        return 1
    fi

    [[ "${major_version}" == "10" ]]
}

##
# Return the running kernel release.
#
# Outputs:
#   Kernel release reported by uname.
#
# Returns:
#   0 when the kernel release is available.
#   1 otherwise.
##
system_kernel_release() {
    if ! system_require_command "uname"; then
        return 1
    fi

    uname -r
}

##
# Return the system architecture.
#
# Outputs:
#   Machine architecture reported by uname.
#
# Returns:
#   0 when the architecture is available.
#   1 otherwise.
##
system_architecture() {
    if ! system_require_command "uname"; then
        return 1
    fi

    uname -m
}

##
# Return the system hostname.
#
# hostnamectl is preferred when available. The hostname command is used as a
# fallback.
#
# Outputs:
#   Static or current system hostname.
#
# Returns:
#   0 when the hostname is available.
#   1 otherwise.
##
system_hostname() {
    local hostname_value

    if system_command_exists "hostnamectl"; then
        if hostname_value="$(
            hostnamectl --static 2>/dev/null
        )" && [[ -n "${hostname_value}" ]]; then
            printf '%s\n' "${hostname_value}"
            return 0
        fi
    fi

    if system_command_exists "hostname"; then
        if hostname_value="$(
            hostname 2>/dev/null
        )" && [[ -n "${hostname_value}" ]]; then
            printf '%s\n' "${hostname_value}"
            return 0
        fi
    fi

    error_message "Unable to determine the system hostname."
    return 1
}

##
# Determine whether systemd is the active init system.
#
# Returns:
#   0 when PID 1 is systemd.
#   1 otherwise.
##
system_is_systemd() {
    local process_name

    if [[ ! -r "/proc/1/comm" ]]; then
        return 1
    fi

    if ! IFS= read -r process_name <"/proc/1/comm"; then
        return 1
    fi

    [[ "${process_name}" == "systemd" ]]
}

##
# Return the current system boot identifier.
#
# Arguments:
#   $1 Optional boot identifier file path.
#
# Outputs:
#   System boot identifier.
#
# Returns:
#   0 when the boot identifier is available.
#   1 otherwise.
##
system_boot_id() {
    local boot_id_file="${
        1:-${RLCH_SYSTEM_BOOT_ID_FILE:-${RLCH_SYSTEM_DEFAULT_BOOT_ID_FILE}}
    }"
    local boot_id

    if ! readable_file_exists "${boot_id_file}"; then
        return 1
    fi

    if ! IFS= read -r boot_id <"${boot_id_file}"; then
        return 1
    fi

    boot_id="$(trim "${boot_id}")"

    if [[ -z "${boot_id}" ]]; then
        return 1
    fi

    printf '%s\n' "${boot_id}"
}

##
# Return the system uptime as a whole number of seconds.
#
# Arguments:
#   $1 Optional uptime file path.
#
# Outputs:
#   Whole number of elapsed seconds since boot.
#
# Returns:
#   0 when uptime is available and valid.
#   1 otherwise.
##
system_uptime_seconds() {
    local uptime_file="${
        1:-${RLCH_SYSTEM_UPTIME_FILE:-${RLCH_SYSTEM_DEFAULT_UPTIME_FILE}}
    }"
    local uptime_value
    local uptime_seconds

    if ! readable_file_exists "${uptime_file}"; then
        return 1
    fi

    if ! read -r uptime_value _ <"${uptime_file}"; then
        return 1
    fi

    if [[ ! "${uptime_value}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        return 1
    fi

    uptime_seconds="${uptime_value%%.*}"

    printf '%s\n' "${uptime_seconds}"
}