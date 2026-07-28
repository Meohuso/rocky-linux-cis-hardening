#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_BOOTSTRAP_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_BOOTSTRAP_LOADED=1

if ! RLCH_BOOTSTRAP_LIB_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"; then
    printf '%s\n' \
        "RLCH bootstrap error: Unable to determine the library directory." >&2
    return 1
fi

readonly RLCH_BOOTSTRAP_LIB_DIR

##
# Print a bootstrap error before the framework logging subsystem is available.
#
# Arguments:
#   $1 Error message.
#
# Returns:
#   0 on success.
##
_bootstrap_print_error() {
    local message="${1:-Unknown bootstrap error.}"

    printf 'RLCH bootstrap error: %s\n' "${message}" >&2
}

##
# Load a framework library.
#
# Arguments:
#   $1 Library filename.
#
# Returns:
#   0 on success.
#   1 when the library cannot be loaded.
##
_bootstrap_load_library() {
    local library_name="${1:-}"
    local library_path

    if [[ -z "${library_name}" ]]; then
        _bootstrap_print_error "A library filename is required."
        return 1
    fi

    library_path="${RLCH_BOOTSTRAP_LIB_DIR}/${library_name}"

    if [[ ! -f "${library_path}" ]]; then
        _bootstrap_print_error \
            "Framework library does not exist: ${library_path}"
        return 1
    fi

    if [[ ! -r "${library_path}" ]]; then
        _bootstrap_print_error \
            "Framework library is not readable: ${library_path}"
        return 1
    fi

    # shellcheck source=/dev/null
    if ! source "${library_path}"; then
        _bootstrap_print_error \
            "Unable to load framework library: ${library_path}"
        return 1
    fi

    return 0
}

##
# Load the core framework libraries in dependency order.
#
# Returns:
#   0 on success.
#   1 when a library cannot be loaded.
##
_bootstrap_load_core_libraries() {
    local library_name
    local -a libraries=(
        "constants.sh"
        "common.sh"
        "error.sh"
        "configuration.sh"
        "logging.sh"
        "system.sh"
        "filesystem.sh"
        "modules.sh"
        "module_api.sh"
        "execution.sh"
    )

    for library_name in "${libraries[@]}"; do
        if ! _bootstrap_load_library "${library_name}"; then
            return 1
        fi
    done

    return 0
}

##
# Print the command-line help.
#
# Outputs:
#   Framework usage information.
#
# Returns:
#   0 on success.
##
show_help() {
    cat <<EOF
${RLCH_PROJECT_NAME}

Usage:
  rlch [COMMAND] [ARGUMENT]
  rlch [OPTION]

Commands:
  help                  Display this help message.
  version               Display the framework version.
  modules [FILTER]      List discovered modules.

Options:
  -h, --help            Display this help message.
  -V, --version         Display the framework version.

Module filters:
  *                     Match all modules.
  1.*                   Match all modules in section 1.
  1.1.*                 Match all modules in section 1.1.
  1.1.1                 Match a specific module.

Examples:
  rlch
  rlch help
  rlch --version
  rlch modules
  rlch modules '1.1.*'
EOF
}

##
# Print the framework version.
#
# Outputs:
#   Framework name and version.
#
# Returns:
#   0 on success.
##
show_version() {
    printf '%s %s\n' "${RLCH_PROJECT_NAME}" "${RLCH_VERSION}"
}

##
# Normalize a command-line command or option.
#
# Arguments:
#   $1 Command or option.
#
# Outputs:
#   Canonical command name.
#
# Returns:
#   0 when the command is recognized.
#   1 otherwise.
##
_bootstrap_normalize_command() {
    local command_name="${1:-}"

    case "${command_name}" in
        help | -h | --help)
            printf '%s\n' "help"
            ;;
        version | -V | --version)
            printf '%s\n' "version"
            ;;
        modules | list-modules)
            printf '%s\n' "modules"
            ;;
        *)
            return 1
            ;;
    esac
}

##
# Initialize the framework core.
#
# Returns:
#   0 on success.
#   Terminates execution when initialization fails.
##
initialize_framework() {
    if ! load_constants; then
        die_environment "Unable to initialize framework constants."
    fi

    if ! load_configuration; then
        die_configuration "Unable to load framework configuration."
    fi

    if ! initialize_logging; then
        die_configuration "Unable to initialize framework logging."
    fi

    log_debug "Framework core initialized."
}

##
# Execute a framework command.
#
# Arguments:
#   $1 Command name.
#   Remaining arguments are passed to the command.
#
# Returns:
#   0 on success.
#   Terminates execution when the command is invalid.
##
execute_command() {
    local command_name="${1:-}"

    shift || true

    case "${command_name}" in
        help)
            if (($# > 0)); then
                die_invalid_argument \
                    "The help command does not accept arguments."
            fi

            show_help
            ;;
        version)
            if (($# > 0)); then
                die_invalid_argument \
                    "The version command does not accept arguments."
            fi

            show_version
            ;;
        modules)
            if (($# > 1)); then
                die_invalid_argument \
                    "The modules command accepts at most one filter."
            fi

            if ! list_modules "${1:-${RLCH_MODULE_DEFAULT_FILTER}}"; then
                die_execution "Unable to discover framework modules."
            fi
            ;;
        *)
            die_invalid_argument \
                "Unsupported command: ${command_name}. Use --help for usage."
            ;;
    esac
}

##
# Main framework entry point.
#
# Arguments:
#   All command-line arguments.
#
# Returns:
#   0 on success.
#   A framework-specific exit status on failure.
##
main() {
    local requested_command="${1:-}"
    local normalized_command

    if ! _bootstrap_load_core_libraries; then
        return 1
    fi

    initialize_framework

    if [[ -z "${requested_command}" ]]; then
        requested_command="${RLCH_DEFAULT_COMMAND}"
    else
        shift
    fi

    if ! normalized_command="$(
        _bootstrap_normalize_command "${requested_command}"
    )"; then
        die_invalid_argument \
            "Unsupported command: ${requested_command}. Use --help for usage."
    fi

    execute_command "${normalized_command}" "$@"
}