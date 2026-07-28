#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_CONFIGURATION_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_CONFIGURATION_LOADED=1

RLCH_REQUIRE_ROOT="${RLCH_REQUIRE_ROOT:-true}"
RLCH_STRICT_CONFIGURATION="${RLCH_STRICT_CONFIGURATION:-true}"
RLCH_DEFAULT_COMMAND="${RLCH_DEFAULT_COMMAND:-help}"
RLCH_OPENSCAP_PROFILE="${RLCH_OPENSCAP_PROFILE:-}"

##
# Load a configuration file.
#
# Arguments:
#   $1 Configuration file path.
#   $2 Optional requirement flag:
#      required
#      optional
#
# Returns:
#   0 on success.
#   1 when a required file cannot be loaded.
##
load_configuration_file() {
    local configuration_file="${1:-}"
    local requirement="${2:-required}"

    if [[ -z "${configuration_file}" ]]; then
        printf 'Configuration file path is required.\n' >&2
        return 1
    fi

    case "${requirement}" in
        required | optional) ;;
        *)
            printf 'Invalid configuration requirement: %s\n' \
                "${requirement}" >&2
            return 1
            ;;
    esac

    if [[ ! -e "${configuration_file}" ]]; then
        if [[ "${requirement}" == "optional" ]]; then
            return 0
        fi

        printf 'Configuration file does not exist: %s\n' \
            "${configuration_file}" >&2
        return 1
    fi

    if [[ ! -f "${configuration_file}" ]]; then
        printf 'Configuration path is not a regular file: %s\n' \
            "${configuration_file}" >&2
        return 1
    fi

    if [[ ! -r "${configuration_file}" ]]; then
        printf 'Configuration file is not readable: %s\n' \
            "${configuration_file}" >&2
        return 1
    fi

    # shellcheck source=/dev/null
    if ! source "${configuration_file}"; then
        printf 'Unable to load configuration file: %s\n' \
            "${configuration_file}" >&2
        return 1
    fi

    return 0
}

##
# Validate the framework configuration.
#
# Returns:
#   0 when the configuration is valid.
#   1 otherwise.
##
validate_framework_configuration() {
    if ! is_boolean "${RLCH_REQUIRE_ROOT}"; then
        printf 'RLCH_REQUIRE_ROOT must be a boolean value.\n' >&2
        return 1
    fi

    if ! is_boolean "${RLCH_STRICT_CONFIGURATION}"; then
        printf 'RLCH_STRICT_CONFIGURATION must be a boolean value.\n' >&2
        return 1
    fi

    if [[ -z "${RLCH_DEFAULT_COMMAND}" ]]; then
        printf 'RLCH_DEFAULT_COMMAND must not be empty.\n' >&2
        return 1
    fi

    if [[ -z "${RLCH_OPENSCAP_PROFILE}" ]]; then
        printf 'RLCH_OPENSCAP_PROFILE must not be empty.\n' >&2
        return 1
    fi

    return 0
}

##
# Load all framework configuration files.
#
# Globals:
#   RLCH_CONFIG_DIR
#
# Returns:
#   0 on success.
#   1 on failure.
##
load_configuration() {
    local framework_configuration
    local logging_configuration

    if [[ -z "${RLCH_CONFIG_DIR:-}" ]]; then
        printf 'RLCH_CONFIG_DIR is not initialized.\n' >&2
        return 1
    fi

    framework_configuration="${RLCH_CONFIG_DIR}/framework.conf"
    logging_configuration="${RLCH_CONFIG_DIR}/logging.conf"

    if ! load_configuration_file \
        "${framework_configuration}" \
        "required"; then
        return 1
    fi

    if ! validate_framework_configuration; then
        return 1
    fi

    if ! load_configuration_file \
        "${logging_configuration}" \
        "required"; then
        return 1
    fi

    return 0
}