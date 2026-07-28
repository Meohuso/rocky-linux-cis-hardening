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
RLCH_MODULE_DISCOVERY_ENABLED="${RLCH_MODULE_DISCOVERY_ENABLED:-true}"
RLCH_MODULE_ROOT="${RLCH_MODULE_ROOT:-}"
RLCH_MODULE_NAMESPACE="${RLCH_MODULE_NAMESPACE:-cis}"
RLCH_MODULE_DEFAULT_FILTER="${RLCH_MODULE_DEFAULT_FILTER:-*}"
RLCH_MODULE_METADATA_FILENAME="${RLCH_MODULE_METADATA_FILENAME:-metadata.conf}"
RLCH_MODULE_IMPLEMENTATION_FILENAME="${
    RLCH_MODULE_IMPLEMENTATION_FILENAME:-module.sh
}"

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
        error_message "Configuration file path is required."
        return 1
    fi

    case "${requirement}" in
        required | optional) ;;
        *)
            error_message \
                "Invalid configuration requirement: ${requirement}"
            return 1
            ;;
    esac

    if [[ ! -e "${configuration_file}" ]]; then
        if [[ "${requirement}" == "optional" ]]; then
            return 0
        fi

        error_message \
            "Configuration file does not exist: ${configuration_file}"
        return 1
    fi

    if [[ ! -f "${configuration_file}" ]]; then
        error_message \
            "Configuration path is not a regular file: ${configuration_file}"
        return 1
    fi

    if [[ ! -r "${configuration_file}" ]]; then
        error_message \
            "Configuration file is not readable: ${configuration_file}"
        return 1
    fi

    # shellcheck source=/dev/null
    if ! source "${configuration_file}"; then
        error_message \
            "Unable to load configuration file: ${configuration_file}"
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
        error_message "RLCH_REQUIRE_ROOT must be a boolean value."
        return 1
    fi

    if ! is_boolean "${RLCH_STRICT_CONFIGURATION}"; then
        error_message \
            "RLCH_STRICT_CONFIGURATION must be a boolean value."
        return 1
    fi

    if [[ -z "${RLCH_DEFAULT_COMMAND}" ]]; then
        error_message "RLCH_DEFAULT_COMMAND must not be empty."
        return 1
    fi

    if [[ -z "${RLCH_OPENSCAP_PROFILE}" ]]; then
        error_message "RLCH_OPENSCAP_PROFILE must not be empty."
        return 1
    fi

    return 0
}

##
# Validate the module discovery configuration.
#
# Returns:
#   0 when the configuration is valid.
#   1 otherwise.
##
validate_module_configuration() {
    if ! is_boolean "${RLCH_MODULE_DISCOVERY_ENABLED}"; then
        error_message \
            "RLCH_MODULE_DISCOVERY_ENABLED must be a boolean value."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_ROOT}" ]]; then
        error_message "RLCH_MODULE_ROOT must not be empty."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_NAMESPACE}" ]]; then
        error_message "RLCH_MODULE_NAMESPACE must not be empty."
        return 1
    fi

    if [[ "${RLCH_MODULE_NAMESPACE}" == */* ]]; then
        error_message \
            "RLCH_MODULE_NAMESPACE must be a single directory name."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_DEFAULT_FILTER}" ]]; then
        error_message "RLCH_MODULE_DEFAULT_FILTER must not be empty."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_METADATA_FILENAME}" ]]; then
        error_message \
            "RLCH_MODULE_METADATA_FILENAME must not be empty."
        return 1
    fi

    if [[ "${RLCH_MODULE_METADATA_FILENAME}" == */* ]]; then
        error_message \
            "RLCH_MODULE_METADATA_FILENAME must not contain a path."
        return 1
    fi

    if [[ -z "${RLCH_MODULE_IMPLEMENTATION_FILENAME}" ]]; then
        error_message \
            "RLCH_MODULE_IMPLEMENTATION_FILENAME must not be empty."
        return 1
    fi

    if [[ "${RLCH_MODULE_IMPLEMENTATION_FILENAME}" == */* ]]; then
        error_message \
            "RLCH_MODULE_IMPLEMENTATION_FILENAME must not contain a path."
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
    local modules_configuration

    if [[ -z "${RLCH_CONFIG_DIR:-}" ]]; then
        error_message "RLCH_CONFIG_DIR is not initialized."
        return 1
    fi

    framework_configuration="${RLCH_CONFIG_DIR}/framework.conf"
    logging_configuration="${RLCH_CONFIG_DIR}/logging.conf"
    modules_configuration="${RLCH_CONFIG_DIR}/modules.conf"

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

    if ! load_configuration_file \
        "${modules_configuration}" \
        "required"; then
        return 1
    fi

    if ! validate_module_configuration; then
        return 1
    fi

    return 0
}