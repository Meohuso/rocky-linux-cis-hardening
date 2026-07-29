#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# Generic kernel module hardening helpers.
#
# SPDX-License-Identifier: MIT
#

# Prevent multiple sourcing.
if [[ -n "${RLCH_KERNEL_MODULE_LIBRARY_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_KERNEL_MODULE_LIBRARY_LOADED=1

RLCH_KERNEL_MODULE_PROC_MODULES="${RLCH_KERNEL_MODULE_PROC_MODULES:-/proc/modules}"

##
# Determine whether a kernel module exists on the system.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   0 when the module exists.
#   1 when the module is unavailable.
##
kernel_module_exists() {
    local module_name="${1:-}"

    [[ -n "${module_name}" ]] || return 1

    modprobe --showconfig 2>/dev/null |
        grep -Eq \
            "^[[:space:]]*(alias|install)[[:space:]]+${module_name}([[:space:]]|$)" &&
        return 0

    modinfo "${module_name}" >/dev/null 2>&1
}

##
# Determine whether a kernel module is currently loaded.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   0 when the module is loaded.
#   1 otherwise.
##
kernel_module_is_loaded() {
    local module_name="${1:-}"

    [[ -n "${module_name}" ]] || return 1

    awk \
        -v module_name="${module_name}" \
        '$1 == module_name { found = 1 } END { exit !found }' \
        "${RLCH_KERNEL_MODULE_PROC_MODULES}"
}

##
# Determine whether an effective install directive disables a kernel module.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   0 when the module is disabled through an install directive.
#   1 otherwise.
##
kernel_module_has_install_directive() {
    local module_name="${1:-}"

    [[ -n "${module_name}" ]] || return 1

    modprobe --showconfig 2>/dev/null |
        awk \
            -v module_name="${module_name}" '
                $1 == "install" && $2 == module_name {
                    command = ""

                    for (field = 3; field <= NF; field++) {
                        if (command != "") {
                            command = command " "
                        }

                        command = command $field
                    }

                    if (command == "/bin/false" ||
                        command == "/usr/bin/false" ||
                        command == "/bin/true" ||
                        command == "/usr/bin/true") {
                        found = 1
                    }
                }

                END {
                    exit !found
                }
            '
}

##
# Determine whether an effective blacklist directive exists.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   0 when the module is blacklisted.
#   1 otherwise.
##
kernel_module_has_blacklist_directive() {
    local module_name="${1:-}"

    [[ -n "${module_name}" ]] || return 1

    modprobe --showconfig 2>/dev/null |
        awk \
            -v module_name="${module_name}" '
                $1 == "blacklist" && $2 == module_name {
                    found = 1
                }

                END {
                    exit !found
                }
            '
}

##
# Determine whether a framework-managed configuration file is compliant.
#
# Arguments:
#   $1 Kernel module name.
#   $2 Managed configuration file.
#
# Returns:
#   0 when the expected directives exist.
#   1 otherwise.
##
kernel_module_managed_file_is_compliant() {
    local module_name="${1:-}"
    local configuration_file="${2:-}"
    local install_directive
    local blacklist_directive

    [[ -n "${module_name}" && -n "${configuration_file}" ]] || return 1

    install_directive="install ${module_name} /bin/false"
    blacklist_directive="blacklist ${module_name}"

    [[ -f "${configuration_file}" ]] || return 1

    grep -Fqx "${install_directive}" "${configuration_file}" &&
        grep -Fqx "${blacklist_directive}" "${configuration_file}"
}

##
# Write a framework-managed modprobe configuration atomically.
#
# Arguments:
#   $1 CIS control identifier.
#   $2 Kernel module name.
#   $3 Modprobe configuration directory.
#   $4 Managed configuration file.
#
# Returns:
#   0 on success.
#   1 on failure.
##
kernel_module_write_configuration() {
    local control_identifier="${1:-}"
    local module_name="${2:-}"
    local modprobe_directory="${3:-}"
    local configuration_file="${4:-}"
    local temporary_file

    if [[ -z "${control_identifier}" ||
        -z "${module_name}" ||
        -z "${modprobe_directory}" ||
        -z "${configuration_file}" ]]; then
        error_message "Kernel module configuration arguments must not be empty."
        return 1
    fi

    if ! mkdir -p "${modprobe_directory}"; then
        error_message \
            "Unable to create modprobe directory: ${modprobe_directory}"
        return 1
    fi

    if ! temporary_file="$(
        mktemp "${modprobe_directory}/.rlch-cis-${control_identifier}.XXXXXX"
    )"; then
        error_message \
            "Unable to create temporary modprobe configuration."
        return 1
    fi

    if ! cat >"${temporary_file}" <<EOF_CONFIGURATION
# Managed by Rocky Linux CIS Hardening Framework.
# CIS ${control_identifier} - Ensure ${module_name} kernel module is not available.
install ${module_name} /bin/false
blacklist ${module_name}
EOF_CONFIGURATION
    then
        rm -f "${temporary_file}"
        error_message \
            "Unable to write temporary modprobe configuration."
        return 1
    fi

    if ! chmod 0644 "${temporary_file}"; then
        rm -f "${temporary_file}"
        error_message \
            "Unable to set permissions on temporary modprobe configuration."
        return 1
    fi

    if ! mv -f "${temporary_file}" "${configuration_file}"; then
        rm -f "${temporary_file}"
        error_message \
            "Unable to install modprobe configuration: ${configuration_file}"
        return 1
    fi

    return 0
}

##
# Unload a kernel module when it is currently loaded.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   0 when the module is unloaded or was not loaded.
#   1 when the module cannot be unloaded.
##
kernel_module_unload() {
    local module_name="${1:-}"

    [[ -n "${module_name}" ]] || return 1

    if ! kernel_module_is_loaded "${module_name}"; then
        return 0
    fi

    if ! modprobe -r "${module_name}"; then
        error_message "Unable to unload kernel module: ${module_name}"
        return 1
    fi

    return 0
}

##
# Check whether a kernel module is unavailable or correctly disabled.
#
# Arguments:
#   $1 Kernel module name.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when compliant.
#   RLCH_MODULE_RESULT_NON_COMPLIANT when remediation is required.
#   RLCH_MODULE_RESULT_ERROR when the check cannot be completed.
##
kernel_module_check() {
    local module_name="${1:-}"

    if [[ -z "${module_name}" ]]; then
        error_message "Kernel module name must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v modprobe >/dev/null 2>&1; then
        error_message "Required command is unavailable: modprobe"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v modinfo >/dev/null 2>&1; then
        error_message "Required command is unavailable: modinfo"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! kernel_module_exists "${module_name}"; then
        log_debug "Kernel module ${module_name} is not available."
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if kernel_module_is_loaded "${module_name}"; then
        log_warning "Kernel module ${module_name} is currently loaded."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! kernel_module_has_install_directive "${module_name}"; then
        log_warning \
            "Kernel module ${module_name} is not disabled by an install directive."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! kernel_module_has_blacklist_directive "${module_name}"; then
        log_warning "Kernel module ${module_name} is not blacklisted."
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

##
# Apply kernel module hardening.
#
# Arguments:
#   $1 CIS control identifier.
#   $2 Kernel module name.
#   $3 Modprobe configuration directory.
#   $4 Managed configuration file.
#   $5 Effective user identifier.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when no change is required.
#   RLCH_MODULE_RESULT_CHANGED when remediation is applied.
#   RLCH_MODULE_RESULT_ERROR when remediation fails.
##
kernel_module_apply() {
    local control_identifier="${1:-}"
    local module_name="${2:-}"
    local modprobe_directory="${3:-}"
    local configuration_file="${4:-}"
    local effective_uid="${5:-}"
    local configuration_changed="false"
    local module_was_loaded="false"

    if [[ -z "${control_identifier}" ||
        -z "${module_name}" ||
        -z "${modprobe_directory}" ||
        -z "${configuration_file}" ||
        -z "${effective_uid}" ]]; then
        error_message "Kernel module remediation arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" -ne 0 ]]; then
        error_message \
            "Root privileges are required to remediate CIS control ${control_identifier}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v modprobe >/dev/null 2>&1; then
        error_message "Required command is unavailable: modprobe"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if kernel_module_is_loaded "${module_name}"; then
        module_was_loaded="true"
    fi

    if ! kernel_module_managed_file_is_compliant \
        "${module_name}" \
        "${configuration_file}"; then
        if ! kernel_module_write_configuration \
            "${control_identifier}" \
            "${module_name}" \
            "${modprobe_directory}" \
            "${configuration_file}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        configuration_changed="true"
    fi

    if ! kernel_module_unload "${module_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${configuration_changed}" == "true" ||
        "${module_was_loaded}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

##
# Remove a framework-managed kernel module configuration.
#
# Arguments:
#   $1 CIS control identifier.
#   $2 Managed configuration file.
#   $3 Effective user identifier.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when no managed configuration exists.
#   RLCH_MODULE_RESULT_CHANGED when the managed file is removed.
#   RLCH_MODULE_RESULT_ERROR when rollback fails.
##
kernel_module_rollback() {
    local control_identifier="${1:-}"
    local configuration_file="${2:-}"
    local effective_uid="${3:-}"

    if [[ -z "${control_identifier}" ||
        -z "${configuration_file}" ||
        -z "${effective_uid}" ]]; then
        error_message "Kernel module rollback arguments must not be empty."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" -ne 0 ]]; then
        error_message \
            "Root privileges are required to roll back CIS control ${control_identifier}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${configuration_file}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${configuration_file}" ]]; then
        error_message \
            "Managed configuration path is not a regular file: ${configuration_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -f "${configuration_file}"; then
        error_message \
            "Unable to remove managed configuration: ${configuration_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
