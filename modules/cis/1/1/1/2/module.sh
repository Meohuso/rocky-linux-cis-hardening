#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.1.1.1 - Ensure cramfs kernel module is not available.
#
# SPDX-License-Identifier: MIT
#

readonly RLCH_CIS_1_1_1_1_MODULE_NAME="cramfs"

RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY="${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY:-/etc/modprobe.d}"
RLCH_CIS_1_1_1_1_CONFIGURATION_FILE="${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE:-${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY}/rlch-cis-1.1.1.1-cramfs.conf}"
RLCH_CIS_1_1_1_1_EFFECTIVE_UID="${RLCH_CIS_1_1_1_1_EFFECTIVE_UID:-${EUID}}"

##
# Determine whether the cramfs module exists on the system.
#
# Returns:
#   0 when the module exists.
#   1 when the module is not available.
##
_cis_1_1_1_1_module_exists() {
    modprobe --showconfig 2>/dev/null |
        grep -Eq \
            "^[[:space:]]*(alias|install)[[:space:]]+${RLCH_CIS_1_1_1_1_MODULE_NAME}([[:space:]]|$)" &&
        return 0

    modinfo "${RLCH_CIS_1_1_1_1_MODULE_NAME}" >/dev/null 2>&1
}

##
# Determine whether the cramfs module is currently loaded.
#
# Returns:
#   0 when the module is loaded.
#   1 otherwise.
##
_cis_1_1_1_1_module_is_loaded() {
    awk \
        -v module_name="${RLCH_CIS_1_1_1_1_MODULE_NAME}" \
        '$1 == module_name { found = 1 } END { exit !found }' \
        /proc/modules
}

##
# Determine whether an effective modprobe install directive disables cramfs.
#
# Returns:
#   0 when cramfs is disabled through an install directive.
#   1 otherwise.
##
_cis_1_1_1_1_has_install_directive() {
    modprobe --showconfig 2>/dev/null |
        awk \
            -v module_name="${RLCH_CIS_1_1_1_1_MODULE_NAME}" '
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
# Determine whether an effective modprobe blacklist directive exists.
#
# Returns:
#   0 when cramfs is blacklisted.
#   1 otherwise.
##
_cis_1_1_1_1_has_blacklist_directive() {
    modprobe --showconfig 2>/dev/null |
        awk \
            -v module_name="${RLCH_CIS_1_1_1_1_MODULE_NAME}" '
                $1 == "blacklist" && $2 == module_name {
                    found = 1
                }

                END {
                    exit !found
                }
            '
}

##
# Determine whether the framework-managed configuration file is compliant.
#
# Returns:
#   0 when the file contains the expected configuration.
#   1 otherwise.
##
_cis_1_1_1_1_managed_file_is_compliant() {
    local install_directive
    local blacklist_directive

    install_directive="install ${RLCH_CIS_1_1_1_1_MODULE_NAME} /bin/false"
    blacklist_directive="blacklist ${RLCH_CIS_1_1_1_1_MODULE_NAME}"

    [[ -f "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]] ||
        return 1

    grep -Fqx \
        "${install_directive}" \
        "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" &&
        grep -Fqx \
            "${blacklist_directive}" \
            "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"
}

##
# Write the framework-managed modprobe configuration atomically.
#
# Returns:
#   0 on success.
#   1 on failure.
##
_cis_1_1_1_1_write_configuration() {
    local temporary_file

    if ! mkdir -p "${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY}"; then
        error_message \
            "Unable to create modprobe directory: ${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY}"
        return 1
    fi

    if ! temporary_file="$(
        mktemp \
            "${RLCH_CIS_1_1_1_1_MODPROBE_DIRECTORY}/.rlch-cis-1.1.1.1.XXXXXX"
    )"; then
        error_message \
            "Unable to create temporary modprobe configuration."
        return 1
    fi

    if ! cat >"${temporary_file}" <<EOF
# Managed by Rocky Linux CIS Hardening Framework.
# CIS 1.1.1.1 - Ensure cramfs kernel module is not available.
install ${RLCH_CIS_1_1_1_1_MODULE_NAME} /bin/false
blacklist ${RLCH_CIS_1_1_1_1_MODULE_NAME}
EOF
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

    if ! mv -f \
        "${temporary_file}" \
        "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"; then
        rm -f "${temporary_file}"

        error_message \
            "Unable to install modprobe configuration: ${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"
        return 1
    fi

    return 0
}

##
# Unload cramfs when it is currently loaded.
#
# Returns:
#   0 when the module is unloaded or was not loaded.
#   1 when the module cannot be unloaded.
##
_cis_1_1_1_1_unload_module() {
    if ! _cis_1_1_1_1_module_is_loaded; then
        return 0
    fi

    if ! modprobe -r "${RLCH_CIS_1_1_1_1_MODULE_NAME}"; then
        error_message \
            "Unable to unload kernel module: ${RLCH_CIS_1_1_1_1_MODULE_NAME}"
        return 1
    fi

    return 0
}

##
# Check CIS control 1.1.1.1.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when compliant.
#   RLCH_MODULE_RESULT_NON_COMPLIANT when remediation is required.
#   RLCH_MODULE_RESULT_ERROR when the check cannot be completed.
##
check() {
    if ! command -v modprobe >/dev/null 2>&1; then
        error_message "Required command is unavailable: modprobe"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v modinfo >/dev/null 2>&1; then
        error_message "Required command is unavailable: modinfo"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! _cis_1_1_1_1_module_exists; then
        log_debug \
            "Kernel module ${RLCH_CIS_1_1_1_1_MODULE_NAME} is not available."

        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if _cis_1_1_1_1_module_is_loaded; then
        log_warning \
            "Kernel module ${RLCH_CIS_1_1_1_1_MODULE_NAME} is currently loaded."

        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! _cis_1_1_1_1_has_install_directive; then
        log_warning \
            "Kernel module ${RLCH_CIS_1_1_1_1_MODULE_NAME} is not disabled by an install directive."

        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    if ! _cis_1_1_1_1_has_blacklist_directive; then
        log_warning \
            "Kernel module ${RLCH_CIS_1_1_1_1_MODULE_NAME} is not blacklisted."

        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

##
# Apply CIS control 1.1.1.1.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when no change is required.
#   RLCH_MODULE_RESULT_CHANGED when remediation is applied.
#   RLCH_MODULE_RESULT_ERROR when remediation fails.
##
apply() {
    local configuration_changed="false"
    local module_was_loaded="false"

    if [[ "${RLCH_CIS_1_1_1_1_EFFECTIVE_UID}" -ne 0 ]]; then
        error_message \
            "Root privileges are required to remediate CIS control 1.1.1.1."

        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! command -v modprobe >/dev/null 2>&1; then
        error_message "Required command is unavailable: modprobe"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if _cis_1_1_1_1_module_is_loaded; then
        module_was_loaded="true"
    fi

    if ! _cis_1_1_1_1_managed_file_is_compliant; then
        if ! _cis_1_1_1_1_write_configuration; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        configuration_changed="true"
    fi

    if ! _cis_1_1_1_1_unload_module; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${configuration_changed}" == "true" ||
        "${module_was_loaded}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_CHANGED}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

##
# Validate CIS control 1.1.1.1 after remediation.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when compliant.
#   RLCH_MODULE_RESULT_NON_COMPLIANT when still non-compliant.
#   RLCH_MODULE_RESULT_ERROR when validation cannot be completed.
##
validate() {
    check
}

##
# Roll back the framework-managed configuration.
#
# The rollback removes only the file created by this framework. It does not
# modify unrelated administrator-managed modprobe configuration files and does
# not automatically load the cramfs module.
#
# Returns:
#   RLCH_MODULE_RESULT_SUCCESS when no managed configuration exists.
#   RLCH_MODULE_RESULT_CHANGED when the managed file is removed.
#   RLCH_MODULE_RESULT_ERROR when rollback fails.
##
rollback() {
    if [[ "${RLCH_CIS_1_1_1_1_EFFECTIVE_UID}" -ne 0 ]]; then
        error_message \
            "Root privileges are required to roll back CIS control 1.1.1.1."

        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ ! -e "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ ! -f "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}" ]]; then
        error_message \
            "Managed configuration path is not a regular file: ${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"

        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! rm -f "${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"; then
        error_message \
            "Unable to remove managed configuration: ${RLCH_CIS_1_1_1_1_CONFIGURATION_FILE}"

        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}