#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
#
# CIS 1.8.10 - Ensure XDMCP is not enabled.
#
# SPDX-License-Identifier: MIT
#

RLCH_CIS_1_8_10_GDM_PACKAGE="${RLCH_CIS_1_8_10_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_10_CONFIG_FILE="${RLCH_CIS_1_8_10_CONFIG_FILE:-/etc/gdm/custom.conf}"
RLCH_CIS_1_8_10_STATE_DIR="${RLCH_CIS_1_8_10_STATE_DIR:-/var/lib/rlch/cis/1.8.10}"

cis_1_8_10_gdm_installed() {
    rpm -q "${RLCH_CIS_1_8_10_GDM_PACKAGE}" >/dev/null 2>&1
}

cis_1_8_10_xdmcp_disabled() {
    local section=""
    local line
    local value
    local found=false

    if [[ ! -f "${RLCH_CIS_1_8_10_CONFIG_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi

    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        if [[ "${line}" =~ ^\[(.*)\]$ ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi

        if [[ "${section,,}" != "xdmcp" ]]; then
            continue
        fi

        if [[ "${line}" =~ ^[Ee]nable[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            value="${BASH_REMATCH[1]}"
            value="${value%%[[:space:]#;]*}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            found=true

            if [[ "${value,,}" != "false" ]]; then
                return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
            fi
        fi
    done < "${RLCH_CIS_1_8_10_CONFIG_FILE}"

    if [[ "${found}" == "true" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

cis_1_8_10_backup_state() {
    if [[ -e "${RLCH_CIS_1_8_10_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p -- "${RLCH_CIS_1_8_10_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_1_8_10_CONFIG_FILE}" ]]; then
        if ! cp -a -- \
            "${RLCH_CIS_1_8_10_CONFIG_FILE}" \
            "${RLCH_CIS_1_8_10_STATE_DIR}/custom.conf.backup"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    else
        if ! : > "${RLCH_CIS_1_8_10_STATE_DIR}/custom.conf.created"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! : > "${RLCH_CIS_1_8_10_STATE_DIR}/state"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

cis_1_8_10_render_config() {
    local input_file="${1:-}"
    local output_file="${2:-}"
    local section=""
    local line
    local xdmcp_seen=false
    local enable_written=false

    if [[ -z "${output_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -f "${input_file}" ]]; then
        while IFS= read -r line || [[ -n "${line}" ]]; do
            if [[ "${line}" =~ ^[[:space:]]*\[(.*)\][[:space:]]*$ ]]; then
                if [[ "${section,,}" == "xdmcp" && "${enable_written}" == "false" ]]; then
                    printf '%s\n' 'Enable=false' >> "${output_file}" ||
                        return "${RLCH_MODULE_RESULT_ERROR}"
                    enable_written=true
                fi

                section="${BASH_REMATCH[1]}"

                if [[ "${section,,}" == "xdmcp" ]]; then
                    xdmcp_seen=true
                    enable_written=false
                fi

                printf '%s\n' "${line}" >> "${output_file}" ||
                    return "${RLCH_MODULE_RESULT_ERROR}"
                continue
            fi

            if [[ "${section,,}" == "xdmcp" &&
                  "${line}" =~ ^[[:space:]]*[Ee]nable[[:space:]]*= ]]; then
                if [[ "${enable_written}" == "false" ]]; then
                    printf '%s\n' 'Enable=false' >> "${output_file}" ||
                        return "${RLCH_MODULE_RESULT_ERROR}"
                    enable_written=true
                fi
                continue
            fi

            printf '%s\n' "${line}" >> "${output_file}" ||
                return "${RLCH_MODULE_RESULT_ERROR}"
        done < "${input_file}"

        if [[ "${section,,}" == "xdmcp" && "${enable_written}" == "false" ]]; then
            printf '%s\n' 'Enable=false' >> "${output_file}" ||
                return "${RLCH_MODULE_RESULT_ERROR}"
            enable_written=true
        fi
    fi

    if [[ "${xdmcp_seen}" == "false" ]]; then
        if [[ -s "${output_file}" ]]; then
            printf '\n' >> "${output_file}" ||
                return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        printf '%s\n' '[xdmcp]' 'Enable=false' >> "${output_file}" ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_1_8_10_write_config() {
    local directory
    local temporary_file

    directory="$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"

    if ! mkdir -p -- "${directory}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    temporary_file="$(mktemp "${directory}/.rlch-gdm-xdmcp.XXXXXX")" ||
        return "${RLCH_MODULE_RESULT_ERROR}"

    if ! cis_1_8_10_render_config \
        "${RLCH_CIS_1_8_10_CONFIG_FILE}" \
        "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chmod 0644 -- "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! chown 0:0 -- "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! mv -f -- "${temporary_file}" "${RLCH_CIS_1_8_10_CONFIG_FILE}"; then
        rm -f -- "${temporary_file}"
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

check() {
    if ! cis_1_8_10_gdm_installed; then
        return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    fi

    cis_1_8_10_xdmcp_disabled
}

apply() {
    local result

    check
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ||
          "${result}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]]; then
        return "${result}"
    fi

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    cis_1_8_10_backup_state
    result=$?

    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_ERROR}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_1_8_10_write_config; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    if [[ ! -e "${RLCH_CIS_1_8_10_STATE_DIR}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if [[ -e "${RLCH_CIS_1_8_10_STATE_DIR}/custom.conf.backup" ]]; then
        if ! mkdir -p -- "$(dirname -- "${RLCH_CIS_1_8_10_CONFIG_FILE}")"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi

        if ! cp -a -- \
            "${RLCH_CIS_1_8_10_STATE_DIR}/custom.conf.backup" \
            "${RLCH_CIS_1_8_10_CONFIG_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif [[ -e "${RLCH_CIS_1_8_10_STATE_DIR}/custom.conf.created" ]]; then
        if ! rm -f -- "${RLCH_CIS_1_8_10_CONFIG_FILE}"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi

    if ! rm -rf -- "${RLCH_CIS_1_8_10_STATE_DIR}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
