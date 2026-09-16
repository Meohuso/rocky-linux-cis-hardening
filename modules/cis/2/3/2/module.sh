#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# CIS 2.3.2 - Ensure chrony is configured.
# SPDX-License-Identifier: MIT
#

RLCH_CIS_2_3_2_CONFIG="${RLCH_CIS_2_3_2_CONFIG:-/etc/chrony.conf}"
RLCH_CIS_2_3_2_SERVERS="${RLCH_CIS_2_3_2_SERVERS:-0.rhel.pool.ntp.org,1.rhel.pool.ntp.org,2.rhel.pool.ntp.org,3.rhel.pool.ntp.org}"
RLCH_CIS_2_3_2_ID_COMMAND="${RLCH_CIS_2_3_2_ID_COMMAND:-id}"
RLCH_CIS_2_3_2_STATE_DIR="${RLCH_CIS_2_3_2_STATE_DIR:-/var/lib/rlch/cis/2.3.2}"
RLCH_CIS_2_3_2_STATE_FILE="${RLCH_CIS_2_3_2_STATE_FILE:-${RLCH_CIS_2_3_2_STATE_DIR}/original-state}"
RLCH_CIS_2_3_2_BACKUP_FILE="${RLCH_CIS_2_3_2_BACKUP_FILE:-${RLCH_CIS_2_3_2_STATE_DIR}/chrony.conf}"

cis_2_3_2_file_has_source() {
    local config_file="${1:-}"

    [[ -f "${config_file}" ]] || return 1

    awk '
        /^[[:space:]]*(server|pool)[[:space:]]+[^[:space:]#]+/ {
            found = 1
        }
        END {
            exit found ? 0 : 1
        }
    ' "${config_file}"
}

cis_2_3_2_has_remote_source() {
    local directive
    local directory
    local extension
    local include
    local included_file
    local -a includes=()
    local -a files=()

    [[ -f "${RLCH_CIS_2_3_2_CONFIG}" ]] || return 1

    if cis_2_3_2_file_has_source "${RLCH_CIS_2_3_2_CONFIG}"; then
        return 0
    fi

    mapfile -t includes < <(
        awk '
            /^[[:space:]]*(sourcedir|confdir)[[:space:]]+[^[:space:]#]+/ {
                print $1, $2
            }
        ' "${RLCH_CIS_2_3_2_CONFIG}"
    )

    for include in "${includes[@]}"; do
        read -r directive directory <<< "${include}"

        case "${directive}" in
            sourcedir)
                extension="sources"
                ;;
            confdir)
                extension="conf"
                ;;
            *)
                continue
                ;;
        esac

        files=()
        while IFS= read -r -d '' included_file; do
            files+=("${included_file}")
        done < <(find "${directory}" -maxdepth 1 -type f -name "*.${extension}" -print0 2>/dev/null)

        for included_file in "${files[@]}"; do
            if cis_2_3_2_file_has_source "${included_file}"; then
                return 0
            fi
        done
    done

    return 1
}

cis_2_3_2_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_CIS_2_3_2_ID_COMMAND}" -u 2>/dev/null)"; then
        error_message "Unable to determine effective user ID for CIS 2.3.2."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ "${effective_uid}" != "0" ]]; then
        error_message "CIS 2.3.2 requires root privileges."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_3_2_capture_state() {
    if [[ -e "${RLCH_CIS_2_3_2_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    if ! mkdir -p "${RLCH_CIS_2_3_2_STATE_DIR}"; then
        error_message "Unable to create CIS 2.3.2 state directory."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if [[ -e "${RLCH_CIS_2_3_2_CONFIG}" ]]; then
        if ! cp -p "${RLCH_CIS_2_3_2_CONFIG}" "${RLCH_CIS_2_3_2_BACKUP_FILE}"; then
            error_message "Unable to back up ${RLCH_CIS_2_3_2_CONFIG}."
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        printf '%s\n' "existing" > "${RLCH_CIS_2_3_2_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    else
        printf '%s\n' "absent" > "${RLCH_CIS_2_3_2_STATE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

cis_2_3_2_write_sources() {
    local server
    local -a servers=()

    IFS=',' read -r -a servers <<< "${RLCH_CIS_2_3_2_SERVERS}"

    {
        printf '\n# Managed by RLCH CIS 2.3.2\n'
        for server in "${servers[@]}"; do
            [[ -n "${server}" ]] || continue
            printf 'pool %s iburst\n' "${server}"
        done
    } >> "${RLCH_CIS_2_3_2_CONFIG}"
}

check() {
    if cis_2_3_2_has_remote_source; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

apply() {
    if cis_2_3_2_has_remote_source; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_3_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_2_3_2_capture_state || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! touch "${RLCH_CIS_2_3_2_CONFIG}"; then
        error_message "Unable to create ${RLCH_CIS_2_3_2_CONFIG}."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_3_2_write_sources; then
        error_message "Unable to configure remote chrony sources."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! cis_2_3_2_has_remote_source; then
        error_message "Chrony has no remote source after remediation."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() {
    check
}

rollback() {
    local original_state

    if [[ ! -e "${RLCH_CIS_2_3_2_STATE_FILE}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi

    cis_2_3_2_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if ! IFS= read -r original_state < "${RLCH_CIS_2_3_2_STATE_FILE}"; then
        error_message "Unable to read CIS 2.3.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    case "${original_state}" in
        existing)
            if [[ ! -f "${RLCH_CIS_2_3_2_BACKUP_FILE}" ]] ||
               ! cp -p "${RLCH_CIS_2_3_2_BACKUP_FILE}" "${RLCH_CIS_2_3_2_CONFIG}"; then
                error_message "Unable to restore ${RLCH_CIS_2_3_2_CONFIG}."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        absent)
            if ! rm -f "${RLCH_CIS_2_3_2_CONFIG}"; then
                error_message "Unable to remove ${RLCH_CIS_2_3_2_CONFIG}."
                return "${RLCH_MODULE_RESULT_ERROR}"
            fi
            ;;
        *)
            error_message "Invalid CIS 2.3.2 rollback state."
            return "${RLCH_MODULE_RESULT_ERROR}"
            ;;
    esac

    if ! rm -rf "${RLCH_CIS_2_3_2_STATE_DIR}"; then
        error_message "Unable to remove CIS 2.3.2 rollback state."
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    return "${RLCH_MODULE_RESULT_CHANGED}"
}
