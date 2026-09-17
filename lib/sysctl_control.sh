#!/usr/bin/env bash
#
# Rocky Linux CIS Hardening Framework
# Transactional helpers for isolated CIS sysctl controls.
# SPDX-License-Identifier: MIT
#

if [[ -n "${RLCH_SYSCTL_CONTROL_LOADED:-}" ]]; then
    return 0
fi
readonly RLCH_SYSCTL_CONTROL_LOADED=1

RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND="${RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND:-sysctl}"
RLCH_SYSCTL_CONTROL_ID_COMMAND="${RLCH_SYSCTL_CONTROL_ID_COMMAND:-id}"

sysctl_control_validate_arrays() {
    local parameters_name="${1:-}"
    local values_name="${2:-}"

    [[ -n "${parameters_name}" && -n "${values_name}" ]] || return 1
    local -n parameters_ref="${parameters_name}"
    local -n values_ref="${values_name}"
    local index

    (( ${#parameters_ref[@]} > 0 )) || return 1
    (( ${#parameters_ref[@]} == ${#values_ref[@]} )) || return 1
    for index in "${!parameters_ref[@]}"; do
        [[ "${parameters_ref[${index}]}" =~ ^[a-zA-Z0-9_.-]+$ ]] || return 1
        [[ -n "${values_ref[${index}]}" && "${values_ref[${index}]}" != *$'\n'* ]] || return 1
    done
}

sysctl_control_require_root() {
    local effective_uid

    if ! effective_uid="$("${RLCH_SYSCTL_CONTROL_ID_COMMAND}" -u 2>/dev/null)"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    [[ "${effective_uid}" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
}

sysctl_control_runtime_value() {
    local parameter="${1:?Parameter is required}"

    "${RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND}" -n "${parameter}" 2>/dev/null
}

sysctl_control_config_value_is() {
    local config_file="${1:?Configuration file is required}"
    local parameter="${2:?Parameter is required}"
    local expected_value="${3:?Expected value is required}"

    [[ -f "${config_file}" ]] || return 1
    awk -v parameter="${parameter}" -v expected="${expected_value}" '
        /^[[:space:]]*#/ { next }
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            separator = index(line, "=")
            if (separator == 0) { next }
            key = substr(line, 1, separator - 1)
            value = substr(line, separator + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (key == parameter) {
                count++
                if (value == expected) { matches++ }
            }
        }
        END { exit(count == 1 && matches == 1 ? 0 : 1) }
    ' "${config_file}"
}

sysctl_control_check() {
    local config_file="${1:-}"
    local parameters_name="${2:-}"
    local values_name="${3:-}"
    local current_value
    local index
    local non_compliant=false

    if [[ -z "${config_file}" ]] ||
       ! sysctl_control_validate_arrays "${parameters_name}" "${values_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    local -n parameters_ref="${parameters_name}"
    local -n values_ref="${values_name}"

    for index in "${!parameters_ref[@]}"; do
        if ! sysctl_control_config_value_is "${config_file}" "${parameters_ref[${index}]}" "${values_ref[${index}]}"; then
            non_compliant=true
        fi
        if ! current_value="$(sysctl_control_runtime_value "${parameters_ref[${index}]}")"; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if [[ "${current_value}" != "${values_ref[${index}]}" ]]; then
            non_compliant=true
        fi
    done

    if [[ "${non_compliant}" == true ]]; then
        return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

sysctl_control_capture_state() {
    local config_file="${1:?Configuration file is required}"
    local state_dir="${2:?State directory is required}"
    local parameters_name="${3:?Parameters array is required}"
    local current_value
    local index
    local state_parent
    local temporary_dir

    local -n parameters_ref="${parameters_name}"

    if [[ -f "${state_dir}/state" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ -e "${state_dir}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ -e "${config_file}" || -L "${config_file}" ]] && [[ ! -f "${config_file}" || -L "${config_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    state_parent="$(dirname -- "${state_dir}")"
    if ! mkdir -p -- "${state_parent}" || ! temporary_dir="$(mktemp -d "${state_dir}.tmp.XXXXXX")"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if ! chmod 0700 -- "${temporary_dir}" || ! : > "${temporary_dir}/runtime.state"; then
        rmdir -- "${temporary_dir}" 2>/dev/null || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for index in "${!parameters_ref[@]}"; do
        if ! current_value="$(sysctl_control_runtime_value "${parameters_ref[${index}]}")" ||
           [[ "${current_value}" == *$'\n'* ]] ||
           ! printf '%s=%s\n' "${parameters_ref[${index}]}" "${current_value}" >> "${temporary_dir}/runtime.state"; then
            rm -f -- "${temporary_dir}/runtime.state"
            rmdir -- "${temporary_dir}" 2>/dev/null || true
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done

    if [[ -f "${config_file}" ]]; then
        if ! cp -a -- "${config_file}" "${temporary_dir}/original.conf" ||
           ! printf '%s\n' present > "${temporary_dir}/file.state"; then
            rm -f -- "${temporary_dir}/runtime.state" "${temporary_dir}/original.conf" "${temporary_dir}/file.state"
            rmdir -- "${temporary_dir}" 2>/dev/null || true
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    elif ! printf '%s\n' absent > "${temporary_dir}/file.state"; then
        rm -f -- "${temporary_dir}/runtime.state" "${temporary_dir}/file.state"
        rmdir -- "${temporary_dir}" 2>/dev/null || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    if ! : > "${temporary_dir}/state" ||
       ! chmod 0600 -- "${temporary_dir}/runtime.state" "${temporary_dir}/file.state" "${temporary_dir}/state" ||
       ! mv -- "${temporary_dir}" "${state_dir}"; then
        rm -f -- "${temporary_dir}/runtime.state" "${temporary_dir}/original.conf" "${temporary_dir}/file.state" "${temporary_dir}/state"
        rmdir -- "${temporary_dir}" 2>/dev/null || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_SUCCESS}"
}

sysctl_control_write_config() {
    local config_file="${1:?Configuration file is required}"
    local parameters_name="${2:?Parameters array is required}"
    local values_name="${3:?Values array is required}"
    local config_dir
    local index
    local joined_parameters
    local temporary_file

    local -n parameters_ref="${parameters_name}"
    local -n values_ref="${values_name}"

    config_dir="$(dirname -- "${config_file}")"
    [[ -d "${config_dir}" ]] || return 1
    if [[ -e "${config_file}" || -L "${config_file}" ]] && [[ ! -f "${config_file}" || -L "${config_file}" ]]; then
        return 1
    fi
    temporary_file="$(mktemp "${config_dir}/.rlch-sysctl-control.XXXXXX")" || return 1
    joined_parameters="$(IFS=,; printf '%s' "${parameters_ref[*]}")"

    if [[ -f "${config_file}" ]] &&
       ! awk -v parameters="${joined_parameters}" '
            BEGIN {
                count = split(parameters, list, ",")
                for (i = 1; i <= count; i++) { managed[list[i]] = 1 }
            }
            {
                if ($0 ~ /^[[:space:]]*#/) { print; next }
                line = $0
                sub(/[[:space:]]*#.*/, "", line)
                separator = index(line, "=")
                if (separator == 0) { print; next }
                key = substr(line, 1, separator - 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                if (!(key in managed)) { print }
            }
        ' "${config_file}" > "${temporary_file}"; then
        rm -f -- "${temporary_file}"
        return 1
    fi
    for index in "${!parameters_ref[@]}"; do
        if ! printf '%s = %s\n' "${parameters_ref[${index}]}" "${values_ref[${index}]}" >> "${temporary_file}"; then
            rm -f -- "${temporary_file}"
            return 1
        fi
    done
    if ! chmod 0644 -- "${temporary_file}" || ! chown 0:0 -- "${temporary_file}" ||
       ! mv -f -- "${temporary_file}" "${config_file}"; then
        rm -f -- "${temporary_file}"
        return 1
    fi
}

sysctl_control_apply() {
    local config_file="${1:-}"
    local state_dir="${2:-}"
    local parameters_name="${3:-}"
    local values_name="${4:-}"
    local index
    local result=0

    sysctl_control_check "${config_file}" "${parameters_name}" "${values_name}" || result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ "${result}" -ne "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] ||
       ! sysctl_control_require_root ||
       ! sysctl_control_validate_arrays "${parameters_name}" "${values_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    local -n parameters_ref="${parameters_name}"
    local -n values_ref="${values_name}"

    sysctl_control_capture_state "${config_file}" "${state_dir}" "${parameters_name}" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    if ! sysctl_control_write_config "${config_file}" "${parameters_name}" "${values_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for index in "${!parameters_ref[@]}"; do
        if ! "${RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND}" -w "${parameters_ref[${index}]}=${values_ref[${index}]}" >/dev/null 2>&1; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    if ! sysctl_control_check "${config_file}" "${parameters_name}" "${values_name}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

sysctl_control_saved_runtime_value() {
    local state_file="${1:?State file is required}"
    local parameter="${2:?Parameter is required}"

    awk -F= -v parameter="${parameter}" '
        $1 == parameter {
            count++
            value = substr($0, length($1) + 2)
        }
        END {
            if (count == 1) { print value; exit 0 }
            exit 1
        }
    ' "${state_file}"
}

sysctl_control_rollback() {
    local config_file="${1:-}"
    local state_dir="${2:-}"
    local parameters_name="${3:-}"
    local current_value
    local file_state
    local index
    local saved_value

    [[ -n "${config_file}" && -n "${state_dir}" && -n "${parameters_name}" ]] ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ ! -e "${state_dir}" ]]; then
        return "${RLCH_MODULE_RESULT_SUCCESS}"
    fi
    if [[ ! -f "${state_dir}/state" || ! -f "${state_dir}/runtime.state" || ! -f "${state_dir}/file.state" ]] ||
       ! IFS= read -r file_state < "${state_dir}/file.state" ||
       [[ "${file_state}" != present && "${file_state}" != absent ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    local -n parameters_ref="${parameters_name}"
    for index in "${!parameters_ref[@]}"; do
        sysctl_control_saved_runtime_value "${state_dir}/runtime.state" "${parameters_ref[${index}]}" >/dev/null ||
            return "${RLCH_MODULE_RESULT_ERROR}"
    done
    if [[ "${file_state}" == present && ! -f "${state_dir}/original.conf" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    sysctl_control_require_root || return "${RLCH_MODULE_RESULT_ERROR}"

    if [[ "${file_state}" == present ]]; then
        cp -a -- "${state_dir}/original.conf" "${config_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    elif ! rm -f -- "${config_file}"; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    for index in "${!parameters_ref[@]}"; do
        saved_value="$(sysctl_control_saved_runtime_value "${state_dir}/runtime.state" "${parameters_ref[${index}]}")" ||
            return "${RLCH_MODULE_RESULT_ERROR}"
        if ! "${RLCH_SYSCTL_CONTROL_SYSCTL_COMMAND}" -w "${parameters_ref[${index}]}=${saved_value}" >/dev/null 2>&1 ||
           ! current_value="$(sysctl_control_runtime_value "${parameters_ref[${index}]}")" ||
           [[ "${current_value}" != "${saved_value}" ]]; then
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    done
    if [[ "${file_state}" == present ]]; then
        cmp -s -- "${state_dir}/original.conf" "${config_file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    elif [[ -e "${config_file}" || -L "${config_file}" ]]; then
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi

    rm -f -- "${state_dir}/state" "${state_dir}/runtime.state" "${state_dir}/file.state" ||
        return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ "${file_state}" == present ]]; then
        rm -f -- "${state_dir}/original.conf" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rmdir -- "${state_dir}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
