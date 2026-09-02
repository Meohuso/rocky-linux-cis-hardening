#!/usr/bin/env bash
RLCH_CIS_1_8_2_GDM_PACKAGE="${RLCH_CIS_1_8_2_GDM_PACKAGE:-gdm}"
RLCH_CIS_1_8_2_PROFILE_FILE="${RLCH_CIS_1_8_2_PROFILE_FILE:-/etc/dconf/profile/gdm}"
RLCH_CIS_1_8_2_CONFIG_FILE="${RLCH_CIS_1_8_2_CONFIG_FILE:-/etc/dconf/db/gdm.d/01-banner-message}"
RLCH_CIS_1_8_2_STATE_DIR="${RLCH_CIS_1_8_2_STATE_DIR:-/var/lib/rlch/cis/1.8.2}"
RLCH_CIS_1_8_2_BANNER="${RLCH_CIS_1_8_2_BANNER:-Authorized users only. All activity may be monitored and reported.}"

cis_1_8_2_gdm_installed() { rpm -q "${RLCH_CIS_1_8_2_GDM_PACKAGE}" >/dev/null 2>&1; }
cis_1_8_2_expected_profile() { printf '%s\n' 'user-db:user' 'system-db:gdm' 'file-db:/usr/share/gdm/greeter-dconf-defaults'; }
cis_1_8_2_expected_config() { printf '%s\n' '[org/gnome/login-screen]' 'banner-message-enable=true' "banner-message-text='${RLCH_CIS_1_8_2_BANNER}'"; }

cis_1_8_2_matches() {
    local actual
    [[ -f "$1" ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    actual="$(cat -- "$1")" || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${actual}" == "$2" ]] && return "${RLCH_MODULE_RESULT_SUCCESS}"
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

check() {
    local result
    cis_1_8_2_gdm_installed || return "${RLCH_MODULE_RESULT_NOT_APPLICABLE}"
    cis_1_8_2_matches "${RLCH_CIS_1_8_2_PROFILE_FILE}" "$(cis_1_8_2_expected_profile)"
    result=$?
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${result}"
    cis_1_8_2_matches "${RLCH_CIS_1_8_2_CONFIG_FILE}" "$(cis_1_8_2_expected_config)"
}

cis_1_8_2_save() {
    local label="$1" file="$2"
    mkdir -p -- "${RLCH_CIS_1_8_2_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ -e "${file}" ]]; then
        cp -a -- "${file}" "${RLCH_CIS_1_8_2_STATE_DIR}/${label}.backup" || return "${RLCH_MODULE_RESULT_ERROR}"
    else
        : > "${RLCH_CIS_1_8_2_STATE_DIR}/${label}.created" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
}

cis_1_8_2_write() {
    local file="$1" content="$2"
    mkdir -p -- "$(dirname -- "${file}")" || return "${RLCH_MODULE_RESULT_ERROR}"
    printf '%s\n' "${content}" > "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    chmod 0644 -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    chown 0:0 -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
}

apply() {
    local result
    check
    result=$?
    if [[ "${result}" -eq "${RLCH_MODULE_RESULT_SUCCESS}" || "${result}" -eq "${RLCH_MODULE_RESULT_NOT_APPLICABLE}" ]]; then return "${result}"; fi
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_ERROR}" ]] || return "${result}"
    if [[ ! -e "${RLCH_CIS_1_8_2_STATE_DIR}/state" ]]; then
        cis_1_8_2_save profile "${RLCH_CIS_1_8_2_PROFILE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
        cis_1_8_2_save config "${RLCH_CIS_1_8_2_CONFIG_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
        : > "${RLCH_CIS_1_8_2_STATE_DIR}/state" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    cis_1_8_2_write "${RLCH_CIS_1_8_2_PROFILE_FILE}" "$(cis_1_8_2_expected_profile)" || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_2_write "${RLCH_CIS_1_8_2_CONFIG_FILE}" "$(cis_1_8_2_expected_config)" || return "${RLCH_MODULE_RESULT_ERROR}"
    dconf update || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

cis_1_8_2_restore() {
    local label="$1" file="$2"
    if [[ -e "${RLCH_CIS_1_8_2_STATE_DIR}/${label}.backup" ]]; then
        cp -a -- "${RLCH_CIS_1_8_2_STATE_DIR}/${label}.backup" "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    elif [[ -e "${RLCH_CIS_1_8_2_STATE_DIR}/${label}.created" ]]; then
        rm -f -- "${file}" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
}

rollback() {
    [[ -e "${RLCH_CIS_1_8_2_STATE_DIR}/state" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    cis_1_8_2_restore profile "${RLCH_CIS_1_8_2_PROFILE_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    cis_1_8_2_restore config "${RLCH_CIS_1_8_2_CONFIG_FILE}" || return "${RLCH_MODULE_RESULT_ERROR}"
    if cis_1_8_2_gdm_installed; then dconf update || return "${RLCH_MODULE_RESULT_ERROR}"; fi
    rm -rf -- "${RLCH_CIS_1_8_2_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
