#!/usr/bin/env bash
# CIS 5.2.7 - Restrict su with the CIS-tailored pam_wheel group.
# SPDX-License-Identifier: MIT

# ComplianceAsCode's option named "cis" has the value "sugroup".
RLCH_CIS_5_2_7_GROUP="sugroup"
RLCH_CIS_5_2_7_PAM_FILE="${RLCH_CIS_5_2_7_PAM_FILE:-/etc/pam.d/su}"
RLCH_CIS_5_2_7_STATE_DIR="${RLCH_CIS_5_2_7_STATE_DIR:-/var/lib/rlch/cis/5.2.7}"
RLCH_CIS_5_2_7_GETENT="${RLCH_CIS_5_2_7_GETENT:-getent}"
RLCH_CIS_5_2_7_GROUPADD="${RLCH_CIS_5_2_7_GROUPADD:-groupadd}"
RLCH_CIS_5_2_7_GROUPDEL="${RLCH_CIS_5_2_7_GROUPDEL:-groupdel}"
RLCH_CIS_5_2_7_ID="${RLCH_CIS_5_2_7_ID:-id}"

# Exit 0: absent; 1: present and empty; 2: present but populated; 3: query error.
rlch_5_2_7_group_state() {
    local entry gid members passwd_entries account
    entry="$("${RLCH_CIS_5_2_7_GETENT}" group "${RLCH_CIS_5_2_7_GROUP}" 2>/dev/null)"
    case $? in
        0) ;;
        2) return 0 ;;
        *) return 3 ;;
    esac
    [[ "${entry}" != *$'\n'* ]] || return 3
    IFS=: read -r account _ gid members <<< "${entry}"
    [[ "${account}" == "${RLCH_CIS_5_2_7_GROUP}" && "${gid}" =~ ^[0-9]+$ ]] || return 3
    [[ -z "${members}" ]] || return 2
    passwd_entries="$("${RLCH_CIS_5_2_7_GETENT}" passwd)" || return 3
    # Also reject primary group membership, even though the OpenSCAP group-file
    # expression only examines supplementary members.
    while IFS=: read -r _ _ _ account _; do
        [[ "${account}" != "${gid}" ]] || return 2
    done <<< "${passwd_entries}"
    return 1
}

# Exit 0: exact active rule; 1: absent; 2: other active pam_wheel rule or bad file.
rlch_5_2_7_pam_state() {
    [[ -f "${RLCH_CIS_5_2_7_PAM_FILE}" && ! -L "${RLCH_CIS_5_2_7_PAM_FILE}" ]] || return 2
    awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            n = split($0, f, /[[:space:]]+/)
            start = (f[1] == "" ? 2 : 1)
            found = 0
            for (i = start; i <= n; i++) if (f[i] == "pam_wheel.so") found = 1
            if (!found) next
            count++
            if (f[start] != "auth" || f[start+1] != "required" || n != start+4 ||
                f[start+3] != "use_uid" || f[start+4] != "group=sugroup") bad = 1
        }
        END { if (bad || count > 1) exit 2; if (count == 1) exit 0; exit 1 }
    ' "${RLCH_CIS_5_2_7_PAM_FILE}"
}

check() {
    local group_state=0 pam_state=0
    rlch_5_2_7_group_state || group_state=$?
    rlch_5_2_7_pam_state || pam_state=$?
    [[ "${group_state}" -ne 3 && "${pam_state}" -ne 2 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "${group_state}" -ne 2 ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    [[ "${group_state}" -eq 1 && "${pam_state}" -eq 0 ]] && return "${RLCH_MODULE_RESULT_SUCCESS}"
    return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
}

# The backup and applied checksum make rollback refuse to overwrite later edits.
rlch_5_2_7_restore_pam() {
    local saved_checksum current_checksum temporary
    if cmp -s -- "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original" "${RLCH_CIS_5_2_7_PAM_FILE}"; then
        return 0
    fi
    saved_checksum="$(cat "${RLCH_CIS_5_2_7_STATE_DIR}/applied.sha256")" || return 1
    current_checksum="$(sha256sum "${RLCH_CIS_5_2_7_PAM_FILE}")" || return 1
    [[ "${current_checksum%% *}" == "${saved_checksum}" ]] || return 1
    temporary="$(mktemp "$(dirname -- "${RLCH_CIS_5_2_7_PAM_FILE}")/.rlch-su-restore.XXXXXX")" || return 1
    if ! cp -a -- "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original" "${temporary}" ||
       ! mv -f -- "${temporary}" "${RLCH_CIS_5_2_7_PAM_FILE}"; then
        rm -f -- "${temporary}"
        return 1
    fi
}

rlch_5_2_7_remove_created_group() {
    local state=0 entry gid
    [[ -f "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid" ]] || return 0
    gid="$(cat "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid")" || return 1
    entry="$("${RLCH_CIS_5_2_7_GETENT}" group "${RLCH_CIS_5_2_7_GROUP}")" || return 1
    [[ "${entry}" == "${RLCH_CIS_5_2_7_GROUP}:"*":${gid}:" ]] || return 1
    rlch_5_2_7_group_state || state=$?
    [[ "${state}" -eq 1 ]] || return 1
    "${RLCH_CIS_5_2_7_GROUPDEL}" "${RLCH_CIS_5_2_7_GROUP}" || return 1
}

apply() {
    local result=0 group_state=0 pam_state=0 temporary entry gid
    check || result=$?
    [[ "${result}" -ne "${RLCH_MODULE_RESULT_SUCCESS}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "${result}" -eq "${RLCH_MODULE_RESULT_NON_COMPLIANT}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ "$("${RLCH_CIS_5_2_7_ID}" -u 2>/dev/null)" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    [[ ! -e "${RLCH_CIS_5_2_7_STATE_DIR}" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    rlch_5_2_7_group_state || group_state=$?
    rlch_5_2_7_pam_state || pam_state=$?
    [[ "${group_state}" -ne 2 && "${group_state}" -ne 3 ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    [[ "${pam_state}" -ne 2 ]] || return "${RLCH_MODULE_RESULT_NON_COMPLIANT}"
    mkdir -p -- "$(dirname -- "${RLCH_CIS_5_2_7_STATE_DIR}")" || return "${RLCH_MODULE_RESULT_ERROR}"
    mkdir -m 0700 -- "${RLCH_CIS_5_2_7_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ "${group_state}" -eq 0 ]]; then
        if ! "${RLCH_CIS_5_2_7_GROUPADD}" "${RLCH_CIS_5_2_7_GROUP}"; then
            rmdir -- "${RLCH_CIS_5_2_7_STATE_DIR}" 2>/dev/null || true
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        entry="$("${RLCH_CIS_5_2_7_GETENT}" group "${RLCH_CIS_5_2_7_GROUP}")" || return "${RLCH_MODULE_RESULT_ERROR}"
        gid="${entry#*:*:}"; gid="${gid%%:*}"
        printf '%s\n' "${gid}" > "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid" || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ "${pam_state}" -eq 1 ]]; then
        if ! cp -a -- "${RLCH_CIS_5_2_7_PAM_FILE}" "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original"; then
            rm -f -- "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original"
            if rlch_5_2_7_remove_created_group; then
                rm -f -- "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid"
                rmdir -- "${RLCH_CIS_5_2_7_STATE_DIR}" 2>/dev/null || true
            fi
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        temporary="$(mktemp "$(dirname -- "${RLCH_CIS_5_2_7_PAM_FILE}")/.rlch-su.XXXXXX")" || return "${RLCH_MODULE_RESULT_ERROR}"
        # Copy metadata (including SELinux context and ACLs) before changing content.
        if ! cp -a -- "${RLCH_CIS_5_2_7_PAM_FILE}" "${temporary}" || ! awk '
            BEGIN { inserted = 0 }
            !inserted && $1 == "auth" && $3 != "pam_rootok.so" {
                print "auth required pam_wheel.so use_uid group=sugroup"; inserted = 1
            }
            { print }
            END { if (!inserted) print "auth required pam_wheel.so use_uid group=sugroup" }
        ' "${RLCH_CIS_5_2_7_PAM_FILE}" > "${temporary}"; then
            rm -f -- "${temporary}"
            rollback >/dev/null 2>&1 || true
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
        if ! sha256sum "${temporary}" | cut -d' ' -f1 > "${RLCH_CIS_5_2_7_STATE_DIR}/applied.sha256" ||
           ! mv -f -- "${temporary}" "${RLCH_CIS_5_2_7_PAM_FILE}"; then
            rm -f -- "${temporary}"
            rollback >/dev/null 2>&1 || true
            return "${RLCH_MODULE_RESULT_ERROR}"
        fi
    fi
    if ! check; then
        rollback >/dev/null 2>&1 || true
        return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    return "${RLCH_MODULE_RESULT_CHANGED}"
}

validate() { check; }

rollback() {
    local group_state=0 entry gid
    [[ -d "${RLCH_CIS_5_2_7_STATE_DIR}" ]] || return "${RLCH_MODULE_RESULT_SUCCESS}"
    [[ "$("${RLCH_CIS_5_2_7_ID}" -u 2>/dev/null)" == 0 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    if [[ -f "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid" ]]; then
        gid="$(cat "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid")" || return "${RLCH_MODULE_RESULT_ERROR}"
        entry="$("${RLCH_CIS_5_2_7_GETENT}" group "${RLCH_CIS_5_2_7_GROUP}")" || return "${RLCH_MODULE_RESULT_ERROR}"
        [[ "${entry}" == "${RLCH_CIS_5_2_7_GROUP}:"*":${gid}:" ]] || return "${RLCH_MODULE_RESULT_ERROR}"
        rlch_5_2_7_group_state || group_state=$?
        [[ "${group_state}" -eq 1 ]] || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    if [[ -f "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original" ]]; then
        rlch_5_2_7_restore_pam || return "${RLCH_MODULE_RESULT_ERROR}"
    fi
    rlch_5_2_7_remove_created_group || return "${RLCH_MODULE_RESULT_ERROR}"
    rm -f -- "${RLCH_CIS_5_2_7_STATE_DIR}/pam.original" "${RLCH_CIS_5_2_7_STATE_DIR}/applied.sha256" \
        "${RLCH_CIS_5_2_7_STATE_DIR}/created.gid" || return "${RLCH_MODULE_RESULT_ERROR}"
    rmdir -- "${RLCH_CIS_5_2_7_STATE_DIR}" || return "${RLCH_MODULE_RESULT_ERROR}"
    return "${RLCH_MODULE_RESULT_CHANGED}"
}
