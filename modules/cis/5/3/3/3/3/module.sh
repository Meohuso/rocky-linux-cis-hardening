#!/usr/bin/env bash
# CIS 5.3.3.3.3 - Check authselect-managed pam_pwhistory use_authtok.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_3_3_AUTHSELECT="${RLCH_CIS_5_3_3_3_3_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_3_3_PAM_DIR="${RLCH_CIS_5_3_3_3_3_PAM_DIR:-/etc/pam.d}"

# Return 0 for a single compliant password hook, 1 for a missing option,
# 2 for an ambiguous/unsafe stack. Never edit authselect-generated files.
rlch_5_3_3_3_3_stack() {
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && /pam_pwhistory\.so([[:space:]]|$)/ {
            line=$0; sub(/[[:space:]]+#.*/, "", line)
            n=split(line, fields, /[[:space:]]+/)
            idx=0
            for (i=1; i<=n; i++) if (fields[i]=="pam_pwhistory.so") {idx=i; break}
            if (!idx || (fields[idx-1]!="required" && fields[idx-1]!="requisite")) bad=1
            found=0
            for (i=idx+1; i<=n; i++) {
                if (fields[i]=="use_authtok") found++
                else if (fields[i] ~ /^use_authtok=/ || fields[i]=="use_authok" ||
                         fields[i] ~ /^use_authok=/) bad=1
            }
            if (found>1) bad=1
            if (found==0) missing=1
            hooks++
        }
        END {if (bad || hooks!=1) exit 2; if (missing) exit 1}
    ' "$1"
}

check() {
    local file result=0 missing=0
    "$RLCH_CIS_5_3_3_3_3_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    for file in system-auth password-auth; do
        rlch_5_3_3_3_3_stack "$RLCH_CIS_5_3_3_3_3_PAM_DIR/$file" || result=$?
        [[ "$result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$result" -ne 1 ]] || missing=1
        result=0
    done
    [[ "$missing" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    error_message 'CIS 5.3.3.3.3 requires a reviewed authselect profile change; generated PAM files cannot be edited directly.'
    return "$RLCH_MODULE_RESULT_ERROR"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
