#!/usr/bin/env bash
# CIS 5.3.3.4.1 - Detect active nullok in authselect-managed PAM stacks.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_4_1_AUTHSELECT="${RLCH_CIS_5_3_3_4_1_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_4_1_PAM_DIR="${RLCH_CIS_5_3_3_4_1_PAM_DIR:-/etc/pam.d}"

# ComplianceAsCode no_empty_passwords checks both files, without limiting
# matching lines to pam_unix.so. A token on another active module is therefore
# a finding too; comments and longer option names are not exact nullok.
rlch_5_3_3_4_1_stack() {
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/#.*/, "", line)
            if (line !~ /[^[:space:]]/) next
            n=split(line, fields, /[[:space:]]+/)
            start=(fields[1]=="" ? 2 : 1)
            if (fields[start] !~ /^(auth|password|account|session)$/) {
                if (line ~ /(^|[[:space:]])nullok([[:space:]]|$)/) bad=1
                next
            }
            # A PAM line must have type, control, module, then options. For
            # extended [success=...] controls, determine the module boundary.
            module=start+2
            if (fields[start+1] ~ /^\[/) {
                module=start+1
                while (module<=n && fields[module] !~ /\]$/) module++
                module++
            }
            if (module>n || fields[module] !~ /\.so$/) {bad=1; next}
            for (i=module+1; i<=n; i++) if (fields[i]=="nullok") found=1
        }
        END {if (bad) exit 2; if (found) exit 1}
    ' "$1"
}

check() {
    local file result=0 finding=0
    "$RLCH_CIS_5_3_3_4_1_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    for file in system-auth password-auth; do
        rlch_5_3_3_4_1_stack "$RLCH_CIS_5_3_3_4_1_PAM_DIR/$file" || result=$?
        [[ "$result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$result" -ne 1 ]] || finding=1
        result=0
    done
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

apply() {
    local result=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    error_message 'CIS 5.3.3.4.1 requires a reviewed authselect profile change; generated PAM files cannot be edited directly.'
    return "$RLCH_MODULE_RESULT_ERROR"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
