#!/usr/bin/env bash
# CIS 5.3.3.4.3 - Inspect pam_unix hashing in authselect-generated PAM stacks.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_4_3_AUTHSELECT="${RLCH_CIS_5_3_3_4_3_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_4_3_PAM_DIR="${RLCH_CIS_5_3_3_4_3_PAM_DIR:-/etc/pam.d}"

rlch_5_3_3_4_3_stack() {
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/#.*/, "", line)
            n=split(line, fields, /[[:space:]]+/)
            start=(fields[1]=="" ? 2 : 1)
            if (fields[start]!="password") next
            module=start+2
            if (fields[start+1] ~ /^\[/) {
                module=start+1
                while (module<=n && fields[module] !~ /\]$/) module++
                module++
            }
            if (fields[module]!="pam_unix.so") next
            if (fields[start+1]!="required" && fields[start+1]!="sufficient") next
            hooks++
            algorithms=0; selected=""
            for (i=module+1; i<=n; i++) {
                if (fields[i] ~ /^(sha512|yescrypt|gost_yescrypt|blowfish|sha256|md5|bigcrypt|des)$/) {
                    algorithms++
                    selected=fields[i]
                }
            }
            if (algorithms!=1 || selected!="sha512") finding=1
        }
        END {if (!hooks || finding) exit 1}
    ' "$1"
}

check() {
    local file result=0 finding=0
    "$RLCH_CIS_5_3_3_4_3_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    for file in system-auth password-auth; do
        rlch_5_3_3_4_3_stack "$RLCH_CIS_5_3_3_4_3_PAM_DIR/$file" || result=$?
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
    error_message 'CIS 5.3.3.4.3 requires a reviewed authselect profile change; generated PAM files cannot be edited directly.'
    return "$RLCH_MODULE_RESULT_ERROR"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
