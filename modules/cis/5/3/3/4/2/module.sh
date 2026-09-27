#!/usr/bin/env bash
# CIS 5.3.3.4.2 - Detect pam_unix password remember= in generated PAM stacks.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_4_2_AUTHSELECT="${RLCH_CIS_5_3_3_4_2_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_4_2_PAM_DIR="${RLCH_CIS_5_3_3_4_2_PAM_DIR:-/etc/pam.d}"

rlch_5_3_3_4_2_stack() {
    [[ -f "$1" && -r "$1" && ! -L "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && /pam_unix\.so([[:space:]]|$)/ {
            line=$0; sub(/#.*/, "", line)
            n=split(line, fields, /[[:space:]]+/)
            module=0
            for (i=1; i<=n; i++) if (fields[i]=="pam_unix.so") {module=i; break}
            if (!module || module<3) {bad=1; next}
            for (i=module+1; i<=n; i++) {
                if (fields[i] ~ /^remember=/) {
                    if (fields[i] !~ /^remember=[0-9]+$/ || length(fields[i])>13) bad=1
                    else found=1
                    count++
                } else if (fields[i]=="remember") bad=1
            }
            if (count>1) bad=1
            count=0
        }
        END {if (bad) exit 2; if (found) exit 1}
    ' "$1"
}

check() {
    local file result=0 finding=0
    "$RLCH_CIS_5_3_3_4_2_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    for file in system-auth password-auth; do
        rlch_5_3_3_4_2_stack "$RLCH_CIS_5_3_3_4_2_PAM_DIR/$file" || result=$?
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
    error_message 'CIS 5.3.3.4.2 requires a reviewed authselect profile change; generated PAM files cannot be edited directly.'
    return "$RLCH_MODULE_RESULT_ERROR"
}

validate() { check; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
