#!/usr/bin/env bash
# CIS 5.3.3.1.1 - Effective pam_faillock deny threshold.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_1_1_CONF="${RLCH_CIS_5_3_3_1_1_CONF:-/etc/security/faillock.conf}"
RLCH_CIS_5_3_3_1_1_PAM_DIR="${RLCH_CIS_5_3_3_1_1_PAM_DIR:-/etc/pam.d}"
RLCH_CIS_5_3_3_1_1_AUTHSELECT="${RLCH_CIS_5_3_3_1_1_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_1_1_STATE="${RLCH_CIS_5_3_3_1_1_STATE:-/var/lib/rlch/cis/5.3.3.1.1}"
RLCH_CIS_5_3_3_1_1_MARKER="# rlch-cis-5.3.3.1.1"

# Exit 0: no active setting; 1: one setting (printed); 2: malformed or ambiguous.
rlch_5_3_3_1_1_config_value() {
    [[ ! -L "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return 2
    [[ -e "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return 0
    [[ -f "$RLCH_CIS_5_3_3_1_1_CONF" && -r "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return 2
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*deny([[:space:]]|=|$)/ {
            count++
            line=$0
            sub(/^[[:space:]]*deny[[:space:]]*=[[:space:]]*/, "", line)
            if (line !~ /^[0-9]+([[:space:]]*(#.*)?)?$/) bad=1
            else { sub(/[[:space:]#].*$/, "", line); value=line }
        }
        END {
            if (bad || count > 1) exit 2
            if (!count) exit 0
            print value
            exit 1
        }
    ' "$RLCH_CIS_5_3_3_1_1_CONF"
}

# Print "number_of_inline_options number_of_lines_using_config". Exit 2 on
# malformed/duplicated inline options or unreadable generated PAM files.
rlch_5_3_3_1_1_pam_values() {
    local file
    for file in system-auth password-auth; do
        [[ -f "$RLCH_CIS_5_3_3_1_1_PAM_DIR/$file" && -r "$RLCH_CIS_5_3_3_1_1_PAM_DIR/$file" ]] || return 2
    done
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*auth[[:space:]]+/ && /pam_faillock\.so([[:space:]]|$)/ {
            sub(/[[:space:]]+#.*/, "")
            sub(/^.*pam_faillock\.so[[:space:]]*/, "")
            n=split($0, fields, /[[:space:]]+/)
            found=0
            for (i=1; i<=n; i++) {
                if (fields[i] == "deny" || fields[i] ~ /^deny=/) {
                    found++
                    if (fields[i] !~ /^deny=[0-9]+$/) bad=1
                    else {
                        value=fields[i]; sub(/^deny=/, "", value)
                        if (value+0 < 1 || value+0 > 5) noncompliant=1
                    }
                }
            }
            if (found > 1) bad=1
            if (found) inline++
            else config++
            seen[FILENAME]++
        }
        END {
            if (bad) exit 2
            if (noncompliant) exit 1
            if (length(seen) != 2) exit 2
            print inline+0, config+0
        }
    ' "$RLCH_CIS_5_3_3_1_1_PAM_DIR/system-auth" "$RLCH_CIS_5_3_3_1_1_PAM_DIR/password-auth"
}

rlch_5_3_3_1_1_in_range() {
    [[ "$1" =~ ^0*[1-5]$ ]]
}

check() {
    local pam config_value pam_result=0 config_result=0 inline uses_config
    "$RLCH_CIS_5_3_3_1_1_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    pam="$(rlch_5_3_3_1_1_pam_values)" || pam_result=$?
    [[ "$pam_result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    config_value="$(rlch_5_3_3_1_1_config_value)" || config_result=$?
    [[ "$config_result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$pam_result" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    read -r inline uses_config <<< "$pam"
    [[ "$inline" -ge 0 && "$uses_config" -ge 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if (( uses_config > 0 )); then
        [[ "$config_result" -eq 1 ]] && rlch_5_3_3_1_1_in_range "$config_value" ||
            return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

# Replace only the active deny line, preserving every unrelated line and file metadata.
rlch_5_3_3_1_1_write() {
    local temp
    temp="$(mktemp "${RLCH_CIS_5_3_3_1_1_CONF}.XXXXXX")" || return 1
    if [[ -f "$RLCH_CIS_5_3_3_1_1_CONF" ]]; then
        cp -p --attributes-only "$RLCH_CIS_5_3_3_1_1_CONF" "$temp" || { rm -f "$temp"; return 1; }
        awk -v replacement="deny = 5 ${RLCH_CIS_5_3_3_1_1_MARKER}" '
            /^[[:space:]]*#/ { print; next }
            /^[[:space:]]*deny([[:space:]]|=|$)/ { print replacement; found=1; next }
            { print }
            END { if (!found) print replacement }
        ' "$RLCH_CIS_5_3_3_1_1_CONF" > "$temp" || { rm -f "$temp"; return 1; }
    else
        chmod 0644 "$temp" || { rm -f "$temp"; return 1; }
        printf 'deny = 5 %s\n' "$RLCH_CIS_5_3_3_1_1_MARKER" > "$temp" || { rm -f "$temp"; return 1; }
    fi
    mv -f "$temp" "$RLCH_CIS_5_3_3_1_1_CONF"
}

apply() {
    local result=0 pam_result=0 pam config_result=0 config_value
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    pam="$(rlch_5_3_3_1_1_pam_values)" || pam_result=$?
    if [[ "$pam_result" -ne 0 ]] || [[ "${pam%% *}" -gt 0 ]]; then
        error_message "CIS 5.3.3.1.1: PAM inline deny options require a reviewed authselect profile change."
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    config_value="$(rlch_5_3_3_1_1_config_value)" || config_result=$?
    [[ "$config_result" -ne 2 && ! -e "$RLCH_CIS_5_3_3_1_1_STATE" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ ! -L "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ ! -e "$RLCH_CIS_5_3_3_1_1_CONF" || -f "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    mkdir -p "$RLCH_CIS_5_3_3_1_1_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_3_3_1_1_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$RLCH_CIS_5_3_3_1_1_CONF" ]]; then
        printf 'present\n' > "$RLCH_CIS_5_3_3_1_1_STATE/file"
    else
        printf 'absent\n' > "$RLCH_CIS_5_3_3_1_1_STATE/file"
    fi
    if [[ "$config_result" -eq 1 ]]; then
        awk '/^[[:space:]]*#/ { next } /^[[:space:]]*deny([[:space:]]|=|$)/ { print; exit }' "$RLCH_CIS_5_3_3_1_1_CONF" > "$RLCH_CIS_5_3_3_1_1_STATE/original"
    else
        : > "$RLCH_CIS_5_3_3_1_1_STATE/original"
    fi
    if ! rlch_5_3_3_1_1_write; then
        rm -rf "$RLCH_CIS_5_3_3_1_1_STATE"
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if ! check; then
        rollback >/dev/null 2>&1 || true
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_CHANGED"
}

validate() { check; }

rollback() {
    local temp count active
    [[ -f "$RLCH_CIS_5_3_3_1_1_STATE/file" && -f "$RLCH_CIS_5_3_3_1_1_STATE/original" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -f "$RLCH_CIS_5_3_3_1_1_CONF" && ! -L "$RLCH_CIS_5_3_3_1_1_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(grep -Fxc "deny = 5 ${RLCH_CIS_5_3_3_1_1_MARKER}" "$RLCH_CIS_5_3_3_1_1_CONF")" || true
    [[ "$count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    active="$(awk '/^[[:space:]]*#/ { next } /^[[:space:]]*deny([[:space:]]|=|$)/ { count++ } END { print count+0 }' "$RLCH_CIS_5_3_3_1_1_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$active" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    temp="$(mktemp "${RLCH_CIS_5_3_3_1_1_CONF}.XXXXXX")" || return "$RLCH_MODULE_RESULT_ERROR"
    cp -p --attributes-only "$RLCH_CIS_5_3_3_1_1_CONF" "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    awk -v marker="deny = 5 ${RLCH_CIS_5_3_3_1_1_MARKER}" -v original="$(cat "$RLCH_CIS_5_3_3_1_1_STATE/original")" '
        $0 == marker { if (original != "") print original; next }
        { print }
    ' "$RLCH_CIS_5_3_3_1_1_CONF" > "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    if [[ "$(cat "$RLCH_CIS_5_3_3_1_1_STATE/file")" == absent && ! -s "$temp" ]]; then
        rm -f "$temp" "$RLCH_CIS_5_3_3_1_1_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    else
        mv -f "$temp" "$RLCH_CIS_5_3_3_1_1_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_3_3_1_1_STATE"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
