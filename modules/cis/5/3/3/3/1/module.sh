#!/usr/bin/env bash
# CIS 5.3.3.3.1 - pam_pwhistory remember >= 24.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_3_1_CONF="${RLCH_CIS_5_3_3_3_1_CONF:-/etc/security/pwhistory.conf}"
RLCH_CIS_5_3_3_3_1_PAM_DIR="${RLCH_CIS_5_3_3_3_1_PAM_DIR:-/etc/pam.d}"
RLCH_CIS_5_3_3_3_1_AUTHSELECT="${RLCH_CIS_5_3_3_3_1_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_3_1_STATE="${RLCH_CIS_5_3_3_3_1_STATE:-/var/lib/rlch/cis/5.3.3.3.1}"
RLCH_CIS_5_3_3_3_1_MARKER='remember = 24 # rlch-cis-5.3.3.3.1'

# Return 0 absent, 1 with value, 2 malformed/ambiguous or unsafe path.
rlch_5_3_3_3_1_file_value() {
    [[ ! -L "$1" ]] || return 2
    [[ -e "$1" ]] || return 0
    [[ -f "$1" && -r "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*remember([[:space:]]|=|$)/ {
            line=$0; sub(/#.*/, "", line)
            if (line !~ /^[[:space:]]*remember[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*$/) bad=1
            sub(/^[[:space:]]*remember[[:space:]]*=[[:space:]]*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (length(line)>3 || line+0>400) bad=1
            value=line; count++
        }
        END {if (bad || count>1) exit 2; if (count) {print value; exit 1}}
    ' "$1"
}

# One hook per generated stack. Inline remember is permissible only when the
# same source is used consistently on both stacks, without custom conf=.
rlch_5_3_3_3_1_pam() {
    local file
    for file in system-auth password-auth; do
        [[ -f "$RLCH_CIS_5_3_3_3_1_PAM_DIR/$file" && -r "$RLCH_CIS_5_3_3_3_1_PAM_DIR/$file" && ! -L "$RLCH_CIS_5_3_3_3_1_PAM_DIR/$file" ]] || return 2
    done
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && /pam_pwhistory\.so([[:space:]]|$)/ {
            line=$0; sub(/[[:space:]]+#.*/, "", line)
            n=split(line, fields, /[[:space:]]+/)
            idx=0
            for (i=1; i<=n; i++) if (fields[i]=="pam_pwhistory.so") {idx=i; break}
            if (!idx || (fields[idx-1]!="required" && fields[idx-1]!="requisite")) bad=1
            found=0; value=""
            for (i=idx+1; i<=n; i++) {
                if (fields[i] ~ /^conf=/ || fields[i]=="conf") bad=1
                if (fields[i] ~ /^remember([=]|$)/) {
                    found++
                    if (fields[i] !~ /^remember=[0-9]+$/) bad=1
                    else {
                        value=fields[i]; sub(/^remember=/, "", value)
                        if (length(value)>3 || value+0>400) bad=1
                    }
                }
            }
            if (found>1) bad=1
            count[FILENAME]++
            if (found) print FILENAME "=" value
            else print FILENAME "="
        }
        END {if (bad || count[ARGV[1]]!=1 || count[ARGV[2]]!=1) exit 2}
    ' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth" "$RLCH_CIS_5_3_3_3_1_PAM_DIR/password-auth"
}

check() {
    local pam config=0 value first second
    "$RLCH_CIS_5_3_3_3_1_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    pam="$(rlch_5_3_3_3_1_pam)" || return "$RLCH_MODULE_RESULT_ERROR"
    first="${pam%%$'\n'*}"; second="${pam#*$'\n'}"
    first="${first#*=}"; second="${second#*=}"
    value="$(rlch_5_3_3_3_1_file_value "$RLCH_CIS_5_3_3_3_1_CONF")" || config=$?
    [[ "$config" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$config" -eq 0 || ( -z "$first" && -z "$second" ) ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -n "$first" || -n "$second" ]]; then
        [[ -n "$first" && -n "$second" ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
        [[ "$first" -ge 24 && "$second" -ge 24 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    else
        [[ "$config" -eq 1 && "$value" -ge 24 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

rlch_5_3_3_3_1_write() {
    local original="$1" temp
    temp="$(mktemp "${RLCH_CIS_5_3_3_3_1_CONF}.XXXXXX")" || return 1
    if [[ -e "$RLCH_CIS_5_3_3_3_1_CONF" ]]; then
        cp -p --attributes-only "$RLCH_CIS_5_3_3_3_1_CONF" "$temp" || { rm -f "$temp"; return 1; }
        awk -v old="$original" -v marker="$RLCH_CIS_5_3_3_3_1_MARKER" '
            $0==old && old!="" {print marker; next}
            {print}
            END {if (old=="") print marker}
        ' "$RLCH_CIS_5_3_3_3_1_CONF" > "$temp" || { rm -f "$temp"; return 1; }
    else
        chmod 0644 "$temp" || { rm -f "$temp"; return 1; }
        printf '%s\n' "$RLCH_CIS_5_3_3_3_1_MARKER" > "$temp" || { rm -f "$temp"; return 1; }
    fi
    mv -f "$temp" "$RLCH_CIS_5_3_3_3_1_CONF"
}

apply() {
    local result=0 pam first second original='' config=0 count
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    pam="$(rlch_5_3_3_3_1_pam)" || return "$RLCH_MODULE_RESULT_ERROR"
    first="${pam%%$'\n'*}"; second="${pam#*$'\n'}"
    [[ "${first#*=}" == '' && "${second#*=}" == '' ]] || {
        error_message 'CIS 5.3.3.3.1: inline remember requires a reviewed authselect profile change.'
        return "$RLCH_MODULE_RESULT_ERROR"
    }
    [[ ! -e "$RLCH_CIS_5_3_3_3_1_STATE" && ! -L "$RLCH_CIS_5_3_3_3_1_STATE" && ! -L "$RLCH_CIS_5_3_3_3_1_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(rlch_5_3_3_3_1_file_value "$RLCH_CIS_5_3_3_3_1_CONF")" || config=$?
    [[ "$config" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -s "$RLCH_CIS_5_3_3_3_1_CONF" && "$(tail -c 1 "$RLCH_CIS_5_3_3_3_1_CONF" | wc -l)" -ne 1 ]]; then
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if [[ "$config" -eq 1 ]]; then
        original="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*remember([[:space:]]|=|$)/ {print; exit}' "$RLCH_CIS_5_3_3_3_1_CONF")"
    fi
    [[ ! -e "$RLCH_CIS_5_3_3_3_1_CONF" ]] && count=absent || count=present
    mkdir -p "$RLCH_CIS_5_3_3_3_1_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_3_3_3_1_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$count" > "$RLCH_CIS_5_3_3_3_1_STATE/file" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$original" > "$RLCH_CIS_5_3_3_3_1_STATE/original" || return "$RLCH_MODULE_RESULT_ERROR"
    if ! rlch_5_3_3_3_1_write "$original"; then
        rm -rf "$RLCH_CIS_5_3_3_3_1_STATE"
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
    local original temp count active
    [[ -f "$RLCH_CIS_5_3_3_3_1_STATE/file" && -f "$RLCH_CIS_5_3_3_3_1_STATE/original" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -f "$RLCH_CIS_5_3_3_3_1_CONF" && ! -L "$RLCH_CIS_5_3_3_3_1_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(grep -Fxc "$RLCH_CIS_5_3_3_3_1_MARKER" "$RLCH_CIS_5_3_3_3_1_CONF")" || true
    active="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*remember([[:space:]]|=|$)/ {n++} END {print n+0}' "$RLCH_CIS_5_3_3_3_1_CONF")"
    [[ "$count" -eq 1 && "$active" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    original="$(cat "$RLCH_CIS_5_3_3_3_1_STATE/original")"
    temp="$(mktemp "${RLCH_CIS_5_3_3_3_1_CONF}.XXXXXX")" || return "$RLCH_MODULE_RESULT_ERROR"
    cp -p --attributes-only "$RLCH_CIS_5_3_3_3_1_CONF" "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    awk -v marker="$RLCH_CIS_5_3_3_3_1_MARKER" -v original="$original" '
        $0==marker {if (original!="") print original; next}
        {print}
    ' "$RLCH_CIS_5_3_3_3_1_CONF" > "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    if [[ "$(cat "$RLCH_CIS_5_3_3_3_1_STATE/file")" == absent && ! -s "$temp" ]]; then
        rm -f "$temp" "$RLCH_CIS_5_3_3_3_1_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    else
        mv -f "$temp" "$RLCH_CIS_5_3_3_3_1_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_3_3_3_1_STATE"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
