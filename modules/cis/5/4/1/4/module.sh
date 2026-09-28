#!/usr/bin/env bash
# CIS 5.4.1.4 - Password hashing defaults, without changing PAM or shadow.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_4_1_4_LOGIN_DEFS="${RLCH_CIS_5_4_1_4_LOGIN_DEFS:-/etc/login.defs}"
RLCH_CIS_5_4_1_4_LIBUSER="${RLCH_CIS_5_4_1_4_LIBUSER:-/etc/libuser.conf}"
RLCH_CIS_5_4_1_4_RPM="${RLCH_CIS_5_4_1_4_RPM:-rpm}"
RLCH_CIS_5_4_1_4_STATE="${RLCH_CIS_5_4_1_4_STATE:-/var/lib/rlch/cis/5.4.1.4}"
RLCH_CIS_5_4_1_4_LOGIN_MARKER='ENCRYPT_METHOD SHA512 # rlch-cis-5.4.1.4'
RLCH_CIS_5_4_1_4_LIB_MARKER='# rlch-cis-5.4.1.4 crypt_style'
RLCH_CIS_5_4_1_4_LIB_LINE='crypt_style = sha512'

# 0: no active property, 1: one value printed, 2: malformed or unsafe.
rlch_5_4_1_4_login_value() {
    [[ -f "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" && -r "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" && ! -L "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*ENCRYPT_METHOD([[:space:]]|$)/ {
            line=$0; sub(/#.*/, "", line)
            if (line !~ /^[[:space:]]*ENCRYPT_METHOD[[:space:]]+[[:alnum:]_]+[[:space:]]*$/) bad=1
            n=split(line, fields, /[[:space:]]+/)
            for (i=1; i<=n; i++) if (fields[i]=="ENCRYPT_METHOD") value=fields[i+1]
            count++
        }
        END {if (bad || count>1) exit 2; if (count) {print value; exit 1}}
    ' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
}

# 0: package absent, 1: installed, 2: query failed.
rlch_5_4_1_4_lib_installed() {
    local result=0
    "$RLCH_CIS_5_4_1_4_RPM" -q --quiet libuser >/dev/null 2>&1 || result=$?
    case "$result" in 0) return 1;; 1) return 0;; *) return 2;; esac
}

# Require one [defaults] section and an unambiguous crypt_style there.
# 0: missing (including missing file/section); 1: value printed; 2: error.
rlch_5_4_1_4_lib_value() {
    [[ ! -L "$RLCH_CIS_5_4_1_4_LIBUSER" ]] || return 2
    [[ -e "$RLCH_CIS_5_4_1_4_LIBUSER" ]] || return 0
    [[ -f "$RLCH_CIS_5_4_1_4_LIBUSER" && -r "$RLCH_CIS_5_4_1_4_LIBUSER" ]] || return 2
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*\[/ {
            if ($0 !~ /^[[:space:]]*\[[^]]+\][[:space:]]*(#.*)?$/) bad=1
            section=$0; sub(/^[[:space:]]*\[/, "", section); sub(/\].*$/, "", section)
            active=(section=="defaults")
            if (active) sections++
            next
        }
        active && /^[[:space:]]*crypt_style([[:space:]]|=|$)/ {
            line=$0
            if (line !~ /^[[:space:]]*crypt_style[[:space:]]*=[[:space:]]*[[:alnum:]_]+([[:space:]]+#.*)?[[:space:]]*$/) bad=1
            commented=(line ~ /[[:space:]]+#/)
            sub(/[[:space:]]+#.*$/, "", line)
            sub(/^[[:space:]]*crypt_style[[:space:]]*=[[:space:]]*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            value=line (commented ? " # comment" : ""); count++
        }
        END {if (bad || sections>1 || count>1) exit 2; if (count) {print value; exit 1}}
    ' "$RLCH_CIS_5_4_1_4_LIBUSER"
}

check() {
    local value code=0 installed=0 finding=0
    value="$(rlch_5_4_1_4_login_value)" || code=$?
    [[ "$code" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$code" -eq 1 && "$value" == SHA512 ]] || finding=1
    rlch_5_4_1_4_lib_installed || installed=$?
    [[ "$installed" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$installed" -eq 1 ]]; then
        code=0
        value="$(rlch_5_4_1_4_lib_value)" || code=$?
        [[ "$code" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        [[ "$code" -eq 1 && "$value" == sha512 ]] || finding=1
    fi
    [[ "$finding" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

rlch_5_4_1_4_write_login() {
    local old="$1" new="$2" temp
    temp="$(mktemp "${RLCH_CIS_5_4_1_4_LOGIN_DEFS}.XXXXXX")" || return 1
    cp -p --attributes-only "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" "$temp" || { rm -f "$temp"; return 1; }
    awk -v old="$old" -v replacement="$new" '
        $0==old && old!="" {if (replacement!="") print replacement; next}
        {print}
        END {if (old=="" && replacement!="") print replacement}
    ' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" > "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_4_1_4_LOGIN_DEFS"
}

# Only the [defaults] section is changed. A separate comment identifies the
# inserted line without breaking ComplianceAsCode's end-anchored OVAL regex.
rlch_5_4_1_4_write_lib() {
    local old="$1" replacement="$2" temp
    temp="$(mktemp "${RLCH_CIS_5_4_1_4_LIBUSER}.XXXXXX")" || return 1
    cp -p --attributes-only "$RLCH_CIS_5_4_1_4_LIBUSER" "$temp" || { rm -f "$temp"; return 1; }
    awk -v old="$old" -v marker="$RLCH_CIS_5_4_1_4_LIB_MARKER" -v line="$RLCH_CIS_5_4_1_4_LIB_LINE" -v restore="$replacement" '
        /^[[:space:]]*\[/ {
            if (active && !done && old=="" && restore=="managed") {print marker; print line; done=1}
            section=$0; sub(/^[[:space:]]*\[/, "", section); sub(/\].*$/, "", section)
            active=(section=="defaults")
        }
        active && old!="" && $0==old {
            if (restore=="managed") {print marker; print line}
            else if (restore!="") print restore
            done=1; next
        }
        active && $0==marker && restore!="managed" {next}
        {print}
        END {if (active && !done && old=="" && restore=="managed") {print marker; print line}}
    ' "$RLCH_CIS_5_4_1_4_LIBUSER" > "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_4_1_4_LIBUSER"
}

apply() {
    local result=0 code=0 value installed=0 login_old='' lib_old='' login_change=no lib_change=no
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$(id -u)" -eq 0 && ! -e "$RLCH_CIS_5_4_1_4_STATE" && ! -L "$RLCH_CIS_5_4_1_4_STATE" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ -s "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" && "$(tail -c 1 "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" | wc -l)" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    value="$(rlch_5_4_1_4_login_value)" || code=$?
    if [[ "$code" -eq 0 || "$value" != SHA512 ]]; then
        login_change=yes
        if [[ "$code" -eq 1 ]]; then
            login_old="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*ENCRYPT_METHOD([[:space:]]|$)/ {print; exit}' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS")"
        fi
    fi
    rlch_5_4_1_4_lib_installed || installed=$?
    if [[ "$installed" -eq 1 ]]; then
        [[ -f "$RLCH_CIS_5_4_1_4_LIBUSER" && ! -L "$RLCH_CIS_5_4_1_4_LIBUSER" && -s "$RLCH_CIS_5_4_1_4_LIBUSER" && "$(tail -c 1 "$RLCH_CIS_5_4_1_4_LIBUSER" | wc -l)" -eq 1 ]] || {
            error_message 'CIS 5.4.1.4: installed libuser requires a reviewed, existing /etc/libuser.conf.'
            return "$RLCH_MODULE_RESULT_ERROR"
        }
        code=0
        value="$(rlch_5_4_1_4_lib_value)" || code=$?
        if [[ "$code" -eq 0 || "$value" != sha512 ]]; then
            lib_change=yes
            grep -Eq '^[[:space:]]*\[defaults\][[:space:]]*(#.*)?$' "$RLCH_CIS_5_4_1_4_LIBUSER" || {
                error_message 'CIS 5.4.1.4: missing [defaults] section requires review.'
                return "$RLCH_MODULE_RESULT_ERROR"
            }
            if [[ "$code" -eq 1 ]]; then
                lib_old="$(awk '/^[[:space:]]*\[defaults\]/ {active=1; next} /^[[:space:]]*\[/ {active=0} active && /^[[:space:]]*crypt_style([[:space:]]|=|$)/ {print; exit}' "$RLCH_CIS_5_4_1_4_LIBUSER")"
            fi
        fi
    fi
    mkdir -p "$RLCH_CIS_5_4_1_4_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_4_1_4_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$login_old" > "$RLCH_CIS_5_4_1_4_STATE/login_original" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$lib_old" > "$RLCH_CIS_5_4_1_4_STATE/lib_original" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$login_change" > "$RLCH_CIS_5_4_1_4_STATE/login_changed" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$lib_change" > "$RLCH_CIS_5_4_1_4_STATE/lib_changed" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$login_change" == yes ]] && ! rlch_5_4_1_4_write_login "$login_old" "$RLCH_CIS_5_4_1_4_LOGIN_MARKER"; then
        rollback >/dev/null 2>&1 || true; return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if [[ "$lib_change" == yes ]] && ! rlch_5_4_1_4_write_lib "$lib_old" managed; then
        rollback >/dev/null 2>&1 || true; return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if ! check; then
        rollback >/dev/null 2>&1 || true; return "$RLCH_MODULE_RESULT_ERROR"
    fi
    return "$RLCH_MODULE_RESULT_CHANGED"
}

validate() { check; }

rollback() {
    local login_change lib_change login_old lib_old login_rows lib_rows file
    [[ -e "$RLCH_CIS_5_4_1_4_STATE" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -d "$RLCH_CIS_5_4_1_4_STATE" && ! -L "$RLCH_CIS_5_4_1_4_STATE" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    for file in login_original lib_original login_changed lib_changed; do
        [[ -f "$RLCH_CIS_5_4_1_4_STATE/$file" && ! -L "$RLCH_CIS_5_4_1_4_STATE/$file" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    done
    login_change="$(cat "$RLCH_CIS_5_4_1_4_STATE/login_changed")"
    lib_change="$(cat "$RLCH_CIS_5_4_1_4_STATE/lib_changed")"
    login_old="$(cat "$RLCH_CIS_5_4_1_4_STATE/login_original")"
    lib_old="$(cat "$RLCH_CIS_5_4_1_4_STATE/lib_original")"
    [[ -f "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" && ! -L "$RLCH_CIS_5_4_1_4_LOGIN_DEFS" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$login_change" == yes ]]; then
        login_rows="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*ENCRYPT_METHOD([[:space:]]|$)/ {print}' "$RLCH_CIS_5_4_1_4_LOGIN_DEFS")"
        [[ "$login_rows" == "$RLCH_CIS_5_4_1_4_LOGIN_MARKER" || "$login_rows" == "$login_old" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    elif [[ "$login_change" != no ]]; then return "$RLCH_MODULE_RESULT_ERROR"; fi
    if [[ "$lib_change" == yes ]]; then
        [[ -f "$RLCH_CIS_5_4_1_4_LIBUSER" && ! -L "$RLCH_CIS_5_4_1_4_LIBUSER" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        lib_rows="$(awk '/^[[:space:]]*\[defaults\]/ {active=1; next} /^[[:space:]]*\[/ {active=0} active && /^[[:space:]]*crypt_style([[:space:]]|=|$)/ {print}' "$RLCH_CIS_5_4_1_4_LIBUSER")"
        [[ "$lib_rows" == "$RLCH_CIS_5_4_1_4_LIB_LINE" || "$lib_rows" == "$lib_old" ]] || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ "$lib_rows" == "$RLCH_CIS_5_4_1_4_LIB_LINE" ]]; then
            [[ "$(grep -Fxc "$RLCH_CIS_5_4_1_4_LIB_MARKER" "$RLCH_CIS_5_4_1_4_LIBUSER")" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        fi
    elif [[ "$lib_change" != no ]]; then return "$RLCH_MODULE_RESULT_ERROR"; fi
    if [[ "$lib_change" == yes && "$lib_rows" != "$lib_old" ]]; then
        rlch_5_4_1_4_write_lib "$RLCH_CIS_5_4_1_4_LIB_LINE" "$lib_old" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if [[ "$login_change" == yes && "$login_rows" != "$login_old" ]]; then
        rlch_5_4_1_4_write_login "$RLCH_CIS_5_4_1_4_LOGIN_MARKER" "$login_old" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_4_1_4_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
