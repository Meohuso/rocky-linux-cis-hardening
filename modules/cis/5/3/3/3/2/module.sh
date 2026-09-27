#!/usr/bin/env bash
# CIS 5.3.3.3.2 - Explicit administrator pwhistory enforce_for_root.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_3_2_CONF="${RLCH_CIS_5_3_3_3_2_CONF:-/etc/security/pwhistory.conf}"
RLCH_CIS_5_3_3_3_2_BASE="${RLCH_CIS_5_3_3_3_2_BASE:-/usr/lib/security/pwhistory.conf}"
RLCH_CIS_5_3_3_3_2_PAM_DIR="${RLCH_CIS_5_3_3_3_2_PAM_DIR:-/etc/pam.d}"
RLCH_CIS_5_3_3_3_2_AUTHSELECT="${RLCH_CIS_5_3_3_3_2_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_3_2_STATE="${RLCH_CIS_5_3_3_3_2_STATE:-/var/lib/rlch/cis/5.3.3.3.2}"
RLCH_CIS_5_3_3_3_2_TAG='# rlch-cis-5.3.3.3.2 managed directive'

# Linux-PAM search_key accepts an empty value for a bare flag; the runtime
# checks for a non-NULL result. Values after = also activate the flag, but are
# misleading and outside the benchmark's canonical syntax.
rlch_5_3_3_3_2_scan() {
    [[ ! -L "$1" ]] || return 2
    [[ -e "$1" ]] || { printf '0\n'; return 0; }
    [[ -f "$1" && -r "$1" ]] || return 2
    awk '
        {line=$0; sub(/#.*/, "", line)
         if (line ~ /^[[:space:]]*enforce_for_root([[:space:]]|=|$)/) {
             if (line !~ /^[[:space:]]*enforce_for_root[[:space:]]*$/) bad=1
             else count++
         }
        }
        END {if (bad) exit 2; print count+0}
    ' "$1"
}

rlch_5_3_3_3_2_pam() {
    local file
    for file in system-auth password-auth; do
        [[ -f "$RLCH_CIS_5_3_3_3_2_PAM_DIR/$file" && -r "$RLCH_CIS_5_3_3_3_2_PAM_DIR/$file" && ! -L "$RLCH_CIS_5_3_3_3_2_PAM_DIR/$file" ]] || return 2
    done
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && /pam_pwhistory\.so([[:space:]]|$)/ {
            line=$0; sub(/[[:space:]]+#.*/, "", line)
            n=split(line, fields, /[[:space:]]+/)
            idx=0
            for (i=1; i<=n; i++) if (fields[i]=="pam_pwhistory.so") {idx=i; break}
            if (!idx || (fields[idx-1]!="required" && fields[idx-1]!="requisite")) bad=1
            for (i=idx+1; i<=n; i++) {
                if (fields[i] ~ /^conf=/ || fields[i]=="conf" ||
                    fields[i] ~ /^enforce_for_root=/) bad=1
            }
            count[FILENAME]++
        }
        END {if (bad || count[ARGV[1]]!=1 || count[ARGV[2]]!=1) exit 2}
    ' "$RLCH_CIS_5_3_3_3_2_PAM_DIR/system-auth" "$RLCH_CIS_5_3_3_3_2_PAM_DIR/password-auth"
}

check() {
    local count
    "$RLCH_CIS_5_3_3_3_2_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_5_3_3_3_2_pam || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(rlch_5_3_3_3_2_scan "$RLCH_CIS_5_3_3_3_2_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    # Vendor-only config is active at runtime when /etc is absent, but this
    # CIS rule explicitly requires an administrator pwhistory.conf witness.
    if [[ ! -e "$RLCH_CIS_5_3_3_3_2_CONF" ]]; then
        rlch_5_3_3_3_2_scan "$RLCH_CIS_5_3_3_3_2_BASE" >/dev/null || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$count" -gt 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

rlch_5_3_3_3_2_append() {
    local temp
    temp="$(mktemp "${RLCH_CIS_5_3_3_3_2_CONF}.XXXXXX")" || return 1
    if [[ -e "$RLCH_CIS_5_3_3_3_2_CONF" ]]; then
        cp -p "$RLCH_CIS_5_3_3_3_2_CONF" "$temp" || { rm -f "$temp"; return 1; }
    else
        chmod 0644 "$temp" || { rm -f "$temp"; return 1; }
    fi
    printf '%s\nenforce_for_root\n' "$RLCH_CIS_5_3_3_3_2_TAG" >> "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_3_3_3_2_CONF"
}

apply() {
    local result=0 count present
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ ! -e "$RLCH_CIS_5_3_3_3_2_STATE" && ! -L "$RLCH_CIS_5_3_3_3_2_STATE" && ! -L "$RLCH_CIS_5_3_3_3_2_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(rlch_5_3_3_3_2_scan "$RLCH_CIS_5_3_3_3_2_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$count" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -s "$RLCH_CIS_5_3_3_3_2_CONF" && "$(tail -c 1 "$RLCH_CIS_5_3_3_3_2_CONF" | wc -l)" -ne 1 ]]; then
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ ! -e "$RLCH_CIS_5_3_3_3_2_CONF" ]] && present=absent || present=present
    mkdir -p "$RLCH_CIS_5_3_3_3_2_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_3_3_3_2_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$present" > "$RLCH_CIS_5_3_3_3_2_STATE/file" || return "$RLCH_MODULE_RESULT_ERROR"
    if ! rlch_5_3_3_3_2_append; then
        rm -rf "$RLCH_CIS_5_3_3_3_2_STATE"
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
    local count temp
    [[ -f "$RLCH_CIS_5_3_3_3_2_STATE/file" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -f "$RLCH_CIS_5_3_3_3_2_CONF" && ! -L "$RLCH_CIS_5_3_3_3_2_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(awk -v tag="$RLCH_CIS_5_3_3_3_2_TAG" '
        $0==tag && (getline line)>0 && line=="enforce_for_root" {n++}
        END {print n+0}
    ' "$RLCH_CIS_5_3_3_3_2_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    temp="$(mktemp "${RLCH_CIS_5_3_3_3_2_CONF}.XXXXXX")" || return "$RLCH_MODULE_RESULT_ERROR"
    cp -p --attributes-only "$RLCH_CIS_5_3_3_3_2_CONF" "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    awk -v tag="$RLCH_CIS_5_3_3_3_2_TAG" '
        $0==tag {if ((getline line)>0 && line=="enforce_for_root") next; print; print line; next}
        {print}
    ' "$RLCH_CIS_5_3_3_3_2_CONF" > "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    if [[ "$(cat "$RLCH_CIS_5_3_3_3_2_STATE/file")" == absent && ! -s "$temp" ]]; then
        rm -f "$temp" "$RLCH_CIS_5_3_3_3_2_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    else
        mv -f "$temp" "$RLCH_CIS_5_3_3_3_2_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_3_3_3_2_STATE"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
