#!/usr/bin/env bash
# CIS 5.3.3.2.3 - Effective pam_pwquality minclass.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_2_3_CONF="${RLCH_CIS_5_3_3_2_3_CONF:-/etc/security/pwquality.conf}"
RLCH_CIS_5_3_3_2_3_BASE="${RLCH_CIS_5_3_3_2_3_BASE:-/usr/lib/security/pwquality.conf}"
RLCH_CIS_5_3_3_2_3_PAM_DIR="${RLCH_CIS_5_3_3_2_3_PAM_DIR:-/etc/pam.d}"
RLCH_CIS_5_3_3_2_3_AUTHSELECT="${RLCH_CIS_5_3_3_2_3_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_2_3_STATE="${RLCH_CIS_5_3_3_2_3_STATE:-/var/lib/rlch/cis/5.3.3.2.3}"
RLCH_CIS_5_3_3_2_3_MARKER='minclass = 4 # rlch-cis-5.3.3.2.3'

# Return 0 for absent, 1 for a value, 2 for malformed/unreadable input.
rlch_5_3_3_2_3_file_value() {
    [[ ! -L "$1" ]] || return 2
    [[ -e "$1" ]] || return 0
    [[ -f "$1" && -r "$1" ]] || return 2
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*minclass([[:space:]]|=|$)/ {
            line=$0; sub(/#.*/, "", line)
            sub(/^[[:space:]]*minclass[[:space:]]*=[[:space:]]*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line !~ /^[0-9]+$/ || length(line) > 9 || line+0 > 4) bad=1
            value=line; count++
        }
        END { if (bad) exit 2; if (!count) exit 0; print value; exit 1 }
    ' "$1"
}

# libpwquality merges vendor and administrator drop-ins by filename, then reads
# the administrator main file, falling back to the vendor main file if absent.
rlch_5_3_3_2_3_effective() {
    local name file value result=0 effective='' main
    local -A files=()
    for file in "$RLCH_CIS_5_3_3_2_3_BASE.d"/*.conf; do
        [[ -e "$file" || -L "$file" ]] || continue
        files["${file##*/}"]="$file"
    done
    for file in "$RLCH_CIS_5_3_3_2_3_CONF.d"/*.conf; do
        [[ -e "$file" || -L "$file" ]] || continue
        files["${file##*/}"]="$file"
    done
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        value="$(rlch_5_3_3_2_3_file_value "${files[$name]}")" || result=$?
        [[ "$result" -ne 2 ]] || return 2
        [[ "$result" -ne 1 ]] || effective="$value"
        result=0
    done < <(printf '%s\n' "${!files[@]}" | LC_ALL=C sort)
    main="$RLCH_CIS_5_3_3_2_3_CONF"
    [[ -e "$main" || -L "$main" ]] || main="$RLCH_CIS_5_3_3_2_3_BASE"
    value="$(rlch_5_3_3_2_3_file_value "$main")" || result=$?
    [[ "$result" -ne 2 ]] || return 2
    [[ "$result" -ne 1 ]] || effective="$value"
    [[ -n "$effective" ]] || return 0
    printf '%s\n' "$effective"
    return 1
}

# Print the count of password hooks using configuration. Inline minclass takes
# precedence; a custom conf= path requires a separately reviewed profile.
rlch_5_3_3_2_3_pam() {
    local file
    for file in system-auth password-auth; do
        [[ -f "$RLCH_CIS_5_3_3_2_3_PAM_DIR/$file" && -r "$RLCH_CIS_5_3_3_2_3_PAM_DIR/$file" ]] || return 2
    done
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*password[[:space:]]+/ && /pam_pwquality\.so([[:space:]]|$)/ {
            sub(/[[:space:]]+#.*/, "")
            sub(/^.*pam_pwquality\.so[[:space:]]*/, "")
            n=split($0, fields, /[[:space:]]+/); found=0
            for (i=1; i<=n; i++) {
                if (fields[i] ~ /^conf=/ || fields[i] == "conf") bad=1
                if (fields[i] == "minclass" || fields[i] ~ /^minclass=/) {
                    found++
                    if (fields[i] !~ /^minclass=[0-9]+$/ || length(fields[i]) > 18) bad=1
                    else { value=fields[i]; sub(/^minclass=/, "", value); if (value+0 > 4) bad=1; else if (value+0 < 4) weak=1 }
                }
            }
            if (found > 1) bad=1
            if (!found) config++
            seen[FILENAME]++
        }
        END {
            if (bad || seen[ARGV[1]] != 1 || seen[ARGV[2]] != 1) exit 2
            if (weak) exit 1
            print config+0
        }
    ' "$RLCH_CIS_5_3_3_2_3_PAM_DIR/system-auth" "$RLCH_CIS_5_3_3_2_3_PAM_DIR/password-auth"
}

check() {
    local pam_result=0 config_result=0 uses_config effective
    "$RLCH_CIS_5_3_3_2_3_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    uses_config="$(rlch_5_3_3_2_3_pam)" || pam_result=$?
    [[ "$pam_result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    effective="$(rlch_5_3_3_2_3_effective)" || config_result=$?
    [[ "$config_result" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$pam_result" -eq 0 ]] || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    if (( uses_config > 0 )); then
        [[ "$config_result" -eq 1 && "$effective" =~ ^[0-9]+$ && "$effective" -eq 4 ]] ||
            return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
}

rlch_5_3_3_2_3_write() {
    local replacement="$1" original="$2" temp
    temp="$(mktemp "${RLCH_CIS_5_3_3_2_3_CONF}.XXXXXX")" || return 1
    if [[ -f "$RLCH_CIS_5_3_3_2_3_CONF" ]]; then
        cp -p --attributes-only "$RLCH_CIS_5_3_3_2_3_CONF" "$temp" || { rm -f "$temp"; return 1; }
        awk -v replacement="$replacement" -v original="$original" '
            $0 == original && original != "" { if (replacement != "") print replacement; next }
            { print }
            END { if (original == "" && replacement != "") print replacement }
        ' "$RLCH_CIS_5_3_3_2_3_CONF" > "$temp" || { rm -f "$temp"; return 1; }
    else
        chmod 0644 "$temp" || { rm -f "$temp"; return 1; }
        printf '%s\n' "$replacement" > "$temp" || { rm -f "$temp"; return 1; }
    fi
    mv -f "$temp" "$RLCH_CIS_5_3_3_2_3_CONF"
}

apply() {
    local result=0 pam=0 config=0 value original='' count=0
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    pam="$(rlch_5_3_3_2_3_pam)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$pam" -eq 2 ]] || { error_message 'CIS 5.3.3.2.3: inline PAM options require a reviewed authselect profile change.'; return "$RLCH_MODULE_RESULT_ERROR"; }
    [[ ! -e "$RLCH_CIS_5_3_3_2_3_STATE" && ! -L "$RLCH_CIS_5_3_3_2_3_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    value="$(rlch_5_3_3_2_3_file_value "$RLCH_CIS_5_3_3_2_3_CONF")" || config=$?
    [[ "$config" -ne 2 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ "$config" -eq 1 ]]; then
        count="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*minclass([[:space:]]|=|$)/ {n++} END {print n+0}' "$RLCH_CIS_5_3_3_2_3_CONF")"
        [[ "$count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
        original="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*minclass([[:space:]]|=|$)/ {print; exit}' "$RLCH_CIS_5_3_3_2_3_CONF")"
    fi
    mkdir -p "$RLCH_CIS_5_3_3_2_3_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_3_3_2_3_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    if [[ -e "$RLCH_CIS_5_3_3_2_3_CONF" ]]; then printf 'present\n' > "$RLCH_CIS_5_3_3_2_3_STATE/file"; else printf 'absent\n' > "$RLCH_CIS_5_3_3_2_3_STATE/file"; fi
    printf '%s\n' "$original" > "$RLCH_CIS_5_3_3_2_3_STATE/original"
    if ! rlch_5_3_3_2_3_write "$RLCH_CIS_5_3_3_2_3_MARKER" "$original"; then
        rm -rf "$RLCH_CIS_5_3_3_2_3_STATE"
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
    [[ -f "$RLCH_CIS_5_3_3_2_3_STATE/file" && -f "$RLCH_CIS_5_3_3_2_3_STATE/original" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -f "$RLCH_CIS_5_3_3_2_3_CONF" && ! -L "$RLCH_CIS_5_3_3_2_3_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(grep -Fxc "$RLCH_CIS_5_3_3_2_3_MARKER" "$RLCH_CIS_5_3_3_2_3_CONF")" || true
    active="$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*minclass([[:space:]]|=|$)/ {n++} END {print n+0}' "$RLCH_CIS_5_3_3_2_3_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$count" -eq 1 && "$active" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    original="$(cat "$RLCH_CIS_5_3_3_2_3_STATE/original")"
    temp="$(mktemp "${RLCH_CIS_5_3_3_2_3_CONF}.XXXXXX")" || return "$RLCH_MODULE_RESULT_ERROR"
    cp -p --attributes-only "$RLCH_CIS_5_3_3_2_3_CONF" "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    awk -v marker="$RLCH_CIS_5_3_3_2_3_MARKER" -v original="$original" '
        $0 == marker { if (original != "") print original; next }
        { print }
    ' "$RLCH_CIS_5_3_3_2_3_CONF" > "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    if [[ "$(cat "$RLCH_CIS_5_3_3_2_3_STATE/file")" == absent && ! -s "$temp" ]]; then
        rm -f "$temp" "$RLCH_CIS_5_3_3_2_3_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    else
        mv -f "$temp" "$RLCH_CIS_5_3_3_2_3_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_3_3_2_3_STATE"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
