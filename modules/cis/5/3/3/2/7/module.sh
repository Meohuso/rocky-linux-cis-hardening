#!/usr/bin/env bash
# CIS 5.3.3.2.7 - Explicit administrator enforce_for_root flag.
# SPDX-License-Identifier: MIT

RLCH_CIS_5_3_3_2_7_CONF="${RLCH_CIS_5_3_3_2_7_CONF:-/etc/security/pwquality.conf}"
RLCH_CIS_5_3_3_2_7_BASE="${RLCH_CIS_5_3_3_2_7_BASE:-/usr/lib/security/pwquality.conf}"
RLCH_CIS_5_3_3_2_7_PAM_DIR="${RLCH_CIS_5_3_3_2_7_PAM_DIR:-/etc/pam.d}"
RLCH_CIS_5_3_3_2_7_AUTHSELECT="${RLCH_CIS_5_3_3_2_7_AUTHSELECT:-authselect}"
RLCH_CIS_5_3_3_2_7_STATE="${RLCH_CIS_5_3_3_2_7_STATE:-/var/lib/rlch/cis/5.3.3.2.7}"
RLCH_CIS_5_3_3_2_7_TAG='# rlch-cis-5.3.3.2.7 managed directive'

# Output canonical occurrence count; return 2 on a misleading or unsafe form.
# libpwquality treats even enforce_for_root=0 as SET, not as a false value.
rlch_5_3_3_2_7_scan() {
    local path="$1"
    [[ ! -L "$path" ]] || return 2
    [[ -e "$path" ]] || { printf '0\n'; return 0; }
    [[ -f "$path" && -r "$path" ]] || return 2
    awk '
        { line=$0; sub(/#.*/, "", line)
          if (line ~ /^[[:space:]]*enforce_for_root([[:space:]]|=|$)/) {
              if (line !~ /^[[:space:]]*enforce_for_root[[:space:]]*$/) bad=1
              else count++
          }
        }
        END { if (bad) exit 2; print count+0 }
    ' "$path"
}

# Inspect all files that libpwquality would read, including vendor files hidden
# by an administrator drop-in with the same basename. Require an /etc witness.
rlch_5_3_3_2_7_config() {
    local path name count admin=0 runtime=0
    local -A files=()
    for path in "$RLCH_CIS_5_3_3_2_7_BASE.d"/*.conf; do
        [[ -e "$path" || -L "$path" ]] || continue
        files["${path##*/}"]="$path"
    done
    for path in "$RLCH_CIS_5_3_3_2_7_CONF.d"/*.conf; do
        [[ -e "$path" || -L "$path" ]] || continue
        files["${path##*/}"]="$path"
    done
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        path="${files[$name]}"
        count="$(rlch_5_3_3_2_7_scan "$path")" || return 2
        (( runtime += count ))
        [[ "$path" != "$RLCH_CIS_5_3_3_2_7_CONF.d/"* ]] || (( admin += count ))
    done < <(printf '%s\n' "${!files[@]}" | LC_ALL=C sort)
    path="$RLCH_CIS_5_3_3_2_7_CONF"
    [[ -e "$path" || -L "$path" ]] || path="$RLCH_CIS_5_3_3_2_7_BASE"
    count="$(rlch_5_3_3_2_7_scan "$path")" || return 2
    (( runtime += count ))
    [[ "$path" != "$RLCH_CIS_5_3_3_2_7_CONF" ]] || (( admin += count ))
    # Vendor-only SET is runtime active, but lacks an administrator CIS witness.
    (( runtime > 0 && admin > 0 ))
}

rlch_5_3_3_2_7_pam() {
    local file
    for file in system-auth password-auth; do
        [[ -f "$RLCH_CIS_5_3_3_2_7_PAM_DIR/$file" && -r "$RLCH_CIS_5_3_3_2_7_PAM_DIR/$file" ]] || return 2
    done
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*password[[:space:]]+/ && /pam_pwquality\.so([[:space:]]|$)/ {
            sub(/[[:space:]]+#.*/, "")
            sub(/^.*pam_pwquality\.so[[:space:]]*/, "")
            n=split($0, fields, /[[:space:]]+/)
            for (i=1; i<=n; i++) {
                if (fields[i] ~ /^conf=/ || fields[i] == "conf" ||
                    fields[i] ~ /^enforce_for_root=/) bad=1
            }
            seen[FILENAME]++
        }
        END {if (bad || seen[ARGV[1]] != 1 || seen[ARGV[2]] != 1) exit 2}
    ' "$RLCH_CIS_5_3_3_2_7_PAM_DIR/system-auth" "$RLCH_CIS_5_3_3_2_7_PAM_DIR/password-auth"
}

check() {
    "$RLCH_CIS_5_3_3_2_7_AUTHSELECT" check >/dev/null 2>&1 || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_5_3_3_2_7_pam || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_5_3_3_2_7_config && return "$RLCH_MODULE_RESULT_SUCCESS"
    case $? in
        1) return "$RLCH_MODULE_RESULT_NON_COMPLIANT" ;;
        *) return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}

rlch_5_3_3_2_7_append() {
    local temp
    temp="$(mktemp "${RLCH_CIS_5_3_3_2_7_CONF}.XXXXXX")" || return 1
    if [[ -e "$RLCH_CIS_5_3_3_2_7_CONF" ]]; then
        cp -p "$RLCH_CIS_5_3_3_2_7_CONF" "$temp" || { rm -f "$temp"; return 1; }
        [[ ! -s "$temp" || "$(tail -c 1 "$temp" | wc -l)" -eq 1 ]] || printf '\n' >> "$temp"
    else
        chmod 0644 "$temp" || { rm -f "$temp"; return 1; }
    fi
    printf '%s\nenforce_for_root\n' "$RLCH_CIS_5_3_3_2_7_TAG" >> "$temp" || { rm -f "$temp"; return 1; }
    mv -f "$temp" "$RLCH_CIS_5_3_3_2_7_CONF"
}

apply() {
    local result=0 present count
    check || result=$?
    [[ "$result" -ne "$RLCH_MODULE_RESULT_SUCCESS" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$result" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    [[ ! -e "$RLCH_CIS_5_3_3_2_7_STATE" && ! -L "$RLCH_CIS_5_3_3_2_7_STATE" && ! -L "$RLCH_CIS_5_3_3_2_7_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(rlch_5_3_3_2_7_scan "$RLCH_CIS_5_3_3_2_7_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$count" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    # Appending to a file without a final newline would make an exact, isolated
    # rollback ambiguous; request administrator review rather than alter it.
    if [[ -s "$RLCH_CIS_5_3_3_2_7_CONF" && "$(tail -c 1 "$RLCH_CIS_5_3_3_2_7_CONF" | wc -l)" -ne 1 ]]; then
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ ! -e "$RLCH_CIS_5_3_3_2_7_CONF" ]] && present=absent || present=present
    mkdir -p "$RLCH_CIS_5_3_3_2_7_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    chmod 0700 "$RLCH_CIS_5_3_3_2_7_STATE" || return "$RLCH_MODULE_RESULT_ERROR"
    printf '%s\n' "$present" > "$RLCH_CIS_5_3_3_2_7_STATE/file" || return "$RLCH_MODULE_RESULT_ERROR"
    if ! rlch_5_3_3_2_7_append; then
        rm -rf "$RLCH_CIS_5_3_3_2_7_STATE"
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
    [[ -f "$RLCH_CIS_5_3_3_2_7_STATE/file" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ -f "$RLCH_CIS_5_3_3_2_7_CONF" && ! -L "$RLCH_CIS_5_3_3_2_7_CONF" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    count="$(awk -v tag="$RLCH_CIS_5_3_3_2_7_TAG" '
        $0==tag && (getline line)>0 && line=="enforce_for_root" {n++}
        END {print n+0}
    ' "$RLCH_CIS_5_3_3_2_7_CONF")" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$count" -eq 1 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    temp="$(mktemp "${RLCH_CIS_5_3_3_2_7_CONF}.XXXXXX")" || return "$RLCH_MODULE_RESULT_ERROR"
    cp -p --attributes-only "$RLCH_CIS_5_3_3_2_7_CONF" "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    awk -v tag="$RLCH_CIS_5_3_3_2_7_TAG" '
        $0==tag {if ((getline line)>0 && line=="enforce_for_root") next; print; print line; next}
        {print}
    ' "$RLCH_CIS_5_3_3_2_7_CONF" > "$temp" || { rm -f "$temp"; return "$RLCH_MODULE_RESULT_ERROR"; }
    if [[ "$(cat "$RLCH_CIS_5_3_3_2_7_STATE/file")" == absent && ! -s "$temp" ]]; then
        rm -f "$temp" "$RLCH_CIS_5_3_3_2_7_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    else
        mv -f "$temp" "$RLCH_CIS_5_3_3_2_7_CONF" || return "$RLCH_MODULE_RESULT_ERROR"
    fi
    rm -rf "$RLCH_CIS_5_3_3_2_7_STATE"
    return "$RLCH_MODULE_RESULT_CHANGED"
}
