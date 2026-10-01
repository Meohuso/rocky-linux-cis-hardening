#!/usr/bin/env bash
# Safe read-only identity observation. No password/hash leaves this library.
# SPDX-License-Identifier: MIT

rlch_accounts_stamp() {
    local file="$1" canonical mode
    [[ -f "$file" && -r "$file" && ! -L "$file" ]] || return 2
    canonical="$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" || return 2
    [[ "$canonical" == "$file" ]] || return 2
    mode="$(/usr/bin/stat -Lc '%a' -- "$file" 2>/dev/null)" || return 2
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 2
    (( (8#$mode & 0444) != 0 )) || return 2
    /usr/bin/stat -Lc '%d:%i:%s:%y:%z:%a' -- "$file" 2>/dev/null
}

rlch_accounts_rows() {
    local file="$1" kind="$2" before after fd rows result=0
    before="$(rlch_accounts_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%s:%y:%z:%a' -- "/proc/self/fd/$fd" 2>/dev/null)" || after=''
    if [[ "$before" != "$after" ]]; then
        exec {fd}<&-
        return 2
    fi
    rows="$(LC_ALL=C /usr/bin/awk -v kind="$kind" '
        function integer(s) {return s ~ /^[0-9]+$/ && length(s)<=32 && s+0<=4294967294}
        function name(s) {return s ~ /^[a-zA-Z_][a-zA-Z0-9_.-]*$/}
        {clean=$0; if (kind=="login_defs" || kind=="shells") gsub(/\t/, "", clean)
         if (kind=="shadow_shells") gsub(/[\t\r]/, "", clean)
         if (index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/ || $0 ~ /\|/) {bad=1; next}}
        kind=="passwd" {
            count=split($0,f,":")
            if (count!=7 || !name(f[1]) || seen[f[1]]++ || !integer(f[3]) || !integer(f[4])) {bad=1; next}
            out[++n]=f[1] "|" sprintf("%.0f",f[3]+0) "|" (f[2]=="x" ? "shadow" : "other") "|" f[7]
            next
        }
        (kind=="shadow" || kind=="shadow_shells") {
            count=split($0,f,":")
            if (count!=9 || !name(f[1]) || seen[f[1]]++) {bad=1; next}
            for (j=3;j<=8;j++) if (f[j]!="" && f[j]!="-1" && (!integer(f[j]) || f[j]+0>2147483647)) bad=1
            if (f[9]!="" && !integer(f[9])) bad=1
            if (kind=="shadow_shells") out[++n]=f[1] "|" (f[2] ~ /^[ \t\r;*!\\]*$/ ? "locked" : "unlocked")
            else out[++n]=f[1] "|" (f[2] ~ /^[!*]/ ? "locked" : "unlocked")
            next
        }
        kind=="login_defs" {
            if ($0 ~ /^[[:space:]]*(#|$)/) next
            if ($0 ~ /^[[:space:]]*(UID_MIN|SYS_UID_MIN|SYS_UID_MAX)([[:space:]=]|$)/ && $1!="UID_MIN" && $1!="SYS_UID_MIN" && $1!="SYS_UID_MAX") {bad=1; next}
            if ($1=="UID_MIN" || $1=="SYS_UID_MIN" || $1=="SYS_UID_MAX") {
                if (NF!=2 || !integer($2)) {bad=1; next}
                settings[$1]=sprintf("%.0f",$2+0)
            }
            next
        }
        kind=="shells" {
            # CAS collects exact slash-leading lines; no tokenization, trim,
            # executable/existence check or inline-comment normalization.
            if ($0 ~ /^\// && !seen[$0]++) out[++n]=$0
            next
        }
        {bad=1}
        END {
            if (bad || ((kind=="passwd" || kind=="shadow" || kind=="shadow_shells" || kind=="shells") && n==0)) exit 2
            if (kind=="login_defs") {
                keys[1]="UID_MIN"; keys[2]="SYS_UID_MIN"; keys[3]="SYS_UID_MAX"
                for (i=1;i<=3;i++) print keys[i] "|" (keys[i] in settings ? settings[keys[i]] : "unset")
            } else for (i=1;i<=n;i++) print out[i]
        }
    ' <&"$fd" 2>/dev/null)" || result=2
    exec {fd}<&-
    after="$(rlch_accounts_stamp "$file")" || return 2
    [[ "$result" -eq 0 && "$before" == "$after" ]] || return 2
    printf '%s\n' "$rows"
}

# Detect a change to any observed file across the entire multi-file check.
rlch_accounts_fingerprint() {
    local file stamp
    for file in "$@"; do
        stamp="$(rlch_accounts_stamp "$file")" || return 2
        printf '%s\n' "$stamp"
    done
}
