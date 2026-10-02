#!/usr/bin/env bash
# shellcheck disable=SC2034 # Public inventories are consumed by the CIS module.
# Static RHEL9 CAS cron audit; never execute a scheduler or AIDE.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/aide_observation.sh
source "${BASH_SOURCE[0]%/*}/aide_observation.sh"

rlch_aide_cron_access() {
    local file="$1" owner mode
    rlch_tmout_file_stamp "$file" >/dev/null || return 2
    owner="$(/usr/bin/stat -Lc '%u' -- "$file")" || return 2
    mode="$(/usr/bin/stat -Lc '%a' -- "$file")" || return 2
    [[ "$owner" == 0 || "$owner" == "$EUID" ]] || return 2
    (( (8#$mode & 0022) == 0 )) || return 2
}

# Inventory all CAS locations; only this control's verified private journal is
# excluded. An unsafe entry cannot be hidden by a good entry in another file.
rlch_aide_cron_inventory() {
    local fixed_system="$1" fixed_root="$2" cron_d="$3" daily="$4" weekly="$5" state="$6" file dir stamp
    for file in "$fixed_system" "$fixed_root" "$cron_d" "$daily" "$weekly" "$state"; do
        [[ "$file" == /* && "$file" != *[[:cntrl:]\|]* ]] || return 2
    done
    RLCH_AIDE_CRON_FILES=(); RLCH_AIDE_CRON_KINDS=()
    for file in "$fixed_system" "$fixed_root"; do
        if [[ -e "$file" || -L "$file" ]]; then
            rlch_aide_cron_access "$file" || return 2
            stamp="$(rlch_tmout_file_stamp "$file")" || return 2
            RLCH_AIDE_CRON_FILES+=("$file")
            if [[ "$file" == "$fixed_system" ]]; then RLCH_AIDE_CRON_KINDS+=(system); else RLCH_AIDE_CRON_KINDS+=(root); fi
        else stamp="$(rlch_aide_absent_stamp "$file")" || return 2
        fi
        printf '%s|%s\n' "$file" "$stamp"
    done
    for dir in "$cron_d" "$daily" "$weekly"; do
        if [[ ! -e "$dir" && ! -L "$dir" ]]; then
            stamp="$(rlch_aide_absent_stamp "$dir")" || return 2
            printf '%s|%s\n' "$dir" "$stamp"; continue
        fi
        rlch_tmout_writable_directory "$dir" || return 2
        stamp="$(rlch_tmout_directory "$dir")" || return 2
        printf '%s|%s\n' "$dir" "$stamp"
        for file in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
            [[ -e "$file" || -L "$file" ]] || continue
            [[ "$file" != *[[:cntrl:]\|]* ]] || return 2
            if [[ "$dir" == "$cron_d" && "$file" == "$state" ]]; then
                rlch_tmout_writable_directory "$state" || return 2
                [[ "$(/usr/bin/stat -Lc '%a' -- "$state")" == 700 ]] || return 2
                continue
            fi
            rlch_aide_cron_access "$file" || return 2
            stamp="$(rlch_tmout_file_stamp "$file")" || return 2
            printf '%s|%s\n' "$file" "$stamp"
            RLCH_AIDE_CRON_FILES+=("$file")
            if [[ "$dir" == "$cron_d" ]]; then RLCH_AIDE_CRON_KINDS+=(system); else RLCH_AIDE_CRON_KINDS+=(script); fi
        done
    done
}

# Returns recognized count|AIDE activity; all parsing is inert and redacted.
# Temporal regex mirrors CAS, with additional syntax/range/command safeguards.
rlch_aide_cron_scan() {
    local file="$1" kind="$2" before after fd rows result=0 mode name
    before="$(rlch_tmout_file_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    after="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%s:%y:%z' -- "/proc/self/fd/$fd")" || after=''
    if [[ "$before" != "$after" ]]; then exec {fd}<&-; return 2; fi
    rows="$(LC_ALL=C /usr/bin/awk -v kind="$kind" '
        function validnum(v,max) {return v ~ /^[0-9]+$/ && length(v)<=2 && v+0<=max}
        function fieldnumber(v,days) {
            if(days) {
                if(v=="sun") return 0;if(v=="mon") return 1;if(v=="tue") return 2
                if(v=="wed") return 3;if(v=="thu") return 4;if(v=="fri") return 5;if(v=="sat") return 6
            }
            if(v ~ /^[0-9]+$/ && length(v)<=2) return v+0
            return -1
        }
        function validfield(v,low,high,days, a,b,c,n,i,k,start,finish) {
            n=split(v,a,",")
            for(i=1;i<=n;i++) {
                k=split(a[i],b,"/")
                if(k<1 || k>2 || (k==2 && (b[2] !~ /^[0-9]+$/ || length(b[2])>4 || b[2]+0<1))) return 0
                if(b[1]=="*") continue
                k=split(b[1],c,"-");if(k<1 || k>2) return 0
                start=fieldnumber(c[1],days);if(start<low || start>high) return 0
                if(k==2) {finish=fieldnumber(c[2],days);if(finish<start || finish>high) return 0}
            }
            return n>0
        }
        function goodday(v, a,n) {
            if (v=="*" || v ~ /^[0-7]$/ || v ~ /^(mon|tue|wed|thu|fri|sat|sun)$/) return 1
            if (v ~ /^[0-7]-[0-7]$/) {split(v,a,"-");return a[1]<=a[2]}
            return 0
        }
        {clean=$0;gsub(/\t/,"",clean);if (index($0,sprintf("%c",0)) || clean ~ /[[:cntrl:]]/) {bad=1;next}}
        /^[[:space:]]*(#|$)/ {next}
        /^[A-Z_][A-Z_0-9]*[[:space:]]*=/ {
            if (kind=="script") {other=1;next}
            if (/^SHELL[[:space:]]*=/ && $0 !~ /^SHELL[[:space:]]*=[[:space:]]*\/bin\/(ba)?sh[[:space:]]*$/) bad=1
            if ($0 !~ /^(MAILTO|MAILFROM|HOME|PATH|SHELL|CRON_TZ|RANDOM_DELAY)[[:space:]]*=/) bad=1
            # Dynamic environment evaluation is outside this literal audit.
            if (/[$`]/) bad=1
            next
        }
        {
            line=$0
            if (line !~ /aide/) {if (kind=="script") other=1;next}
            active++
            if (kind=="script") {
                if (line ~ /^(\/usr\/bin\/nice[[:space:]]+)?(\/usr\/bin\/ionice[[:space:]]+)?\/usr\/sbin\/aide[[:space:]]+--check[[:space:]]*$/) found++
                else bad=1
                next
            }
            leading=(line ~ /^[[:space:]]/)
            sub(/^[[:space:]]+/,"",line)
            n=split(line,fields,/[[:space:]]+/);pos=0;frequency=0
            if (fields[1] ~ /^@/) {
                if (fields[1] !~ /^@(hourly|daily|weekly|monthly|annually|yearly|reboot)$/) {bad=1;next}
                frequency=(fields[1] ~ /^@(hourly|daily|weekly)$/);pos=2
            } else {
                if (n<6) {bad=1;next}
                # Safe simple numeric fields; valid CAS-excluded steps/lists
                # remain noncompliant instead of silently broadening CAS.
                for(i=1;i<=5;i++) if(fields[i] !~ /^([0-9*,\/-]+|mon|tue|wed|thu|fri|sat|sun)$/) bad=1
                if (fields[1] ~ /^[0-9]+$/ && !validnum(fields[1],59)) bad=1
                if (fields[2] ~ /^[0-9]+$/ && !validnum(fields[2],23)) bad=1
                if (fields[3] ~ /^[0-9]+$/ && (!validnum(fields[3],31) || fields[3]+0<1)) bad=1
                if (fields[4] ~ /^[0-9]+$/ && (!validnum(fields[4],12) || fields[4]+0<1)) bad=1
                if (fields[5] ~ /^[0-9]+$/ && !validnum(fields[5],7)) bad=1
                if (fields[5] ~ /^[0-7]-[0-7]$/ && !goodday(fields[5])) bad=1
                if(!validfield(fields[1],0,59,0) || !validfield(fields[2],0,23,0) || !validfield(fields[3],1,31,0) || !validfield(fields[4],1,12,0) || !validfield(fields[5],0,7,1)) bad=1
                frequency=(validnum(fields[1],59) && validnum(fields[2],23) && fields[3]=="*" && fields[4]=="*" && goodday(fields[5]));pos=6
            }
            userok=1
            if(kind=="system") {userok=(fields[pos]=="root");pos++}
            else if(fields[pos]=="root") {bad=1;next} # OVAL permits an invalid extra root token.
            command="";for(i=pos;i<=n;i++) command=command (i==pos ? "" : " ") fields[i]
            if(command ~ /^\/[^[:space:]]*aide[[:space:]]+--(check|version)$/ && command !~ /^\/usr\/sbin\/aide /) next
            if(command=="/usr/sbin/aide --version") next
            if(command !~ /^\/usr\/sbin\/aide --check([[:space:]]*|[[:space:]]+&>[[:space:]]*\/dev\/null[[:space:]]*|[[:space:]]+>[[:space:]]*\/dev\/null[[:space:]]+2>&1[[:space:]]*|[[:space:]]+#.*)$/) {bad=1;next}
            if(frequency && userok && !leading) found++
        }
        END {if(bad || (kind=="script" && active && other)) exit 2;print found+0 "|" active+0}
    ' <&"$fd" 2>/dev/null)" || result=2
    exec {fd}<&-
    after="$(rlch_tmout_file_stamp "$file")" || return 2
    [[ "$result" -eq 0 && "$before" == "$after" ]] || return 2
    if [[ "${rows#*|}" -ne 0 ]]; then
        name="${file##*/}"
        # cron.d/run-parts names must be runnable, not just a CAS filename match.
        if [[ "$kind" != root && "$name" != crontab && ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then return 2; fi
        if [[ "$kind" == script ]]; then
            mode="$(/usr/bin/stat -Lc '%a' -- "$file")" || return 2
            if [[ ! -x "$file" ]] || (( (8#$mode & 0111) == 0 )); then return 2; fi
            # A directly executed run-parts script needs an approved interpreter.
            IFS= read -r name < "$file" || return 2
            [[ "$name" == '#!/bin/sh' || "$name" == '#!/bin/bash' ]] || return 2
        else
            [[ "$(/usr/bin/tail -c 1 -- "$file" | /usr/bin/od -An -tu1)" =~ 10[[:space:]]*$ ]] || return 2
        fi
    fi
    printf '%s\n' "$rows"
}

# Separate hook permits unprivileged fixture tests; production uses root:root.
rlch_aide_cron_set_owner() { /usr/bin/chown 0:0 -- "$1"; }

# Ensure pathnames still designate the directories held by this transaction.
rlch_aide_cron_attached() {
    local directory="$1" directory_fd="$2" state="$3" state_fd="$4" path_stamp fd_stamp
    path_stamp="$(rlch_tmout_directory "$directory")" || return 2
    fd_stamp="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "/proc/self/fd/$directory_fd")" || return 2
    [[ "$path_stamp" == "$fd_stamp" ]] || return 2
    path_stamp="$(rlch_tmout_directory "$state")" || return 2
    fd_stamp="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "/proc/self/fd/$state_fd")" || return 2
    [[ "$path_stamp" == "$fd_stamp" ]] || return 2
}
