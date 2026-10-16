#!/usr/bin/env bash
# Bounded non-secret projections of stable local identity/configuration files.
# SPDX-License-Identifier: MIT
# This library does not assert NSS enumeration completeness or select CIS bases.
# rlch_identity_rows PATH passwd|group|nss => normalized projections on stdout.
# passwd/group: one canonical numeric UID/GID per row (aliases permitted).
# nss: passwd|RAW and group|RAW (exact captures after key/separator).
# Returns 0/2. No raw password, member list, user name or file name is emitted.
# Caller must compare snapshots across the entire evaluation. Limits 4 MiB,
# 65536 lines, 16384 bytes/line. Malformed/empty/ambiguous data fails closed.

rlch_identity_stamp() {
    local file="$1" evidence owner mode
    [[ -f "$file" && ! -L "$file" && -r "$file" ]] || return 2
    # No path aliases or symlink ancestors; names ending in newline are not
    # identity-base paths supported by this API (filesystem walks allow them).
    [[ "$file" == /* && "$file" != *$'\n'* ]] || return 2
    [[ "$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" == "$file" ]] || return 2
    evidence="$(LC_ALL=C /usr/bin/stat -c '%u|%g|%a|%d|%i|%s|%y|%z' -- "$file" 2>/dev/null)" || return 2
    [[ "$evidence" =~ ^[0-9]+\|[0-9]+\|[0-7]{3,4}\| ]] || return 2
    owner="${evidence%%|*}"; mode="${evidence#*|}"; mode="${mode#*|}"; mode="${mode%%|*}"
    [[ "$owner" == 0 || "$owner" == "$(id -u)" ]] || return 2
    (( (8#$mode & 022)==0 && (8#$mode & 0444)!=0 )) || return 2
    printf '%s\n' "$evidence"
}
rlch_identity_stream() { /usr/bin/cat; }
rlch_identity_rows() (
    local file="$1" kind="$2" before opened after fd rows
    case "$kind" in passwd|group|nss) :;; *) return 2;; esac
    before="$(rlch_identity_stamp "$file")" || return 2
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    opened="$(LC_ALL=C /usr/bin/stat -Lc '%u|%g|%a|%d|%i|%s|%y|%z' -- "/proc/self/fd/$fd" 2>/dev/null)" || return 2
    [[ "$before" == "$opened" ]] || return 2
    set -o pipefail
    rows="$(
      {
        { rlch_identity_stream <&"$fd" 2>&1 1>&3 | /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'; } 3>&1 || exit 2
        printf 'RLCH-IDENTITY-END\n'
      } |
      /usr/bin/head -c 4194305 | LC_ALL=C /usr/bin/awk -v kind="$kind" '
      function invalid() {bad=1;exit 2}
      function uint(s) {return s ~ /^[0-9]+$/ && length(s)<=10 && s+0<=4294967294}
      {bytes+=length($0)+1
       if(bytes>4194304 || NR>65537 || length($0)>16384 || ended || index($0,sprintf("%c",0))) invalid()
       if($0=="RLCH-IDENTITY-END") {ended=1;next}
       clean=$0;if(kind=="nss") gsub(/\t/,"",clean)
       if(clean ~ /[[:cntrl:]]/) invalid()
       if(kind=="nss") {
         if($0 ~ /^[[:space:]]*(#|$)/) next
         # Unsupported spelling of either key must not silently disappear.
         line=$0;sub(/^[[:space:]]*/,"",line)
         if(line ~ /^(passwd|group)[[:space:]]*:/) {
           key=line;sub(/[[:space:]]*:.*/,"",key)
           if(line !~ /^(passwd|group):[[:space:]]+[^[:space:]]/ || seen[key]++) invalid()
           sub(/^[^:]+:[[:space:]]+/,"",line)
           if(line ~ /\|/ || length(line)>2048) invalid()
           out[++n]=key "|" line
         }
         next
       }
       count=split($0,f,":")
       if((kind=="passwd" && count!=7) || (kind=="group" && count!=4) ||
          f[1]=="" || f[1] ~ /^[+-]/ || seen[f[1]]++ || !uint(f[3])) invalid()
       if(kind=="passwd" && !uint(f[4])) invalid()
       out[++n]=sprintf("%.0f",f[3]+0)
      }
      END {if(bad || !ended || !n || (kind=="nss" && (!seen["passwd"] || !seen["group"]))) exit 2
           for(i=1;i<=n;i++) print out[i]}'
    )" || return 2
    exec {fd}<&-
    after="$(rlch_identity_stamp "$file")" || return 2
    [[ "$before" == "$after" ]] || return 2
    printf '%s\n' "$rows"
)
