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

rlch_identity_stamp() { _rlch_identity_file_stamp "$1" false; }

# Shared metadata mechanism; allow mode 0000 only for an actually readable
# shadow observation. Existing public stamps retain their readable-bit guard.
_rlch_identity_file_stamp() {
    local file="$1" allow_zero="$2" evidence owner mode
    [[ -f "$file" && ! -L "$file" && -r "$file" ]] || return 2
    # No path aliases or symlink ancestors; names ending in newline are not
    # identity-base paths supported by this API (filesystem walks allow them).
    [[ "$file" == /* && "$file" != *$'\n'* ]] || return 2
    [[ "$(/usr/bin/realpath -e -- "$file" 2>/dev/null)" == "$file" ]] || return 2
    evidence="$(LC_ALL=C /usr/bin/stat -c '%u|%g|%a|%d|%i|%s|%y|%z' -- "$file" 2>/dev/null)" || return 2
    [[ "$evidence" =~ ^[0-9]+\|[0-9]+\|(0|[0-7]{3,4})\| ]] || return 2
    owner="${evidence%%|*}"; mode="${evidence#*|}"; mode="${mode#*|}"; mode="${mode%%|*}"
    [[ "$owner" == 0 || "$owner" == "$(id -u)" ]] || return 2
    (( (8#$mode & 022)==0 )) || return 2
    if (( (8#$mode & 0444)==0 )); then
        [[ "$allow_zero" == true && "$mode" == 0* && $((8#$mode)) -eq 0 ]] || return 2
    fi
    printf '%s\n' "$evidence"
}
rlch_identity_stream() { /usr/bin/cat; }
# Existing public projection contract is unchanged; marker projection is exposed
# only through the dedicated API below.
rlch_identity_rows() {
    case "${2:-}" in passwd|group|nss) :;; *) return 2;; esac
    _rlch_identity_rows "$1" "$2"
}

# PATH => X, STAR or OTHER, one row per validated passwd entry in file order.
# These are literal-field classifications, not password/hash identification or
# compliance decisions. No name, UID, GID or raw second field is returned.
# Same bounds/parser as identity_rows; additionally require one hardlink and
# exact input byte count. All diagnostics suppressed; returns 0/2 only.
rlch_identity_password_markers() {
    [[ $# -eq 1 ]] || return 2
    _rlch_identity_rows "$1" password_markers 2>/dev/null || return 2
}

# PATH => EMPTY/NONEMPTY per validated nine-field shadow record, in order.
# Presence only: no password algorithm/validity/lock or CIS policy inference.
# Same bounds and exact-byte/single-link guards as password_markers. Raw fields
# stay inside awk; diagnostics and partially collected projections are withheld.
rlch_identity_shadow_password_presence() {
    [[ $# -eq 1 ]] || return 2
    _rlch_identity_rows "$1" shadow_presence 2>/dev/null || return 2
}

_rlch_identity_observation_stamp() {
    if [[ "$2" == shadow_presence ]]; then
        _rlch_identity_file_stamp "$1" true
    else
        rlch_identity_stamp "$1"
    fi
}

_rlch_identity_rows() (
    local file="$1" kind="$2" before opened after fd rows expected=0 links=''
    before="$(_rlch_identity_observation_stamp "$file" "$kind")" || return 2
    if [[ "$kind" == password_markers || "$kind" == shadow_presence ]]; then
        links="$(/usr/bin/stat -c '%h' -- "$file" 2>/dev/null)" || return 2
        [[ "$links" == 1 ]] || return 2
        expected="${before#*|}"; expected="${expected#*|}"; expected="${expected#*|}"
        expected="${expected#*|}"; expected="${expected#*|}"; expected="${expected%%|*}"
        [[ "$expected" =~ ^[0-9]+$ && ${#expected} -le 7 ]] || return 2
        (( expected > 0 && expected <= 4194286 )) || return 2
    fi
    { exec {fd}<"$file"; } 2>/dev/null || return 2
    opened="$(LC_ALL=C /usr/bin/stat -Lc '%u|%g|%a|%d|%i|%s|%y|%z' -- "/proc/self/fd/$fd" 2>/dev/null)" || return 2
    [[ "$before" == "$opened" ]] || return 2
    if [[ "$kind" == password_markers || "$kind" == shadow_presence ]]; then
        [[ "$(/usr/bin/stat -Lc '%h' -- "/proc/self/fd/$fd" 2>/dev/null)" == 1 ]] || return 2
    fi
    set -o pipefail
    rows="$(
      {
        { rlch_identity_stream <&"$fd" 2>&1 1>&3 | /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'; } 3>&1 || exit 2
        printf 'RLCH-IDENTITY-END\n'
      } |
      /usr/bin/head -c 4194305 | LC_ALL=C /usr/bin/awk -v kind="$kind" -v expected="$expected" '
      function invalid() {bad=1;exit 2}
      function uint(s) {return s ~ /^[0-9]+$/ && length(s)<=10 && s+0<=4294967294}
      function shadow_number(s,flag,negative,bound) {
        if(s=="") return 1
        if(s !~ /^[+-]?[0-9]+$/) return 0
        negative=(substr(s,1,1)=="-")
        if(flag && negative) return 0
        sub(/^[+-]/,"",s);sub(/^0+/,"",s);if(s=="") s="0"
        bound=(flag ? "18446744073709551615" : (negative ? "9223372036854775808" : "9223372036854775807"))
        return length(s)<length(bound) || (length(s)==length(bound) && "x"s<="x"bound)
      }
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
       if(kind=="shadow_presence") {
         if(count!=9 || f[1]=="" || f[1] ~ /^[+-]/ || seen[f[1]]++) invalid()
         # Structural parsing, not an age policy: optional decimal signed-long
         # fields; do not impose the older account helper UID/day limits here.
         for(j=3;j<=8;j++) if(!shadow_number(f[j],0)) invalid()
         if(!shadow_number(f[9],1)) invalid()
         out[++n]=(length(f[2])==0 ? "EMPTY" : "NONEMPTY")
         next
       }
       if(((kind=="passwd" || kind=="password_markers") && count!=7) || (kind=="group" && count!=4) ||
          f[1]=="" || f[1] ~ /^[+-]/ || seen[f[1]]++ || !uint(f[3])) invalid()
       if((kind=="passwd" || kind=="password_markers") && !uint(f[4])) invalid()
       if(kind=="password_markers") out[++n]=(f[2]=="x" ? "X" : (f[2]=="*" ? "STAR" : "OTHER"))
       else out[++n]=sprintf("%.0f",f[3]+0)
      }
      END {if(bad || !ended || !n || ((kind=="password_markers" || kind=="shadow_presence") && bytes-18!=expected) || (kind=="nss" && (!seen["passwd"] || !seen["group"]))) exit 2
           for(i=1;i<=n;i++) print out[i]}'
    )" || return 2
    exec {fd}<&-
    after="$(_rlch_identity_observation_stamp "$file" "$kind")" || return 2
    [[ "$before" == "$after" ]] || return 2
    if [[ "$kind" == password_markers || "$kind" == shadow_presence ]]; then
        [[ "$(/usr/bin/stat -c '%h' -- "$file" 2>/dev/null)" == 1 ]] || return 2
    fi
    printf '%s\n' "$rows"
)
