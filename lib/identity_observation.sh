#!/usr/bin/env bash
# Bounded projections of stable local identity/configuration files.
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

# PATH passwd|group => NAME_PRESENT|FIELD2_PRESENT|UID_KIND|GID_LITERAL.
# Presence tokens: EMPTY/PRESENT. UID_KIND: DECIMAL/OTHER (passwd), NA (group).
# GID_LITERAL: exact ASCII decimal spelling, or NONE for a nondecimal field.
# Seven/four-field records only; retain duplicates and aliases. Numeric ranges,
# name policy and capture selection are deliberately not inferred by this API.
# No names, UID values, credential fields or member lists leave the parser.
# Strict single-link/exact-byte guards; 0/2, diagnostics suppressed.
rlch_identity_gid_fields() {
    [[ $# -eq 2 ]] || return 2
    case "$2" in
        passwd) _rlch_identity_rows "$1" gid_passwd 2>/dev/null || return 2 ;;
        group) _rlch_identity_rows "$1" gid_group 2>/dev/null || return 2 ;;
        *) return 2 ;;
    esac
}

# PASSWD_PATH NSS_PATH => SOURCE|FILES or SOURCE|OTHER, then UID|DECIMAL.
# Each UID is canonical decimal in 0..4294967294; duplicates are retained.
# Source classification describes the explicit passwd database declaration:
# FILES means the single token files, optionally followed by a comment. Other
# valid nonempty declarations are OTHER; no CIS result is decided here.
# Exact-byte/single-link guards apply to BOTH sources. No credential/name/raw
# NSS configuration is emitted. No partial projection on read/parse failure.
# Caller must bracket/compare complete observations; no inter-file transaction.
rlch_identity_uid_values() {
    [[ $# -eq 2 ]] || return 2
    local sources values
    sources="$(_rlch_identity_rows "$2" uid_sources 2>/dev/null)" || return 2
    values="$(_rlch_identity_rows "$1" uid_values 2>/dev/null)" || return 2
    printf '%s\n%s\n' "$sources" "$values" || return 2
}

# PASSWD_PATH => NAME|LITERAL or SKIP per supported seven-field source row.
# NAME contains the exact nonempty first field, including case/spaces/pipes;
# SKIP is an empty first field, not selected by ^([^:]+):.*$. No UID/GID/shell
# or name-policy filters. Preserve all instances and duplicates in input order.
# Controlled stdout contains names ONLY; no authentication/other fields. Never
# log it. A subshell disables xtrace without changing the caller. Strict UTF-8,
# single-link/exact-byte reads; no projection on read/parse/stability failure.
# 0 complete observation, 2 error; diagnostics suppressed. Caller must check
# status (output-device failure is not transactional) and compare snapshots.
rlch_identity_user_names() (
    set +x
    [[ $# -eq 1 ]] || return 2
    _rlch_identity_rows "$1" user_names 2>/dev/null || return 2
)

# GROUP_PATH => COUNTS|SELECTED|DISTINCT after a complete stable observation.
# Exact ^(.+):.+ captures stay inside awk, including any authentication fields.
# No field-count/name/GID policy: nonmatching supported text rows are ignored.
# Greedy capture ends before the rightmost colon with nonempty text on BOTH
# sides. On valid UTF-8 LF-delimited control-free text this reproduces the
# pinned textfilecontent54 pattern, without normalization or numeric coercion.
# Strict byte/link/descriptor/metadata guards and existing bounds apply. Empty
# files are unsupported; a nonempty unselected source returns COUNTS|0|0.
# Return 0 only for complete counts (duplicates valid), 2 otherwise, with no
# diagnostic/partial counts. Caller checks status, brackets observations and
# decides empty-collection policy. Output-device failure is not transactional.
# A private subshell disables xtrace and preserves the caller tracing state.
rlch_identity_group_name_counts() (
    set +x
    [[ $# -eq 1 ]] || return 2
    _rlch_identity_rows "$1" group_name_counts 2>/dev/null || return 2
)

_rlch_identity_observation_stamp() {
    if [[ "$2" == shadow_presence ]]; then
        _rlch_identity_file_stamp "$1" true
    else
        rlch_identity_stamp "$1"
    fi
}

_rlch_identity_rows() (
    local file="$1" kind="$2" before opened after fd rows expected=0 links='' strict=0
    case "$kind" in password_markers|shadow_presence|gid_passwd|gid_group|uid_values|uid_sources|user_names|group_name_counts) strict=1;; esac
    before="$(_rlch_identity_observation_stamp "$file" "$kind")" || return 2
    if [[ "$strict" -eq 1 ]]; then
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
    if [[ "$strict" -eq 1 ]]; then
        [[ "$(/usr/bin/stat -Lc '%h' -- "/proc/self/fd/$fd" 2>/dev/null)" == 1 ]] || return 2
    fi
    set -o pipefail
    rows="$(
      {
        { rlch_identity_stream <&"$fd" 2>&1 1>&3 | /usr/bin/head -c 1 | /usr/bin/awk 'NR {exit 2}'; } 3>&1 || exit 2
        printf 'RLCH-IDENTITY-END\n'
      } |
      /usr/bin/head -c 4194305 | LC_ALL=C /usr/bin/awk -v kind="$kind" -v expected="$expected" -v strict="$strict" '
      function invalid() {bad=1;exit 2}
      function uint(s) {return s ~ /^[0-9]+$/ && length(s)<=10 && s+0<=4294967294}
      # Additive text capture modes validate UTF-8, matching the text probe
      # encoding domain without normalizing captured code points or bytes.
      function name_utf8(s,i,b,c,need,j,lo,hi) {
        for(i=1;i<=length(s);i++) {
          b=octet[substr(s,i,1)];if(b<128) continue
          lo=128;hi=191
          if(b>=194 && b<=223) need=1
          else if(b>=224 && b<=239) {need=2;if(b==224) lo=160;if(b==237) hi=159}
          else if(b>=240 && b<=244) {need=3;if(b==240) lo=144;if(b==244) hi=143}
          else return 0
          if(i+need>length(s)) return 0
          c=octet[substr(s,++i,1)];if(c<lo || c>hi) return 0
          for(j=1;j<need;j++) {c=octet[substr(s,++i,1)];if(c<128 || c>191) return 0}
        }
        return 1
      }
      BEGIN {if(kind=="user_names" || kind=="group_name_counts") for(i=1;i<256;i++) octet[sprintf("%c",i)]=i}
      function uid_decimal(s) {
        if(s !~ /^[0-9]+$/) return "INVALID"
        sub(/^0+/,"",s);if(s=="") s="0"
        if(length(s)>10 || (length(s)==10 && "x"s>"x4294967294")) return "INVALID"
        return s
      }
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
       clean=$0;if(kind=="nss" || kind=="uid_sources") gsub(/\t/,"",clean)
       if(clean ~ /[[:cntrl:]]/) invalid()
       if(kind=="uid_sources") {
         if($0 ~ /^[[:space:]]*(#|$)/) next
         line=$0;sub(/^[[:space:]]*/,"",line)
         if(line ~ /^passwd([[:space:]:]|$)/) {
           if(line !~ /^passwd:/ || seen["passwd"]++) invalid()
           sub(/^passwd:[[:space:]]*/,"",line);sub(/#.*/,"",line)
           sub(/[[:space:]]*$/,"",line)
           if(line=="") invalid()
           out[++n]=(line=="files" ? "SOURCE|FILES" : "SOURCE|OTHER")
         }
         next
       }
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
       if(kind=="group_name_counts") {
         if(!name_utf8($0)) invalid()
         n++
         # No POSIX submatch ambiguity: rightmost eligible literal colon.
         # Byte offsets are safe here: ASCII colon cannot occur in a UTF-8
         # continuation sequence. Exclude the first and final byte positions.
         for(p=length($0)-1;p>=2;p--) if(substr($0,p,1)==":") {
           capture=substr($0,1,p-1);selected++
           if(!captures["capture:" capture]++) distinct++
           break
         }
         next
       }
       count=split($0,f,":")
       if(kind=="user_names") {
         if(count!=7 || !name_utf8($0)) invalid()
         out[++n]=(length(f[1]) ? "NAME|" f[1] : "SKIP")
         next
       }
       if(kind=="uid_values") {
         # Native files enumeration skips leading whitespace, blank lines and
         # comments before parsing accounts. Controls remain unsupported above.
         line=$0;sub(/^[[:space:]]*/,"",line)
         if(line ~ /^(#|$)/) next
         count=split(line,f,":")
         if(count!=7 || f[1]=="" || f[1] ~ /^[+-]/ || seen[f[1]]++) invalid()
         uid=uid_decimal(f[3]);gid=uid_decimal(f[4])
         if(uid=="INVALID" || gid=="INVALID") invalid()
         out[++n]="UID|" uid
         next
       }
       if(kind=="gid_passwd" || kind=="gid_group") {
         if((kind=="gid_passwd" && count!=7) || (kind=="gid_group" && count!=4)) invalid()
         name_present=(length(f[1]) ? "PRESENT" : "EMPTY")
         field2_present=(length(f[2]) ? "PRESENT" : "EMPTY")
         uid_kind=(kind=="gid_group" ? "NA" : (f[3] ~ /^[0-9]+$/ ? "DECIMAL" : "OTHER"))
         gid=(kind=="gid_group" ? f[3] : f[4])
         out[++n]=name_present "|" field2_present "|" uid_kind "|" (gid ~ /^[0-9]+$/ ? gid : "NONE")
         next
       }
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
      END {if(bad || !ended || !n || (strict && bytes-18!=expected) || (kind=="nss" && (!seen["passwd"] || !seen["group"]))) exit 2
           if(kind=="group_name_counts") printf "COUNTS|%d|%d\n",selected,distinct
           else for(i=1;i<=n;i++) print out[i]}'
    )" || return 2
    exec {fd}<&-
    after="$(_rlch_identity_observation_stamp "$file" "$kind")" || return 2
    [[ "$before" == "$after" ]] || return 2
    if [[ "$strict" -eq 1 ]]; then
        [[ "$(/usr/bin/stat -c '%h' -- "$file" 2>/dev/null)" == 1 ]] || return 2
    fi
    printf '%s\n' "$rows"
)
