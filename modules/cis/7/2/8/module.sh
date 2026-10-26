#!/usr/bin/env bash
# CIS 7.2.8 - Three pinned local rules; bounded proven regex domain.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_8_PASSWD="${RLCH_CIS_7_2_8_PASSWD:-/etc/passwd}"
RLCH_CIS_7_2_8_RPM="${RLCH_CIS_7_2_8_RPM:-/usr/bin/rpm}"

# Private controlled stdin/stdout. No dynamic expression is compiled/executed.
# On ASCII seven-field rows, each supported name is a concatenation of literals
# and single-character dots. Fixed-width comparison is exactly its PCRE meaning.
# The surrounding fixed field separators prevent dots crossing a colon. No name
# can add groups, anchors, quantifiers, escapes, alternations or callouts.
rlch_7_2_8_captures() {
    LC_ALL=C /usr/bin/awk -F '|' '
      function invalid() {bad=1;exit 2}
      function decimal(s) {sub(/^0+/,"",s);return s=="" ? "0" : s}
      function matches(p,s,k,c) {
        if(length(p)!=length(s)) return 0
        for(k=1;k<=length(p);k++){c=substr(p,k,1);if(c!="." && c!=substr(s,k,1)) return 0}
        return 1
      }
      {bytes+=length($0)+1
       if(bytes>4194304 || NR>65536 || NF!=5 || $1!="ROW" || $0 ~ /[^ -~]/ ||
          $2 !~ /^[A-Za-z0-9_.-]+$/ || length($2)>128 || $3 !~ /^[0-9]+$/ || length($3)>32 || length($4)>4096) invalid()
       u=decimal($3);if(length(u)>10 || (length(u)==10 && "x"u>"x4294967294")) invalid()
       names[NR]=$2;uids[NR]=$3;homes[NR]=$4;shells[NR]=$5
       if(length($3)>=4 && $2!="nobody" && $2!="nfsnobody" &&
          $5 !~ /^\/sbin\/nologin/ && $5 !~ /^\/usr\/sbin\/nologin/ &&
          $5 !~ /^\/bin\/false/ && $5 !~ /^\/usr\/bin\/false/ && !patterns["n:"$2]++) patterns_order[++p]=$2
      }
      END {
        if(bad || !NR || p*NR>262144) exit 2
        # Each distinct pattern is an OVAL variable value. Every matching text
        # instance contributes its sole subexpression; overlap is NOT deduped.
        for(i=1;i<=p;i++) for(j=1;j<=NR;j++) if(matches(patterns_order[i],names[j])) {
          if(++total>65536) exit 2
          u=decimal(uids[j]);key="u:"u
          if(!uid_count[key]++) uid_order[++nu]=u
          if(homes[j]!="") {
            nh++;key="h:"homes[j]
            if(!home_seen[key]++) home_order[++nd]=homes[j]
          }
        }
        printf "CAPTURES|%d|%d|%d|%d\n",p,total,nh,nd
        for(i=1;i<=nu;i++) printf "UID|%s|%d\n",uid_order[i],uid_count["u:"uid_order[i]]
        for(i=1;i<=nd;i++) printf "HOME|%d|%s\n",i,home_order[i]
      }' 2>/dev/null
}

# Generic result aggregation. Only existence has a kernel precondition on RHEL;
# ownership/permissions remain applicable. All-NA is supported defensively, but
# is not manufactured from kernel absence by this module.
rlch_7_2_8_result() {
    local code applicable=0 finding=0
    [[ $# -eq 3 ]] || return 2
    for code in "$@"; do
        case "$code" in 0) applicable=1;; 1) applicable=1; finding=1;; 3) :;; *) return 2;; esac
    done
    (( finding==0 )) || return 1
    (( applicable!=0 )) || return 3
    return 0
}

rlch_7_2_8_observe() (
    set +x
    local app=0 after_app=0 before after rows second projection row kind a b extra
    local patterns total wanted distinct uid_total=0 home_total=0 count=0 index mode owner raw
    local exists=0 ownership=0 permissions=0 existing=0 first second_meta result=0
    local -a paths=() evidence=()
    local -A uid_counts=() owner_seen=()
    rlch_rpm_package_status "$RLCH_CIS_7_2_8_RPM" kernel-core 2>/dev/null || app=$?
    [[ "$app" -eq 0 || "$app" -eq 1 ]] || return 2
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_8_PASSWD" 2>/dev/null)" || return 2
    rows="$(rlch_identity_home_rows "$RLCH_CIS_7_2_8_PASSWD")" || return 2
    set -o pipefail
    projection="$(printf '%s\n' "$rows" | rlch_7_2_8_captures)" || return 2
    (( ${#projection}<=8388608 )) || return 2
    row="${projection%%$'\n'*}"
    [[ "$row" =~ ^CAPTURES\|([0-9]{1,5})\|([0-9]{1,5})\|([0-9]{1,5})\|([0-9]{1,5})$ ]] || return 2
    patterns="${BASH_REMATCH[1]}"; total="${BASH_REMATCH[2]}"; wanted="${BASH_REMATCH[3]}"; distinct="${BASH_REMATCH[4]}"
    for a in "$patterns" "$total" "$wanted" "$distinct"; do [[ "$a" =~ ^(0|[1-9][0-9]*)$ ]] || return 2; done
    (( patterns<=65536 && patterns<=total && total<=65536 && wanted<=total && distinct<=wanted )) || return 2
    while IFS= read -r row; do
        count=$((count+1)); (( count<=131073 && ${#row}<=4200 )) || return 2
        [[ "$count" -ne 1 ]] || continue
        IFS='|' read -r kind a b extra <<< "$row"
        [[ -z "$extra" ]] || return 2
        case "$kind" in
            UID)
                [[ "$a" =~ ^(0|[1-9][0-9]{0,9})$ && "$b" =~ ^[1-9][0-9]{0,4}$ ]] || return 2
                (( a<=4294967294 && b<=65536 )) || return 2
                [[ ! ${uid_counts[u:$a]+set} ]] || return 2
                uid_counts["u:$a"]="$b"; uid_total=$((uid_total+b)) ;;
            HOME)
                [[ "$a" =~ ^[1-9][0-9]{0,4}$ && -n "$b" ]] || return 2
                home_total=$((home_total+1)); (( a==home_total && a<=65536 )) || return 2
                paths+=("$b") ;;
            *) return 2 ;;
        esac
    done <<< "$projection"
    (( uid_total==total && home_total==distinct )) || return 2
    for ((index=0;index<${#paths[@]};index++)); do
        first="$(rlch_identity_home_metadata "${paths[index]}")" || return 2
        evidence+=("$first")
        [[ "$first" =~ ^(PRESENT|ABSENT)\|[0-9a-f]{4,8}\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-7]{1,4}\|[0-9]+\|[0-9:.+\ -]+\|[0-9:.+\ -]+$ ]] || return 2
        if [[ "$first" == ABSENT\|* ]]; then continue; fi
        IFS='|' read -r kind raw a b owner extra mode row <<< "$first"
        [[ "$raw" =~ ^[0-9a-f]{4,8}$ && "$owner" =~ ^(0|[1-9][0-9]{0,9})$ && "$mode" =~ ^[0-7]{1,4}$ ]] || return 2
        (( owner<=4294967294 && (16#$raw & 0170000)==0040000 )) || return 2
        existing=$((existing+1))
        # Literal OVAL var_check="only one": keep multiplicity of UID captures.
        [[ "${uid_counts[u:$owner]:-0}" -eq 1 ]] || ownership=1
        [[ ! ${owner_seen[u:$owner]+set} ]] || ownership=1
        owner_seen["u:$owner"]=1
        (( (8#$mode & 07027)==0 )) || permissions=1
    done
    # Validate the complete source again, not a cached projection or count.
    second="$(rlch_identity_home_rows "$RLCH_CIS_7_2_8_PASSWD")" || return 2
    [[ "$rows" == "$second" ]] || return 2
    for ((index=0;index<${#paths[@]};index++)); do
        second_meta="$(rlch_identity_home_metadata "${paths[index]}")" || return 2
        [[ "$second_meta" == "${evidence[index]}" ]] || return 2
    done
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_8_PASSWD" 2>/dev/null)" || return 2
    rlch_rpm_package_status "$RLCH_CIS_7_2_8_RPM" kernel-core 2>/dev/null || after_app=$?
    [[ "$app" -eq "$after_app" && "$before" == "$after" ]] || return 2
    if [[ "$app" -eq 1 ]]; then exists=3
    elif (( wanted!=existing )); then exists=1
    fi
    rlch_7_2_8_result "$exists" "$ownership" "$permissions" || result=$?
    printf 'RULES|%s|%s|%s|%s|%s|%s\n' "$exists" "$ownership" "$permissions" "$wanted" "$distinct" "$existing"
    return "$result"
)
check() (
    set +x
    local result=0 verified=0 data e o p h d m value label text=''
    data="$(rlch_7_2_8_observe)" || result=$?
    if [[ "$result" =~ ^[013]$ && "$data" =~ ^RULES\|[013]\|[01]\|[01]\|[0-9]{1,5}\|[0-9]{1,5}\|[0-9]{1,5}$ ]]; then
        IFS='|' read -r label e o p h d m <<< "$data"
        rlch_7_2_8_result "$e" "$o" "$p" || verified=$?
        [[ "$result" -eq "$verified" ]] || { printf 'CIS 7.2.8: inconsistent subresults; evidence rejected\n' >&2; return 2; }
        for value in "$e" "$o" "$p"; do
            case "$value" in 0) label=SUCCESS;; 1) label=NON_COMPLIANT;; 3) label=NOT_APPLICABLE;; *) return 2;; esac
            text+="${text:+/}$label"
        done
        printf 'CIS 7.2.8: existence/ownership/permissions=%s; home captures=%s distinct=%s existing=%s\n' "$text" "$h" "$d" "$m" >&2
        return "$result"
    fi
    printf 'CIS 7.2.8: existence/ownership/permissions=ERROR/ERROR/ERROR; complete stable supported evidence unavailable\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
)
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.8: manual remediation required; review home configuration and dependencies\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
