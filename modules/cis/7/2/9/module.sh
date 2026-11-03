#!/usr/bin/env bash
# CIS 7.2.9 - Six pinned rules and the explicitly approved history complement.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/filesystem_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/filesystem_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_9_PASSWD="${RLCH_CIS_7_2_9_PASSWD:-/etc/passwd}"
RLCH_CIS_7_2_9_NSS="${RLCH_CIS_7_2_9_NSS:-/etc/nsswitch.conf}"
RLCH_CIS_7_2_9_RPM="${RLCH_CIS_7_2_9_RPM:-/usr/bin/rpm}"
RLCH_CIS_7_2_9_MOUNTINFO="${RLCH_CIS_7_2_9_MOUNTINFO:-/proc/self/mountinfo}"
RLCH_CIS_7_2_9_HOME="${RLCH_CIS_7_2_9_HOME:-/home}"
RLCH_CIS_7_2_9_ROOT="${RLCH_CIS_7_2_9_ROOT:-/root}"
RLCH_CIS_7_2_9_ETC="${RLCH_CIS_7_2_9_ETC:-/etc}"

# Controlled internal projections only. The local dynamic-name fragment is the
# proven fixed-width ASCII domain used by CIS 7.2.8: literals plus dot wildcard;
# no injected group or other PCRE construction can pass home_rows validation.
# NSS selection instead uses numeric UID>=1000 and EXACT shell exclusions.
rlch_729_populations() {
    LC_ALL=C /usr/bin/awk -F '|' '
      function bad(){invalid=1;exit 2}
      function dec(s){sub(/^0+/,"",s);return s==""?"0":s}
      function integer(s,t){t=dec(s);return s~/^[0-9]+$/ && length(s)<=32 && (length(t)<10 || (length(t)==10 && "x"t<="x4294967294"))}
      function matches(p,s,k,c){if(length(p)!=length(s))return 0;for(k=1;k<=length(p);k++){c=substr(p,k,1);if(c!="." && c!=substr(s,k,1))return 0}return 1}
      $1=="ROW" {
        if(NF!=5 || $2!~/^[A-Za-z0-9_.-]+$/ || length($2)>128 || !integer($3) || length($4)>4096 || $0~/[^ -~]/)bad()
        if(++n>65536)bad();name[n]=$2;uid[n]=$3;home[n]=$4;shell[n]=$5
        if(length($3)>=4 && $2!="nobody" && $2!="nfsnobody" && $5!~/^(\/usr)?(\/sbin\/nologin|\/bin\/false)/ && !pattern_seen["n:"$2]++)pattern[++np]=$2
        next
      }
      $1=="PRESENT" {
        if(NF!=4 || $3!="DECIMAL" || !integer($4) || ++ng>65536)bad()
        gid[ng]=$4;next
      }
      {bad()}
      END {
        if(invalid || !n || n!=ng || np*n>262144)exit 2
        for(i=1;i<=np;i++)for(j=1;j<=n;j++)if(matches(pattern[i],name[j])) {
          if(++captures>65536)exit 2
          u=dec(uid[j]);g=dec(gid[j]);uc["u:"u]++
          if(!us["u:"u]++)uo[++nu]=u
          # OVAL unique operates on captured TEXT before integer comparison.
          # Retain the number of distinct spellings matching each numeric GID.
          if(!gs["raw:"gid[j]]++) {
            gc["g:"g]++
            if(!gn["g:"g]++)go[++nq]=g
          }
          if(home[j]!="" && !hs["h:"home[j]]++)ho[++nh]=home[j]
        }
        for(i=1;i<=n;i++)if(dec(uid[i])+0>=1000 && name[i]!="nobody" && name[i]!="nfsnobody" && shell[i]!~/^(\/usr)?(\/sbin\/nologin|\/bin\/false)$/) {
          if(home[i]==""){nss_bad=1;continue}
          if(!ns["h:"home[i]]++)no[++nn]=home[i]
        }
        if(nh>64 || nn>64)exit 2
        print "POPULATIONS"
        if(nss_bad)print "NSS_ERROR"
        for(i=1;i<=nu;i++)print "UID|"uo[i]"|"uc["u:"uo[i]]
        for(i=1;i<=nq;i++)print "GID|"go[i]"|"gc["g:"go[i]]
        for(i=1;i<=nh;i++)print "LOCAL|"ho[i]
        for(i=1;i<=nn;i++)print "NSS|"no[i]
      }' 2>/dev/null
}
rlch_729_result() {
    local value applicable=0 finding=0
    [[ $# -eq 7 ]] || return 2
    for value in "$@"; do
        case "$value" in 0) applicable=1;; 1) applicable=1;finding=1;; 3) :;; *) return 2;; esac
    done
    (( finding==0 )) || return 1
    (( applicable!=0 )) || return 3
    return 0
}
rlch_729_read_snapshot() {
    local path="$1" depth="$2" policy="$3" output="$4" fd pid rc=0 i size=0
    local -n target="$output"
    local -a collected=()
    exec {fd}< <(rlch_fs_snapshot "$path" "$depth" "$policy" "$RLCH_CIS_7_2_9_MOUNTINFO"); pid=$!
    mapfile -d '' -t collected <&"$fd" || rc=2
    exec {fd}<&-
    wait "$pid" || rc=2
    [[ "$rc" == 0 ]] || return 2
    (( ${#collected[@]}>0 && ${#collected[@]}<=196608 && ${#collected[@]}%12==0 )) || return 2
    for ((i=0;i<${#collected[@]};i+=12)); do
        [[ "${collected[i]}" == /* && "${collected[i+1]}" =~ ^[adflbcps]$ &&
           "${collected[i+5]}" =~ ^(0|[1-9][0-9]{0,9})$ && "${collected[i+6]}" =~ ^(0|[1-9][0-9]{0,9})$ &&
           "${collected[i+7]}" =~ ^[0-7]{1,4}$ && "${collected[i+11]}" =~ ^[0-8]$ ]] || return 2
        (( collected[i+5]<=4294967294 && collected[i+6]<=4294967294 )) || return 2
        size=$((size+${#collected[i]}+256)); (( size<=8388608 )) || return 2
    done
    [[ "${collected[0]}" == "$path" && ( "${collected[1]}" == d || "${collected[1]}" == a ) ]] || return 2
    target=("${collected[@]}")
}
rlch_729_snapshot() {
    local path="$1" depth="$2" policy="$3" rule="$4" i offset length value
    # shellcheck disable=SC2034 # Written through a nameref.
    local -a data=()
    for ((i=0;i<${#_729_paths[@]};i++)); do
        if [[ "${_729_paths[i]}" == "$path" && "${_729_depths[i]}" == "$depth" && "${_729_policies[i]}" == "$policy" ]]; then
            _729_affected[i]=$(( _729_affected[i] | (1<<rule) ))
            offset="${_729_offsets[i]}"; length="${_729_lengths[i]}"
            _729_current=("${_729_data[@]:offset:length}"); return 0
        fi
    done
    (( ${#_729_paths[@]}<256 )) || return 2
    rlch_729_read_snapshot "$path" "$depth" "$policy" data || return 2
    for value in "${data[@]}"; do _729_bytes=$((_729_bytes+${#value}+1)); done
    (( _729_bytes<=33554432 && ${#_729_data[@]}+${#data[@]}<=1572864 )) || return 2
    _729_paths+=("$path"); _729_depths+=("$depth"); _729_policies+=("$policy")
    _729_offsets+=("${#_729_data[@]}"); _729_lengths+=("${#data[@]}"); _729_affected+=("$((1<<rule))")
    _729_data+=("${data[@]}"); _729_current=("${data[@]}")
}
rlch_729_finding() {
    [[ "${_729_codes[$1]}" == 2 ]] || _729_codes[$1]=1
}
rlch_729_evaluate_path() {
    local rule="$1" path="$2" depth="$3" policy="$4" i name type owner mode
    rlch_729_snapshot "$path" "$depth" "$policy" "$rule" || return 2
    for ((i=12;i<${#_729_current[@]};i+=12)); do
        type="${_729_current[i+1]}"; [[ "$type" != d && "$type" != a ]] || continue
        name="${_729_current[i]##*/}"; mode="${_729_current[i+7]}"
        # PCRE file-name matching uses UTF8 without UCP/multiline. The accepted
        # ASCII/control-free domain makes the fixed patterns exactly decidable.
        # Reject unsupported names, never silently omit them.
        [[ "$name" != *[!\ -~]* ]] || return 2
        case "$rule" in
            0|1)
                [[ "$name" == .* ]] || continue
                if [[ "$rule" == 0 ]]; then
                    owner="${_729_current[i+6]}"; [[ "${_729_gids[g:$owner]:-0}" -eq 1 ]] || rlch_729_finding "$rule"
                else
                    owner="${_729_current[i+5]}"; [[ "${_729_uids[u:$owner]:-0}" -eq 1 ]] || rlch_729_finding "$rule"
                fi ;;
            2)
                [[ "$name" =~ ^\.[A-Za-z0-9_\ -]+$ ]] || continue
                (( (8#$mode & 07037)==0 )) || rlch_729_finding "$rule" ;;
            3) [[ "$name" != *.forward ]] || rlch_729_finding "$rule" ;;
            4) [[ "$name" != .netrc ]] || rlch_729_finding "$rule" ;;
            5)
                if [[ "$path" == "$RLCH_CIS_7_2_9_ETC" ]]; then [[ "$name" != hosts.equiv ]] || rlch_729_finding "$rule"
                else [[ "$name" != .rhosts ]] || rlch_729_finding "$rule"
                fi ;;
            6)
                [[ "$name" == .bash_history && "$type" != l ]] || continue
                (( (8#$mode & 07177)==0 )) || rlch_729_finding "$rule" ;;
            *) return 2 ;;
        esac
    done
}
rlch_729_observe() (
    set +x
    # shellcheck disable=SC2031 # Deliberately private locale.
    export LC_ALL=C
    ulimit -v 262144 || return 2
    local kernel=0 bash_package=0 rsh=0 later=0 source_ok=0 local_ok=0 nss_ok=0 _729_bytes=0
    local before='' after='' nss_before='' nss_after='' rows='' gids='' proof='' projection='' kind a b extra rule path i j offset length rc=0
    local -a _729_codes=(0 0 0 0 0 0 0) local_paths=() nss_paths=() _729_paths=() _729_depths=() _729_policies=()
    local -a _729_offsets=() _729_lengths=() _729_affected=() _729_data=() _729_current=() fresh=() original=()
    local -A _729_uids=() _729_gids=()
    rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" kernel-core 2>/dev/null || kernel=$?
    rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" bash 2>/dev/null || bash_package=$?
    rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" rsh-server 2>/dev/null || rsh=$?
    for rule in 0 1 3 4; do case "$kernel" in 0) :;; 1) _729_codes[rule]=3;; *) _729_codes[rule]=2;; esac; done
    case "$bash_package" in 0) :;; 1) _729_codes[6]=3;; *) _729_codes[6]=2;; esac
    case "$rsh" in 0) :;; 1) _729_codes[5]=3;; *) _729_codes[5]=2;; esac
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_9_PASSWD" 2>/dev/null)" || source_ok=2
    rows="$(rlch_identity_home_rows "$RLCH_CIS_7_2_9_PASSWD")" || source_ok=2
    gids="$(rlch_identity_gid_fields "$RLCH_CIS_7_2_9_PASSWD" passwd)" || source_ok=2
    if [[ "$source_ok" == 0 ]]; then
        set -o pipefail
        projection="$(printf '%s\n%s\n' "$rows" "$gids" | rlch_729_populations)" || local_ok=2
        if [[ "$local_ok" == 0 && "${projection%%$'\n'*}" == POPULATIONS ]]; then
            while IFS='|' read -r kind a b extra; do
                case "$kind" in
                    POPULATIONS) :;;
                    NSS_ERROR) nss_ok=2;;
                    UID) [[ "$a" =~ ^(0|[1-9][0-9]{0,9})$ && "$b" =~ ^[1-9][0-9]{0,4}$ && -z "$extra" ]] || { local_ok=2; break; }; _729_uids["u:$a"]="$b" ;;
                    GID) [[ "$a" =~ ^(0|[1-9][0-9]{0,9})$ && "$b" =~ ^[1-9][0-9]{0,4}$ && -z "$extra" ]] || { local_ok=2; break; }; _729_gids["g:$a"]="$b" ;;
                    LOCAL) [[ -n "$a" && -z "$b$extra" ]] || { local_ok=2; break; }; local_paths+=("$a") ;;
                    NSS) [[ -n "$a" && -z "$b$extra" ]] || { local_ok=2; break; }; nss_paths+=("$a") ;;
                    *) local_ok=2; break ;;
                esac
            done <<< "$projection"
        else local_ok=2
        fi
    else local_ok=2
    fi
    # No external identity enumeration or raw getent/password output. For the
    # standard trusted glibc runtime, the complete canonical nsswitch source
    # must declare exactly one passwd service: files (optional comment only).
    nss_before="$(rlch_identity_stamp "$RLCH_CIS_7_2_9_NSS" 2>/dev/null)" || nss_ok=2
    proof="$(rlch_identity_uid_values "$RLCH_CIS_7_2_9_PASSWD" "$RLCH_CIS_7_2_9_NSS" 2>/dev/null)" || nss_ok=2
    [[ "${proof%%$'\n'*}" == 'SOURCE|FILES' && -z "${LD_PRELOAD:-}${LD_LIBRARY_PATH:-}${NSS_WRAPPER_PASSWD:-}${NSS_WRAPPER_LIBC:-}" ]] || nss_ok=2
    [[ "$local_ok" == 0 ]] || { for rule in 0 1 2 3 6; do [[ "${_729_codes[rule]}" == 3 ]] || _729_codes[rule]=2; done; }
    [[ "$nss_ok" == 0 ]] || { for rule in 2 3 6; do [[ "${_729_codes[rule]}" == 3 ]] || _729_codes[rule]=2; done; }
    for rule in 0 1 2 3 4 5 6; do
        [[ "${_729_codes[rule]}" == 0 ]] || continue
        case "$rule" in
            0|1) for path in "${local_paths[@]}"; do rlch_729_evaluate_path "$rule" "$path" 2 local || _729_codes[rule]=2; done ;;
            2|3|6) for path in "${nss_paths[@]}"; do rlch_729_evaluate_path "$rule" "$path" 1 all || _729_codes[rule]=2; done ;;
            4) rlch_729_evaluate_path "$rule" "$RLCH_CIS_7_2_9_HOME" 2 all || _729_codes[rule]=2 ;;
            5)
                rlch_729_evaluate_path "$rule" "$RLCH_CIS_7_2_9_HOME" 2 all || _729_codes[rule]=2
                rlch_729_evaluate_path "$rule" "$RLCH_CIS_7_2_9_ROOT" 1 all || _729_codes[rule]=2
                rlch_729_evaluate_path "$rule" "$RLCH_CIS_7_2_9_ETC" 1 all || _729_codes[rule]=2 ;;
        esac
    done
    # Re-observe every dependency across the entire evaluation. A finding
    # cannot mask another rule's collection error, including shared snapshots.
    for ((i=0;i<${#_729_paths[@]};i++)); do
        rc=0
        # shellcheck disable=SC2034 # Output nameref.
        fresh=()
        rlch_729_read_snapshot "${_729_paths[i]}" "${_729_depths[i]}" "${_729_policies[i]}" fresh || rc=2
        offset="${_729_offsets[i]}"; length="${_729_lengths[i]}"
        # shellcheck disable=SC2034 # Compared through a nameref.
        original=("${_729_data[@]:offset:length}")
        rlch_fs_equal fresh original || rc=2
        if [[ "$rc" != 0 ]]; then for ((j=0;j<7;j++)); do (( (_729_affected[i] & (1<<j))==0 )) || _729_codes[j]=2; done; fi
    done
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_9_PASSWD" 2>/dev/null)" || source_ok=2
    [[ "$before" == "$after" && "$rows" == "$(rlch_identity_home_rows "$RLCH_CIS_7_2_9_PASSWD")" && "$gids" == "$(rlch_identity_gid_fields "$RLCH_CIS_7_2_9_PASSWD" passwd)" ]] || source_ok=2
    if [[ "$source_ok" != 0 ]]; then for rule in 0 1 2 3 6; do [[ "${_729_codes[rule]}" == 3 ]] || _729_codes[rule]=2; done; fi
    nss_after="$(rlch_identity_stamp "$RLCH_CIS_7_2_9_NSS" 2>/dev/null)" || nss_ok=2
    [[ "$nss_before" == "$nss_after" && "$proof" == "$(rlch_identity_uid_values "$RLCH_CIS_7_2_9_PASSWD" "$RLCH_CIS_7_2_9_NSS" 2>/dev/null)" ]] || nss_ok=2
    if [[ "$nss_ok" != 0 ]]; then for rule in 2 3 6; do [[ "${_729_codes[rule]}" == 3 ]] || _729_codes[rule]=2; done; fi
    later=0; rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" kernel-core 2>/dev/null || later=$?
    if [[ "$kernel" != "$later" ]]; then for rule in 0 1 3 4; do _729_codes[rule]=2; done; fi
    later=0; rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" bash 2>/dev/null || later=$?
    [[ "$bash_package" == "$later" ]] || _729_codes[6]=2
    later=0; rlch_rpm_package_status "$RLCH_CIS_7_2_9_RPM" rsh-server 2>/dev/null || later=$?
    [[ "$rsh" == "$later" ]] || _729_codes[5]=2
    printf 'RULES|%s|%s|%s|%s|%s|%s|%s\n' "${_729_codes[@]}"
)
check() (
    set +x
    local data rc=0 label value i
    local -a codes=() labels=(accounts_user_dot_group_ownership accounts_user_dot_user_ownership file_permission_user_init_files no_forward_files no_netrc_files no_rsh_trust_files file_permission_user_bash_history)
    data="$(rlch_729_observe)" || rc=2
    if [[ "$rc" == 0 && "$data" =~ ^RULES\|[0-3]\|[0-3]\|[0-3]\|[0-3]\|[0-3]\|[0-3]\|[0-3]$ ]]; then
        IFS='|' read -r label 'codes[0]' 'codes[1]' 'codes[2]' 'codes[3]' 'codes[4]' 'codes[5]' 'codes[6]' <<< "$data"
    else codes=(2 2 2 2 2 2 2)
    fi
    for ((i=0;i<7;i++)); do
        value="${codes[i]}"
        case "$value" in 0) label=SUCCESS;; 1) label=NON_COMPLIANT;; 2) label=ERROR;; 3) label=NOT_APPLICABLE;; esac
        printf 'CIS 7.2.9: %s=%s\n' "${labels[i]}" "$label" >&2
    done
    rlch_729_result "${codes[@]}"
)
validate() { check; }
apply() {
    local rc=0
    check || rc=$?
    case "$rc" in 0|3) return "$rc";; *) printf 'CIS 7.2.9: manual remediation required; observation only\n' >&2; return "$RLCH_MODULE_RESULT_ERROR";; esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
