#!/usr/bin/env bash
# CIS 7.2.6 - Pinned local textfilecontent54 username captures, not NSS.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_6_PASSWD="${RLCH_CIS_7_2_6_PASSWD:-/etc/passwd}"
RLCH_CIS_7_2_6_RPM="${RLCH_CIS_7_2_6_RPM:-/usr/bin/rpm}"

# All name-bearing variables/pipelines stay inside an untraced subshell. The
# caller retains its tracing state; only fixed guidance/counts leave this scope.
rlch_7_2_6_observe() (
    set +x
    local applicable=0 after_applicable=0 before after first second counts selected distinct
    rlch_rpm_package_status "$RLCH_CIS_7_2_6_RPM" kernel-core 2>/dev/null || applicable=$?
    case "$applicable" in
        0) : ;;
        1) return "$RLCH_MODULE_RESULT_NOT_APPLICABLE" ;;
        *) return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
    before="$(rlch_identity_stamp "$RLCH_CIS_7_2_6_PASSWD" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    first="$(rlch_identity_user_names "$RLCH_CIS_7_2_6_PASSWD" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    second="$(rlch_identity_user_names "$RLCH_CIS_7_2_6_PASSWD" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    after="$(rlch_identity_stamp "$RLCH_CIS_7_2_6_PASSWD" 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    rlch_rpm_package_status "$RLCH_CIS_7_2_6_RPM" kernel-core 2>/dev/null || after_applicable=$?
    [[ "$after_applicable" -eq 0 && -n "$first" && "$first" == "$second" && "$before" == "$after" ]] || return "$RLCH_MODULE_RESULT_ERROR"
    (( ${#first} <= 4194304 )) || return "$RLCH_MODULE_RESULT_ERROR"
    # Untrusted names are data on stdin, never shell expressions, arguments to
    # eval, or Bash array subscripts. Prefixed awk keys retain numeric spellings.
    set -o pipefail
    counts="$(printf '%s\n' "$first" | LC_ALL=C /usr/bin/awk '
        {bytes+=length($0)+1
         if(bytes>4194304 || NR>65536 || length($0)>16400 || index($0,sprintf("%c",0)) || /[[:cntrl:]]/) {bad=1;exit 2}
         if($0=="SKIP") next
         if(substr($0,1,5)!="NAME|" || length($0)==5 || index(substr($0,6),":")) {bad=1;exit 2}
         selected++
         if(!seen["name:" substr($0,6)]++) distinct++
        }
        END {if(bad || !selected) exit 2;printf "%d|%d\n",selected,distinct}
    ' 2>/dev/null)" || return "$RLCH_MODULE_RESULT_ERROR"
    [[ "$counts" =~ ^[1-9][0-9]{0,4}\|[1-9][0-9]{0,4}$ ]] || return "$RLCH_MODULE_RESULT_ERROR"
    IFS='|' read -r selected distinct <<< "$counts"
    (( selected <= 65536 && distinct <= selected )) || return "$RLCH_MODULE_RESULT_ERROR"
    if (( selected != distinct )); then
        printf 'CIS 7.2.6: %s selected local account entries have %s distinct name captures; account names withheld\n' "$selected" "$distinct" >&2
        return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    fi
    return "$RLCH_MODULE_RESULT_SUCCESS"
)
check() {
    local result=0
    rlch_7_2_6_observe || result=$?
    case "$result" in
        0|1|3) return "$result" ;;
        *) printf 'CIS 7.2.6: cannot reliably evaluate local name uniqueness; applicability or complete stable supported captures unproven\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.6: manual remediation required; review account access and ownership before changing account names\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
