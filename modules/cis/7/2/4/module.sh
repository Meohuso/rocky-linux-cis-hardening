#!/usr/bin/env bash
# CIS 7.2.4 - All collected numeric user IDs, not interactive-only OCIL prose.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_2_4_PASSWD="${RLCH_CIS_7_2_4_PASSWD:-/etc/passwd}"
RLCH_CIS_7_2_4_NSS="${RLCH_CIS_7_2_4_NSS:-/etc/nsswitch.conf}"
RLCH_CIS_7_2_4_RPM="${RLCH_CIS_7_2_4_RPM:-/usr/bin/rpm}"

rlch_7_2_4_observe() {
    local applicable=0 after_applicable=0 before_p before_n after_p after_n first second
    local row uid total=0 distinct=0 source_count=0
    local -A seen=()
    rlch_rpm_package_status "$RLCH_CIS_7_2_4_RPM" kernel-core 2>/dev/null || applicable=$?
    case "$applicable" in 0) :;; 1) return 3;; *) return 2;; esac
    before_p="$(rlch_identity_stamp "$RLCH_CIS_7_2_4_PASSWD" 2>/dev/null)" || return 2
    before_n="$(rlch_identity_stamp "$RLCH_CIS_7_2_4_NSS" 2>/dev/null)" || return 2
    first="$(rlch_identity_uid_values "$RLCH_CIS_7_2_4_PASSWD" "$RLCH_CIS_7_2_4_NSS" 2>/dev/null)" || return 2
    second="$(rlch_identity_uid_values "$RLCH_CIS_7_2_4_PASSWD" "$RLCH_CIS_7_2_4_NSS" 2>/dev/null)" || return 2
    after_p="$(rlch_identity_stamp "$RLCH_CIS_7_2_4_PASSWD" 2>/dev/null)" || return 2
    after_n="$(rlch_identity_stamp "$RLCH_CIS_7_2_4_NSS" 2>/dev/null)" || return 2
    rlch_rpm_package_status "$RLCH_CIS_7_2_4_RPM" kernel-core 2>/dev/null || after_applicable=$?
    [[ "$after_applicable" -eq 0 && -n "$first" && "$first" == "$second" &&
       "$before_p" == "$after_p" && "$before_n" == "$after_n" ]] || return 2
    (( ${#first} <= 1048576 )) || return 2
    while IFS= read -r row; do
        if (( source_count == 0 )); then
            # Only the explicit single files backend establishes supported
            # coverage. External/conditional sources cannot be blessed by a
            # local uniqueness result, even when local duplicates are present.
            [[ "$row" == 'SOURCE|FILES' ]] || return 2
            source_count=1
            continue
        fi
        [[ "$row" =~ ^UID\|(0|[1-9][0-9]{0,9})$ ]] || return 2
        uid="${row#UID|}"
        (( 10#$uid <= 4294967294 )) || return 2
        total=$((total + 1)); (( total <= 65536 )) || return 2
        if [[ -z "${seen[uid:$uid]+present}" ]]; then
            seen["uid:$uid"]=1; distinct=$((distinct + 1))
        fi
    done <<< "$first"
    (( source_count == 1 && total > 0 )) || return 2
    if (( total != distinct )); then
        printf 'CIS 7.2.4: %s local account entries have %s distinct numeric UIDs; identities and UID values withheld\n' "$total" "$distinct" >&2
        return 1
    fi
    return 0
}
check() {
    local result=0
    rlch_7_2_4_observe || result=$?
    case "$result" in
        0|1|3) return "$result" ;;
        *) printf 'CIS 7.2.4: cannot reliably evaluate UID uniqueness; applicability, files-only NSS coverage or stable complete evidence unproven\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
validate() { check; }
apply() {
    local result=0
    check || result=$?
    case "$result" in
        0|3) return "$result" ;;
        *) printf 'CIS 7.2.4: manual remediation required; review identity access and protected ownership restoration before changing UIDs\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR" ;;
    esac
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
