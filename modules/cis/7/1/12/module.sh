#!/usr/bin/env bash
# CIS 7.1.12: pinned CAS partial OVAL coverage, observation only.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/filesystem_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/filesystem_observation.sh"
# shellcheck source=lib/identity_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/identity_observation.sh"
# shellcheck source=lib/rpm_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/rpm_observation.sh"
RLCH_CIS_7_1_12_ROOT="${RLCH_CIS_7_1_12_ROOT:-/}"
RLCH_CIS_7_1_12_MOUNTINFO="${RLCH_CIS_7_1_12_MOUNTINFO:-/proc/self/mountinfo}"
RLCH_CIS_7_1_12_RPM="${RLCH_CIS_7_1_12_RPM:-rpm}"

rlch_7_1_12_select() {
    local -n inventory="$1"
    local source="${inventory[$2+5]}"
    [[ "$source" == /dev/* ]] || return 1
    [[ "$source" != *$'\n'* ]] || return 2
}
# Only local files-only enumeration has a supported completeness proof.
# getent success, per-UID lookup or SSSD enumerate=true alone is insufficient.
# The group rule intentionally does NOT substitute NSS for OVAL local GIDs.
rlch_7_1_12_identities() {
    local prefix="$1" nss passwd_source='' group_source='' line package=1 users groups extra='' stamp
    nss="$(rlch_identity_rows "$prefix/etc/nsswitch.conf" nss)" || return 2
    while IFS= read -r line; do
        case "$line" in passwd\|*) passwd_source="${line#*|}";; group\|*) group_source="${line#*|}";; esac
    done <<< "$nss"
    [[ "$passwd_source" =~ ^files[[:space:]]*(#.*)?$ ]] || return 2
    users="$(rlch_identity_rows "$prefix/etc/passwd" passwd)" || return 2
    groups="$(rlch_identity_rows "$prefix/etc/group" group)" || return 2
    if [[ "$group_source" == *altfiles* ]]; then
        # Match the pinned OVAL substring test, including comments. Package
        # absence is established by the existing complete RPM inventory API.
        package=0
        rlch_rpm_package_status "$RLCH_CIS_7_1_12_RPM" nss-altfiles || package=$?
        case "$package" in
            0) extra="$(rlch_identity_rows "$prefix/usr/lib/group" group)" || return 2;;
            1) :;;
            *) return 2;;
        esac
    fi
    # Preserve stamps as well as IDs to detect same-ID replacement/ABA that
    # changes ctime, permissions, inode or NSS configuration between samples.
    printf 'NSS\n%s\nUSERS\n%s\nGROUPS\n%s\nALT|%s\n%s\n' "$nss" "$users" "$groups" "$package" "$extra"
    for line in "$prefix/etc/nsswitch.conf" "$prefix/etc/passwd" "$prefix/etc/group"; do
        stamp="$(rlch_identity_stamp "$line")" || return 2
        printf 'STAMP|%s\n' "$stamp"
    done
    if [[ "$package" == 0 ]]; then
        stamp="$(rlch_identity_stamp "$prefix/usr/lib/group")" || return 2
        printf 'STAMP|%s\n' "$stamp"
    fi
}
rlch_7_1_12_visit() {
    local -n records="$1"
    local prefix="$2" i logical uid gid
    for ((i=0;i<${#records[@]};i+=10)); do
        # OVAL filename is non-nil; directories are explicitly not assessed.
        [[ "${records[i+1]}" != d ]] || continue
        logical="${records[i]#"$prefix"}"; uid="${records[i+5]}"; gid="${records[i+6]}"
        if [[ ! ${RLCH_7112_USERS[$uid]+known} ]]; then RLCH_7112_DEFICIT=1; fi
        # PCRE ^/sysroot/.*$ with newline paths requires engine semantics not
        # proved by a glob; refuse uncertainty rather than widening coverage.
        if [[ "$logical" == /sysroot/* ]]; then
            [[ "$logical" != *$'\n'* ]] || return 2
            continue
        fi
        if [[ ! ${RLCH_7112_GROUPS[$gid]+known} ]]; then RLCH_7112_DEFICIT=1; fi
    done
}
rlch_7_1_12_observe() {
    local prefix="${RLCH_CIS_7_1_12_ROOT%/}" before after line section=''
    local RLCH_7112_DEFICIT=0
    local -A RLCH_7112_USERS=() RLCH_7112_GROUPS=()
    rlch_fs_canonical "${prefix:-/}" || return 2
    before="$(rlch_7_1_12_identities "$prefix")" || return 2
    while IFS= read -r line; do
        case "$line" in
            USERS|GROUPS) section="$line";;
            ALT\|0) section=GROUPS;;
            ALT\|1|STAMP\|*) section='';;
            *)
                if [[ "$line" =~ ^(0|[1-9][0-9]{0,9})$ ]]; then
                    case "$section" in USERS) RLCH_7112_USERS[$line]=1;; GROUPS) RLCH_7112_GROUPS[$line]=1;; esac
                fi;;
        esac
    done <<< "$before"
    (( ${#RLCH_7112_USERS[@]}>0 && ${#RLCH_7112_GROUPS[@]}>0 )) || return 2
    rlch_fs_observe "${prefix:-/}" "$RLCH_CIS_7_1_12_MOUNTINFO" rlch_7_1_12_select rlch_7_1_12_visit || return 2
    after="$(rlch_7_1_12_identities "$prefix")" || return 2
    [[ "$before" == "$after" ]] || return 2
    (( RLCH_7112_DEFICIT==0 )) || return "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    return "$RLCH_MODULE_RESULT_SUCCESS"
}
check() {
    local result=0
    rlch_7_1_12_observe 2>/dev/null || result=$?
    case "$result" in
        0) printf 'CIS 7.1.12: pinned CAS partial OVAL scope complete and stable; no orphan UID/GID; directories excluded; full CIS conformity not demonstrated\n' >&2;;
        1) printf 'CIS 7.1.12: orphan UID and/or local-base GID in complete stable pinned CAS partial OVAL scope; directories excluded; manual review required\n' >&2;;
        *) result=2; printf 'CIS 7.1.12: ERROR; mount traversal, identity completeness, local bases/altfiles or stability unproven; no conformity conclusion\n' >&2;;
    esac
    return "$result"
}
validate() { check; }
apply() {
    local result=0
    rlch_7_1_12_observe 2>/dev/null || result=$?
    if [[ "$result" == 0 ]]; then
        printf 'CIS 7.1.12: partial OVAL criteria satisfied; directories excluded; observation only, no mutation\n' >&2
        return "$RLCH_MODULE_RESULT_SUCCESS"
    fi
    printf 'CIS 7.1.12: manual review required; establish complete stable identity and mount evidence, investigate application ownership before assigning any UID/GID; no automatic chown/chgrp, backup or state; exact restoration must be validated in isolation\n' >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
