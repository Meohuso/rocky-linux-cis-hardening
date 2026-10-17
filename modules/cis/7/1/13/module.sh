#!/usr/bin/env bash
# CIS 7.1.13 Manual: authorized partial technical inventory, never approval.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/filesystem_observation.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/filesystem_observation.sh"
RLCH_CIS_7_1_13_ROOT="${RLCH_CIS_7_1_13_ROOT:-/}"
RLCH_CIS_7_1_13_MOUNTINFO="${RLCH_CIS_7_1_13_MOUNTINFO:-/proc/self/mountinfo}"
RLCH_CIS_7_1_13_EMIT_INVENTORY="${RLCH_CIS_7_1_13_EMIT_INVENTORY:-false}"

# The selector/visitor callbacks contain CIS inventory policy only; traversal,
# framing, device checks, races and resource enforcement belong to the library.
rlch_7_1_13_select() {
    local -n inventory="$1"
    local index="$2" row
    if (( ${#RLCH_7113_MOUNTS[@]}==0 )); then RLCH_7113_MOUNTS=("${inventory[@]}"); fi
    [[ "${inventory[index+5]}" == /dev/* ]] || return 1
    [[ "${inventory[index+5]}" != *$'\n'* ]] || return 2
    RLCH_7113_SELECTED[${inventory[index]}]=1
    printf -v row 'MOUNT id=%s parent=%s device=%s root=%q target=%q source=%q fstype=%q vfs=%q\n' \
        "${inventory[index]}" "${inventory[index+1]}" "${inventory[index+2]}" "${inventory[index+3]}" \
        "${inventory[index+4]}" "${inventory[index+5]}" "${inventory[index+6]}" "${inventory[index+7]}"
    RLCH_7113_TEXT+="$row"
    (( ${#RLCH_7113_TEXT}<=8388608 )) || return 2
}
rlch_7_1_13_visit() {
    local -n records="$1"
    local prefix="$2" i j logical mode suid sgid chosen target row
    for ((i=0;i<${#records[@]};i+=10)); do
        [[ "${records[i+1]}" == f ]] || continue
        mode="${records[i+7]}"
        (( (8#$mode & 06000)!=0 )) || continue
        logical="${records[i]#"$prefix"}"
        if [[ "$logical" == /sysroot/* ]]; then
            # Do not approximate newline-sensitive anchored PCRE exclusions.
            [[ "$logical" != *$'\n'* ]] || return 2
            continue
        fi
        # Associate the evidence with the nearest visible mount from the
        # selector's validated inventory, including excluded bind boundaries.
        chosen=-1
        for ((j=0;j<${#RLCH_7113_MOUNTS[@]};j+=10)); do
            target="${RLCH_7113_MOUNTS[j+4]}"
            if [[ "$target" == / || "$logical" == "$target/"* ]]; then
                if (( chosen<0 )) || (( ${#target}>${#RLCH_7113_MOUNTS[chosen+4]} )); then chosen="$j"; fi
            fi
        done
        (( chosen>=0 )) || return 2
        [[ ${RLCH_7113_SELECTED[${RLCH_7113_MOUNTS[chosen]}]+selected} ]] || return 2
        suid=0; sgid=0
        if (( (8#$mode & 04000)!=0 )); then suid=1; fi
        if (( (8#$mode & 02000)!=0 )); then sgid=1; fi
        RLCH_7113_COUNT=$((RLCH_7113_COUNT+1))
        (( RLCH_7113_COUNT<=4096 )) || return 2
        printf -v row 'FILE mount_id=%s path=%q type=f device=%s inode=%s nlink=%s uid=%s gid=%s mode=%s ctime=%s suid=%s sgid=%s\n' \
            "${RLCH_7113_MOUNTS[chosen]}" "$logical" "${records[i+2]}" "${records[i+3]}" "${records[i+4]}" \
            "${records[i+5]}" "${records[i+6]}" "$mode" "${records[i+8]}" "$suid" "$sgid"
        RLCH_7113_TEXT+="$row"
        (( ${#RLCH_7113_TEXT}<=8388608 )) || return 2
    done
    return 0
}
rlch_7_1_13_evaluate() {
    local LC_ALL=C RLCH_7113_TEXT='' RLCH_7113_COUNT=0
    local -a RLCH_7113_MOUNTS=()
    local -A RLCH_7113_SELECTED=()
    case "$RLCH_CIS_7_1_13_EMIT_INVENTORY" in
        true|false) :;;
        *) printf 'CIS 7.1.13: ERROR; invalid inventory output setting; no evidence emitted\n' >&2
           return "$RLCH_MODULE_RESULT_ERROR";;
    esac
    if ! rlch_fs_observe "$RLCH_CIS_7_1_13_ROOT" "$RLCH_CIS_7_1_13_MOUNTINFO" rlch_7_1_13_select rlch_7_1_13_visit 2>/dev/null; then
        printf 'CIS 7.1.13: ERROR; partial-scope inventory unavailable: traversal, mount evidence, stability or resource limits unproven; no review or conformity conclusion\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    if [[ "$RLCH_CIS_7_1_13_EMIT_INVENTORY" == true ]]; then
        # Trusted caller explicitly opts into stdout disclosure and chooses its
        # recipient/redirection. Buffer until the ENTIRE observation succeeds.
        # Only a received END frame confirms complete transport of this scope.
        # Quoted paths are display data; never eval/source/execute this text.
        if ! (trap '' PIPE; printf 'BEGIN CIS_7_1_13_INVENTORY version=1 scope=CAS_RELATED_OVAL_PARTIAL review=UNVERIFIED complete=UNCONFIRMED\n%sEND CIS_7_1_13_INVENTORY files=%s mounts=%s observation=COMPLETE review=UNVERIFIED conformity=UNDEMONSTRATED\n' \
            "$RLCH_7113_TEXT" "$RLCH_7113_COUNT" "${#RLCH_7113_SELECTED[@]}") 2>/dev/null; then
            printf 'CIS 7.1.13: ERROR; inventory output failed; received partial transport must not be accepted as complete\n' >&2
            return "$RLCH_MODULE_RESULT_ERROR"
        fi
    fi
    printf 'CIS 7.1.13: ERROR; technical inventory complete only for authorized partial CAS-related scope (%s files); human review required and unverified, including for an empty inventory; full CIS conformity not demonstrated; no mutation\n' "$RLCH_7113_COUNT" >&2
    return "$RLCH_MODULE_RESULT_ERROR"
}
check() { rlch_7_1_13_evaluate; }
validate() { rlch_7_1_13_evaluate; }
apply() { rlch_7_1_13_evaluate; }
rollback() { return "$RLCH_MODULE_RESULT_SUCCESS"; }
