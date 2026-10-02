#!/usr/bin/env bash
# CIS 6.1.2 - RHEL9 CAS periodic AIDE checks, with isolated create-only cron.
# SPDX-License-Identifier: MIT
# shellcheck source=lib/aide_schedule.sh
source "${BASH_SOURCE[0]%/*}/../../../../../lib/aide_schedule.sh"
RLCH_CIS_6_1_2_CRONTAB="${RLCH_CIS_6_1_2_CRONTAB:-/etc/crontab}"
RLCH_CIS_6_1_2_ROOT_CRON="${RLCH_CIS_6_1_2_ROOT_CRON:-/var/spool/cron/root}"
RLCH_CIS_6_1_2_CRON_D="${RLCH_CIS_6_1_2_CRON_D:-/etc/cron.d}"
RLCH_CIS_6_1_2_DAILY="${RLCH_CIS_6_1_2_DAILY:-/etc/cron.daily}"
RLCH_CIS_6_1_2_WEEKLY="${RLCH_CIS_6_1_2_WEEKLY:-/etc/cron.weekly}"
RLCH_CIS_6_1_2_STATE="${RLCH_CIS_6_1_2_STATE:-$RLCH_CIS_6_1_2_CRON_D/.rlch-6.1.2}"
RLCH_CIS_6_1_2_RPM="${RLCH_CIS_6_1_2_RPM:-${RLCH_RPM_COMMAND:-/usr/bin/rpm}}"
RLCH_CIS_6_1_2_BINARY="${RLCH_CIS_6_1_2_BINARY:-/usr/sbin/aide}"
RLCH_CIS_6_1_2_ID_COMMAND="${RLCH_CIS_6_1_2_ID_COMMAND:-/usr/bin/id}"

rlch_6_1_2_inventory() {
    rlch_aide_cron_inventory "$RLCH_CIS_6_1_2_CRONTAB" "$RLCH_CIS_6_1_2_ROOT_CRON" "$RLCH_CIS_6_1_2_CRON_D" \
        "$RLCH_CIS_6_1_2_DAILY" "$RLCH_CIS_6_1_2_WEEKLY" "$RLCH_CIS_6_1_2_STATE"
}
rlch_6_1_2_fingerprint() { rlch_6_1_2_inventory; }
rlch_6_1_2_others_fingerprint() {
    local rows line
    rows="$(rlch_6_1_2_fingerprint)" || return 2
    while IFS= read -r line; do
        [[ "$line" != "$1|"* ]] || continue
        printf '%s\n' "$line"
    done <<< "$rows"
}

rlch_6_1_2_check() {
    local package=0 final_package=0 before after rows count found=0 i
    rlch_aide_package_status "$RLCH_CIS_6_1_2_RPM" || package=$?
    [[ "$package" -ne 2 ]] || return 2
    before="$(rlch_6_1_2_fingerprint)" || return 2
    rlch_6_1_2_inventory >/dev/null || return 2
    for i in "${!RLCH_AIDE_CRON_FILES[@]}"; do
        rows="$(rlch_aide_cron_scan "${RLCH_AIDE_CRON_FILES[$i]}" "${RLCH_AIDE_CRON_KINDS[$i]}")" || return 2
        count="${rows%%|*}"
        found=$((found + count))
    done
    after="$(rlch_6_1_2_fingerprint)" || return 2
    [[ "$before" == "$after" ]] || return 2
    rlch_aide_package_status "$RLCH_CIS_6_1_2_RPM" || final_package=$?
    [[ "$package" == "$final_package" ]] || return 2
    RLCH_AIDE_CRON_SNAPSHOT="$after"
    [[ "$package" -eq 0 && "$found" -gt 0 ]] || return 1
    return 0
}
check() {
    local result=0
    rlch_6_1_2_check || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 6.1.2: unsafe/ambiguous cron input, query error or concurrent change; manual review required\n' >&2
    fi
    return "$result"
}

rlch_6_1_2_apply() (
    local result=0 target state lock_fd current binary_stamp directory_stamp directory_fd original_snapshot
    check || result=$?
    [[ "$result" -ne 0 ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    if [[ "$result" -ne 1 ]] || ! rlch_aide_package_status "$RLCH_CIS_6_1_2_RPM"; then
        printf 'CIS 6.1.2: manual remediation required for absent AIDE or unsafe cron configuration\n' >&2
        return "$RLCH_MODULE_RESULT_ERROR"
    fi
    [[ "$("$RLCH_CIS_6_1_2_ID_COMMAND" -u)" == 0 ]] || return 2
    target="$RLCH_CIS_6_1_2_CRON_D/rlch-aide-check"; state="$RLCH_CIS_6_1_2_STATE"
    [[ ! -e "$target" && ! -L "$target" ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_6_1_2_CRON_D" || return 2
    rlch_aide_cron_access "$RLCH_CIS_6_1_2_BINARY" || return 2
    [[ -x "$RLCH_CIS_6_1_2_BINARY" ]] || return 2
    binary_stamp="$(rlch_tmout_file_stamp "$RLCH_CIS_6_1_2_BINARY")" || return 2
    directory_stamp="$(rlch_tmout_directory "$RLCH_CIS_6_1_2_CRON_D")" || return 2
    { exec {directory_fd}<"$RLCH_CIS_6_1_2_CRON_D"; } 2>/dev/null || return 2
    if ! /usr/bin/flock -n -x "$directory_fd"; then exec {directory_fd}<&-; return 2; fi
    current="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "/proc/self/fd/$directory_fd")" || current=''
    if [[ "$directory_stamp" != "$current" ]]; then exec {directory_fd}<&-; return 2; fi
    # Keep a private same-filesystem journal outside the regular cron-file set.
    [[ "$state" == "$RLCH_CIS_6_1_2_CRON_D/"* && "${state##*/}" == .rlch-6.1.2 && "${state%/*}" == "$RLCH_CIS_6_1_2_CRON_D" ]] || return 2
    [[ ! -e "$state" && ! -L "$state" ]] || return 2
    (umask 077; /usr/bin/mkdir -- "$state") || return 2
    if ! { exec {lock_fd}<"$state"; } 2>/dev/null; then
        /usr/bin/rmdir -- "$state" || true
        return 2
    fi
    if ! /usr/bin/flock -n -x "$lock_fd"; then
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
    current="$(rlch_6_1_2_fingerprint)" || current=''
    if [[ "$current" != "$RLCH_AIDE_CRON_SNAPSHOT" ]]; then
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    if ! (set -o noclobber; printf '# CIS 6.1.2 managed periodic AIDE check\n05 4 * * * root /usr/sbin/aide --check\n' > "$state/payload") ||
       ! /usr/bin/chmod 0644 -- "$state/payload" ||
       ! rlch_aide_cron_set_owner "$state/payload" ||
       ! rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" ||
       ! (set -o noclobber; rlch_tmout_payload_identity "$state/payload" > "$state/identity"); then
        rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
        /usr/bin/rm -f -- "$state/payload" "$state/identity"
        /usr/bin/rmdir -- "$state" || true
        exec {lock_fd}<&-
        return 2
    fi
    rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
    current="$(rlch_6_1_2_fingerprint)" || current=''
    if [[ "$current" != "$RLCH_AIDE_CRON_SNAPSHOT" || "$(rlch_tmout_file_stamp "$RLCH_CIS_6_1_2_BINARY")" != "$binary_stamp" ]] ||
       ! rlch_aide_package_status "$RLCH_CIS_6_1_2_RPM"; then
        rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
        /usr/bin/rm -f -- "$state/payload" "$state/identity"
        /usr/bin/rmdir -- "$state" || true
        return 2
    fi
    original_snapshot="$RLCH_AIDE_CRON_SNAPSHOT"
    if ! rlch_tmout_link "/proc/self/fd/$lock_fd/payload" "/proc/self/fd/$directory_fd/rlch-aide-check"; then
        rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
        if [[ "$target" -ef "$state/payload" ]]; then
            rlch_tmout_restore_created "$state" "$target" || true
        else
            rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
        /usr/bin/rm -f -- "$state/payload" "$state/identity"
            /usr/bin/rmdir -- "$state" || true
        fi
        exec {lock_fd}<&-
        return 2
    fi
    rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
    if ! (set -o noclobber; rlch_tmout_file_stamp "$target" > "$state/installed"); then
        /usr/bin/rm -f -- "$state/installed"
        rlch_tmout_restore_created "$state" "$target" || true
        exec {lock_fd}<&-
        return 2
    fi
    rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
    current="$(rlch_6_1_2_others_fingerprint "$target")" || current=''
    if [[ "$current" != "$original_snapshot" ]] || ! validate || ! rlch_tmout_created_matches "$state" "$target"; then
        if ! rlch_tmout_restore_created "$state" "$target"; then
            printf 'CIS 6.1.2: restoration failed; retain isolated state for manual recovery\n' >&2
        fi
        exec {lock_fd}<&-
        return 2
    fi
    exec {lock_fd}<&-
    return "$RLCH_MODULE_RESULT_CHANGED"
)

validate() { check; }
rlch_6_1_2_rollback() (
    local state="$RLCH_CIS_6_1_2_STATE" target="$RLCH_CIS_6_1_2_CRON_D/rlch-aide-check" lock_fd result=0 directory_fd directory_stamp current
    [[ -e "$state" || -L "$state" ]] || return "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$("$RLCH_CIS_6_1_2_ID_COMMAND" -u)" == 0 ]] || return 2
    [[ "$state" == "$RLCH_CIS_6_1_2_CRON_D/.rlch-6.1.2" ]] || return 2
    rlch_tmout_writable_directory "$RLCH_CIS_6_1_2_CRON_D" || return 2
    directory_stamp="$(rlch_tmout_directory "$RLCH_CIS_6_1_2_CRON_D")" || return 2
    { exec {directory_fd}<"$RLCH_CIS_6_1_2_CRON_D"; } 2>/dev/null || return 2
    /usr/bin/flock -n -x "$directory_fd" || return 2
    current="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a' -- "/proc/self/fd/$directory_fd")" || return 2
    [[ "$current" == "$directory_stamp" ]] || return 2
    rlch_tmout_writable_directory "$state" || return 2
    [[ "$(/usr/bin/stat -Lc '%a' -- "$state")" == 700 ]] || return 2
    { exec {lock_fd}<"$state"; } 2>/dev/null || return 2
    if ! /usr/bin/flock -n -x "$lock_fd"; then exec {lock_fd}<&-; return 2; fi
    rlch_aide_cron_attached "$RLCH_CIS_6_1_2_CRON_D" "$directory_fd" "$state" "$lock_fd" || return 2
    rlch_tmout_restore_created "$state" "$target" || result=2
    exec {lock_fd}<&-
    [[ "$result" -eq 0 ]] || return "$RLCH_MODULE_RESULT_ERROR"
    return "$RLCH_MODULE_RESULT_CHANGED"
)

apply() {
    local result=0
    rlch_6_1_2_apply || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 6.1.2: no safe automatic correction completed; review configuration, paths and any retained isolated state\n' >&2
    fi
    return "$result"
}
rollback() {
    local result=0
    rlch_6_1_2_rollback || result=$?
    if [[ "$result" -eq 2 ]]; then
        printf 'CIS 6.1.2: rollback refused or failed; preserve concurrent changes and review isolated state\n' >&2
    fi
    return "$result"
}
