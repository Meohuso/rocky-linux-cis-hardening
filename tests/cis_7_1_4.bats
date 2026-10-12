#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_4_ROOT="$BATS_TEST_TMPDIR/root" GB_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_4_ROOT"; GB="$R/etc/group-"
    mkdir -p "$R/etc"
    printf 'PRIVATE account content not evaluated\n' > "$GB"; chmod 0644 "$GB"
    for file in passwd passwd- group shadow shadow- gshadow gshadow- unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/4/module.sh"
    eval "$(declare -f rlch_7_1_4_stat | sed '1s/rlch_7_1_4_stat/real_gb_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.4:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "714 exact metadata L1 title Automated scalar multi-rule fallback" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.4 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/group- are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; validate_loaded_module_metadata 7.1.4; validate_loaded_module_functions
}
@test "714 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/3"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/4"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.4 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    run check
    if [[ "$(stat -c %u "$GB")" == 0 && "$(stat -c %g "$GB")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "714 root root 0644 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "714 every subset of 0644 accepted including 0000" {
    for mode in 0000 0004 0040 0044 0200 0204 0240 0244 0400 0404 0440 0444 0600 0604 0640 0644; do
        chmod "$mode" "$GB"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    done
}
@test "714 all forbidden bits independently rejected including suid sgid sticky" {
    for mode in 0744 0654 0645 0664 0646 4644 2644 1644; do chmod "$mode" "$GB"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "714 combined forbidden bits rejected" { chmod 7777 "$GB"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "714 UID deficit production numeric evaluation" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 GID deficit production numeric evaluation" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 combined UID GID and permission deficits" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$GB"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_4_stat() { real_gb_stat "$@"; }; run check
    if [[ "$(stat -c %u "$GB")" == 0 && "$(stat -c %g "$GB")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "714 stable absence SUCCESS no API creates backup" {
    rm "$GB"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ ! -e "$GB" ]; [ "$before" = "$(snapshot)" ]
}
@test "714 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "714 symlink and dangling symlink ERROR without touching target" {
    mv "$GB" "$GB.real"; ln -s group-.real "$GB"; [ -f "$GB" ]; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$GB"; ln -s absent "$GB"; unknown; [ "$(readlink "$GB")" = absent ]
}
@test "714 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "714 hardlink ERROR preserves both names" { ln "$GB" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "714 directory and FIFO ERROR no opening" { rm "$GB"; mkdir "$GB"; unknown; rmdir "$GB"; mkfifo "$GB"; unknown; }
@test "714 special socket type injected without privileged fixture skip" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c1a4";print}'; }; unknown
}
@test "714 block and character type evidence rejected" {
    for raw in 61a4 21a4; do rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "714 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_4_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_4_stat() { real_gb_stat "$@"; real_gb_stat "$@"; }; unknown
    rlch_7_1_4_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_4_stat() { real_gb_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_4_stat() { printf '\r\n'; }; unknown
}
@test "714 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_4_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "714 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_4_stat() { real_gb_stat "$@"; return 99; }; unknown
}
@test "714 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=81a0'; do
        rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "714 actual inode replacement between observations ERROR" {
    rlch_7_1_4_stat() {
        real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; mv "$GB" "$GB.old"; printf 'replacement\n' > "$GB"; chmod 0644 "$GB"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$GB"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 stat ctime change between observations ERROR" {
    : > "$GB_CALLS"
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v n="$(wc -l < "$GB_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$GB_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 UID change between observations ERROR" {
    : > "$GB_CALLS"
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v n="$(wc -l < "$GB_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$GB_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 GID change between observations ERROR" {
    : > "$GB_CALLS"
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v n="$(wc -l < "$GB_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$GB_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 second snapshot fails or type changes ERROR" {
    : > "$GB_CALLS"
    rlch_7_1_4_stat() {
        if [[ ! -s "$GB_CALLS" ]]; then real_gb_stat "$@"; printf 'call\n' >> "$GB_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$GB_CALLS"
    rlch_7_1_4_stat() { real_gb_stat "$@"; if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; rm "$GB"; ln -s group "$GB"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$GB"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "714 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:PRIVATE' 'PRIVATE invalid bytes'; do printf '%s\n' "$text" > "$GB"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "714 group backup size unrelated to attribute check no content limit" {
    truncate -s 2097152 "$GB"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "714 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon groupadd groupmod groupdel gpasswd vigr setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$GB_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GB_CALLS" ]; ! declare -F rm
}
@test "714 noncompliant apply also excludes every mutation command" {
    chmod 0666 "$GB"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$GB_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GB_CALLS" ]
}
@test "714 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "714 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$GB"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "714 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "714 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "714 preservation includes group backup and all seven neighboring account fixtures" {
    ln -s group "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "714 adjacent passwd group shadow absent or special do not affect observation" {
    rm "$R/etc/group" "$R/etc/shadow" "$R/etc/passwd"; mkfifo "$R/etc/group"; ln -s /dev/null "$R/etc/shadow"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "714 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_4_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "714 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_4_ROOT="$path"; unknown; done
}
@test "714 fixed redacted bounded stderr no stdout" {
    for mode in 0644 0666; do chmod "$mode" "$GB"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "714 guidance identifies POSIX ACL limit and remediation preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'extended ACL'* && "$output" == *'not assessed'* ]]
    chmod 0666 "$GB"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'remove only bits' 'more restrictive' 'ACL/xattr/SELinux' 'account-file replacement' 'rollback' 'no automatic'; do [[ "$output" == *"$word"* ]]; done
}
@test "714 direct reusable path and mode helpers retain contracts" {
    run rlch_journal_path "$GB"; [ "$status" -eq 0 ]
    run rlch_journal_path "$R/etc/../etc/group-"; [ "$status" -eq 2 ]
    for mode in 0000 0640 0600 0444 0644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 0 ]; done
    for mode in 0664 0646 0744 1644 2644 4644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 1 ]; done
    run rlch_journal_mode invalid 0644; [ "$status" -eq 2 ]
}
@test "714 absent to present between snapshots ERROR even if new file complies" {
    rm "$GB"
    eval "$(declare -f rlch_7_1_4_snapshot | sed '1s/rlch_7_1_4_snapshot/real_backup_snapshot/')"
    rlch_7_1_4_snapshot() {
        real_backup_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; printf 'new backup\n' > "$GB"; chmod 0644 "$GB"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 present to absent between snapshots ERROR not compliant absence" {
    eval "$(declare -f rlch_7_1_4_snapshot | sed '1s/rlch_7_1_4_snapshot/real_backup_snapshot/')"
    rlch_7_1_4_snapshot() {
        real_backup_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; rm "$GB"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 every evaluating API rejects observed absence transition" {
    eval "$(declare -f rlch_7_1_4_snapshot | sed '1s/rlch_7_1_4_snapshot/real_backup_snapshot/')"
    rlch_7_1_4_snapshot() {
        real_backup_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; printf 'new\n' > "$GB"; chmod 0666 "$GB"; fi
    }
    for api in check validate apply; do rm -f "$GB" "$GB_CALLS"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "714 fresh validate observes created deficit and later removed backup" {
    rm "$GB"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'new\n' > "$GB"; chmod 0666 "$GB"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    rm "$GB"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "714 creation during absent snapshot rejected" {
    rm "$GB"
    rlch_7_1_4_stat() { real_gb_stat "$@"; printf 'new\n' > "$GB"; chmod 0644 "$GB"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 transient create delete rejected by parent ctime" {
    rm "$GB"
    rlch_7_1_4_stat() {
        real_gb_stat "$@"
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; touch "$GB"; rm "$GB"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$GB" ]
}
@test "714 replaced parent during absence ERROR" {
    rm "$GB"
    rlch_7_1_4_stat() {
        real_gb_stat "$@"
        if [[ ! -e "$GB_CALLS" ]]; then : > "$GB_CALLS"; mv "$R/etc" "$R/old-etc"; mkdir "$R/etc"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 absent parent symlink missing directory or regular file ERROR" {
    rm "$GB"; mv "$R/etc" "$R/real-etc"; ln -s real-etc "$R/etc"; unknown
    rm "$R/etc"; unknown
    printf 'not directory\n' > "$R/etc"; unknown
}
@test "714 absent backup requires observable parent even under privileged harness" {
    rm "$GB"
    for mode in 0000 0100 0400; do chmod "$mode" "$R/etc"; unknown; chmod 0755 "$R/etc"; done
}
@test "714 absence parent stat failure and invalid evidence ERROR" {
    rm "$GB"
    rlch_7_1_4_stat() { return 99; }; unknown
    rlch_7_1_4_stat() { printf 'malformed\n'; }; unknown
    for change in '3=0' '4=bad' '7=81ed' '8=invalid'; do
        rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "714 absence parent numeric ownership not target policy" {
    rm "$GB"
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "714 parent device inode nlink ctime changes reject absence" {
    rm "$GB"
    for field in 1 2 3 8; do
        : > "$GB_CALLS"
        rlch_7_1_4_stat() {
            real_gb_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$GB_CALLS")" 'BEGIN{OFS="|"} {if(field==8) $8="2026-01-01 00:00:00.00000000"n" +0000";else $field+=n;print}'
            printf 'call\n' >> "$GB_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "714 present device and nlink changes reject stable deficit classification" {
    for field in 1 3; do
        : > "$GB_CALLS"
        rlch_7_1_4_stat() {
            real_gb_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$GB_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0;$field+=n;print}'
            printf 'call\n' >> "$GB_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "714 absence isolated from caller glob settings and preserves settings" {
    rm "$GB"; GLOBIGNORE=group-; set -f; shopt -s failglob
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$GLOBIGNORE" == group- && "$-" == *f* ]]; shopt -q failglob
    unset GLOBIGNORE; set +f; shopt -u failglob
}
@test "714 all 4096 modes satisfy exact allowed-subset property in helper" {
    for ((value=0;value<4096;value++)); do
        printf -v mode '%04o' "$value"
        case "$mode" in 0000|0004|0040|0044|0200|0204|0240|0244|0400|0404|0440|0444|0600|0604|0640|0644) expected="$RLCH_MODULE_RESULT_SUCCESS";; *) expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";; esac
        result="$RLCH_MODULE_RESULT_SUCCESS"; rlch_journal_mode "$mode" 0644 || result=$?
        [ "$result" -eq "$expected" ]
    done
}
@test "714 absence invokes no content NSS or mutation commands" {
    rm "$GB"
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon logrotate groupadd groupmod groupdel gpasswd vigr setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$GB_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GB_CALLS" ]; ! declare -F rm
}
@test "714 absence guidance distinguishes optional backup no creation" {
    rm "$GB"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'stable absence'* ]]
    expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'no mutation'* ]]
    chmod 0000 "$R/etc"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [[ "$output" == *'never create a missing /etc/group-'* ]]; chmod 0755 "$R/etc"
}
@test "714 preserve all seven adjacent account fixtures and unrelated config" {
    mkdir -p "$R/etc/logrotate.d"; printf 'unrelated\n' > "$R/etc/logrotate.conf"; ln -s ../group "$R/etc/logrotate.d/context"
    for state in present absent deficit; do
        case "$state" in present) expected="$RLCH_MODULE_RESULT_SUCCESS";; absent) rm "$GB"; expected="$RLCH_MODULE_RESULT_SUCCESS";; deficit) printf 'backup\n' > "$GB"; chmod 0666 "$GB"; expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";; esac
        before="$(snapshot)"; expect check "$expected"; expect validate "$expected"
        if [[ "$state" == deficit ]]; then expect apply "$RLCH_MODULE_RESULT_ERROR"; else expect apply "$RLCH_MODULE_RESULT_SUCCESS"; fi
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ "$before" = "$(snapshot)" ]
    done
}

@test "714 direct snapshot neither reads content nor changes atime" {
    # No hashing/content read here: compare the actual target timestamps only.
    before="$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GB")"
    for api in check validate apply rollback; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ "$before" = "$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GB")" ]
}
@test "714 attached extra fields and invalid ctime are rejected before classification" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | sed 's/$/|extra/'; }; unknown
    for change in '1=-1' '1=00' '2=bad' '3=-1' '5=00' '5=4294967295' '6=08' '7=xyz' '8=invalid'; do
        rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "714 tab embedded NUL and extra blank line cannot disappear in substitution" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | sed 's/|/\t/'; }; unknown
    rlch_7_1_4_stat() { printf '\000'; real_gb_stat "$@"; }; unknown
    rlch_7_1_4_stat() { real_gb_stat "$@"; printf '\n'; }; unknown
}

@test "714 stable UID GID extremes evaluated numerically without NSS" {
    rlch_7_1_4_stat() { real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=4294967294;$5=4294967294;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "714 metadata documents three primary XCCDF and contextual CCE mappings" {
    document="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    for rule in file_groupowner_backup_etc_group file_owner_backup_etc_group file_permissions_backup_etc_group; do
        run grep -F "xccdf_org.ssgproject.content_rule_$rule" "$document"; [ "$status" -eq 0 ]
    done
    for cce in CCE-83928-2 CCE-83944-9 CCE-83939-9 CCE-89477-4 CCE-89017-8 CCE-86579-0; do run grep -F "$cce" "$document"; [ "$status" -eq 0 ]; done
}
@test "714 backup absent SUCCESS differs from primary group ERROR in isolated roots" {
    rm "$GB"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
    # Exercise the previously validated primary API without altering it.
    export RLCH_CIS_7_1_3_ROOT="$R"
    rm "$R/etc/group"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/4/module.sh"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
    [ ! -e "$GB" ]; [ ! -e "$R/etc/group" ]
}
@test "714 private stat only targets present backup or absence parent" {
    rlch_7_1_4_stat() {
        printf '%s\n' "$1" >> "$GB_CALLS"
        real_gb_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
    }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$GB_CALLS")" -eq 2 ]; [ "$(sort -u "$GB_CALLS")" = "$GB" ]
    rm "$GB" "$GB_CALLS"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$GB_CALLS")" -eq 4 ]; [ "$(sort -u "$GB_CALLS")" = "$R/etc" ]
}
@test "714 absence exact-name glob ignores primary and similarly named files" {
    rm "$GB"; printf 'neighbor\n' > "$R/etc/group--"; printf 'neighbor\n' > "$R/etc/groupx-"
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    [ "$before" = "$(snapshot)" ]; [ ! -e "$GB" ]
}
