#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_6_ROOT="$BATS_TEST_TMPDIR/root" SH_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_6_ROOT"; SH="$R/etc/shadow-"
    mkdir -p "$R/etc"
    printf 'PRIVATE account content not evaluated\n' > "$SH"; chmod 0000 "$SH"
    for file in passwd passwd- group group- shadow gshadow gshadow- unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/6/module.sh"
    eval "$(declare -f rlch_7_1_6_stat | sed '1s/rlch_7_1_6_stat/real_sh_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.6:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -perm /0444 -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "716 exact metadata L1 title Automated scalar multi-rule fallback" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/6/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.6 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/shadow- are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; validate_loaded_module_metadata 7.1.6; validate_loaded_module_functions
}
@test "716 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/5"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/6"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.6 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    run check
    if [[ "$(stat -c %u "$SH")" == 0 && "$(stat -c %g "$SH")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "716 root root 0000 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "716 only mode 0000 satisfies check validate apply" {
    chmod 0000 "$SH"; before="$(snapshot)"
    for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    [ "$before" = "$(snapshot)" ]
}
@test "716 all twelve permission and special bits independently rejected" {
    for mode in 0001 0002 0004 0010 0020 0040 0100 0200 0400 1000 2000 4000; do
        chmod "$mode" "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "716 combined forbidden bits rejected" { chmod 7777 "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "716 UID deficit production numeric evaluation" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 GID deficit production numeric evaluation" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 combined UID GID and permission deficits" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_6_stat() { real_sh_stat "$@"; }; run check
    if [[ "$(stat -c %u "$SH")" == 0 && "$(stat -c %g "$SH")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "716 absent backup SUCCESS never created" { rm "$SH"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ ! -e "$SH" ]; }
@test "716 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "716 symlink and dangling symlink ERROR without touching target" {
    mv "$SH" "$SH.real"; ln -s shadow-.real "$SH"; [ -f "$SH" ]; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$SH"; ln -s absent "$SH"; unknown; [ "$(readlink "$SH")" = absent ]
}
@test "716 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "716 hardlink ERROR preserves both names" { ln "$SH" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "716 directory and FIFO ERROR no opening" { rm "$SH"; mkdir "$SH"; unknown; rmdir "$SH"; mkfifo "$SH"; unknown; }
@test "716 special socket type injected without privileged fixture skip" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c000";print}'; }; unknown
}
@test "716 block and character type evidence rejected" {
    for raw in 6000 2000; do rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "716 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_6_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_6_stat() { real_sh_stat "$@"; real_sh_stat "$@"; }; unknown
    rlch_7_1_6_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_6_stat() { real_sh_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_6_stat() { printf '\r\n'; }; unknown
}
@test "716 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_6_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "716 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_6_stat() { real_sh_stat "$@"; return 99; }; unknown
}
@test "716 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=81a0'; do
        rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "716 actual inode replacement between observations ERROR" {
    rlch_7_1_6_stat() {
        real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; mv "$SH" "$SH.old"; printf 'replacement\n' > "$SH"; chmod 0000 "$SH"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 stat ctime change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 UID change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 GID change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 second snapshot fails or type changes ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() {
        if [[ ! -s "$SH_CALLS" ]]; then real_sh_stat "$@"; printf 'call\n' >> "$SH_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$SH_CALLS"
    rlch_7_1_6_stat() { real_sh_stat "$@"; if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; rm "$SH"; ln -s passwd "$SH"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$SH"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "716 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:PRIVATE'  'PRIVATE invalid bytes'; do chmod 0600 "$SH"; printf '%s\n' "$text" > "$SH"; chmod 0000 "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "716 shadow size unrelated to attribute check no content limit" {
    chmod 0600 "$SH"; truncate -s 2097162 "$SH"; chmod 0000 "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "716 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon useradd usermod userdel passwd chpasswd pwconv pwunconv groupadd groupmod groupdel setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$SH_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$SH_CALLS" ]; ! declare -F rm
}
@test "716 noncompliant apply also excludes every mutation command" {
    chmod 0666 "$SH"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$SH_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$SH_CALLS" ]
}
@test "716 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "716 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$SH"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "716 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "716 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "716 preservation includes artificial shadow backup content and neighboring account fixtures" {
    ln -s passwd "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "716 neighboring passwd shadow and backup absent or special do not affect observation" {
    rm "$R/etc/passwd" "$R/etc/shadow" "$R/etc/group-"; mkfifo "$R/etc/passwd"; ln -s /dev/null "$R/etc/shadow"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "716 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_6_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "716 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_6_ROOT="$path"; unknown; done
}
@test "716 fixed redacted bounded stderr no stdout" {
    for mode in 0000 0666; do chmod "$mode" "$SH"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "716 guidance identifies POSIX ACL limit and remediation preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'extended ACL'* && "$output" == *'not assessed'* ]]
    chmod 0666 "$SH"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'clear all permission and special bits' 'RHEL mode 0000' 'ACL/xattr/SELinux' 'account-file replacement' 'rollback' 'no automatic'; do [[ "$output" == *"$word"* ]]; done
}
@test "716 unchanged reusable path and mode helpers support zero policy" {
    run rlch_journal_path "$SH"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rlch_journal_path "$R/etc/../etc/shadow-"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    for mode in 000 0000; do run rlch_journal_mode "$mode" 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    for mode in 0001 0600 0640 0644 1000 2000 4000; do run rlch_journal_mode "$mode" 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done
    run rlch_journal_mode invalid 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}
@test "716 exhaustive 4096 modes accept exactly zero in shared helper" {
    for ((value=0;value<4096;value++)); do
        printf -v mode '%04o' "$value"
        if [[ "$value" -eq 0 ]]; then expected="$RLCH_MODULE_RESULT_SUCCESS"; else expected="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
        result="$RLCH_MODULE_RESULT_SUCCESS"; rlch_journal_mode "$mode" 0000 || result=$?
        [ "$result" -eq "$expected" ]
    done
}
@test "716 backup absence every API repeated preserves all neighboring fixtures" {
    rm "$SH"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
    [ ! -e "$SH" ]; [ "$before" = "$(snapshot)" ]
}
@test "716 fresh validate observes removed and recreated backup file" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; rm "$SH"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
    printf 'new fixture\n' > "$SH"; chmod 0666 "$SH"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    chmod 0000 "$SH"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "716 removal between full snapshots rejected for every evaluating API" {
    eval "$(declare -f rlch_7_1_6_snapshot | sed '1s/rlch_7_1_6_snapshot/real_shadow_snapshot/')"
    rlch_7_1_6_snapshot() {
        real_shadow_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        rm "$SH"
    }
    for api in check validate apply; do rm -f "$SH"; printf 'fixture\n' > "$SH"; chmod 0000 "$SH"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "716 disappearance during stat followed by recreation is not cached" {
    rlch_7_1_6_stat() { real_sh_stat "$@"; rm "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$SH" ]
    printf 'new fixture\n' > "$SH"; chmod 0000 "$SH"
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
    expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "716 device and inode differences invalidate complete evidence" {
    for field in 1 2; do
        : > "$SH_CALLS"
        rlch_7_1_6_stat() {
            real_sh_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0;$field+=n;print}'
            printf 'call\n' >> "$SH_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "716 nlink change ERROR even when ownership already deficient" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() {
        real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;$3+=n;print}'
        printf 'call\n' >> "$SH_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 direct snapshot neither reads content nor changes atime" {
    # No hashing/content read here: compare the actual target timestamps only.
    before="$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$SH")"
    for api in check validate apply rollback; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ "$before" = "$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$SH")" ]
}
@test "716 attached extra fields and invalid ctime are rejected before classification" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | sed 's/$/|extra/'; }; unknown
    for change in '1=-1' '1=00' '2=bad' '3=-1' '5=00' '5=4294967295' '6=08' '7=xyz' '8=invalid'; do
        rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "716 tab embedded NUL and extra blank line cannot disappear in substitution" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | sed 's/|/\t/'; }; unknown
    rlch_7_1_6_stat() { printf '\000'; real_sh_stat "$@"; }; unknown
    rlch_7_1_6_stat() { real_sh_stat "$@"; printf '\n'; }; unknown
}
@test "716 three primary rules and backup absence policy documented" {
    document="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    for rule in file_groupowner_backup_etc_shadow file_owner_backup_etc_shadow file_permissions_backup_etc_shadow; do
        run grep -F "xccdf_org.ssgproject.content_rule_$rule" "$document"; [ "$status" -eq 0 ]
    done
    for cce in CCE-83938-1 CCE-83949-8 CCE-83935-7 CCE-88235-7 CCE-87502-1 CCE-87423-0; do run grep -F "$cce" "$document"; [ "$status" -eq 0 ]; done
}
@test "716 stable UID GID extremes evaluated numerically without NSS" {
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=4294967294;$5=4294967294;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 common readable modes including other-product 0640 are all deficient" {
    for mode in 0600 0640 0644 0660 0666 0777; do
        chmod "$mode" "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "716 other-product shadow GIDs 42 and 15 rejected even with zero mode" {
    for group_id in 42 15; do
        rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v gid="$group_id" 'BEGIN{OFS="|"} {$4=0;$5=gid;print}'; }
        expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "716 every evaluating API rejects appearance after an absent snapshot" {
    eval "$(declare -f rlch_7_1_6_snapshot | sed '1s/rlch_7_1_6_snapshot/real_shadow_snapshot/')"
    rlch_7_1_6_snapshot() {
        local result="$RLCH_MODULE_RESULT_SUCCESS"
        real_shadow_snapshot || result=$?
        if [[ ! -e "$SH" ]]; then printf 'artificial new fixture\n' > "$SH"; chmod 0000 "$SH"; fi
        return "$result"
    }
    for api in check validate apply; do rm -f "$SH"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; [ -f "$SH" ]; done
}
@test "716 apply fresh evaluation does not cache prior compliance or deficit" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0640 "$SH"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    chmod 0000 "$SH"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
    rm "$SH"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ ! -e "$SH" ]
}
@test "716 zero-mode artificial fixture body preserved through preopened descriptors" {
    # Fixture-only reads, opened while readable; no root assumption, production
    # shadow content, chmod during module execution, or shared descriptor offset.
    chmod 0600 "$SH"; exec {before_fd}<"$SH"; exec {after_fd}<"$SH"; chmod 0000 "$SH"
    before_hash="$(sha256sum <&"$before_fd")"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    after_hash="$(sha256sum <&"$after_fd")"; [ "$before_hash" = "$after_hash" ]; [ "$before" = "$(snapshot)" ]
    exec {before_fd}<&-; exec {after_fd}<&-
}
@test "716 raw type changes between complete snapshots take ERROR precedence" {
    : > "$SH_CALLS"
    rlch_7_1_6_stat() {
        real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;if(n) $7="4000";print}'
        printf 'call\n' >> "$SH_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "716 private stat observes only artificial target and emits no evidence" {
    rlch_7_1_6_stat() {
        printf '%s\n' "$1" >> "$SH_CALLS"
        real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
    }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$SH_CALLS")" -eq 2 ]; [ "$(sort -u "$SH_CALLS")" = "$SH" ]; [[ "$output" != *"$R"* ]]
}
@test "716 preserve all seven neighbors and foreign config for present absent deficit" {
    mkdir -p "$R/etc/foreign.d"; printf 'artificial foreign config\n' > "$R/etc/foreign.conf"; ln -s ../group "$R/etc/foreign.d/context"
    for state in present absent deficit; do
        case "$state" in present) expected="$RLCH_MODULE_RESULT_SUCCESS";; absent) rm "$SH"; expected="$RLCH_MODULE_RESULT_SUCCESS";; deficit) printf 'artificial fixture\n' > "$SH"; chmod 0640 "$SH"; expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";; esac
        before="$(snapshot)"; expect check "$expected"; expect validate "$expected"
        if [[ "$state" != deficit ]]; then expect apply "$RLCH_MODULE_RESULT_SUCCESS"; else expect apply "$RLCH_MODULE_RESULT_ERROR"; fi
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ "$before" = "$(snapshot)" ]
    done
}

@test "716 creation during absent snapshot rejected" {
    rm "$SH"
    rlch_7_1_6_stat() { real_sh_stat "$@"; printf 'new\n' > "$SH"; chmod 0000 "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}

@test "716 transient create delete rejected by parent ctime" {
    rm "$SH"
    rlch_7_1_6_stat() {
        real_sh_stat "$@"
        if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; touch "$SH"; rm "$SH"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$SH" ]
}

@test "716 replaced parent during absence ERROR" {
    rm "$SH"
    rlch_7_1_6_stat() {
        real_sh_stat "$@"
        if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; mv "$R/etc" "$R/old-etc"; mkdir "$R/etc"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}

@test "716 absent parent symlink missing directory or regular file ERROR" {
    rm "$SH"; mv "$R/etc" "$R/real-etc"; ln -s real-etc "$R/etc"; unknown
    rm "$R/etc"; unknown
    printf 'not directory\n' > "$R/etc"; unknown
}

@test "716 absent backup requires observable parent even under privileged harness" {
    rm "$SH"
    for mode in 0000 0100 0400; do chmod "$mode" "$R/etc"; unknown; chmod 0755 "$R/etc"; done
}

@test "716 absence parent stat failure and invalid evidence ERROR" {
    rm "$SH"
    rlch_7_1_6_stat() { return 99; }; unknown
    rlch_7_1_6_stat() { printf 'malformed\n'; }; unknown
    for change in '3=0' '4=bad' '7=81ed' '8=invalid'; do
        rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}

@test "716 absence parent numeric ownership not target policy" {
    rm "$SH"
    rlch_7_1_6_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}

@test "716 parent device inode nlink ctime changes reject absence" {
    rm "$SH"
    for field in 1 2 3 8; do
        : > "$SH_CALLS"
        rlch_7_1_6_stat() {
            real_sh_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {if(field==8) $8="2026-01-01 00:00:00.00000000"n" +0000";else $field+=n;print}'
            printf 'call\n' >> "$SH_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}

@test "716 absence isolated from caller glob settings and preserves settings" {
    rm "$SH"; GLOBIGNORE=shadow-; set -f; shopt -s failglob
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [[ "$GLOBIGNORE" == shadow- && "$-" == *f* ]]; shopt -q failglob
    unset GLOBIGNORE; set +f; shopt -u failglob
}

@test "716 absence invokes no content NSS or mutation commands" {
    rm "$SH"
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon logrotate groupadd groupmod groupdel gpasswd vigr setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$SH_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$SH_CALLS" ]; ! declare -F rm
}

@test "716 absence guidance distinguishes optional backup no creation" {
    rm "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'stable absence'* ]]
    expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'no mutation'* ]]
    chmod 0000 "$R/etc"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [[ "$output" == *'never create a missing /etc/shadow-'* ]]; chmod 0755 "$R/etc"
}

@test "716 private stat only targets present backup or absence parent" {
    rlch_7_1_6_stat() {
        printf '%s\n' "$1" >> "$SH_CALLS"
        real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
    }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$SH_CALLS")" -eq 2 ]; [ "$(sort -u "$SH_CALLS")" = "$SH" ]
    rm "$SH" "$SH_CALLS"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$SH_CALLS")" -eq 4 ]; [ "$(sort -u "$SH_CALLS")" = "$R/etc" ]
}

@test "716 absence exact-name glob ignores primary and similarly named files" {
    rm "$SH"; printf 'neighbor\n' > "$R/etc/shadow--"; printf 'neighbor\n' > "$R/etc/shadowx-"
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    [ "$before" = "$(snapshot)" ]; [ ! -e "$SH" ]
}

