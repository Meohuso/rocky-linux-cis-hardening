#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_7_ROOT="$BATS_TEST_TMPDIR/root" GS_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_7_ROOT"; GS="$R/etc/gshadow"
    mkdir -p "$R/etc"
    printf 'PRIVATE account content not evaluated\n' > "$GS"; chmod 0000 "$GS"
    for file in passwd passwd- group group- shadow shadow- gshadow- unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/7/module.sh"
    eval "$(declare -f rlch_7_1_7_stat | sed '1s/rlch_7_1_7_stat/real_gs_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.7:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -perm /0444 -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "717 exact metadata L1 title Automated scalar multi-rule fallback" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.7 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/gshadow are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; validate_loaded_module_metadata 7.1.7; validate_loaded_module_functions
}
@test "717 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/6"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/7"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.7 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    run check
    if [[ "$(stat -c %u "$GS")" == 0 && "$(stat -c %g "$GS")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "717 root root 0000 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "717 only mode 0000 satisfies check validate apply" {
    chmod 0000 "$GS"; before="$(snapshot)"
    for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    [ "$before" = "$(snapshot)" ]
}
@test "717 all twelve permission and special bits independently rejected" {
    for mode in 0001 0002 0004 0010 0020 0040 0100 0200 0400 1000 2000 4000; do
        chmod "$mode" "$GS"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "717 combined forbidden bits rejected" { chmod 7777 "$GS"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "717 UID deficit production numeric evaluation" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 GID deficit production numeric evaluation" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 combined UID GID and permission deficits" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$GS"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_7_stat() { real_gs_stat "$@"; }; run check
    if [[ "$(stat -c %u "$GS")" == 0 && "$(stat -c %g "$GS")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "717 absent primary gshadow ERROR never created" { rm "$GS"; unknown; [ ! -e "$GS" ]; }
@test "717 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "717 symlink and dangling symlink ERROR without touching target" {
    mv "$GS" "$GS.real"; ln -s gshadow.real "$GS"; [ -f "$GS" ]; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$GS"; ln -s absent "$GS"; unknown; [ "$(readlink "$GS")" = absent ]
}
@test "717 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "717 hardlink ERROR preserves both names" { ln "$GS" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "717 directory and FIFO ERROR no opening" { rm "$GS"; mkdir "$GS"; unknown; rmdir "$GS"; mkfifo "$GS"; unknown; }
@test "717 special socket type injected without privileged fixture skip" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c000";print}'; }; unknown
}
@test "717 block and character type evidence rejected" {
    for raw in 6000 2000; do rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "717 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_7_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_7_stat() { real_gs_stat "$@"; real_gs_stat "$@"; }; unknown
    rlch_7_1_7_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_7_stat() { real_gs_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_7_stat() { printf '\r\n'; }; unknown
}
@test "717 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_7_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "717 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_7_stat() { real_gs_stat "$@"; return 99; }; unknown
}
@test "717 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=ffff8000' '7=81a0'; do
        rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "717 actual inode replacement between observations ERROR" {
    rlch_7_1_7_stat() {
        real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$GS_CALLS" ]]; then : > "$GS_CALLS"; mv "$GS" "$GS.old"; printf 'replacement\n' > "$GS"; chmod 0000 "$GS"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$GS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 stat ctime change between observations ERROR" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$GS_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 UID change between observations ERROR" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$GS_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 GID change between observations ERROR" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$GS_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 second snapshot fails or type changes ERROR" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() {
        if [[ ! -s "$GS_CALLS" ]]; then real_gs_stat "$@"; printf 'call\n' >> "$GS_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$GS_CALLS"
    rlch_7_1_7_stat() { real_gs_stat "$@"; if [[ ! -e "$GS_CALLS" ]]; then : > "$GS_CALLS"; rm "$GS"; ln -s passwd "$GS"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$GS"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "717 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:PRIVATE'  'PRIVATE invalid bytes'; do chmod 0600 "$GS"; printf '%s\n' "$text" > "$GS"; chmod 0000 "$GS"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "717 gshadow size unrelated to attribute check no content limit" {
    chmod 0600 "$GS"; truncate -s 2097152 "$GS"; chmod 0000 "$GS"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "717 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon useradd usermod userdel passwd chpasswd pwconv pwunconv groupadd groupmod groupdel setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$GS_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GS_CALLS" ]; ! declare -F rm
}
@test "717 unknown apply also excludes every mutation command" {
    rm "$GS"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$GS_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GS_CALLS" ]
}
@test "717 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "717 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$GS"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "717 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "717 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "717 preservation includes artificial primary gshadow content and neighboring account fixtures" {
    ln -s passwd "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "717 neighboring account files and backup absent or special do not affect observation" {
    rm "$R/etc/passwd" "$R/etc/gshadow-" "$R/etc/group-"; mkfifo "$R/etc/passwd"; ln -s /dev/null "$R/etc/gshadow-"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "717 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_7_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "717 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_7_ROOT="$path"; unknown; done
}
@test "717 fixed redacted bounded stderr no stdout" {
    for mode in 0000 0666; do chmod "$mode" "$GS"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "717 guidance identifies POSIX ACL limit and remediation preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'extended ACL'* && "$output" == *'not assessed'* ]]
    chmod 0666 "$GS"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'clear all permission and special bits' 'RHEL mode 0000' 'ACL/xattr/SELinux' 'account-file replacement' 'rollback' 'no automatic'; do [[ "$output" == *"$word"* ]]; done
}
@test "717 unchanged reusable path and mode helpers support zero policy" {
    run rlch_journal_path "$GS"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rlch_journal_path "$R/etc/../etc/gshadow"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    for mode in 000 0000; do run rlch_journal_mode "$mode" 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    for mode in 0001 0600 0640 0644 1000 2000 4000; do run rlch_journal_mode "$mode" 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; done
    run rlch_journal_mode invalid 0000; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}
@test "717 exhaustive 4096 modes accept exactly zero in shared helper" {
    for ((value=0;value<4096;value++)); do
        printf -v mode '%04o' "$value"
        if [[ "$value" -eq 0 ]]; then expected="$RLCH_MODULE_RESULT_SUCCESS"; else expected="$RLCH_MODULE_RESULT_NON_COMPLIANT"; fi
        result="$RLCH_MODULE_RESULT_SUCCESS"; rlch_journal_mode "$mode" 0000 || result=$?
        [ "$result" -eq "$expected" ]
    done
}
@test "717 primary absence every API repeated preserves all neighboring fixtures" {
    rm "$GS"; before="$(snapshot)"
    for n in 1 2; do unknown; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
    [ ! -e "$GS" ]; [ "$before" = "$(snapshot)" ]
}
@test "717 fresh validate observes removed and recreated primary file" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; rm "$GS"; expect validate "$RLCH_MODULE_RESULT_ERROR"
    printf 'new fixture\n' > "$GS"; chmod 0666 "$GS"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    chmod 0000 "$GS"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "717 removal between full snapshots rejected for every evaluating API" {
    eval "$(declare -f rlch_7_1_7_snapshot | sed '1s/rlch_7_1_7_snapshot/real_shadow_snapshot/')"
    rlch_7_1_7_snapshot() {
        real_shadow_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        rm "$GS"
    }
    for api in check validate apply; do rm -f "$GS"; printf 'fixture\n' > "$GS"; chmod 0000 "$GS"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "717 disappearance during stat followed by recreation is not cached" {
    rlch_7_1_7_stat() { real_gs_stat "$@"; rm "$GS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$GS" ]
    printf 'new fixture\n' > "$GS"; chmod 0000 "$GS"
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
    expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "717 device and inode differences invalidate complete evidence" {
    for field in 1 2; do
        : > "$GS_CALLS"
        rlch_7_1_7_stat() {
            real_gs_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0;$field+=n;print}'
            printf 'call\n' >> "$GS_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "717 nlink change ERROR even when ownership already deficient" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() {
        real_gs_stat "$@" | awk -F'|' -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;$3+=n;print}'
        printf 'call\n' >> "$GS_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 direct snapshot neither reads content nor changes atime" {
    # No hashing/content read here: compare the actual target timestamps only.
    before="$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GS")"
    for api in check validate apply rollback; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ "$before" = "$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GS")" ]
}
@test "717 attached extra fields and invalid ctime are rejected before classification" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | sed 's/$/|extra/'; }; unknown
    for change in '1=-1' '1=00' '2=bad' '3=-1' '5=00' '5=4294967295' '6=08' '7=xyz' '8=invalid'; do
        rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "717 tab embedded NUL and extra blank line cannot disappear in substitution" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | sed 's/|/\t/'; }; unknown
    rlch_7_1_7_stat() { printf '\000'; real_gs_stat "$@"; }; unknown
    rlch_7_1_7_stat() { real_gs_stat "$@"; printf '\n'; }; unknown
}
@test "717 three primary rules and absence divergence documented" {
    document="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    for rule in file_owner_etc_gshadow file_groupowner_etc_gshadow file_permissions_etc_gshadow; do
        run grep -F "xccdf_org.ssgproject.content_rule_$rule" "$document"; [ "$status" -eq 0 ]
    done
    for cce in CCE-83948-0 CCE-83924-1 CCE-83921-7 CCE-90043-1 CCE-87701-9 CCE-86975-0; do run grep -F "$cce" "$document"; [ "$status" -eq 0 ]; done
}
@test "717 stable UID GID extremes evaluated numerically without NSS" {
    rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=4294967294;$5=4294967294;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 common readable modes including other-product 0640 are all deficient" {
    for mode in 0600 0640 0644 0660 0666 0777; do
        chmod "$mode" "$GS"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "717 foreign GIDs 42 and 15 rejected even with zero mode" {
    for group_id in 42 15; do
        rlch_7_1_7_stat() { real_gs_stat "$@" | awk -F'|' -v gid="$group_id" 'BEGIN{OFS="|"} {$4=0;$5=gid;print}'; }
        expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "717 every evaluating API rejects appearance after an absent snapshot" {
    eval "$(declare -f rlch_7_1_7_snapshot | sed '1s/rlch_7_1_7_snapshot/real_shadow_snapshot/')"
    rlch_7_1_7_snapshot() {
        local result="$RLCH_MODULE_RESULT_SUCCESS"
        real_shadow_snapshot || result=$?
        if [[ ! -e "$GS" ]]; then printf 'artificial new fixture\n' > "$GS"; chmod 0000 "$GS"; fi
        return "$result"
    }
    for api in check validate apply; do rm -f "$GS"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; [ -f "$GS" ]; done
}
@test "717 apply fresh evaluation does not cache prior compliance or deficit" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0640 "$GS"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    chmod 0000 "$GS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
    rm "$GS"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$GS" ]
}
@test "717 zero-mode artificial fixture body preserved through preopened descriptors" {
    # Fixture-only reads, opened while readable; no root assumption, production
    # shadow content, chmod during module execution, or shared descriptor offset.
    chmod 0600 "$GS"; exec {before_fd}<"$GS"; exec {after_fd}<"$GS"; chmod 0000 "$GS"
    before_hash="$(sha256sum <&"$before_fd")"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    after_hash="$(sha256sum <&"$after_fd")"; [ "$before_hash" = "$after_hash" ]; [ "$before" = "$(snapshot)" ]
    exec {before_fd}<&-; exec {after_fd}<&-
}
@test "717 raw type changes between complete snapshots take ERROR precedence" {
    : > "$GS_CALLS"
    rlch_7_1_7_stat() {
        real_gs_stat "$@" | awk -F'|' -v n="$(wc -l < "$GS_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;if(n) $7="4000";print}'
        printf 'call\n' >> "$GS_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "717 private stat observes only artificial target and emits no evidence" {
    rlch_7_1_7_stat() {
        printf '%s\n' "$1" >> "$GS_CALLS"
        real_gs_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
    }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$GS_CALLS")" -eq 2 ]; [ "$(sort -u "$GS_CALLS")" = "$GS" ]; [[ "$output" != *"$R"* ]]
}
@test "717 preserve all seven neighbors and foreign config for present absent deficit" {
    mkdir -p "$R/etc/foreign.d"; printf 'artificial foreign config\n' > "$R/etc/foreign.conf"; ln -s ../group "$R/etc/foreign.d/context"
    for state in present absent deficit; do
        case "$state" in present) expected="$RLCH_MODULE_RESULT_SUCCESS";; absent) rm "$GS"; expected="$RLCH_MODULE_RESULT_ERROR";; deficit) printf 'artificial fixture\n' > "$GS"; chmod 0640 "$GS"; expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";; esac
        before="$(snapshot)"; expect check "$expected"; expect validate "$expected"
        if [[ "$state" == present ]]; then expect apply "$RLCH_MODULE_RESULT_SUCCESS"; else expect apply "$RLCH_MODULE_RESULT_ERROR"; fi
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ "$before" = "$(snapshot)" ]
    done
}

@test "717 primary absence is ERROR even when optional backup exists" {
    rm "$GS"; [ -f "$R/etc/gshadow-" ]; before="$(snapshot)"
    unknown; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
    [ ! -e "$GS" ]; [ "$before" = "$(snapshot)" ]
}
@test "717 present unknown apply excludes content reconstruction from backup" {
    ln "$GS" "$R/etc/alias"; before="$(snapshot)"
    unknown; [ "$before" = "$(snapshot)" ]; [ -f "$R/etc/gshadow-" ]
}
