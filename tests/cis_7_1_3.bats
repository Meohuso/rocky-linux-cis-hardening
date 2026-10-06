#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_3_ROOT="$BATS_TEST_TMPDIR/root" GR_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_3_ROOT"; GR="$R/etc/group"
    mkdir -p "$R/etc"
    printf 'PRIVATE account content not evaluated\n' > "$GR"; chmod 0644 "$GR"
    for file in passwd passwd- group- shadow shadow- gshadow gshadow- unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/3/module.sh"
    eval "$(declare -f rlch_7_1_3_stat | sed '1s/rlch_7_1_3_stat/real_gr_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.3:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "713 exact metadata L1 title Automated scalar multi-rule fallback" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.3 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/group are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; validate_loaded_module_metadata 7.1.3; validate_loaded_module_functions
}
@test "713 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/4/1"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/3"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.3 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    run check
    if [[ "$(stat -c %u "$GR")" == 0 && "$(stat -c %g "$GR")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "713 root root 0644 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "713 every subset of 0644 accepted including 0000" {
    for mode in 0000 0004 0040 0044 0200 0204 0240 0244 0400 0404 0440 0444 0600 0604 0640 0644; do
        chmod "$mode" "$GR"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    done
}
@test "713 all forbidden bits independently rejected including suid sgid sticky" {
    for mode in 0744 0654 0645 0664 0646 4644 2644 1644; do chmod "$mode" "$GR"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "713 combined forbidden bits rejected" { chmod 7777 "$GR"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "713 UID deficit production numeric evaluation" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 GID deficit production numeric evaluation" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 combined UID GID and permission deficits" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$GR"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_3_stat() { real_gr_stat "$@"; }; run check
    if [[ "$(stat -c %u "$GR")" == 0 && "$(stat -c %g "$GR")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "713 absent primary group ERROR never created" { rm "$GR"; unknown; [ ! -e "$GR" ]; }
@test "713 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "713 symlink and dangling symlink ERROR without touching target" {
    mv "$GR" "$GR.real"; ln -s group.real "$GR"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$GR"; ln -s absent "$GR"; unknown; [ "$(readlink "$GR")" = absent ]
}
@test "713 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "713 hardlink ERROR preserves both names" { ln "$GR" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "713 directory and FIFO ERROR no opening" { rm "$GR"; mkdir "$GR"; unknown; rmdir "$GR"; mkfifo "$GR"; unknown; }
@test "713 special socket type injected without privileged fixture skip" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c1a4";print}'; }; unknown
}
@test "713 block and character type evidence rejected" {
    for raw in 61a4 21a4; do rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "713 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_3_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_3_stat() { real_gr_stat "$@"; real_gr_stat "$@"; }; unknown
    rlch_7_1_3_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_3_stat() { real_gr_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_3_stat() { printf '\r\n'; }; unknown
}
@test "713 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_3_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "713 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_3_stat() { real_gr_stat "$@"; return 99; }; unknown
}
@test "713 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=81a0'; do
        rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "713 actual inode replacement between observations ERROR" {
    rlch_7_1_3_stat() {
        real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$GR_CALLS" ]]; then : > "$GR_CALLS"; mv "$GR" "$GR.old"; printf 'replacement\n' > "$GR"; chmod 0644 "$GR"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$GR"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 stat ctime change between observations ERROR" {
    : > "$GR_CALLS"
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v n="$(wc -l < "$GR_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$GR_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 UID change between observations ERROR" {
    : > "$GR_CALLS"
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v n="$(wc -l < "$GR_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$GR_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 GID change between observations ERROR" {
    : > "$GR_CALLS"
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v n="$(wc -l < "$GR_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$GR_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 second snapshot fails or type changes ERROR" {
    : > "$GR_CALLS"
    rlch_7_1_3_stat() {
        if [[ ! -s "$GR_CALLS" ]]; then real_gr_stat "$@"; printf 'call\n' >> "$GR_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$GR_CALLS"
    rlch_7_1_3_stat() { real_gr_stat "$@"; if [[ ! -e "$GR_CALLS" ]]; then : > "$GR_CALLS"; rm "$GR"; ln -s passwd "$GR"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$GR"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "713 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:PRIVATE'  'PRIVATE invalid bytes'; do printf '%s\n' "$text" > "$GR"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "713 group size unrelated to attribute check no content limit" {
    truncate -s 2097152 "$GR"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "713 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$GR_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GR_CALLS" ]; ! declare -F rm
}
@test "713 unknown apply also excludes every mutation command" {
    rm "$GR"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$GR_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$GR_CALLS" ]
}
@test "713 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "713 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$GR"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "713 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "713 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "713 preservation includes primary group content and neighboring account fixtures" {
    ln -s passwd "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "713 neighboring passwd shadow and backup absent or special do not affect observation" {
    rm "$R/etc/passwd" "$R/etc/shadow" "$R/etc/group-"; mkfifo "$R/etc/passwd"; ln -s /dev/null "$R/etc/shadow"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "713 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_3_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "713 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_3_ROOT="$path"; unknown; done
}
@test "713 fixed redacted bounded stderr no stdout" {
    for mode in 0644 0666; do chmod "$mode" "$GR"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "713 guidance identifies POSIX ACL limit and remediation preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'extended ACL'* && "$output" == *'not assessed'* ]]
    chmod 0666 "$GR"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'remove only bits' 'more restrictive' 'ACL/xattr/SELinux' 'account-file replacement' 'rollback' 'no automatic'; do [[ "$output" == *"$word"* ]]; done
}
@test "713 direct reusable path and mode helpers retain contracts" {
    run rlch_journal_path "$GR"; [ "$status" -eq 0 ]
    run rlch_journal_path "$R/etc/../etc/group"; [ "$status" -eq 2 ]
    for mode in 0000 0640 0600 0444 0644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 0 ]; done
    for mode in 0664 0646 0744 1644 2644 4644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 1 ]; done
    run rlch_journal_mode invalid 0644; [ "$status" -eq 2 ]
}
@test "713 every 12-bit mode satisfies allowed-subset property" {
    for ((value=0;value<4096;value++)); do
        printf -v mode '%04o' "$value"
        case "$mode" in 0000|0004|0040|0044|0200|0204|0240|0244|0400|0404|0440|0444|0600|0604|0640|0644) expected="$RLCH_MODULE_RESULT_SUCCESS";; *) expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";; esac
        result="$RLCH_MODULE_RESULT_SUCCESS"; rlch_journal_mode "$mode" 0644 || result=$?
        [ "$result" -eq "$expected" ]
    done
}
@test "713 primary absence every API repeated preserves all neighboring fixtures" {
    rm "$GR"; before="$(snapshot)"
    for n in 1 2; do unknown; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
    [ ! -e "$GR" ]; [ "$before" = "$(snapshot)" ]
}
@test "713 fresh validate observes removed and recreated primary file" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; rm "$GR"; expect validate "$RLCH_MODULE_RESULT_ERROR"
    printf 'new fixture\n' > "$GR"; chmod 0666 "$GR"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    chmod 0600 "$GR"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "713 removal between full snapshots rejected for every evaluating API" {
    eval "$(declare -f rlch_7_1_3_snapshot | sed '1s/rlch_7_1_3_snapshot/real_group_snapshot/')"
    rlch_7_1_3_snapshot() {
        real_group_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        rm "$GR"
    }
    for api in check validate apply; do printf 'fixture\n' > "$GR"; chmod 0644 "$GR"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "713 disappearance during stat followed by recreation is not cached" {
    rlch_7_1_3_stat() { real_gr_stat "$@"; rm "$GR"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$GR" ]
    printf 'new fixture\n' > "$GR"; chmod 0644 "$GR"
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
    expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "713 device and inode differences invalidate complete evidence" {
    for field in 1 2; do
        : > "$GR_CALLS"
        rlch_7_1_3_stat() {
            real_gr_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$GR_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0;$field+=n;print}'
            printf 'call\n' >> "$GR_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "713 nlink change ERROR even when ownership already deficient" {
    : > "$GR_CALLS"
    rlch_7_1_3_stat() {
        real_gr_stat "$@" | awk -F'|' -v n="$(wc -l < "$GR_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;$3+=n;print}'
        printf 'call\n' >> "$GR_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "713 direct snapshot neither reads content nor changes atime" {
    # No hashing/content read here: compare the actual target timestamps only.
    before="$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GR")"
    for api in check validate apply rollback; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ "$before" = "$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$GR")" ]
}
@test "713 attached extra fields and invalid ctime are rejected before classification" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | sed 's/$/|extra/'; }; unknown
    for change in '1=-1' '1=00' '2=bad' '3=-1' '5=00' '5=4294967295' '6=08' '7=xyz' '8=invalid'; do
        rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "713 tab embedded NUL and extra blank line cannot disappear in substitution" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | sed 's/|/\t/'; }; unknown
    rlch_7_1_3_stat() { printf '\000'; real_gr_stat "$@"; }; unknown
    rlch_7_1_3_stat() { real_gr_stat "$@"; printf '\n'; }; unknown
}
@test "713 three primary rules and absence divergence documented" {
    document="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    for rule in file_groupowner_etc_group file_owner_etc_group file_permissions_etc_group; do
        run grep -F "xccdf_org.ssgproject.content_rule_$rule" "$document"; [ "$status" -eq 0 ]
    done
}
@test "713 stable UID GID extremes evaluated numerically without NSS" {
    rlch_7_1_3_stat() { real_gr_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=4294967294;$5=4294967294;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
