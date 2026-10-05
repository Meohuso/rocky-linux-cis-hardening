#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_1_ROOT="$BATS_TEST_TMPDIR/root" PW_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_1_ROOT"; PW="$R/etc/passwd"
    mkdir -p "$R/etc"
    printf 'PRIVATE account content not evaluated\n' > "$PW"; chmod 0644 "$PW"
    for file in group shadow passwd- unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/1/module.sh"
    eval "$(declare -f rlch_7_1_1_stat | sed '1s/rlch_7_1_1_stat/real_pw_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.1:'* ]]; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "711 exact metadata L1 title Automated scalar multi-rule fallback" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.1 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/passwd are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; validate_loaded_module_metadata 7.1.1; validate_loaded_module_functions
}
@test "711 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/4/1"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/1"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.1 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    run check
    if [[ "$(stat -c %u "$PW")" == 0 && "$(stat -c %g "$PW")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "711 root root 0644 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "711 every subset of 0644 accepted including 0000" {
    for mode in 0000 0004 0040 0044 0200 0204 0240 0244 0400 0404 0440 0444 0600 0604 0640 0644; do
        chmod "$mode" "$PW"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done
    done
}
@test "711 all forbidden bits independently rejected including suid sgid sticky" {
    for mode in 0744 0654 0645 0664 0646 4644 2644 1644; do chmod "$mode" "$PW"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "711 combined forbidden bits rejected" { chmod 7777 "$PW"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "711 UID deficit production numeric evaluation" {
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 GID deficit production numeric evaluation" {
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 combined UID GID and permission deficits" {
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$PW"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_1_stat() { real_pw_stat "$@"; }; run check
    if [[ "$(stat -c %u "$PW")" == 0 && "$(stat -c %g "$PW")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "711 absent passwd ERROR never created" { rm "$PW"; unknown; [ ! -e "$PW" ]; }
@test "711 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "711 symlink and dangling symlink ERROR without touching target" {
    mv "$PW" "$PW.real"; ln -s passwd.real "$PW"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$PW"; ln -s absent "$PW"; unknown; [ "$(readlink "$PW")" = absent ]
}
@test "711 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "711 hardlink ERROR preserves both names" { ln "$PW" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "711 directory and FIFO ERROR no opening" { rm "$PW"; mkdir "$PW"; unknown; rmdir "$PW"; mkfifo "$PW"; unknown; }
@test "711 special socket type injected without privileged fixture skip" {
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c1a4";print}'; }; unknown
}
@test "711 block and character type evidence rejected" {
    for raw in 61a4 21a4; do rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "711 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_1_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_1_stat() { real_pw_stat "$@"; real_pw_stat "$@"; }; unknown
    rlch_7_1_1_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_1_stat() { real_pw_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_1_stat() { printf '\r\n'; }; unknown
}
@test "711 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_1_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "711 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_1_stat() { real_pw_stat "$@"; return 99; }; unknown
}
@test "711 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=81a0'; do
        rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "711 actual inode replacement between observations ERROR" {
    rlch_7_1_1_stat() {
        real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$PW_CALLS" ]]; then : > "$PW_CALLS"; mv "$PW" "$PW.old"; printf 'replacement\n' > "$PW"; chmod 0644 "$PW"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$PW"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 stat ctime change between observations ERROR" {
    : > "$PW_CALLS"
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' -v n="$(wc -l < "$PW_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$PW_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 UID change between observations ERROR" {
    : > "$PW_CALLS"
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' -v n="$(wc -l < "$PW_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$PW_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 GID change between observations ERROR" {
    : > "$PW_CALLS"
    rlch_7_1_1_stat() { real_pw_stat "$@" | awk -F'|' -v n="$(wc -l < "$PW_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$PW_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 second snapshot fails or type changes ERROR" {
    : > "$PW_CALLS"
    rlch_7_1_1_stat() {
        if [[ ! -s "$PW_CALLS" ]]; then real_pw_stat "$@"; printf 'call\n' >> "$PW_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$PW_CALLS"
    rlch_7_1_1_stat() { real_pw_stat "$@"; if [[ ! -e "$PW_CALLS" ]]; then : > "$PW_CALLS"; rm "$PW"; ln -s group "$PW"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "711 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$PW"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "711 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:1001:PRIVATE' 'PRIVATE invalid bytes'; do printf '%s\n' "$text" > "$PW"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "711 passwd size unrelated to attribute check no content limit" {
    truncate -s 2097152 "$PW"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "711 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$PW_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$PW_CALLS" ]; ! declare -F rm
}
@test "711 unknown apply also excludes every mutation command" {
    rm "$PW"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$PW_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$PW_CALLS" ]
}
@test "711 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "711 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$PW"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "711 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "711 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "711 preservation includes passwd content group shadow passwd backup unrelated links" {
    ln -s group "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "711 group shadow and backup absent or special do not affect observation" {
    rm "$R/etc/group" "$R/etc/shadow" "$R/etc/passwd-"; mkfifo "$R/etc/group"; ln -s /dev/null "$R/etc/shadow"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "711 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_1_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "711 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_1_ROOT="$path"; unknown; done
}
@test "711 fixed redacted bounded stderr no stdout" {
    for mode in 0644 0666; do chmod "$mode" "$PW"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "711 guidance identifies POSIX ACL limit and remediation preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'extended ACL'* && "$output" == *'not assessed'* ]]
    chmod 0666 "$PW"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'remove only bits' 'more restrictive' 'ACL/xattr/SELinux' 'account-file replacement' 'rollback' 'no automatic'; do [[ "$output" == *"$word"* ]]; done
}
@test "711 direct reusable path and mode helpers retain contracts" {
    run rlch_journal_path "$PW"; [ "$status" -eq 0 ]
    run rlch_journal_path "$R/etc/../etc/passwd"; [ "$status" -eq 2 ]
    for mode in 0000 0640 0600 0444 0644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 0 ]; done
    for mode in 0664 0646 0744 1644 2644 4644; do run rlch_journal_mode "$mode" 0644; [ "$status" -eq 1 ]; done
    run rlch_journal_mode invalid 0644; [ "$status" -eq 2 ]
}
