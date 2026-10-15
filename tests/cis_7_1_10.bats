#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_1_10_ROOT="$BATS_TEST_TMPDIR/root" SH_CALLS="$BATS_TEST_TMPDIR/calls"
    R="$RLCH_CIS_7_1_10_ROOT"; SH="$R/etc/security/opasswd"
    mkdir -p "$R/etc/security"
    printf 'PRIVATE account content not evaluated\n' > "$SH"; chmod 0600 "$SH"
    for file in passwd passwd- group group- shadow shadow- gshadow gshadow- shells unrelated; do printf 'PRIVATE preservation fixture\n' > "$R/etc/$file"; done
    export RLCH_CIS_7_1_10_RPM="$BATS_TEST_TMPDIR/rpm-fixture" RLCH_CIS_7_1_10_GETFACL="$BATS_TEST_TMPDIR/getfacl-fixture"
    # Read-only command-boundary fixtures: validate exact arguments, never query
    # host packages or read any password content. Real parser remains active.
    cat > "$RLCH_CIS_7_1_10_RPM" <<'CMD'
#!/usr/bin/env bash
[[ "$#" == 4 && "$1" == -q && "$2" == --qf && "$3" == '%{NAME}\n' && "$4" == pam ]] || exit 99
printf 'pam\n'
CMD
    cat > "$RLCH_CIS_7_1_10_GETFACL" <<'CMD'
#!/usr/bin/env bash
[[ "$#" == 6 && "$1" == -c && "$2" == -n && "$3" == -E && "$4" == -P && "$5" == -- ]] || exit 99
mode="$(/usr/bin/stat -c %a -- "$6")" || exit 99
p=(--- --x -w- -wx r-- r-x rw- rwx)
printf 'user::%s\ngroup::%s\nother::%s\n\n' "${p[$((8#$mode >> 6 & 7))]}" "${p[$((8#$mode >> 3 & 7))]}" "${p[$((8#$mode & 7))]}"
CMD
    chmod +x "$RLCH_CIS_7_1_10_RPM" "$RLCH_CIS_7_1_10_GETFACL"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/10/module.sh"
    eval "$(declare -f rlch_7_1_10_stat | sed '1s/rlch_7_1_10_stat/real_sh_stat/')"
    # Normalize only numeric fixture identities in stat evidence. Every real
    # file/path/type/link/mode and all production classification remain active.
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
}
expect() { run "$1"; [ "$status" -eq "$2" ]; [[ "$output" == 'CIS 7.1.10:'* ]]; }
absent() { expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
unknown() { expect check "$RLCH_MODULE_RESULT_ERROR"; expect validate "$RLCH_MODULE_RESULT_ERROR"; expect apply "$RLCH_MODULE_RESULT_ERROR"; }
snapshot() {
    (set -o pipefail
     find "$R" -printf '%p|%y|%D|%i|%n|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$R" -type f -perm /0444 -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "7110 exact metadata L1 title Automated scalar single-rule partial scope" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/10/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.1.10 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure permissions on /etc/security/opasswd are configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_file_etc_security_opasswd ]; validate_loaded_module_metadata 7.1.10; validate_loaded_module_functions
}
@test "7110 framework load after previous module binds new API and actual ownership" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/9"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/7/1/10"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.1.10 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_file_etc_security_opasswd ]
    run check
    if [[ "$(stat -c %u "$SH")" == 0 && "$(stat -c %g "$SH")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "7110 root root 0600 satisfies check validate apply without mutation" {
    before="$(snapshot)"; for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "7110 only exact 0600 accepted including rejection of stricter modes" {
    for mode in 0000 0200 0400 0440 0604 0640 0644 0660; do
        chmod "$mode" "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    done
}

@test "7110 all forbidden bits independently rejected including suid sgid sticky" {
    for mode in 0744 0654 0645 0664 0646 4644 2644 1644; do chmod "$mode" "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "7110 combined forbidden bits rejected" { chmod 7777 "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "7110 UID deficit production numeric evaluation" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 GID deficit production numeric evaluation" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=1001;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 combined UID GID and permission deficits" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=1002;print}'; }
    chmod 0666 "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 untouched actual stat ownership not assumed fixture root" {
    rlch_7_1_10_stat() { real_sh_stat "$@"; }; run check
    if [[ "$(stat -c %u "$SH")" == 0 && "$(stat -c %g "$SH")" == 0 ]]; then [ "$status" -eq 0 ]; else [ "$status" -eq 1 ]; fi
}
@test "7110 absent stable absent opasswd NON_COMPLIANT never created" { rm "$SH"; absent; [ ! -e "$SH" ]; }
@test "7110 absent etc directory ERROR never created" { rm -r "$R/etc"; unknown; [ ! -e "$R/etc" ]; }
@test "7110 symlink and dangling symlink ERROR without touching target" {
    mv "$SH" "$SH.real"; ln -s opasswd.real "$SH"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]
    rm "$SH"; ln -s absent "$SH"; unknown; [ "$(readlink "$SH")" = absent ]
}
@test "7110 symlink parent ERROR even if target has good attrs" { mv "$R/etc" "$R/real"; ln -s real "$R/etc"; unknown; }
@test "7110 hardlink ERROR preserves both names" { ln "$SH" "$R/etc/alias"; before="$(snapshot)"; unknown; [ "$before" = "$(snapshot)" ]; }
@test "7110 directory and FIFO ERROR no opening" { rm "$SH"; mkdir "$SH"; unknown; rmdir "$SH"; mkfifo "$SH"; unknown; }
@test "7110 special socket type injected without privileged fixture skip" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;$7="c1a4";print}'; }; unknown
}
@test "7110 block and character type evidence rejected" {
    for raw in 61a4 21a4; do rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v raw="$raw" 'BEGIN{OFS="|"} {$7=raw;print}'; }; unknown; done
}
@test "7110 malformed empty multirow oversized NUL CR output ERROR" {
    for evidence in '' 'garbage' '1|2|1|0|0|644|81a4|bad'; do rlch_7_1_10_stat() { printf '%s\n' "$evidence"; }; unknown; done
    rlch_7_1_10_stat() { real_sh_stat "$@"; real_sh_stat "$@"; }; unknown
    rlch_7_1_10_stat() { printf '%01025d\n' 0; }; unknown
    rlch_7_1_10_stat() { real_sh_stat "$@"; printf '\000'; }; unknown
    rlch_7_1_10_stat() { printf '\r\n'; }; unknown
}
@test "7110 stat failure and read-path failure ERROR redacted" {
    rlch_7_1_10_stat() { printf 'PRIVATE stat error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
    rlch_journal_path() { return 2; }; unknown
}
@test "7110 failed command with plausible output remains ERROR via pipefail" {
    rlch_7_1_10_stat() { real_sh_stat "$@"; return 99; }; unknown
}
@test "7110 invalid numeric tuple fields and inconsistent raw mode error" {
    for change in '1=bad' '2=0' '3=0' '3=2' '4=-1' '4=00' '4=4294967295' '5=bad' '6=999' '6=64444' '7=fffffffff' '7=ffff81a4' '7=ffff8000' '7=ffff41ed' '7=81a0'; do
        rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "7110 actual inode replacement between observations ERROR" {
    rlch_7_1_10_stat() {
        real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
        if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; mv "$SH" "$SH.old"; printf 'replacement\n' > "$SH"; chmod 0600 "$SH"; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 actual mode change between observations ERROR dominates deficit" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; chmod 0666 "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 stat ctime change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0; $8="2026-01-01 00:00:00.00000000"n" +0000";print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 UID change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=n;$5=0;print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 GID change between observations ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=n;print}'; printf 'call\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 second snapshot fails or type changes ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() {
        if [[ ! -s "$SH_CALLS" ]]; then real_sh_stat "$@"; printf 'call\n' >> "$SH_CALLS"; else return 99; fi
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
    rm "$SH_CALLS"
    rlch_7_1_10_stat() { real_sh_stat "$@"; if [[ ! -e "$SH_CALLS" ]]; then : > "$SH_CALLS"; rm "$SH"; ln -s passwd "$SH"; fi; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 fresh validate has no cache" { expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0666 "$SH"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; }
@test "7110 malformed contents and root identity entries never read or affect result" {
    for text in '' 'root:x:1001:PRIVATE'  'PRIVATE invalid bytes'; do printf '%s\n' "$text" > "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; done
}
@test "7110 opasswd size unrelated to attribute check no content limit" {
    truncate -s 2097152 "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "7110 no NSS package service content state commands invoked" {
    probe() (
        local cmd api result
        for cmd in cat grep sed find sha256sum getent id rpm dnf systemctl service chmod chown chgrp cp mv rm touch mkdir ln curl kill getfacl setfacl getfattr setfattr restorecon useradd usermod userdel passwd chpasswd pwconv pwunconv groupadd groupmod groupdel setcap; do
            eval "$cmd() { printf '%s\n' '$cmd' >> '$SH_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do result=0; "$api" >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]] || return 1; done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$SH_CALLS" ]; ! declare -F rm
}
@test "7110 unknown apply also excludes every mutation command" {
    rm "$SH"
    probe() (
        local cmd result=0
        for cmd in chmod chown chgrp cp mv rm touch mkdir ln; do eval "$cmd() { printf '%s\n' '$cmd' >> '$SH_CALLS'; return 99; }"; done
        apply >/dev/null 2>/dev/null || result=$?; [[ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]]
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$SH_CALLS" ]
}
@test "7110 compliant apply repeated SUCCESS no CHANGED and no backup or state" {
    before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_SUCCESS"; done; [ "$before" = "$(snapshot)" ]
}
@test "7110 noncompliant apply repeated ERROR leaves attributes intact" {
    chmod 0666 "$SH"; before="$(snapshot)"; for n in 1 2; do expect apply "$RLCH_MODULE_RESULT_ERROR"; done; [ "$before" = "$(snapshot)" ]
}
@test "7110 no-op rollback silent repeatable without resources" {
    rm -r "$R"; for n in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "7110 all API sequence check apply validate apply rollback rollback preserves" {
    before="$(snapshot)"; expect check 0; expect apply 0; expect validate 0; expect apply 0
    for n in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "7110 preservation includes primary opasswd content and neighboring account fixtures" {
    ln -s passwd "$R/etc/context-link"; before="$(snapshot)"
    for n in 1 2; do for api in check validate apply; do expect "$api" "$RLCH_MODULE_RESULT_SUCCESS"; done; run rollback; [ "$status" -eq 0 ]; done
    [ "$before" = "$(snapshot)" ]
}
@test "7110 neighboring passwd shadow and backup absent or special do not affect observation" {
    rm "$R/etc/passwd" "$R/etc/shadow" "$R/etc/group-"; mkfifo "$R/etc/passwd"; ln -s /dev/null "$R/etc/shadow"
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "7110 unusual root literal dollar quote backslash spaces preserved" {
    new="$BATS_TEST_TMPDIR/"'root $ "quote" \nliteral'; mv "$R" "$new"; R="$new"; RLCH_CIS_7_1_10_ROOT="$new"
    before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"; [ "$before" = "$(snapshot)" ]
}
@test "7110 ambiguous root controls pipe relative dot segments ERROR" {
    for path in "$R/../root" 'relative' "$R|extra" "$R"$'\nSECRET'; do RLCH_CIS_7_1_10_ROOT="$path"; unknown; done
}
@test "7110 fixed redacted bounded stderr no stdout" {
    for mode in 0600 0666; do chmod "$mode" "$SH"
        for api in check validate apply; do result=0; "$api" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
            [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ -s "$BATS_TEST_TMPDIR/err" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 1024 ]
            run grep -E "PRIVATE|$R" "$BATS_TEST_TMPDIR/err"; [ "$status" -eq 1 ]
        done
    done
}
@test "7110 guidance identifies partial scope and exact preservation" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; [[ "$output" == *'no extended ACL'* && "$output" == *'full CIS coverage is not demonstrated'* ]]
    chmod 0666 "$SH"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    for word in 'exact regular single-link' 'exact mode 0600' 'original ACL/attributes' 'xattr/SELinux/capabilities' 'PAM history rotation' 'rollback' 'no automatic' 'opasswd.old is not assessed'; do [[ "$output" == *"$word"* ]]; done
}

@test "7110 direct reusable path helper retains canonicality contract" {
    run rlch_journal_path "$SH"; [ "$status" -eq 0 ]
    run rlch_journal_path "$R/etc/security/../security/opasswd"; [ "$status" -eq 2 ]
}

@test "7110 policy requires exact 0600 not shared subset helper semantics" {
    for mode in 0000 0200 0400; do
        run rlch_journal_mode "$mode" 0600; [ "$status" -eq 0 ]
        chmod "$mode" "$SH"; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    done
    chmod 0600 "$SH"; expect check "$RLCH_MODULE_RESULT_SUCCESS"
}

@test "7110 primary absence every API repeated preserves all neighboring fixtures" {
    rm "$SH"; before="$(snapshot)"
    for n in 1 2; do absent; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
    [ ! -e "$SH" ]; [ "$before" = "$(snapshot)" ]
}
@test "7110 fresh validate observes removed and recreated primary file" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; rm "$SH"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    printf 'new fixture\n' > "$SH"; chmod 0666 "$SH"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    chmod 0600 "$SH"; expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "7110 removal between full snapshots rejected for every evaluating API" {
    eval "$(declare -f rlch_7_1_10_snapshot | sed '1s/rlch_7_1_10_snapshot/real_opasswd_snapshot/')"
    rlch_7_1_10_snapshot() {
        real_opasswd_snapshot || return "$RLCH_MODULE_RESULT_ERROR"
        rm "$SH"
    }
    for api in check validate apply; do printf 'fixture\n' > "$SH"; chmod 0600 "$SH"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
}
@test "7110 disappearance during stat followed by recreation is not cached" {
    rlch_7_1_10_stat() { real_sh_stat "$@"; rm "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$SH" ]
    printf 'new fixture\n' > "$SH"; chmod 0600 "$SH"
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'; }
    expect validate "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "7110 device and inode differences invalidate complete evidence" {
    for field in 1 2; do
        : > "$SH_CALLS"
        rlch_7_1_10_stat() {
            real_sh_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=0;$5=0;$field+=n;print}'
            printf 'call\n' >> "$SH_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "7110 nlink change ERROR even when ownership already deficient" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() {
        real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;$3+=n;print}'
        printf 'call\n' >> "$SH_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 direct snapshot neither reads content nor changes atime" {
    # No hashing/content read here: compare the actual target timestamps only.
    before="$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$SH")"
    for api in check validate apply rollback; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    [ "$before" = "$(stat -c '%d|%i|%h|%u|%g|%a|%x|%y|%z' "$SH")" ]
}
@test "7110 attached extra fields and invalid ctime are rejected before classification" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | sed 's/$/|extra/'; }; unknown
    for change in '1=-1' '1=00' '2=bad' '3=-1' '5=00' '5=4294967295' '6=08' '7=xyz' '8=invalid'; do
        rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "7110 tab embedded NUL and extra blank line cannot disappear in substitution" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | sed 's/|/\t/'; }; unknown
    rlch_7_1_10_stat() { printf '\000'; real_sh_stat "$@"; }; unknown
    rlch_7_1_10_stat() { real_sh_stat "$@"; printf '\n'; }; unknown
}
@test "7110 exact CAS rule partial status and old coverage limitation documented" {
    document="$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    for word in xccdf_org.ssgproject.content_rule_file_etc_security_opasswd CCE-86762-2 CCE-86980-0 'opasswd.old' 'all_exist'; do
        run grep -F "$word" "$document"; [ "$status" -eq 0 ]
    done
}

@test "7110 stable UID GID extremes evaluated numerically without NSS" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=4294967294;$5=4294967294;print}'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 high raw bits rejected even when low type and mode match" {
    for pair in '644 ffff81a4' '0 ffff8000' '755 ffff41ed'; do
        read -r mode raw <<< "$pair"
        rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v mode="$mode" -v raw="$raw" 'BEGIN{OFS="|"} {$4=0;$5=0;$6=mode;$7=raw;print}'; }
        unknown
    done
}
@test "7110 inaccessible or unsearchable parent rejected even with privileged fixture access" {
    for mode in 0000 0444 0111; do chmod "$mode" "$R/etc/security"; unknown; chmod 0755 "$R/etc/security"; done
}
@test "7110 parent changing to inaccessible after evidence has ERROR precedence" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;$5=0;print}'; chmod 0000 "$R/etc/security"; }
    unknown; chmod 0755 "$R/etc/security"
}
@test "7110 every evaluating API rejects appearance after absent observation" {
    eval "$(declare -f rlch_7_1_10_snapshot | sed '1s/rlch_7_1_10_snapshot/real_opasswd_snapshot/')"
    rlch_7_1_10_snapshot() {
        local result="$RLCH_MODULE_RESULT_SUCCESS"
        real_opasswd_snapshot || result=$?
        if [[ ! -e "$SH" ]]; then printf 'artificial new fixture\n' > "$SH"; chmod 0600 "$SH"; fi
        return "$result"
    }
    for api in check validate apply; do rm -f "$SH"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; [ -f "$SH" ]; done
}
@test "7110 fresh apply observes deficit repair and primary absence without cache" {
    expect check "$RLCH_MODULE_RESULT_SUCCESS"; chmod 0664 "$SH"; expect apply "$RLCH_MODULE_RESULT_ERROR"
    chmod 0600 "$SH"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
    rm "$SH"; expect apply "$RLCH_MODULE_RESULT_ERROR"; [ ! -e "$SH" ]
}
@test "7110 zero-mode artificial body preserved through independent preopened descriptors" {
    exec {before_fd}<"$SH"; exec {after_fd}<"$SH"; chmod 0000 "$SH"
    before_hash="$(sha256sum <&"$before_fd")"; before="$(snapshot)"
    for n in 1 2; do for api in check validate; do expect "$api" "$RLCH_MODULE_RESULT_NON_COMPLIANT"; done; expect apply "$RLCH_MODULE_RESULT_ERROR"; run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; done
    after_hash="$(sha256sum <&"$after_fd")"; [ "$before_hash" = "$after_hash" ]; [ "$before" = "$(snapshot)" ]
    exec {before_fd}<&-; exec {after_fd}<&-
}
@test "7110 raw type change takes ERROR precedence over stable ownership deficit" {
    : > "$SH_CALLS"
    rlch_7_1_10_stat() {
        real_sh_stat "$@" | awk -F'|' -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=0;if(n) $7="41a4";print}'
        printf 'call\n' >> "$SH_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 private stat targets only artificial opasswd four times and emits no tuple" {
    rlch_7_1_10_stat() {
        printf '%s\n' "$1" >> "$SH_CALLS"
        real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=0;$5=0;print}'
    }
    expect check "$RLCH_MODULE_RESULT_SUCCESS"
    [ "$(wc -l < "$SH_CALLS")" -eq 4 ]; [ "$(sort -u "$SH_CALLS")" = "$SH" ]; [[ "$output" != *"$R"* ]]
}
@test "7110 all eight account neighbors and foreign config preserved present absent deficit" {
    printf 'artificial foreign config\n' > "$R/etc/foreign.conf"
    fixture_times() {
        local file
        stat -c '%n|%d|%i|%h|%u|%g|%a|%x|%y|%z' -- "$SH" 2>/dev/null || [[ ! -e "$SH" ]]
        for file in shells passwd passwd- group group- shadow shadow- gshadow gshadow- foreign.conf; do
            if [[ -e "$R/etc/$file" ]]; then stat -c '%n|%d|%i|%h|%u|%g|%a|%x|%y|%z' -- "$R/etc/$file"; fi
        done
    }
    for state in present absent deficit; do
        case "$state" in
            present) expected="$RLCH_MODULE_RESULT_SUCCESS";;
            absent) rm "$SH"; expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";;
            deficit) printf 'artificial fixture\n' > "$SH"; chmod 0666 "$SH"; expected="$RLCH_MODULE_RESULT_NON_COMPLIANT";;
        esac
        before="$(fixture_times)"; expect check "$expected"; expect validate "$expected"
        if [[ "$state" == present ]]; then expect apply "$RLCH_MODULE_RESULT_SUCCESS"; else expect apply "$RLCH_MODULE_RESULT_ERROR"; fi
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; [ "$before" = "$(fixture_times)" ]
    done
}
@test "7110 similarly named files cannot substitute for absent primary opasswd" {
    rm "$SH"; printf 'fixture\n' > "$R/etc/security/opasswd-"; printf 'fixture\n' > "$R/etc/security/opasswdx"
    before="$(snapshot)"; absent; [ "$before" = "$(snapshot)" ]; [ ! -e "$SH" ]
}
@test "7110 all UID GID mode changes independently invalidate already deficient tuple" {
    for field in 4 5 6; do
        : > "$SH_CALLS"
        rlch_7_1_10_stat() {
            real_sh_stat "$@" | awk -F'|' -v field="$field" -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {$4=1001;$5=1002;if(field==6){$6=n?"666":"644";$7=n?"81b6":"81a4"}else{$field+=n}print}'
            printf 'call\n' >> "$SH_CALLS"
        }
        expect check "$RLCH_MODULE_RESULT_ERROR"
    done
}
@test "7110 oversized and malformed canonical numeric fields never reach arithmetic" {
    for change in '1=100000000000000000000' '2=100000000000000000000' '4=10000000000' '5=+0' '4=0x0' '5=1e2' '3=01' '6=-1' '7=+81a4'; do
        rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' -v change="$change" 'BEGIN{OFS="|";split(change,a,"=")} {$a[1]=a[2];print}'; }; unknown
    done
}
@test "7110 metadata expressly limits coverage and uses real scalar XCCDF" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/10/metadata.conf"
    [[ "$RLCH_MODULE_DESCRIPTION" == *'partial scope'* && "$RLCH_MODULE_DESCRIPTION" == *'opasswd.old is not assessed'* ]]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_file_etc_security_opasswd ]
}
@test "7110 stable absence uses real observable security parent and no ACL content query" {
    rm "$SH"; before="$(snapshot)"
    rlch_7_1_10_getfacl() { printf 'unexpected\n' >> "$SH_CALLS"; return 99; }
    absent; [ ! -e "$SH_CALLS" ]; [ "$before" = "$(snapshot)" ]
}
@test "7110 absent security parent ERROR never created even with etc present" {
    rm -r "$R/etc/security"; unknown; [ ! -e "$R/etc/security" ]
}
@test "7110 absent target with symlink security parent ERROR" {
    rm "$SH"; mv "$R/etc/security" "$R/real-security"; ln -s ../real-security "$R/etc/security"; unknown
}
@test "7110 absent parent evidence high raw bits ERROR" {
    rm "$SH"
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$7="ffff41ed";print}'; }; unknown
}
@test "7110 parent tuple device inode links UID GID mode ctime changes reject absence" {
    rm "$SH"
    for field in 1 2 3 4 5 6 8; do
        : > "$SH_CALLS"
        rlch_7_1_10_stat() {
            real_sh_stat "$@" | awk -F'|' -v f="$field" -v n="$(wc -l < "$SH_CALLS")" 'BEGIN{OFS="|"} {if(n){if(f==6){$6="700";$7="41c0"}else if(f==8){$8="2026-01-01 00:00:00.000000000 +0000"}else{$f+=1}}print}'
            printf 'call\n' >> "$SH_CALLS"
        }
        for api in check validate apply; do : > "$SH_CALLS"; expect "$api" "$RLCH_MODULE_RESULT_ERROR"; done
    done
}
@test "7110 absence glob isolated from caller settings" {
    rm "$SH"; set -f; shopt -s failglob; GLOBIGNORE='*'; absent
    [[ "$-" == *f* ]]; shopt -q failglob; [ "$GLOBIGNORE" = '*' ]
}
@test "7110 old target unsafe absent or deficient does not enter selected CAS scope" {
    for state in absent present symlink hardlink fifo; do
        rm -f "$R/etc/security/opasswd.old" "$R/etc/security/old-alias"
        case "$state" in
            absent) :;;
            present) printf 'artificial old history\n' > "$R/etc/security/opasswd.old"; chmod 0777 "$R/etc/security/opasswd.old";;
            symlink) ln -s opasswd "$R/etc/security/opasswd.old";;
            hardlink) printf 'fixture\n' > "$R/etc/security/opasswd.old"; ln "$R/etc/security/opasswd.old" "$R/etc/security/old-alias";;
            fifo) mkfifo "$R/etc/security/opasswd.old";;
        esac
        before="$(snapshot)"; expect check "$RLCH_MODULE_RESULT_SUCCESS"; expect apply "$RLCH_MODULE_RESULT_SUCCESS"
        [[ "$output" == *'opasswd.old is not assessed'* ]]; [ "$before" = "$(snapshot)" ]
    done
}
@test "7110 old cannot substitute for missing selected primary" {
    mv "$SH" "$R/etc/security/opasswd.old"; absent; [ ! -e "$SH" ]; [ -f "$R/etc/security/opasswd.old" ]
}
@test "7110 empty missing malformed failed PAM query ERROR" {
    for evidence in '' 'other' 'pam pam'; do
        rlch_7_1_10_platform() { printf '%s\n' "$evidence" | LC_ALL=C /usr/bin/awk '{if(NR!=1 || $0!="pam") exit 2; print} END{if(NR!=1) exit 2}' >/dev/null; }; unknown
    done
    # Exercise production platform boundary rather than its fixture override.
    source "$BATS_TEST_DIRNAME/../modules/cis/7/1/10/module.sh"
    RLCH_CIS_7_1_10_RPM=/missing/rpm; unknown
}
@test "7110 production PAM boundary validates exact output and command status" {
    for body in "printf 'pam\\npam\\n'" "printf 'pam\\000\\n'" "printf 'pam\\n'; exit 1" "exit 1"; do
        printf '#!/usr/bin/env bash\n%s\n' "$body" > "$RLCH_CIS_7_1_10_RPM"; unknown
    done
}
@test "7110 PAM applicability changing between complete snapshots ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_platform() { if [[ -s "$SH_CALLS" ]]; then return 2; fi; printf 'called\n' >> "$SH_CALLS"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 missing ACL tool ERROR even for otherwise conforming stat" {
    RLCH_CIS_7_1_10_GETFACL=/missing/getfacl; unknown
}
@test "7110 valid named zero ACL still NON_COMPLIANT per no extended ACL state" {
    rlch_7_1_10_getfacl() { printf 'user::rw-\nuser:123:---\ngroup::---\nmask::---\nother::---\n'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect validate "$RLCH_MODULE_RESULT_NON_COMPLIANT"; expect apply "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 valid group named ACL and mask-only ACL are deficient" {
    for evidence in $'user::rw-\ngroup::---\ngroup:123:rwx\nmask::---\nother::---' $'user::rw-\ngroup::rwx\nmask::---\nother::---'; do
        rlch_7_1_10_getfacl() { printf '%s\n' "$evidence"; }; expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
    done
}
@test "7110 malformed duplicate incomplete nonnumeric default ACL ERROR" {
    for evidence in '' 'garbage' $'user::rw-\ngroup::---' $'user::rw-\nuser::rw-\ngroup::---\nother::---' $'user::rw-\nuser:bad:r--\ngroup::---\nmask::---\nother::---' $'user::rw-\ngroup::---\nother::---\ndefault:user::rw-' $'user::rw-\nuser:123:r--\ngroup::---\nother::---' $'user::rw-\ngroup::---\nmask:123:---\nother::---'; do
        rlch_7_1_10_getfacl() { printf '%s\n' "$evidence"; }; unknown
    done
}
@test "7110 ACL mode contradiction has ERROR precedence over ownership deficit" {
    rlch_7_1_10_stat() { real_sh_stat "$@" | awk -F'|' 'BEGIN{OFS="|"} {$4=1001;print}'; }
    rlch_7_1_10_getfacl() { printf 'user::r--\ngroup::---\nother::---\n'; }; unknown
}
@test "7110 ACL NUL control oversized excessive records rejected before substitution" {
    rlch_7_1_10_getfacl() { printf 'user::rw-\ngroup::---\nother::---\000\n'; }; unknown
    rlch_7_1_10_getfacl() { printf 'user::rw-\ngroup::---\nother::---\t\n'; }; unknown
    rlch_7_1_10_getfacl() { printf '%065537d\n' 0; }; unknown
    rlch_7_1_10_getfacl() { printf 'user::rw-\ngroup::---\nother::---\n'; for ((n=0;n<1024;n++)); do printf '\n'; done; }; unknown
}
@test "7110 failed getfacl with plausible evidence remains ERROR redacted" {
    rlch_7_1_10_getfacl() { printf 'user::rw-\ngroup::---\nother::---\n'; printf 'PRIVATE ACL error\n' >&2; return 99; }; unknown; [[ "$output" != *PRIVATE* ]]
}
@test "7110 extended ACL changing named identity between snapshots ERROR" {
    : > "$SH_CALLS"
    rlch_7_1_10_getfacl() {
        printf 'user::rw-\nuser:%s:---\ngroup::---\nmask::---\nother::---\n' "$((1001+$(wc -l < "$SH_CALLS")))"
        printf 'call\n' >> "$SH_CALLS"
    }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 metadata changes during ACL collection ERROR" {
    rlch_7_1_10_getfacl() { printf 'user::rw-\ngroup::---\nother::---\n'; chmod 0400 "$SH"; }
    expect check "$RLCH_MODULE_RESULT_ERROR"
}
@test "7110 ACL numeric ID extremes and invalid encodings" {
    for who in 00 -1 +0 4294967295 10000000000; do
        rlch_7_1_10_getfacl() { printf 'user::rw-\nuser:%s:---\ngroup::---\nmask::---\nother::---\n' "$who"; }; unknown
    done
    rlch_7_1_10_getfacl() { printf 'user::rw-\nuser:4294967294:---\ngroup::---\nmask::---\nother::---\n'; }
    expect check "$RLCH_MODULE_RESULT_NON_COMPLIANT"
}
@test "7110 actual command availability never silently bypasses ACL inspection" {
    RLCH_CIS_7_1_10_GETFACL=/missing/getfacl
    expect check "$RLCH_MODULE_RESULT_ERROR"
    [[ "$output" == *'invalid stat/ACL evidence or unproven PAM applicability/tools'* ]]
}
