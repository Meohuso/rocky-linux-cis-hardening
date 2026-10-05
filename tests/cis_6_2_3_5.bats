#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export MR_ROOT="$BATS_TEST_TMPDIR/root" MR_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$MR_ROOT/etc/rsyslog.d" "$MR_ROOT/var/log" "$MR_ROOT/state"
    MR_MAIN="$MR_ROOT/etc/rsyslog.conf"
    printf '*.info /var/log/messages\nauthpriv.* /var/log/secure\n' > "$MR_MAIN"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/5/module.sh"
}
manual() {
    local api
    for api in check validate apply; do
        run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [[ "$output" == *'manual'* && "$output" == *'CIS 6.2.3.5'* ]]
        [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$MR_ROOT"* ]]
    done
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
snapshot_all() {
    (set -o pipefail
     find "$MR_ROOT" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$MR_ROOT" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "6235 metadata exact unmapped Manual Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/5/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.5 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog logging is configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 6.2.3.5; validate_loaded_module_functions
}
@test "6235 framework API direct load and context manual mapping" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/5"
    [ "$RLCH_CURRENT_MODULE_ID" = 6.2.3.5 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    manual
}
@test "6235 framework API direct ERROR result recognized" {
    run module_status_from_result "$RLCH_MODULE_RESULT_ERROR"; [ "$status" -eq 0 ]; [ "$output" = error ]
    is_valid_module_result "$RLCH_MODULE_RESULT_ERROR"
}
@test "6235 framework API direct rollback SUCCESS result recognized" {
    run module_status_from_result "$RLCH_MODULE_RESULT_SUCCESS"; [ "$status" -eq 0 ]; [ "$output" = compliant ]
    is_valid_module_result "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6235 documentation exact Manual no invented mappings or predicates" {
    run sed -n '/^## CIS 6.2.3.5 /,$p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: manual'* && "$output" == *'no rules:'* && "$output" == *'no related_rules:'* && "$output" == *'no official XCCDF or CCE'* && "$output" == *'no automated system observation'* ]]
}
@test "6235 plausible legacy logging requires manual review never SUCCESS" { manual; }
@test "6235 RainerScript valid alternative requires review not invented deficit" {
    printf 'module(load="imjournal")\naction(type="omfile" file="/var/log/messages")\n' > "$MR_MAIN"; manual
}
@test "6235 false textual appearance neutralized by stop never SUCCESS" { printf '*.* stop\n*.* /var/log/messages\n' > "$MR_MAIN"; manual; }
@test "6235 custom rulesets and destinations cannot be certified by grep" {
    printf 'ruleset(name="PRIVATE") { if $msg contains "SECRET" then stop }\n' > "$MR_MAIN"; manual
}
@test "6235 absent default main is not an invented universal deficit" { rm "$MR_MAIN"; manual; }
@test "6235 absent snippets directory requires review not NOT APPLICABLE" { rmdir "$MR_ROOT/etc/rsyslog.d"; manual; }
@test "6235 entirely absent fixture resources still Manual ERROR" { rm -r "$MR_ROOT"; manual; }
@test "6235 empty default configuration cannot establish policy compliance" { : > "$MR_MAIN"; manual; }
@test "6235 comments whitespace and apparent directives cannot establish compliance" { printf ' # *.* /var/log/messages\n\t\n' > "$MR_MAIN"; manual; }
@test "6235 malformed configuration never parsed or exposed" { printf 'SECRET invalid\0\r\n' > "$MR_MAIN"; manual; }
@test "6235 unreadable configuration never read and attributes preserved" {
    chmod 0000 "$MR_MAIN"; before="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$MR_MAIN")"
    manual; after="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$MR_MAIN")"; [ "$before" = "$after" ]
}
@test "6235 FIFO config is not opened and cannot block review marker" { rm "$MR_MAIN"; mkfifo "$MR_MAIN"; manual; }
@test "6235 symlink configuration is not followed" { rm "$MR_MAIN"; ln -s /SECRET/missing "$MR_MAIN"; manual; [ "$(readlink "$MR_MAIN")" = /SECRET/missing ]; }
@test "6235 unselected snippet and included configuration are not conflated" {
    printf 'include(file="/etc/rsyslog.d/*.conf" mode="optional")\n' > "$MR_MAIN"
    printf '*.* /var/log/PRIVATE\n' > "$MR_ROOT/etc/rsyslog.d/20.conf"; manual
}
@test "6235 duplicate reordered logging statements remain a policy review" { printf '*.* /var/log/a\n*.* ~\n*.* /var/log/b\n' > "$MR_MAIN"; manual; }
@test "6235 old file creation mode does not prove logging configuration" { printf '$FileCreateMode 0640\n' > "$MR_MAIN"; manual; }
@test "6235 preexisting log contents do not prove current delivery" { printf 'PRIVATE existing records\n' > "$MR_ROOT/var/log/messages"; manual; }
@test "6235 package service parser and filesystem commands are never queried" {
    for command in rpm systemctl rsyslogd logger service id dnf yum cat grep awk find stat sha256sum cp mv rm chmod chown touch mkdir ln sed curl timeout firewall-cmd openssl systemd-analyze getfacl; do
        eval "$command() { printf '%s\\n' '$command' >> '$MR_CALLS'; return 99; }"
    done
    manual
    # Restore commands before Bats performs its own teardown/cleanup.
    for command in rpm systemctl rsyslogd logger service id dnf yum cat grep awk find stat sha256sum cp mv rm chmod chown touch mkdir ln sed curl timeout firewall-cmd openssl systemd-analyze getfacl; do
        unset -f "$command"
    done
    [ ! -e "$MR_CALLS" ]
}
@test "6235 no parser or observation helper imported" {
    ! declare -F rlch_rpm_inventory
    ! declare -F rlch_systemd_properties
    ! declare -F rlch_journal_config_file
    ! declare -F rlch_6_2_3_4_snapshot
}
@test "6235 no executable PATH dependency" {
    without_path() { local PATH="$BATS_TEST_TMPDIR/absent-bin"; "$@"; }
    for api in check validate apply; do run without_path "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; done
    run without_path rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
@test "6235 fresh validate calls check each time without cached result" {
    check() { printf 'review\n' >> "$MR_CALLS"; return "$RLCH_MODULE_RESULT_ERROR"; }
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(wc -l < "$MR_CALLS")" -eq 2 ]
}
@test "6235 changing configuration between calls never turns into determinable conformity" {
    manual; printf '*.* stop\n' > "$MR_MAIN"; manual; rm "$MR_MAIN"; manual
}
@test "6235 fixed diagnostic independent of secret content or injected path" {
    run check; initial="$output"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'PRIVATE SECRET /sensitive/path\n' > "$MR_MAIN"
    export RLCH_CIS_6_2_3_5_ROOT=$'SECRET\\n/path with spaces'
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$output" = "$initial" ]
}
@test "6235 guidance covers policy actual collection selected includes and ordering" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'organization-approved'* && "$output" == *'ordered includes'* && "$output" == *'rulesets'* && "$output" == *'actual log collection'* && "$output" == *'parser success alone'* ]]
}
@test "6235 apply guidance covers legacy RainerScript discard delivery and exact rollback limit" {
    for repeat in 1 2; do
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [[ "$output" == *'legacy/RainerScript'* && "$output" == *'stop and discard'* && "$output" == *'installed parser'* && "$output" == *'delivery and persistence'* && "$output" == *'no exact rollback'* ]]
    done
}
@test "6235 rollback silent repeatable without resources or observations" { rm -r "$MR_ROOT"; for repeat in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done; }
@test "6235 output bounded fixed diagnostics without exposing system data" {
    for api in check validate apply; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "${#output}" -lt 1024 ]; done
}
@test "6235 APIs produce no standard output or state files" {
    for api in check validate apply; do
        result="$RLCH_MODULE_RESULT_SUCCESS"; "$api" > "$BATS_TEST_TMPDIR/stdout" 2> "$BATS_TEST_TMPDIR/stderr" || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -s "$BATS_TEST_TMPDIR/stdout" ]; [ -s "$BATS_TEST_TMPDIR/stderr" ]
    done
    [ -z "$(find "$MR_ROOT/state" -mindepth 1 -print)" ]
}
@test "6235 preservation all APIs twice regular files directories attributes and links" {
    printf 'PRIVATE key\n' > "$MR_ROOT/state/key"; chmod 0600 "$MR_ROOT/state/key"
    printf 'queue state\n' > "$MR_ROOT/state/cursor"
    printf 'old records\n' > "$MR_ROOT/var/log/messages"
    mkdir -p "$MR_ROOT/etc/systemd"
    printf '[Journal]\nForwardToSyslog=yes\n' > "$MR_ROOT/etc/systemd/journald.conf"
    printf '$FileCreateMode 0640\n' > "$MR_ROOT/etc/rsyslog.d/20.conf"
    ln -s ../var/log/messages "$MR_ROOT/state/admin-link"
    before="$(snapshot_all)"
    for repeat in 1 2; do manual; done
    after="$(snapshot_all)"; [ "$before" = "$after" ]
}
@test "6235 backslash fixture path cannot cause false deficit or mutation" {
    new="$BATS_TEST_TMPDIR/root\nliteral"; mv "$MR_ROOT" "$new"; MR_ROOT="$new"; MR_MAIN="$new/etc/rsyslog.conf"
    before="$(snapshot_all)"; for repeat in 1 2; do manual; done; after="$(snapshot_all)"; [ "$before" = "$after" ]
}
@test "6235 spaces quotes dollar fixture path cannot change review result or preservation" {
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"'; mv "$MR_ROOT" "$new"; MR_ROOT="$new"; MR_MAIN="$new/etc/rsyslog.conf"
    before="$(snapshot_all)"; for repeat in 1 2; do manual; done; after="$(snapshot_all)"; [ "$before" = "$after" ]
}
