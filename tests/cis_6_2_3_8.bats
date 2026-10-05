#!/usr/bin/env bats
# Adversarial fixtures are preservation/review context, not parsed evidence.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export LR_ROOT="$BATS_TEST_TMPDIR/root" LR_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$LR_ROOT/etc/logrotate.d" "$LR_ROOT/etc/rsyslog.d" "$LR_ROOT/var/log" "$LR_ROOT/var/lib/logrotate"
    LR_MAIN="$LR_ROOT/etc/logrotate.conf"
    printf 'weekly\nrotate 4\ninclude /etc/logrotate.d\n' > "$LR_MAIN"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/8/module.sh"
}
review() {
    local api
    for api in check validate apply; do
        run "$api"
        [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [[ "$output" == 'CIS 6.2.3.8: manual'* && "$output" == *'approved'* && "$output" == *rsyslog* ]]
        [[ "$output" != *SECRET* && "$output" != *"$LR_ROOT"* ]]
    done
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
snapshot() {
    (set -o pipefail
     find "$LR_ROOT" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$LR_ROOT" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "6238 metadata Manual L1 exact title no related XCCDF assigned" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/8/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.8 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog logrotate is configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 6.2.3.8; validate_loaded_module_functions
}
@test "6238 framework load isolates previous observation API" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/7"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/8"
    [ "$RLCH_CURRENT_MODULE_ID" = 6.2.3.8 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]; review
}
@test "6238 framework recognizes manual ERROR and no-op SUCCESS" {
    run module_status_from_result "$RLCH_MODULE_RESULT_ERROR"; [ "$status" -eq 0 ]; [ "$output" = error ]
    is_valid_module_result "$RLCH_MODULE_RESULT_ERROR"; is_valid_module_result "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6238 repeated APIs require review and never CHANGED" {
    for repeat in 1 2; do review; done
}
@test "6238 fresh validate delegates on every invocation" {
    check() { printf 'fresh\n' >> "$LR_CALLS"; return "$RLCH_MODULE_RESULT_ERROR"; }
    for repeat in 1 2; do run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; done
    [ "$(wc -l < "$LR_CALLS")" -eq 2 ]
}
@test "6238 no package binary timer parser or root prerequisite" {
    without_path() { local PATH="$BATS_TEST_TMPDIR/no-bin"; "$@"; }
    for api in check validate apply; do run without_path "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; done
    run without_path rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
@test "6238 no observation helper imported in fresh shell" {
    ! declare -F rlch_journal_config_file; ! declare -F rlch_tmout_directory
    ! declare -F rlch_systemd_properties; ! declare -F rlch_rpm_package_status
}
@test "6238 absent resources never imply NOT_APPLICABLE or deficit" {
    rm -r "$LR_ROOT"; review
}
@test "6238 empty commented malformed and plausible configurations remain review" {
    for text in '' '# SECRET daily rotate 99' 'malformed { SECRET' 'daily' 'weekly'; do
        printf '%s\n' "$text" > "$LR_MAIN"; review
    done
}
@test "6238 plausible rsyslog stanza policy is not invented" {
    printf '/var/log/messages /var/log/secure {\n daily\n rotate 7\n compress\n delaycompress\n missingok\n notifempty\n create 0640 root root\n sharedscripts\n postrotate\n kill -HUP SECRET\n endscript\n}\n' > "$LR_ROOT/etc/logrotate.d/syslog"
    review
}
@test "6238 global local overrides includes globs duplicate scripts are not parsed" {
    printf 'monthly\ninclude /etc/logrotate.d\ndaily\n' > "$LR_MAIN"
    printf '/var/log/*.log {\n weekly\n size 1M\n minsize 2M\n maxsize 3M\n copytruncate\n prerotate\n touch SECRET\n endscript\n}\n/var/log/*.log { rotate 9 }\n' > "$LR_ROOT/etc/logrotate.d/custom"
    review; [ ! -e SECRET ]
}
@test "6238 rsyslog absent journald only custom or remote logs remain human applicability" {
    for text in '' '*.* @@remote.example' '*.* /custom/PRIVATE.log' 'module(load="imjournal")'; do
        printf '%s\n' "$text" > "$LR_ROOT/etc/rsyslog.conf"; review
    done
}
@test "6238 timer cron custom scheduling and state history are not CIS proof" {
    mkdir -p "$LR_ROOT/etc/systemd/system/timers.target.wants" "$LR_ROOT/etc/cron.daily"
    printf 'logrotate /etc/logrotate.conf\n' > "$LR_ROOT/etc/cron.daily/logrotate"
    printf 'logrotate state -- version 2\n"/var/log/messages" 2026-10-5-0:0:0\n' > "$LR_ROOT/var/lib/logrotate/logrotate.status"
    ln -s /vendor/logrotate.timer "$LR_ROOT/etc/systemd/system/timers.target.wants/logrotate.timer"
    before="$(snapshot)"; review; [ "$before" = "$(snapshot)" ]
}
@test "6238 unreadable symlink special and missing include fixtures never read" {
    chmod 0000 "$LR_MAIN"; review
    chmod 0644 "$LR_MAIN"; rm "$LR_MAIN"; ln -s /dev/null "$LR_MAIN"; review
    rm "$LR_MAIN"; mkfifo "$LR_MAIN"; review
    rm "$LR_MAIN"; printf 'include /SECRET/missing\n' > "$LR_MAIN"; review
}
@test "6238 changes between calls never establish conformity" {
    review; printf 'yearly\nrotate 0\n' > "$LR_MAIN"; review; rm "$LR_MAIN"; review
}
@test "6238 check guidance separates coverage configuration execution continuity and policy" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    for word in 'retention policy' 'ordered includes' 'global/local overrides' 'actual execution' 'frequency' 'rotate count' 'size' 'compression' 'create owner/group/mode' 'rotation scripts' 'installed package, enabled timer, parser success or rotation history alone' 'continues writing'; do [[ "$output" == *"$word"* ]]; done
}
@test "6238 apply guidance requires policy native validation controlled rotation no invented settings" {
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    for word in 'capacity' 'includes/globs' 'duplicate stanzas' 'timer/cron/custom' 'state path' 'prerotate/postrotate' 'non-mutating debug' 'validation environment' 'do not invent' 'no automatic rotation, state update, reload or restart'; do [[ "$output" == *"$word"* ]]; done
}
@test "6238 command spies prove no rotation read write package timer signal network actions" {
    probe() (
        local command api result expected
        for command in logrotate rsyslogd systemctl service rpm dnf yum crontab anacron logger kill killall pkill cat grep awk sed find stat sha256sum cp mv rm chmod chown touch mkdir ln curl timeout ss; do
            eval "$command() { printf '%s\n' '$command' >> '$LR_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do
            expected="$RLCH_MODULE_RESULT_ERROR"
            if [[ "$api" == rollback ]]; then expected="$RLCH_MODULE_RESULT_SUCCESS"; fi
            result="$RLCH_MODULE_RESULT_SUCCESS"; "$api" >/dev/null 2>/dev/null || result=$?
            [[ "$result" -eq "$expected" ]] || return 1
        done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$LR_CALLS" ]
    ! declare -F rm; ! declare -F systemctl; ! declare -F logrotate; ! declare -F kill
}
@test "6238 rollback silent repeatable without resources" {
    rm -r "$LR_ROOT"
    for repeat in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done
}
@test "6238 fixed redacted bounded stderr no stdout and no module state" {
    run check; initial="$output"
    printf 'SECRET PRIVATE\n' > "$LR_MAIN"; run check; [ "$output" = "$initial" ]
    for api in check validate apply; do
        result="$RLCH_MODULE_RESULT_SUCCESS"; "$api" > "$BATS_TEST_TMPDIR/stdout" 2> "$BATS_TEST_TMPDIR/stderr" || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -s "$BATS_TEST_TMPDIR/stdout" ]; [ -s "$BATS_TEST_TMPDIR/stderr" ]
        [ "$(wc -c < "$BATS_TEST_TMPDIR/stderr")" -lt 1024 ]
        ! grep -F SECRET "$BATS_TEST_TMPDIR/stderr"; ! grep -F "$LR_ROOT" "$BATS_TEST_TMPDIR/stderr"
    done
}
@test "6238 preservation repeated APIs regular hashes metadata links config logs and state" {
    printf '*.* /var/log/messages\n' > "$LR_ROOT/etc/rsyslog.conf"
    printf '$FileCreateMode 0640\n' > "$LR_ROOT/etc/rsyslog.d/20.conf"
    printf 'PRIVATE records\n' > "$LR_ROOT/var/log/messages"; chmod 0640 "$LR_ROOT/var/log/messages"
    printf 'PRIVATE state\n' > "$LR_ROOT/var/lib/logrotate/logrotate.status"; chmod 0600 "$LR_ROOT/var/lib/logrotate/logrotate.status"
    ln -s ../rsyslog.conf "$LR_ROOT/etc/logrotate.d/admin-link"
    mkdir -p "$LR_ROOT/etc/systemd"; printf '[Journal]\nForwardToSyslog=yes\n' > "$LR_ROOT/etc/systemd/journald.conf"
    before="$(snapshot)"; for repeat in 1 2; do review; done; [ "$before" = "$(snapshot)" ]
}
@test "6238 unusual fixture paths do not change result or preservation" {
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"\nliteral'; mv "$LR_ROOT" "$new"; LR_ROOT="$new"; LR_MAIN="$new/etc/logrotate.conf"
    before="$(snapshot)"; for repeat in 1 2; do review; done; [ "$before" = "$(snapshot)" ]
}
