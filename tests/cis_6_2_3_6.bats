#!/usr/bin/env bats
# Fixtures are adversarial review context, not inputs to a forwarding parser.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RH_ROOT="$BATS_TEST_TMPDIR/root" RH_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$RH_ROOT/etc/rsyslog.d" "$RH_ROOT/var/log" "$RH_ROOT/state"
    RH_MAIN="$RH_ROOT/etc/rsyslog.conf"
    printf '*.* @@unapproved.example:10514\n' > "$RH_MAIN"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/6/module.sh"
}
review() {
    local api
    for api in check validate apply; do
        run "$api"
        [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [[ "$output" == *'CIS 6.2.3.6: manual'* && "$output" == *'approved'* && "$output" == *'remote'* ]]
        [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RH_ROOT"* && "$output" != *unapproved.example* ]]
    done
    run rollback
    [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
snapshot() {
    (set -o pipefail
     find "$RH_ROOT" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$RH_ROOT" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "6236 metadata Manual L1 no official rule borrowed from related context" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/6/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.6 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog is configured to send logs to a remote log host' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 6.2.3.6; validate_loaded_module_functions
}
@test "6236 documentation separates related rule OVAL address and native RELP context" {
    run sed -n '/^## CIS 6.2.3.6 /,$p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: manual'* && "$output" == *'no rules:'* && "$output" == *'related_rules: [rsyslog_remote_loghost]'* && "$output" == *'context only'* && "$output" == *'CCE-83990-2'* && "$output" == *'remediation only'* && "$output" == *'omrelp'* && "$output" == *'no automated system observation'* ]]
}
@test "6236 framework API direct load isolates previous manual control" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/5"
    run check; [[ "$output" == 'CIS 6.2.3.5:'* ]]
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/6"
    [ "$RLCH_CURRENT_MODULE_ID" = 6.2.3.6 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]
    review
}
@test "6236 framework API direct ERROR and rollback SUCCESS recognized" {
    run module_status_from_result "$RLCH_MODULE_RESULT_ERROR"; [ "$status" -eq 0 ]; [ "$output" = error ]
    run module_status_from_result "$RLCH_MODULE_RESULT_SUCCESS"; [ "$status" -eq 0 ]; [ "$output" = compliant ]
    is_valid_module_result "$RLCH_MODULE_RESULT_ERROR"; is_valid_module_result "$RLCH_MODULE_RESULT_SUCCESS"
}
@test "6236 configured remote target is not approved automatically" { review; }
@test "6236 UDP TCP IPv4 IPv6 and RELP text never certifies the target" {
    for line in '*.* @192.0.2.1:514' '*.* @@[2001:db8::1]:6514' '*.* :omrelp:remote.example:2514'; do
        printf '%s\n' "$line" > "$RH_MAIN"; review
    done
}
@test "6236 plausible omfwd TLS PKI queue and retries still require review" {
    printf 'action(type="omfwd" target="unapproved.example" protocol="tcp" port="6514" StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name" queue.type="linkedList" action.resumeRetryCount="-1")\n' > "$RH_MAIN"
    review
}
@test "6236 multiple conditional targets stop and discard cannot prove expected categories" {
    printf '*.* stop\nif $msg contains "SECRET" then action(type="omfwd" target="PRIVATE")\n*.* @@other.example\n*.* ~\n' > "$RH_MAIN"; review
}
@test "6236 no forwarding or only local logging is not a fabricated automated deficit" { printf '*.* /var/log/messages\n' > "$RH_MAIN"; review; }
@test "6236 absent main snippets package service parser and policy remain review" { rm -r "$RH_ROOT"; review; }
@test "6236 empty comments malformed bytes and apparent forwarding never parsed" {
    for content in '' '# *.* @@unapproved.example' 'action(type="omfwd"'; do printf '%s\n' "$content" > "$RH_MAIN"; review; done
    printf 'SECRET\0\r\n' > "$RH_MAIN"; review
}
@test "6236 inaccessible config attributes preserved without read" {
    chmod 0000 "$RH_MAIN"; before="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RH_MAIN")"
    review; [ "$before" = "$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RH_MAIN")" ]
}
@test "6236 FIFO config never opened" { rm "$RH_MAIN"; mkfifo "$RH_MAIN"; review; }
@test "6236 config symlink never followed or modified" { rm "$RH_MAIN"; ln -s /SECRET/unavailable "$RH_MAIN"; review; [ "$(readlink "$RH_MAIN")" = /SECRET/unavailable ]; }
@test "6236 selected include snippets and unselected targets cannot imply approval" {
    printf 'include(file="/etc/rsyslog.d/*.conf" mode="optional")\n' > "$RH_MAIN"
    printf '*.* @@unapproved.example\n' > "$RH_ROOT/etc/rsyslog.d/20.conf"; review
}
@test "6236 parser package filesystem service and active network spies isolated from cleanup" {
    probe() (
        local command api result expected
        for command in rpm systemctl rsyslogd logger dnf yum cat grep awk find stat sha256sum cp mv rm chmod chown touch mkdir ln sed curl timeout firewall-cmd openssl getfacl ping nc ncat dig host getent ssh; do
            eval "$command() { printf '%s\\n' '$command' >> '$RH_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do
            expected="$RLCH_MODULE_RESULT_ERROR"
            if [[ "$api" == rollback ]]; then expected="$RLCH_MODULE_RESULT_SUCCESS"; fi
            result="$RLCH_MODULE_RESULT_SUCCESS"
            "$api" >/dev/null 2>/dev/null || result=$?
            [[ "$result" -eq "$expected" ]] || return 1
        done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$RH_CALLS" ]
    # Spies lived only in probe's subshell, including on failure.
    ! declare -F rpm; ! declare -F rsyslogd; ! declare -F find; ! declare -F curl
}
@test "6236 no executable PATH dependency or native parser prerequisite" {
    without_path() { local PATH="$BATS_TEST_TMPDIR/no-bin"; "$@"; }
    for api in check validate apply; do run without_path "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; done
    run without_path rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]
}
@test "6236 no production observation helper imported" {
    ! declare -F rlch_journal_config_file; ! declare -F rlch_tmout_directory
    ! declare -F rlch_systemd_properties; ! declare -F rlch_6_2_3_4_snapshot
}
@test "6236 validate performs fresh evaluation each invocation" {
    check() { printf 'review\n' >> "$RH_CALLS"; return "$RLCH_MODULE_RESULT_ERROR"; }
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(wc -l < "$RH_CALLS")" -eq 2 ]
}
@test "6236 changes between calls never establish conformity or deterministic deficit" { review; printf '*.* stop\n' > "$RH_MAIN"; review; rm "$RH_MAIN"; review; }
@test "6236 check distinguishes approval syntax connectivity receipt and retention" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'organization-approved'* && "$output" == *'protocol, port'* && "$output" == *'transport security'* && "$output" == *'log categories'* && "$output" == *'ordered rules/includes'* && "$output" == *'transmission, remote receipt and retention'* && "$output" == *'parser success or connectivity alone'* ]]
}
@test "6236 apply guidance specific remote policy no invented host port PKI or queue" {
    for repeat in 1 2; do
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [[ "$output" == *'approved destination'* && "$output" == *'transport/PKI policy'* && "$output" == *'legacy/RainerScript'* && "$output" == *'templates, queues and retries'* && "$output" == *'installed parser'* && "$output" == *'approved remote host'* && "$output" == *'no exact rollback'* ]]
    done
}
@test "6236 output fixed bounded redacted independent of target content" {
    run check; initial="$output"
    printf '*.* @@SECRET-PRIVATE.example\n' > "$RH_MAIN"
    export RLCH_CIS_6_2_3_6_ROOT=$'SECRET\\n/path with spaces'
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "$output" = "$initial" ]
    for api in check validate apply; do run "$api"; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ "${#output}" -lt 1024 ]; done
}
@test "6236 rollback silent repeatable without resources" { rm -r "$RH_ROOT"; for repeat in 1 2; do run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]; [ -z "$output" ]; done; }
@test "6236 APIs no standard output no state backup or CHANGED" {
    for api in check validate apply; do
        result="$RLCH_MODULE_RESULT_SUCCESS"; "$api" > "$BATS_TEST_TMPDIR/stdout" 2> "$BATS_TEST_TMPDIR/stderr" || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [ ! -s "$BATS_TEST_TMPDIR/stdout" ]; [ -s "$BATS_TEST_TMPDIR/stderr" ]
    done
    [ -z "$(find "$RH_ROOT/state" -mindepth 1 -print)" ]
}
@test "6236 preservation all APIs twice regular contents attributes directories links and prior controls" {
    printf 'PRIVATE key\n' > "$RH_ROOT/state/key"; chmod 0600 "$RH_ROOT/state/key"
    printf 'queue cursor\n' > "$RH_ROOT/state/cursor"
    printf 'old local records\n' > "$RH_ROOT/var/log/messages"
    mkdir -p "$RH_ROOT/etc/systemd" "$RH_ROOT/etc/pki"
    printf '[Journal]\nForwardToSyslog=yes\n' > "$RH_ROOT/etc/systemd/journald.conf"
    printf 'PRIVATE CA\n' > "$RH_ROOT/etc/pki/ca"
    printf '$FileCreateMode 0640\n' > "$RH_ROOT/etc/rsyslog.d/20.conf"
    ln -s ../var/log/messages "$RH_ROOT/state/admin-link"
    before="$(snapshot)"; for repeat in 1 2; do review; done
    [ "$before" = "$(snapshot)" ]
}
@test "6236 backslash fixture root preserved without classification artifact" {
    new="$BATS_TEST_TMPDIR/root\nliteral"; mv "$RH_ROOT" "$new"; RH_ROOT="$new"; RH_MAIN="$new/etc/rsyslog.conf"
    before="$(snapshot)"; for repeat in 1 2; do review; done; [ "$before" = "$(snapshot)" ]
}
@test "6236 spaces quotes dollar fixture root preserved across repeated APIs" {
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"'; mv "$RH_ROOT" "$new"; RH_ROOT="$new"; RH_MAIN="$new/etc/rsyslog.conf"
    before="$(snapshot)"; for repeat in 1 2; do review; done; [ "$before" = "$(snapshot)" ]
}
