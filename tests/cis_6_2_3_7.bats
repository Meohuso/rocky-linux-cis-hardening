#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_3_7_ROOT="$BATS_TEST_TMPDIR/root"
    export NR_ROOT="$RLCH_CIS_6_2_3_7_ROOT" NR_CALLS="$BATS_TEST_TMPDIR/calls"
    NR_MAIN="$NR_ROOT/etc/rsyslog.conf"; NR_DIR="$NR_ROOT/etc/rsyslog.d"
    mkdir -p "$NR_DIR" "$NR_ROOT/state" "$NR_ROOT/var/log"
    printf '*.* /var/log/messages\n' > "$NR_MAIN"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/7/module.sh"
}
teardown() { if [[ -d "$NR_DIR" && ! -L "$NR_DIR" ]]; then chmod u+rwx "$NR_DIR"; fi; }
config() { printf '%s\n' "$@" '*.* /var/log/messages' > "$NR_MAIN"; }
remote() { config 'module(load="imtcp")' 'input(type="imtcp" port="514")'; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *"$NR_ROOT"* ]]; }
model() { local snapshot; snapshot="$(rlch_6_2_3_7_snapshot)" || return 2; rlch_6_2_3_7_model <<< "$snapshot"; }
snapshot() {
    (set -o pipefail
     find "$NR_ROOT" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 1
     find "$NR_ROOT" -type f -exec sha256sum -- {} + | LC_ALL=C sort)
}
@test "6237 metadata Automated L1 context rule never official" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.7 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog is not configured to receive logs from a remote client' ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
    validate_loaded_module_metadata 6.2.3.7; validate_loaded_module_functions
}
@test "6237 framework load and result constants recognized" {
    RLCH_MODULE_ROOT="$RLCH_TEST_REPOSITORY_ROOT/modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/6"
    load_module "$RLCH_TEST_REPOSITORY_ROOT/modules/cis/6/2/3/7"
    [ "$RLCH_CURRENT_MODULE_ID" = 6.2.3.7 ]; [ "$RLCH_CURRENT_MODULE_OPENSCAP_RULE" = manual ]; expect 2
    run module_status_from_result "$RLCH_MODULE_RESULT_NON_COMPLIANT"; [ "$output" = non_compliant ]
}
@test "6237 local logging cannot certify absence" {
    config ; expect 2;
}
@test "6237 empty main" {
    : > "$NR_MAIN"; expect 2;
}
@test "6237 only comments" {
    config '# module(load="imtcp")' '#input(type="imtcp" port="514")'; expect 2;
}
@test "6237 local module only" {
    config 'module(load="imjournal")'; expect 2;
}
@test "6237 imtcp loaded alone not a deficit" {
    config 'module(load="imtcp")'; expect 2;
}
@test "6237 imtcp Rainer input declaration deficit" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514")'; expect 1;
}
@test "6237 imtcp legacy module alone" {
    config '$ModLoad imtcp'; expect 2;
}
@test "6237 imtcp legacy input deficit" {
    config '$ModLoad imtcp' '$InputTCPServerRun 514'; expect 1;
}
@test "6237 imtcp explicit address 127.0.0.1 review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="127.0.0.1")'; expect 2;
}
@test "6237 imtcp explicit address ::1 review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="::1")'; expect 2;
}
@test "6237 imtcp explicit address 192.0.2.1 review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="192.0.2.1")'; expect 2;
}
@test "6237 imtcp explicit address 2001:db8::1 review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="2001:db8::1")'; expect 2;
}
@test "6237 imtcp explicit address ::ffff:127.0.0.1 review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="::ffff:127.0.0.1")'; expect 2;
}
@test "6237 imtcp explicit address example.test review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="example.test")'; expect 2;
}
@test "6237 imtcp explicit address bad:address review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="bad:address")'; expect 2;
}
@test "6237 imtcp explicit address  review" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="")'; expect 2;
}
@test "6237 imtcp explicit wildcard 0.0.0.0" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="0.0.0.0")'; expect 1;
}
@test "6237 imtcp explicit wildcard ::" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" address="::")'; expect 1;
}
@test "6237 imudp loaded alone not a deficit" {
    config 'module(load="imudp")'; expect 2;
}
@test "6237 imudp Rainer input declaration deficit" {
    config 'module(load="imudp")' 'input(type="imudp" port="514")'; expect 1;
}
@test "6237 imudp legacy module alone" {
    config '$ModLoad imudp'; expect 2;
}
@test "6237 imudp legacy input deficit" {
    config '$ModLoad imudp' '$UDPServerRun 514'; expect 1;
}
@test "6237 imudp explicit address 127.0.0.1 review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="127.0.0.1")'; expect 2;
}
@test "6237 imudp explicit address ::1 review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="::1")'; expect 2;
}
@test "6237 imudp explicit address 192.0.2.1 review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="192.0.2.1")'; expect 2;
}
@test "6237 imudp explicit address 2001:db8::1 review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="2001:db8::1")'; expect 2;
}
@test "6237 imudp explicit address ::ffff:127.0.0.1 review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="::ffff:127.0.0.1")'; expect 2;
}
@test "6237 imudp explicit address example.test review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="example.test")'; expect 2;
}
@test "6237 imudp explicit address bad:address review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="bad:address")'; expect 2;
}
@test "6237 imudp explicit address  review" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="")'; expect 2;
}
@test "6237 imudp explicit wildcard 0.0.0.0" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="0.0.0.0")'; expect 1;
}
@test "6237 imudp explicit wildcard ::" {
    config 'module(load="imudp")' 'input(type="imudp" port="514" address="::")'; expect 1;
}
@test "6237 imrelp loaded alone not a deficit" {
    config 'module(load="imrelp")'; expect 2;
}
@test "6237 imrelp Rainer input declaration deficit" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514")'; expect 1;
}
@test "6237 imrelp legacy module alone" {
    config '$ModLoad imrelp'; expect 2;
}
@test "6237 imrelp legacy input deficit" {
    config '$ModLoad imrelp' '$InputRELPServerRun 514'; expect 1;
}
@test "6237 imrelp explicit address 127.0.0.1 review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="127.0.0.1")'; expect 2;
}
@test "6237 imrelp explicit address ::1 review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="::1")'; expect 2;
}
@test "6237 imrelp explicit address 192.0.2.1 review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="192.0.2.1")'; expect 2;
}
@test "6237 imrelp explicit address 2001:db8::1 review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="2001:db8::1")'; expect 2;
}
@test "6237 imrelp explicit address ::ffff:127.0.0.1 review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="::ffff:127.0.0.1")'; expect 2;
}
@test "6237 imrelp explicit address example.test review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="example.test")'; expect 2;
}
@test "6237 imrelp explicit address bad:address review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="bad:address")'; expect 2;
}
@test "6237 imrelp explicit address  review" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="")'; expect 2;
}
@test "6237 imrelp explicit wildcard 0.0.0.0" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="0.0.0.0")'; expect 1;
}
@test "6237 imrelp explicit wildcard ::" {
    config 'module(load="imrelp")' 'input(type="imrelp" port="514" address="::")'; expect 1;
}
@test "6237 tcp star wildcard" {
    config 'module(load="imtcp")' 'input(type="imtcp" address="*" port="514")'; expect 1;
}
@test "6237 udp star wildcard" {
    config 'module(load="imudp")' 'input(type="imudp" address="*" port="514")'; expect 1;
}
@test "6237 relp star not assumed valid" {
    config 'module(load="imrelp")' 'input(type="imrelp" address="*" port="514")'; expect 2;
}
@test "6237 parameter order case whitespace tabs" {
    config 'module ( Load = "imtcp" )' 'input ( PORT = "514" TYPE = "imtcp" )'; expect 1;
}
@test "6237 inline comments quote aware" {
    config 'module(load="imtcp") # SECRET comment' 'input(type="imtcp" port="514")#comment'; expect 1;
}
@test "6237 quoted hash not a comment" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514 # SECRET")'; expect 2;
}
@test "6237 input before module" {
    config 'input(type="imtcp" port="514")' 'module(load="imtcp")'; expect 2;
}
@test "6237 input no module" {
    config 'input(type="imudp" port="514")'; expect 2;
}
@test "6237 multiple inputs different ports" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514")' 'input(type="imtcp" port="1514")'; expect 1;
}
@test "6237 duplicate input ambiguous" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514")' 'input(type="imtcp" port="514")'; expect 2;
}
@test "6237 duplicate module ambiguous" {
    config 'module(load="imudp")' 'module(load="imudp")' 'input(type="imudp" port="514")'; expect 2;
}
@test "6237 duplicate params" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514" Port="515")'; expect 2;
}
@test "6237 unknown parameter dominates deficit" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514")' 'input(type="imtcp" port="515" ruleset="unknown")'; expect 2;
}
@test "6237 module options unresolved" {
    config 'module(load="imtcp" streamDriver.mode="1")' 'input(type="imtcp" port="514")'; expect 2;
}
@test "6237 aggregation comment not exemption" {
    config '# approved aggregation SECRET' 'module(load="imtcp")' 'input(type="imtcp" port="514")'; expect 1;
}
@test "6237 conditional blocks unresolved" {
    config 'module(load="imtcp")' 'if 1 == 1 then { input(type="imtcp" port="514") }'; expect 2;
}
@test "6237 multiline object review" {
    config 'module(load="imtcp")' 'input(type="imtcp"' ' port="514")'; expect 2;
}
@test "6237 single quotes review" {
    config 'module(load='"'"'imtcp'"'"')' 'input(type='"'"'imtcp'"'"' port='"'"'514'"'"')'; expect 2;
}
@test "6237 other input imptcp unresolved" {
    config 'module(load="imptcp")' 'input(type="imptcp" port="514")'; expect 2;
}
@test "6237 other input imdtls unresolved" {
    config 'module(load="imdtls")' 'input(type="imdtls" port="514")'; expect 2;
}
@test "6237 syntax error dominates" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514")' 'SECRET malformed'; expect 2;
}
@test "6237 legacy bind persists before input" {
    config '$ModLoad imtcp' '$InputTCPServerAddress 127.0.0.1' '$InputTCPServerRun 514'; expect 2;
}
@test "6237 legacy udp wildcard" {
    config '$ModLoad imudp' '$UDPServerAddress *' '$UDPServerRun 514'; expect 1;
}
@test "6237 legacy bind after input has unresolved scope" {
    config '$ModLoad imtcp' '$InputTCPServerRun 514' '$InputTCPServerAddress 127.0.0.1'; expect 2;
}
@test "6237 port 0" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="0")'; expect 2;
}
@test "6237 port -1" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="-1")'; expect 2;
}
@test "6237 port 65536" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="65536")'; expect 2;
}
@test "6237 port 999999" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="999999")'; expect 2;
}
@test "6237 port service" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="service")'; expect 2;
}
@test "6237 port 514junk" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="514junk")'; expect 2;
}
@test "6237 port 1" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="1")'; expect 1;
}
@test "6237 port 65535" {
    config 'module(load="imtcp")' 'input(type="imtcp" port="65535")'; expect 1;
}
@test "6237 legacy include selects lexical files at insertion point" {
    config '$ModLoad imtcp' '$IncludeConfig /etc/rsyslog.d/*.conf'
    printf '$InputTCPServerRun 514\n' > "$NR_DIR/20.conf"; expect 1
}
@test "6237 Rainer optional include selects declaration" {
    config 'module(load="imudp")' 'include(file="/etc/rsyslog.d/*.conf" mode="optional")'
    printf 'input(type="imudp" port="514")\n' > "$NR_DIR/20.conf"; expect 1
}
@test "6237 include order module before input across snippets" {
    config '$IncludeConfig /etc/rsyslog.d/*.conf'
    printf '$ModLoad imrelp\n' > "$NR_DIR/10.conf"; printf '$InputRELPServerRun 514\n' > "$NR_DIR/20.conf"; expect 1
    mv "$NR_DIR/10.conf" "$NR_DIR/30.conf"; expect 2
}
@test "6237 include before module is unresolved" {
    config '$IncludeConfig /etc/rsyslog.d/*.conf' '$ModLoad imtcp'
    printf '$InputTCPServerRun 514\n' > "$NR_DIR/20.conf"; expect 2
}
@test "6237 unselected snippet not treated as active declaration" {
    printf '$ModLoad imtcp\n$InputTCPServerRun 514\n' > "$NR_DIR/20.conf"; expect 2
}
@test "6237 unselected unsupported text not a syntax claim" {
    remote; printf 'SECRET unsupported\n' > "$NR_DIR/20.conf"; expect 1
}
@test "6237 hidden and non conf snippets not selected" {
    config '$IncludeConfig /etc/rsyslog.d/*.conf'
    printf '$ModLoad imtcp\n$InputTCPServerRun 514\n' > "$NR_DIR/.hidden.conf"
    cp "$NR_DIR/.hidden.conf" "$NR_DIR/20.disabled"; expect 2
}
@test "6237 nested include rejected without recursion" {
    config '$IncludeConfig /etc/rsyslog.d/*.conf'
    printf '$IncludeConfig /etc/rsyslog.d/*.conf\n' > "$NR_DIR/20.conf"; expect 2
}
@test "6237 arbitrary required dynamic and text includes review" {
    for line in '$IncludeConfig /etc/other/*.conf' 'include(file="/etc/rsyslog.d/*.conf")' 'include(text=`echo SECRET`)' 'include(file="relative")'; do
        remote; printf '%s\n' "$line" >> "$NR_MAIN"; expect 2
    done
}
@test "6237 repeated include duplicate module or port review" {
    config '$IncludeConfig /etc/rsyslog.d/*.conf' '$IncludeConfig /etc/rsyslog.d/*.conf'
    printf '$ModLoad imtcp\n$InputTCPServerRun 514\n' > "$NR_DIR/20.conf"; expect 2
}
@test "6237 absent main never N A or automated deficit" {
    rm "$NR_MAIN"; expect 2;
}
@test "6237 absent snippets directory alone does not hide main declaration" {
    remote; rmdir "$NR_DIR"; expect 1;
}
@test "6237 optional absent directory is not favorable certification" {
    rmdir "$NR_DIR"; config 'include(file="/etc/rsyslog.d/*.conf" mode="optional")'; expect 2;
}
@test "6237 no processing action means unresolved native configuration" {
    printf 'module(load="imtcp")\ninput(type="imtcp" port="514")\n' > "$NR_MAIN"; expect 2;
}
@test "6237 data never sourced or executed" {
    config "touch $BATS_TEST_TMPDIR/EXECUTED"; expect 2; [ ! -e "$BATS_TEST_TMPDIR/EXECUTED" ];
}
@test "6237 escaped quote and continued lines review" {
    remote; printf 'input(type="imtcp" \\\nport="515")\n' >> "$NR_MAIN"; expect 2
    config 'module(load="imtcp")' 'input(type="imtcp" port="514\"SECRET")'; expect 2
}
@test "6237 NUL CR BOM and reserved stream framing rejected" {
    for data in '\0' '\r' '\357\273\277' 'file:SECRET\n' 'stamp:SECRET\n'; do
        remote; printf '%b' "$data" >> "$NR_MAIN"; expect 2
    done
}
@test "6237 excessive line rejected" {
    remote; printf '%9000s\n' x >> "$NR_MAIN"; expect 2;
}
@test "6237 excessive file rejected" {
    head -c 1048577 /dev/zero > "$NR_MAIN"; expect 2;
}
@test "6237 excessive aggregate and candidate count rejected" {
    for n in 1 2 3 4 5; do head -c 900000 /dev/zero | tr '\0' '#' > "$NR_DIR/$n.conf"; done
    expect 2
    rm "$NR_DIR/"*.conf
    for n in {1..1024}; do touch "$NR_DIR/$n.conf"; done
    expect 2
}
@test "6237 unreadable main rejected even root" {
    remote; chmod 0000 "$NR_MAIN"; expect 2;
}
@test "6237 unreadable directory rejected even root" {
    remote; chmod 0000 "$NR_DIR"; expect 2;
}
@test "6237 unreadable unselected snippet rejected" {
    remote; touch "$NR_DIR/20.conf"; chmod 0000 "$NR_DIR/20.conf"; expect 2;
}
@test "6237 writable main and directory unsafe" {
    remote; chmod 0666 "$NR_MAIN"; expect 2; chmod 0644 "$NR_MAIN"; chmod 0777 "$NR_DIR"; expect 2
}
@test "6237 FIFO main never blocked" {
    rm "$NR_MAIN"; mkfifo "$NR_MAIN"; expect 2;
}
@test "6237 FIFO snippet never blocked" {
    mkfifo "$NR_DIR/20.conf"; expect 2;
}
@test "6237 directory main rejected" {
    rm "$NR_MAIN"; mkdir "$NR_MAIN"; expect 2;
}
@test "6237 main symlink rejected not followed" {
    mv "$NR_MAIN" "$BATS_TEST_TMPDIR/target"; ln -s "$BATS_TEST_TMPDIR/target" "$NR_MAIN"; expect 2;
}
@test "6237 directory symlink rejected" {
    mv "$NR_DIR" "$BATS_TEST_TMPDIR/target"; ln -s "$BATS_TEST_TMPDIR/target" "$NR_DIR"; expect 2;
}
@test "6237 dangling or devnull snippets are not masks" {
    ln -s /dev/null "$NR_DIR/20.conf"; expect 2; rm "$NR_DIR/20.conf"; ln -s absent "$NR_DIR/20.conf"; expect 2
}
@test "6237 unsafe root and control filename rejected" {
    RLCH_CIS_6_2_3_7_ROOT="$NR_ROOT/../root"; expect 2; RLCH_CIS_6_2_3_7_ROOT="$NR_ROOT"
    touch "$NR_DIR/"$'bad\n.conf'; expect 2
}
@test "6237 content drift dominates known deficit" {
    remote
    eval "$(declare -f rlch_6_2_3_7_snapshot | sed '1s/rlch_6_2_3_7_snapshot/original_snapshot/')"
    rlch_6_2_3_7_snapshot() { original_snapshot; printf '# drift\n' >> "$NR_MAIN"; }
    expect 2
}
@test "6237 inventory drift dominates known deficit" {
    remote
    eval "$(declare -f rlch_6_2_3_7_snapshot | sed '1s/rlch_6_2_3_7_snapshot/original_snapshot/')"
    rlch_6_2_3_7_snapshot() { original_snapshot; touch "$NR_DIR/new.conf"; }
    expect 2
}
@test "6237 attribute drift dominates known deficit" {
    remote
    eval "$(declare -f rlch_6_2_3_7_snapshot | sed '1s/rlch_6_2_3_7_snapshot/original_snapshot/')"
    rlch_6_2_3_7_snapshot() { original_snapshot; chmod 0600 "$NR_MAIN"; }
    expect 2
}
@test "6237 second observation failure dominates known deficit" {
    remote
    eval "$(declare -f rlch_6_2_3_7_snapshot | sed '1s/rlch_6_2_3_7_snapshot/original_snapshot/')"
    rlch_6_2_3_7_snapshot() { original_snapshot; chmod 0000 "$NR_MAIN"; }
    expect 2
}
@test "6237 validate fresh complete observation" {
    expect 2; remote; run validate; [ "$status" -eq 1 ]; config; run validate; [ "$status" -eq 2 ];
}
@test "6237 apply twice guidance ERROR no CHANGED" {
    remote
    for repeat in 1 2; do run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]; [[ "$output" == *'no exact rollback'* ]]; done
}
@test "6237 rollback twice silent query free" {
    rm -r "$NR_ROOT"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done;
}
@test "6237 helper direct physical file fingerprint" {
    run rlch_journal_config_file "$NR_MAIN"; [ "$status" -eq 0 ]; [[ "$output" == *'|'* ]];
}
@test "6237 helper direct directory never sha256 input" {
    run rlch_journal_config_file "$NR_DIR"; [ "$status" -eq 2 ];
}
@test "6237 helper direct symlink stamp rejection" {
    ln -s "$NR_MAIN" "$NR_DIR/20.conf"; run rlch_tmout_file_stamp "$NR_DIR/20.conf"; [ "$status" -eq 2 ];
}
@test "6237 helper direct unsafe path rejection" {
    run rlch_journal_path "$NR_ROOT/../root/etc/rsyslog.conf"; [ "$status" -eq 2 ];
}
@test "6237 private model direct selected deficit" {
    remote; run model; [ "$status" -eq 1 ]; [ -z "$output" ];
}
@test "6237 private model direct no favorable result" {
    run model; [ "$status" -eq 2 ];
}
@test "6237 native package service socket network commands not invoked spies restored" {
    probe() (
        local command api result expected
        for command in rpm rsyslogd systemctl service dnf ss logger curl nc ncat ping firewall-cmd openssl cp mv rm chmod chown touch mkdir ln; do
            eval "$command() { printf '%s\\n' '$command' >> '$NR_CALLS'; return 99; }"
        done
        for api in check validate apply rollback; do
            expected=2; if [[ "$api" == rollback ]]; then expected=0; fi
            result=0; "$api" >/dev/null 2>/dev/null || result=$?
            [[ "$result" -eq "$expected" ]] || return 1
        done
    )
    run probe; [ "$status" -eq 0 ]; [ ! -e "$NR_CALLS" ]; ! declare -F rm; ! declare -F systemctl
}
@test "6237 all API preservation hashes regular files attributes links prior controls" {
    remote; printf 'SECRET key\n' > "$NR_ROOT/state/key"; chmod 0600 "$NR_ROOT/state/key"
    printf 'queue cursor\n' > "$NR_ROOT/state/cursor"; printf 'existing log\n' > "$NR_ROOT/var/log/messages"
    mkdir -p "$NR_ROOT/etc/systemd"; printf '[Journal]\nForwardToSyslog=yes\n' > "$NR_ROOT/etc/systemd/journald.conf"
    ln -s ../var/log/messages "$NR_ROOT/state/admin-link"
    before="$(snapshot)"
    for repeat in 1 2; do
        expect 1; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
    done
    [ "$before" = "$(snapshot)" ]
    [ "$(readlink "$NR_ROOT/state/admin-link")" = ../var/log/messages ]
}
@test "6237 spaces quotes dollar and literal backslash roots preserve declaration meaning" {
    remote
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"\nliteral'; mv "$NR_ROOT" "$new"
    NR_ROOT="$new"; RLCH_CIS_6_2_3_7_ROOT="$new"; NR_MAIN="$new/etc/rsyslog.conf"; NR_DIR="$new/etc/rsyslog.d"
    before="$(snapshot)"; expect 1; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; [ "$before" = "$(snapshot)" ]
}
@test "6237 public diagnostics bounded redacted and no stdout" {
    remote; printf '# SECRET\n' >> "$NR_MAIN"
    for api in check validate apply; do
        result=0; "$api" > "$BATS_TEST_TMPDIR/stdout" 2> "$BATS_TEST_TMPDIR/stderr" || result=$?
        [ "$result" -ne "$RLCH_MODULE_RESULT_CHANGED" ]; [ ! -s "$BATS_TEST_TMPDIR/stdout" ]; [ "$(wc -c < "$BATS_TEST_TMPDIR/stderr")" -lt 1024 ]
        ! grep -F SECRET "$BATS_TEST_TMPDIR/stderr"; ! grep -F "$NR_ROOT" "$BATS_TEST_TMPDIR/stderr"
    done
    [ -z "$(find "$NR_ROOT/state" -mindepth 1 -print)" ]
}

@test "6237 unproven legacy TCP address even wildcard ERROR" {
    config '$ModLoad imtcp' '$InputTCPServerAddress *' '$InputTCPServerRun 514'; expect 2
}
