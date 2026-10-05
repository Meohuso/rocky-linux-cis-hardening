#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_3_4_ROOT="$BATS_TEST_TMPDIR/root"
    export FM_MAIN="$RLCH_CIS_6_2_3_4_ROOT/etc/rsyslog.conf" FM_DIR="$RLCH_CIS_6_2_3_4_ROOT/etc/rsyslog.d"
    mkdir -p "$FM_DIR"
    config 0640
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/4/module.sh"
}
config() { printf '$FileCreateMode %s\n*.* /var/log/messages\n' "$1" > "$FM_MAIN"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *"$RLCH_CIS_6_2_3_4_ROOT"* ]]; }
model() { local snapshot; snapshot="$(rlch_6_2_3_4_snapshot)" || return 2; rlch_6_2_3_4_model <<< "$snapshot"; }
include() { printf '$IncludeConfig /etc/rsyslog.d/*.conf\n*.* /var/log/messages\n' > "$FM_MAIN"; }
teardown() { if [[ -d "$FM_DIR" && ! -L "$FM_DIR" ]]; then chmod u+rwx "$FM_DIR"; fi; }
@test "6234 metadata exact primary mapping Automated Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.4 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog log file creation mode is configured' ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_rsyslog_filecreatemode ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    validate_loaded_module_metadata 6.2.3.4
    validate_loaded_module_functions
}
@test "6234 documentation primary CAS mapping and conservative adaptation" {
    run sed -n '/^## CIS 6.2.3.4 /,$p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'rules: [rsyslog_filecreatemode]'* && "$output" == *'CCE-88322-3'* && "$output" == *'status: automated'* && "$output" == *'only_one_exists'* && "$output" == *'RainerScript'* ]]
}
@test "6234 favorable legacy evidence never public SUCCESS" { expect 2; }
@test "6234 literal backslash root preserves favorable main identification" {
    new="$BATS_TEST_TMPDIR/root\nliteral"; mv "$RLCH_CIS_6_2_3_4_ROOT" "$new"
    RLCH_CIS_6_2_3_4_ROOT="$new"; FM_MAIN="$new/etc/rsyslog.conf"; FM_DIR="$new/etc/rsyslog.d"
    run model; [ "$status" -eq 0 ]; expect 2
}
@test "6234 literal backslash root preserves actual deficit" {
    config 0666; new="$BATS_TEST_TMPDIR/root\tliteral"; mv "$RLCH_CIS_6_2_3_4_ROOT" "$new"
    RLCH_CIS_6_2_3_4_ROOT="$new"; FM_MAIN="$new/etc/rsyslog.conf"; FM_DIR="$new/etc/rsyslog.d"
    expect 1
}
@test "6234 spaces quotes dollar in fixture root are literal data" {
    new="$BATS_TEST_TMPDIR/"'root $ "quoted"'; mv "$RLCH_CIS_6_2_3_4_ROOT" "$new"
    RLCH_CIS_6_2_3_4_ROOT="$new"; FM_MAIN="$new/etc/rsyslog.conf"; FM_DIR="$new/etc/rsyslog.d"
    run model; [ "$status" -eq 0 ]; expect 2
}
@test "6234 direct model favorable static evidence is not native compliance" { run model; [ "$status" -eq 0 ]; [ -z "$output" ]; }
@test "6234 absent main explicit deficit even unselected snippet" { rm "$FM_MAIN"; printf '$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; expect 1; }
@test "6234 absent main and absent directory deficit" { rm "$FM_MAIN"; rmdir "$FM_DIR"; expect 1; }
@test "6234 absent etc observation impossible ERROR" { rm -r "$RLCH_CIS_6_2_3_4_ROOT/etc"; expect 2; }
@test "6234 absent root ERROR" { RLCH_CIS_6_2_3_4_ROOT="$BATS_TEST_TMPDIR/missing"; expect 2; }
@test "6234 empty main explicit deficit" { : > "$FM_MAIN"; expect 1; }
@test "6234 comment only explicit deficit" { printf '# $FileCreateMode 0640\n# action(type="omfile")\n' > "$FM_MAIN"; expect 1; }
@test "6234 default action lacks explicit mode NON COMPLIANT" { printf '*.* /var/log/messages\n' > "$FM_MAIN"; expect 1; }
@test "6234 mode without file actions unresolved ERROR" { printf '$FileCreateMode 0640\n' > "$FM_MAIN"; expect 2; }
@test "6234 whitespace and trailing comments supported" { printf '  $FileCreateMode \t0640  # note\n \t*.* \t /var/log/messages  # note\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 group writable configuration unsafe ERROR dominates deficit" { config 0666; chmod 0664 "$FM_MAIN"; expect 2; }
@test "6234 world writable configuration unsafe ERROR" { config 0666; chmod 0666 "$FM_MAIN"; expect 2; }
@test "6234 writable etc unsafe ERROR" { chmod 0777 "$RLCH_CIS_6_2_3_4_ROOT/etc"; expect 2; }
@test "6234 writable snippet directory unsafe ERROR" { chmod 0777 "$FM_DIR"; expect 2; }
@test "6234 case sensitive include path never substituted" { printf '$IncludeConfig /etc/RSYSLOG.d/*.CONF\n' > "$FM_MAIN"; expect 2; }
@test "6234 directory action destination ERROR" { printf '*.* /var/log/\n' > "$FM_MAIN"; expect 2; }
@test "6234 aggregate input limit ERROR" {
    for name in 10 20 30 40 50; do
        /usr/bin/awk 'BEGIN {for(i=0;i<14000;i++) print "#123456789012345678901234567890123456789012345678901234567890123456789"}' > "$FM_DIR/$name.conf"
    done
    expect 2
}
@test "6234 directive case insensitive" { printf '$filecreatemode 0640\n*.* /var/log/messages\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 earlier permissive action not cured by later setting" { printf '*.* /var/log/early\n$FileCreateMode 0640\n*.* /var/log/later\n' > "$FM_MAIN"; expect 1; }
@test "6234 later permissive override NON COMPLIANT" { printf '$FileCreateMode 0640\n*.* /var/log/a\n$FileCreateMode 0644\n*.* /var/log/b\n' > "$FM_MAIN"; expect 1; }
@test "6234 unused earlier broad setting then safe setting not false deficit" { printf '$FileCreateMode 0666\n$FileCreateMode 0640\n*.* /var/log/a\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 unused later broad setting does not change earlier action" { printf '$FileCreateMode 0640\n*.* /var/log/a\n$FileCreateMode 0666\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 duplicate good directives legal despite OVAL uniqueness" { printf '$FileCreateMode 0640\n$FileCreateMode 0600\n*.* /var/log/a\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 standard legacy include loading position modeled" { include; printf '$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 lexical snippets last applicable setting broader" { include; printf '$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; printf '$FileCreateMode 0644\n' > "$FM_DIR/90.conf"; expect 1; }
@test "6234 lexical snippets safe later mode" { include; printf '$FileCreateMode 0644\n' > "$FM_DIR/20.conf"; printf '$FileCreateMode 0600\n' > "$FM_DIR/90.conf"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 included file actions retain position not last global mode" { include; printf '*.* /var/log/early\n$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; expect 1; }
@test "6234 include before mode fails earlier action" { printf '$IncludeConfig /etc/rsyslog.d/*.conf\n$FileCreateMode 0640\n*.* /var/log/later\n' > "$FM_MAIN"; printf '*.* /var/log/early\n' > "$FM_DIR/20.conf"; expect 1; }
@test "6234 repeated standard include preserves positional modes" { printf '$FileCreateMode 0640\n$IncludeConfig /etc/rsyslog.d/*.conf\n$IncludeConfig /etc/rsyslog.d/*.conf\n' > "$FM_MAIN"; printf '*.* /var/log/a\n' > "$FM_DIR/20.conf"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 unselected broad snippet cannot neutralize main evidence" { printf '$FileCreateMode 0666\n*.* /var/log/a\n' > "$FM_DIR/20.conf"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 unselected good snippet cannot cure missing main setting" { printf '*.* /var/log/a\n' > "$FM_MAIN"; printf '$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; expect 1; }
@test "6234 optional RainerScript literal include legacy body supported" { printf 'include(file="/etc/rsyslog.d/*.conf" mode="optional")\n*.* /var/log/a\n' > "$FM_MAIN"; printf '$FileCreateMode 0640\n' > "$FM_DIR/20.conf"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 optional RainerScript include absent directory deficit" {
    rmdir "$FM_DIR"; printf 'include(file="/etc/rsyslog.d/*.conf" mode="optional")\n*.* /var/log/a\n' > "$FM_MAIN"; expect 1
    printf 'include(file="/etc/rsyslog.d/*.conf" mode="OPTIONAL")\n*.* /var/log/a\n' > "$FM_MAIN"; expect 2
}
@test "6234 nested include ERROR no recursion" { include; printf '$IncludeConfig /etc/rsyslog.d/*.conf\n' > "$FM_DIR/20.conf"; expect 2; }
@test "6234 arbitrary include ERROR never absent mode deficit" { printf '$IncludeConfig /etc/other/*.conf\n' > "$FM_MAIN"; expect 2; }
@test "6234 RainerScript action valid safe alternative ERROR not NON COMPLIANT" { printf 'action(type="omfile" file="/var/log/a" fileCreateMode="0640")\n' > "$FM_MAIN"; expect 2; }
@test "6234 RainerScript module default valid alternative ERROR" { printf 'module(load="builtin:omfile" fileCreateMode="0600")\naction(type="omfile" file="/var/log/a")\n' > "$FM_MAIN"; expect 2; }
@test "6234 safe legacy plus broader RainerScript action override ERROR" { printf 'action(type="omfile" file="/var/log/a" fileCreateMode="0666")\n' >> "$FM_MAIN"; expect 2; }
@test "6234 mixed RainerScript module and legacy not assumed equivalent" { printf 'module(load="builtin:omfile" fileCreateMode="0640")\n*.* /var/log/a\n' > "$FM_MAIN"; expect 2; }
@test "6234 restrictive explicit umask safe alternative not false deficit" { printf '$Umask 0077\n$FileCreateMode 0666\n*.* /var/log/a\n' > "$FM_MAIN"; expect 2; }
@test "6234 umask after broad action unresolved scope ERROR" { printf '$FileCreateMode 0666\n*.* /var/log/a\n$Umask 0077\n' > "$FM_MAIN"; expect 2; }
@test "6234 explicit zero umask known mode deficit" { printf '$Umask 0000\n$FileCreateMode 0666\n*.* /var/log/a\n' > "$FM_MAIN"; expect 1; }
@test "6234 syntax error dominates known deficit" { config 0666; printf 'not a valid statement SECRET\n' >> "$FM_MAIN"; expect 2; }
@test "6234 incomplete multiline RainerScript ERROR" { printf 'action(type="omfile"\n' >> "$FM_MAIN"; expect 2; }
@test "6234 control NUL ERROR before Bash substitution" { printf '\0' >> "$FM_MAIN"; expect 2; }
@test "6234 control CR ERROR" { printf '\r\n' >> "$FM_MAIN"; expect 2; }
@test "6234 BOM ERROR" { printf '\357\273\277' >> "$FM_MAIN"; expect 2; }
@test "6234 oversized line ERROR" { printf '%9000s\n' x >> "$FM_MAIN"; expect 2; }
@test "6234 oversized file ERROR" { head -c 1048577 /dev/zero > "$FM_MAIN"; expect 2; }
@test "6234 reserved stream marker ERROR" { printf 'file:SECRET\n' >> "$FM_MAIN"; expect 2; }
@test "6234 unreadable main ERROR even privileged observer" { chmod 0000 "$FM_MAIN"; expect 2; }
@test "6234 unreadable selected directory ERROR" { chmod 0000 "$FM_DIR"; expect 2; }
@test "6234 unreadable snippet ERROR even if unselected" { touch "$FM_DIR/20.conf"; chmod 0000 "$FM_DIR/20.conf"; expect 2; }
@test "6234 FIFO main ERROR without blocking" { rm "$FM_MAIN"; mkfifo "$FM_MAIN"; expect 2; }
@test "6234 directory main ERROR" { rm "$FM_MAIN"; mkdir "$FM_MAIN"; expect 2; }
@test "6234 FIFO snippet ERROR without blocking" { mkfifo "$FM_DIR/20.conf"; expect 2; }
@test "6234 symlink main ERROR" { mv "$FM_MAIN" "$BATS_TEST_TMPDIR/target"; ln -s "$BATS_TEST_TMPDIR/target" "$FM_MAIN"; expect 2; }
@test "6234 symlink directory ERROR" { mv "$FM_DIR" "$BATS_TEST_TMPDIR/directory"; ln -s "$BATS_TEST_TMPDIR/directory" "$FM_DIR"; expect 2; }
@test "6234 devnull symlink snippet ERROR not a systemd mask" { ln -s /dev/null "$FM_DIR/20.conf"; expect 2; }
@test "6234 dangling symlink snippet ERROR" { ln -s absent "$FM_DIR/20.conf"; expect 2; }
@test "6234 unsafe noncanonical root ERROR" { RLCH_CIS_6_2_3_4_ROOT="$RLCH_CIS_6_2_3_4_ROOT/../root"; expect 2; }
@test "6234 unsafe filename ERROR" { touch "$FM_DIR/"$'bad\n.conf'; expect 2; }
@test "6234 hidden snippet not selected by glob" { printf '$FileCreateMode 0666\n' > "$FM_DIR/.hidden.conf"; include; expect 1; }
@test "6234 unknown facility syntax ERROR rather than deficit" { printf 'nonsense.info /var/log/a\n' > "$FM_MAIN"; expect 2; }
@test "6234 unknown priority syntax ERROR rather than deficit" { printf 'auth.nonsense /var/log/a\n' > "$FM_MAIN"; expect 2; }
@test "6234 canonical selector exclusions supported" { printf '$FileCreateMode 0640\n*.info;mail.none;authpriv.!debug;cron.=info -/var/log/messages\n' > "$FM_MAIN"; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 dangerous action path ERROR" { printf '$FileCreateMode 0644\n*.* /var/log/../a\n' > "$FM_MAIN"; expect 2; }
@test "6234 dynamic template action ERROR" { printf '*.* ?dynamic\n' >> "$FM_MAIN"; expect 2; }
@test "6234 shell pipe action ERROR never executed" { printf '*.* |/SECRET\n' >> "$FM_MAIN"; expect 2; }
@test "6234 configuration is never sourced" { printf 'touch %s\n' "$BATS_TEST_TMPDIR/EXECUTED" >> "$FM_MAIN"; expect 2; [ ! -e "$BATS_TEST_TMPDIR/EXECUTED" ]; }
@test "6234 snapshot content drift ERROR including unchanged mode" {
    eval "$(declare -f rlch_6_2_3_4_snapshot | sed '1s/rlch_6_2_3_4_snapshot/original_snapshot/')"
    rlch_6_2_3_4_snapshot() { original_snapshot; printf '# changed\n' >> "$FM_MAIN"; }
    expect 2
}
@test "6234 snapshot inventory addition ERROR" {
    eval "$(declare -f rlch_6_2_3_4_snapshot | sed '1s/rlch_6_2_3_4_snapshot/original_snapshot/')"
    rlch_6_2_3_4_snapshot() { original_snapshot; touch "$FM_DIR/new.conf"; }
    config 0666; expect 2
}
@test "6234 snapshot attribute drift ERROR" {
    eval "$(declare -f rlch_6_2_3_4_snapshot | sed '1s/rlch_6_2_3_4_snapshot/original_snapshot/')"
    rlch_6_2_3_4_snapshot() { original_snapshot; chmod 0600 "$FM_MAIN"; }
    config 0666; expect 2
}
@test "6234 second snapshot failure ERROR" {
    eval "$(declare -f rlch_6_2_3_4_snapshot | sed '1s/rlch_6_2_3_4_snapshot/original_snapshot/')"
    rlch_6_2_3_4_snapshot() { original_snapshot; chmod 0000 "$FM_MAIN"; }
    config 0666; expect 2
}
@test "6234 validate fresh observation after administrative change" { expect 2; config 0666; run validate; [ "$status" -eq 1 ]; }
@test "6234 apply always guidance ERROR twice without unjustified CHANGED" { for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'exactly rolled back'* ]]; done; }
@test "6234 rollback repeatable query free even absent config root" { rm -r "$RLCH_CIS_6_2_3_4_ROOT"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; }
@test "6234 package service and native binary absent not guessed NOT APPLICABLE" {
    for cmd in rpm systemctl rsyslogd logger service dnf firewall-cmd openssl; do
        eval "$cmd() { printf 'forbidden %s\\n' '$cmd' >> '$BATS_TEST_TMPDIR/forbidden'; return 99; }"
    done
    expect 2; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; [ ! -e "$BATS_TEST_TMPDIR/forbidden" ]
}
@test "6234 helper direct physical configuration hash regular files only" { run rlch_journal_config_file "$FM_MAIN"; [ "$status" -eq 0 ]; [[ "$output" == *'|'* ]]; }
@test "6234 helper direct directory never passed to sha256sum" { run rlch_journal_config_file "$FM_DIR"; [ "$status" -eq 2 ]; }
@test "6234 helper direct config stamp rejects symlink" { ln -s "$FM_MAIN" "$FM_DIR/20.conf"; run rlch_tmout_file_stamp "$FM_DIR/20.conf"; [ "$status" -eq 2 ]; }
@test "6234 preservation content attributes links administrator state all APIs twice" {
    mkdir -p "$RLCH_CIS_6_2_3_4_ROOT/var/log" "$RLCH_CIS_6_2_3_4_ROOT/state" "$RLCH_CIS_6_2_3_4_ROOT/etc/systemd"
    printf 'SECRET KEY\n' > "$RLCH_CIS_6_2_3_4_ROOT/state/key"; chmod 0600 "$RLCH_CIS_6_2_3_4_ROOT/state/key"
    printf 'existing log\n' > "$RLCH_CIS_6_2_3_4_ROOT/var/log/messages"
    printf '[Journal]\nForwardToSyslog=yes\n' > "$RLCH_CIS_6_2_3_4_ROOT/etc/systemd/journald.conf"
    ln -s ../var/log/messages "$RLCH_CIS_6_2_3_4_ROOT/state/admin-link"
    snapshot_all() { (set -o pipefail; find "$RLCH_CIS_6_2_3_4_ROOT" -printf '%p|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort || return 2; find "$RLCH_CIS_6_2_3_4_ROOT" -type f -exec sha256sum -- {} + | LC_ALL=C sort); }
    for mode in 0640 0666 invalid; do
        config "$mode"; before="$(snapshot_all)"
        for repeat in 1 2; do
            run check; if [[ "$mode" == 0666 ]]; then [ "$status" -eq 1 ]; else [ "$status" -eq 2 ]; fi
            run validate; if [[ "$mode" == 0666 ]]; then [ "$status" -eq 1 ]; else [ "$status" -eq 2 ]; fi
            run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
        done
        after="$(snapshot_all)"; [ "$before" = "$after" ]
    done
}
@test "6234 subset mode 0000 favorable static evidence manual review" { config 0000; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0040 favorable static evidence manual review" { config 0040; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0200 favorable static evidence manual review" { config 0200; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0240 favorable static evidence manual review" { config 0240; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0400 favorable static evidence manual review" { config 0400; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0440 favorable static evidence manual review" { config 0440; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0600 favorable static evidence manual review" { config 0600; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 subset mode 0640 favorable static evidence manual review" { config 0640; run model; [ "$status" -eq 0 ]; expect 2; }
@test "6234 forbidden permission bit mode 0001 NON COMPLIANT" { config 0001; expect 1; }
@test "6234 forbidden permission bit mode 0004 NON COMPLIANT" { config 0004; expect 1; }
@test "6234 forbidden permission bit mode 0010 NON COMPLIANT" { config 0010; expect 1; }
@test "6234 forbidden permission bit mode 0100 NON COMPLIANT" { config 0100; expect 1; }
@test "6234 forbidden permission bit mode 0601 NON COMPLIANT" { config 0601; expect 1; }
@test "6234 forbidden permission bit mode 0610 NON COMPLIANT" { config 0610; expect 1; }
@test "6234 forbidden permission bit mode 0641 NON COMPLIANT" { config 0641; expect 1; }
@test "6234 forbidden permission bit mode 0644 NON COMPLIANT" { config 0644; expect 1; }
@test "6234 forbidden permission bit mode 0660 NON COMPLIANT" { config 0660; expect 1; }
@test "6234 forbidden permission bit mode 0666 NON COMPLIANT" { config 0666; expect 1; }
@test "6234 forbidden permission bit mode 0700 NON COMPLIANT" { config 0700; expect 1; }
@test "6234 forbidden permission bit mode 0755 NON COMPLIANT" { config 0755; expect 1; }
@test "6234 forbidden permission bit mode 0777 NON COMPLIANT" { config 0777; expect 1; }
@test "6234 malformed mode case '640' ERROR" { config '640'; expect 2; }
@test "6234 malformed mode case '06400' ERROR" { config '06400'; expect 2; }
@test "6234 malformed mode case '0888' ERROR" { config '0888'; expect 2; }
@test "6234 malformed mode case '-1' ERROR" { config '-1'; expect 2; }
@test "6234 malformed mode case '0x1a0' ERROR" { config '0x1a0'; expect 2; }
@test "6234 malformed mode case '0640quoted' ERROR" { config '"0640"'; expect 2; }
@test "6234 malformed mode case '0640junk' ERROR" { config '0640junk'; expect 2; }
@test "6234 malformed mode case '1640' ERROR" { config '1640'; expect 2; }
@test "6234 malformed mode case '4640' ERROR" { config '4640'; expect 2; }
@test "6234 malformed mode case '' ERROR" { config ''; expect 2; }
