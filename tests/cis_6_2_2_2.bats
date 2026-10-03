#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_2_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_2_2_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export FW_STATE="$BATS_TEST_TMPDIR/state" FW_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FW_STATE" "$RLCH_CIS_6_2_2_2_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journald.conf.d
    export FW_MAIN="$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf"
    config "$FW_MAIN" no
    cat > "$RLCH_CIS_6_2_2_2_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FW_CALLS"
[[ "$#" == 4 && "$1" == --no-pager && "$2" == "--root=$RLCH_CIS_6_2_2_2_ROOT" && "$3" == cat-config && "$4" == systemd/journald.conf ]] || { touch "$FW_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_PAGER" == cat && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 ]] || exit 3
if [[ -e "$FW_STATE/error" ]]; then echo SECRET-ERROR >&2; exit 1; fi
if [[ $(wc -l < "$FW_CALLS") -ge 2 && -e "$FW_STATE/second-error" ]]; then exit 1; fi
if [[ -e "$FW_STATE/nul" ]]; then printf '# %s\n[Journal]\nForwardToSyslog=no\0\n' "$FW_MAIN"; exit; fi
if [[ -e "$FW_STATE/large" ]]; then printf '%9000s\n' x; exit; fi
if [[ -e "$FW_STATE/program" ]]; then cat "$FW_STATE/program"; exit; fi
/usr/bin/systemd-analyze "$@" || exit
if [[ -e "$FW_STATE/drift" ]]; then printf '# changed\n' >> "$FW_MAIN"; fi
if [[ -e "$FW_STATE/add" ]]; then printf '[Journal]\nForwardToSyslog=yes\n' > "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/new.conf"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_2_2_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/2/module.sh"
}
config() { printf '[Journal]\nForwardToSyslog=%s\n' "$2" > "$1"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RLCH_CIS_6_2_2_2_ROOT"* ]]; }
review() { expect 2; [[ "$output" == *'explicit disabled forwarding configuration observed'* ]]; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_2_ROOT" "$RLCH_CIS_6_2_2_2_ANALYZE" systemd/journald.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_2_2_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$snapshot"
}
teardown() {
    if [[ -d "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d" && ! -L "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d" ]]; then chmod u+rwx "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d"; fi
}
@test "6222 metadata pending control manual mapping Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.2 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure journald ForwardToSyslog is disabled' ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6222 documentation distinguishes related opposite rule and pending mapping" {
    run sed -n '/^## CIS 6.2.2.2 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: pending'* && "$output" == *'no rules:'* && "$output" == *'related_rules: journald_forward_to_syslog'* && "$output" == *'manual'* ]]
}
@test "6222 no explicit configuration never automatically SUCCESS" { review; }
@test "6222 command only native cat-config twice no daemon action" { review; [ "$(wc -l < "$FW_CALLS")" -eq 2 ]; [ ! -e "$FW_STATE/mutation" ]; }
@test "6222 missing setting NON COMPLIANT even implicit disabled default" { printf '[Journal]\n' > "$FW_MAIN"; expect 1; }
@test "6222 commented setting not explicit NON COMPLIANT" { printf '[Journal]\n#ForwardToSyslog=no\n;ForwardToSyslog=no\n' > "$FW_MAIN"; expect 1; }
@test "6222 absent main and all dropins NON COMPLIANT" { rm "$FW_MAIN"; expect 1; }
@test "6222 absent main explicit etc dropin manual review" { rm "$FW_MAIN"; config "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf" no; review; }
@test "6222 wrong section not policy NON COMPLIANT" { printf '[Upload]\nForwardToSyslog=no\n' > "$FW_MAIN"; expect 1; }
@test "6222 section names case sensitive" { printf '[journal]\nForwardToSyslog=no\n' > "$FW_MAIN"; expect 1; }
@test "6222 key names case sensitive" { printf '[Journal]\nforwardtosyslog=no\n' > "$FW_MAIN"; expect 1; }
@test "6222 main duplicates last valid wins disabled" { printf '[Journal]\nForwardToSyslog=yes\nForwardToSyslog=no\n' > "$FW_MAIN"; review; }
@test "6222 main duplicates last valid wins enabled" { printf '[Journal]\nForwardToSyslog=no\nForwardToSyslog=yes\n' > "$FW_MAIN"; expect 1; }
@test "6222 repeated section retains last scalar" { printf '[Journal]\nForwardToSyslog=yes\n[Upload]\nForwardToSyslog=yes\n[Journal]\nForwardToSyslog=no\n' > "$FW_MAIN"; review; }
@test "6222 whitespace comments unrelated settings preserved" { printf ' # comment\n[Journal]\n\t ForwardToSyslog \t=\t No \t\nStorage=persistent\n# tail\n' > "$FW_MAIN"; review; }
@test "6222 etc dropin overrides main" { config "$FW_MAIN" yes; config "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf" no; review; }
@test "6222 later vendor filename overrides earlier admin filename" { config "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf" no; config "$RLCH_CIS_6_2_2_2_ROOT/usr/lib/systemd/journald.conf.d/90-fw.conf" yes; expect 1; }
@test "6222 same basename etc wins run local vendor" { for dir in run usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_2_ROOT/$dir/systemd/journald.conf.d/20-fw.conf" yes; done; config "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf" no; review; }
@test "6222 same basename run wins local vendor" { for dir in usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_2_ROOT/$dir/systemd/journald.conf.d/20-fw.conf" yes; done; config "$RLCH_CIS_6_2_2_2_ROOT/run/systemd/journald.conf.d/20-fw.conf" no; review; }
@test "6222 same basename local wins vendor" { config "$RLCH_CIS_6_2_2_2_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" yes; config "$RLCH_CIS_6_2_2_2_ROOT/usr/local/lib/systemd/journald.conf.d/20-fw.conf" no; review; }
@test "6222 dev null mask suppresses vendor forwarding without reading target" { config "$RLCH_CIS_6_2_2_2_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" yes; ln -s /dev/null "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; review; }
@test "6222 empty admin dropin overrides vendor same basename" { config "$RLCH_CIS_6_2_2_2_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" yes; touch "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; review; }
@test "6222 file boundary resets section ERROR instead of inheriting Journal" { printf 'ForwardToSyslog=no\n' > "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 selected vendor main ambiguous daemon version ERROR" { mv "$FW_MAIN" "$RLCH_CIS_6_2_2_2_ROOT/usr/lib/systemd/journald.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 incomplete continuation ERROR" { printf '[Journal]\nForwardToSyslog=no\\\n' > "$FW_MAIN"; expect 2; }
@test "6222 malformed section ERROR" { printf '[Journal\nForwardToSyslog=no\n' > "$FW_MAIN"; expect 2; }
@test "6222 assignment before section ERROR" { printf 'ForwardToSyslog=no\n' > "$FW_MAIN"; expect 2; }
@test "6222 unknown malformed line inside Journal ERROR" { printf '[Journal]\nForwardToSyslog=no\nmalformed\n' > "$FW_MAIN"; expect 2; }
@test "6222 inaccessible directory ERROR including root readable mode check" { chmod 0000 "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6222 inaccessible file ERROR" { chmod 0000 "$FW_MAIN"; expect 2; }
@test "6222 FIFO configuration ERROR no block" { rm "$FW_MAIN"; mkfifo "$FW_MAIN"; expect 2; }
@test "6222 directory at configuration path ERROR" { rm "$FW_MAIN"; mkdir "$FW_MAIN"; expect 2; }
@test "6222 symlink configuration ERROR except dev null mask" { mv "$FW_MAIN" "$FW_STATE/target"; ln -s "$FW_STATE/target" "$FW_MAIN"; expect 2; }
@test "6222 symlink directory ERROR" { mv "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d" "$FW_STATE/directory"; ln -s "$FW_STATE/directory" "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6222 unsafe root ERROR" { RLCH_CIS_6_2_2_2_ROOT="$RLCH_CIS_6_2_2_2_ROOT/../root"; expect 2; }
@test "6222 malicious provenance filename ERROR" { touch "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/"$'bad\n.conf'; expect 2; }
@test "6222 header shaped comment ERROR before cat-config" { printf '# /etc/systemd/fake.conf\n' >> "$FW_MAIN"; expect 2; [ ! -e "$FW_CALLS" ]; }
@test "6222 raw file NUL rejected before Bash substitution" { printf '\0' >> "$FW_MAIN"; expect 2; }
@test "6222 raw program NUL ERROR" { touch "$FW_STATE/nul"; expect 2; }
@test "6222 oversized program ERROR" { touch "$FW_STATE/large"; expect 2; }
@test "6222 oversized input line ERROR" { printf '%9000s\n' x >> "$FW_MAIN"; expect 2; }
@test "6222 unavailable command ERROR redacted" { touch "$FW_STATE/error"; expect 2; }
@test "6222 second observation command failure ERROR" { touch "$FW_STATE/second-error"; expect 2; }
@test "6222 missing binary ERROR" { RLCH_CIS_6_2_2_2_ANALYZE="$FW_STATE/missing"; expect 2; }
@test "6222 nonexecutable binary ERROR" { chmod 0644 "$RLCH_CIS_6_2_2_2_ANALYZE"; expect 2; }
@test "6222 content drift even same policy ERROR" { touch "$FW_STATE/drift"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6222 inventory addition during observation ERROR" { touch "$FW_STATE/add"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6222 forged untracked program header ERROR" { printf '# %s\n[Journal]\nForwardToSyslog=no\n' "$FW_STATE/untracked.conf" > "$FW_STATE/program"; expect 2; }
@test "6222 repeated program header ERROR" { for repeat in 1 2; do printf '# %s\n[Journal]\nForwardToSyslog=no\n' "$FW_MAIN"; done > "$FW_STATE/program"; expect 2; }
@test "6222 config text without provenance ERROR" { printf '[Journal]\nForwardToSyslog=no\n' > "$FW_STATE/program"; expect 2; }
@test "6222 check and validate repeatable same result for disabled enabled absent" {
    for value in no yes; do config "$FW_MAIN" "$value"; for repeat in 1 2; do run check; code=$status; diagnostic=$output; run validate; [ "$status" -eq "$code" ]; [ "$output" = "$diagnostic" ]; [ "$code" -ne 0 ]; done; done
    rm "$FW_MAIN"; expect 1; run validate; [ "$status" -eq 1 ]
}
@test "6222 apply repeated ERROR guidance no artificial change even disabled" { for value in no yes; do config "$FW_MAIN" "$value"; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; done; [ ! -e "$FW_STATE/mutation" ]; }
@test "6222 rollback repeatable SUCCESS without command or query" { rm "$RLCH_CIS_6_2_2_2_ANALYZE"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$FW_CALLS" ]; }
@test "6222 all APIs preserve admin files directories symlinks permissions and prior controls" {
    set -o pipefail
    mkdir -p "$RLCH_CIS_6_2_2_2_ROOT"/{etc/pki/private,var/lib/rlch,previous}
    for file in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/pki/private/key.pem etc/rsyslog.conf previous/62211 previous/62212 previous/62213 previous/62214 var/lib/rlch/admin-state; do printf 'SECRET-PRIVATE\n' > "$RLCH_CIS_6_2_2_2_ROOT/$file"; done
    ln -s /dev/null "$RLCH_CIS_6_2_2_2_ROOT/etc/systemd/journald.conf.d/admin-mask.conf"
    before=$(find "$RLCH_CIS_6_2_2_2_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$RLCH_CIS_6_2_2_2_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in systemctl rpm dnf yum openssl curl wget chmod chown rm cp ln sed tee; do printf '#!/usr/bin/env bash\ntouch "$FW_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for repeat in 1 2; do for api in check validate apply rollback; do run "$api"; [ "$status" -ne 4 ]; [[ "$output" != *SECRET* ]]; done; done
    export PATH="$saved_path"
    [ "$(find "$RLCH_CIS_6_2_2_2_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
    [ "$(find "$RLCH_CIS_6_2_2_2_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
    [ ! -e "$FW_STATE/mutation" ]
}
@test "6222 helper direct normalized scalar origin value" { run rows; [ "$status" -eq 0 ]; [ "$output" = "ForwardToSyslog|$FW_MAIN|2|no" ]; }
@test "6222 helper direct absent scalar row" { rm "$FW_MAIN"; run rows; [ "$status" -eq 0 ]; [ "$output" = 'ForwardToSyslog|||' ]; }
@test "6222 helper direct unsupported relative path rejected before command" { run rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_2_ROOT" "$RLCH_CIS_6_2_2_2_ANALYZE" systemd/../journald.conf; [ "$status" -eq 2 ]; [ ! -e "$FW_CALLS" ]; }
@test "6222 helper direct malformed provenance fails" { run rlch_sdconf_scalars "$RLCH_CIS_6_2_2_2_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< $'===program===\n# /untracked.conf\n[Journal]\nForwardToSyslog=no'; [ "$status" -eq 2 ]; }
@test "6222 disabled boolean no technical observation requires review" { config "$FW_MAIN" no; review; }
@test "6222 disabled boolean n technical observation requires review" { config "$FW_MAIN" n; review; }
@test "6222 disabled boolean false technical observation requires review" { config "$FW_MAIN" false; review; }
@test "6222 disabled boolean f technical observation requires review" { config "$FW_MAIN" f; review; }
@test "6222 disabled boolean off technical observation requires review" { config "$FW_MAIN" off; review; }
@test "6222 disabled boolean 0 technical observation requires review" { config "$FW_MAIN" 0; review; }
@test "6222 disabled boolean NO technical observation requires review" { config "$FW_MAIN" NO; review; }
@test "6222 disabled boolean False technical observation requires review" { config "$FW_MAIN" False; review; }
@test "6222 disabled boolean OFF technical observation requires review" { config "$FW_MAIN" OFF; review; }
@test "6222 enabled boolean yes NON COMPLIANT" { config "$FW_MAIN" yes; expect 1; }
@test "6222 enabled boolean y NON COMPLIANT" { config "$FW_MAIN" y; expect 1; }
@test "6222 enabled boolean true NON COMPLIANT" { config "$FW_MAIN" true; expect 1; }
@test "6222 enabled boolean t NON COMPLIANT" { config "$FW_MAIN" t; expect 1; }
@test "6222 enabled boolean on NON COMPLIANT" { config "$FW_MAIN" on; expect 1; }
@test "6222 enabled boolean 1 NON COMPLIANT" { config "$FW_MAIN" 1; expect 1; }
@test "6222 enabled boolean YES NON COMPLIANT" { config "$FW_MAIN" YES; expect 1; }
@test "6222 enabled boolean True NON COMPLIANT" { config "$FW_MAIN" True; expect 1; }
@test "6222 enabled boolean ON NON COMPLIANT" { config "$FW_MAIN" ON; expect 1; }
@test "6222 malformed final value empty ERROR" { config "$FW_MAIN" ''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value quoted ERROR" { config "$FW_MAIN" '"no"'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value singlequoted ERROR" { config "$FW_MAIN" ''\''no'\'''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value inlinecomment ERROR" { config "$FW_MAIN" 'no # comment'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value unknown ERROR" { config "$FW_MAIN" 'auto'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value negative ERROR" { config "$FW_MAIN" '-1'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value multiple ERROR" { config "$FW_MAIN" 'no yes'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value pipe ERROR" { config "$FW_MAIN" 'no|yes'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6222 malformed final value percent ERROR" { config "$FW_MAIN" '%s'; expect 2; [[ "$output" == *unsupported* ]]; }
