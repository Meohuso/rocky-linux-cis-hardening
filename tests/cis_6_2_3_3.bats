#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_3_3_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_3_3_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export FW_STATE="$BATS_TEST_TMPDIR/state" FW_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FW_STATE" "$RLCH_CIS_6_2_3_3_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journald.conf.d
    export FW_MAIN="$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf"
    config "$FW_MAIN" yes
    cat > "$RLCH_CIS_6_2_3_3_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FW_CALLS"
[[ "$#" == 4 && "$1" == --no-pager && "$2" == "--root=$RLCH_CIS_6_2_3_3_ROOT" && "$3" == cat-config && "$4" == systemd/journald.conf ]] || { touch "$FW_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_PAGER" == cat && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 ]] || exit 3
if [[ -e "$FW_STATE/error" ]]; then echo SECRET-ERROR >&2; exit 1; fi
if [[ $(wc -l < "$FW_CALLS") -ge 2 && -e "$FW_STATE/second-error" ]]; then exit 1; fi
if [[ -e "$FW_STATE/nul" ]]; then printf '# %s\n[Journal]\nForwardToSyslog=yes\0\n' "$FW_MAIN"; exit; fi
if [[ -e "$FW_STATE/large" ]]; then printf '%9000s\n' x; exit; fi
if [[ -e "$FW_STATE/program" ]]; then cat "$FW_STATE/program"; exit; fi
/usr/bin/systemd-analyze "$@" || exit
if [[ -e "$FW_STATE/drift" ]]; then printf '# changed\n' >> "$FW_MAIN"; fi
if [[ -e "$FW_STATE/add" ]]; then printf '[Journal]\nForwardToSyslog=no\n' > "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/new.conf"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_3_3_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/3/module.sh"
}
config() { printf '[Journal]\nForwardToSyslog=%s\n' "$2" > "$1"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RLCH_CIS_6_2_3_3_ROOT"* ]]; }
review() { expect 2; [[ "$output" == *'explicit enabled forwarding configuration observed'* ]]; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_3_3_ROOT" "$RLCH_CIS_6_2_3_3_ANALYZE" systemd/journald.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_3_3_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< "$snapshot"
}
teardown() {
    if [[ -d "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d" && ! -L "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d" ]]; then chmod u+rwx "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d"; fi
}
@test "6233 metadata supported control manual mapping Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.3 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure journald is configured to send logs to rsyslog' ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6233 documentation exact supported related only mapping" {
    run sed -n '/^## CIS 6.2.3.3 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: supported'* && "$output" == *'no rules:'* && "$output" == *'related_rules: [journald_forward_to_syslog]'* && "$output" == *'CCE-85996-7'* && "$output" == *'context only'* && "$output" == *'NOT an official CIS mapping'* ]]
}
@test "6233 explicit enabled configuration never automatically SUCCESS" { review; }
@test "6233 command only native cat-config twice no daemon action" { review; [ "$(wc -l < "$FW_CALLS")" -eq 2 ]; [ ! -e "$FW_STATE/mutation" ]; }
@test "6233 missing setting NON COMPLIANT without inferred default" { printf '[Journal]\n' > "$FW_MAIN"; expect 1; }
@test "6233 commented setting not explicit NON COMPLIANT" { printf '[Journal]\n#ForwardToSyslog=yes\n;ForwardToSyslog=yes\n' > "$FW_MAIN"; expect 1; }
@test "6233 absent main and all dropins NON COMPLIANT" { rm "$FW_MAIN"; expect 1; }
@test "6233 absent main explicit etc dropin manual review" { rm "$FW_MAIN"; config "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf" yes; review; }
@test "6233 wrong section not policy NON COMPLIANT" { printf '[Upload]\nForwardToSyslog=yes\n' > "$FW_MAIN"; expect 1; }
@test "6233 section names case sensitive" { printf '[journal]\nForwardToSyslog=yes\n' > "$FW_MAIN"; expect 1; }
@test "6233 key names case sensitive" { printf '[Journal]\nforwardtosyslog=yes\n' > "$FW_MAIN"; expect 1; }
@test "6233 main duplicates last valid wins enabled" { printf '[Journal]\nForwardToSyslog=no\nForwardToSyslog=yes\n' > "$FW_MAIN"; review; }
@test "6233 main duplicates last valid wins disabled" { printf '[Journal]\nForwardToSyslog=yes\nForwardToSyslog=no\n' > "$FW_MAIN"; expect 1; }
@test "6233 repeated section retains last scalar" { printf '[Journal]\nForwardToSyslog=no\n[Upload]\nForwardToSyslog=no\n[Journal]\nForwardToSyslog=yes\n' > "$FW_MAIN"; review; }
@test "6233 whitespace comments unrelated settings preserved" { printf ' # comment\n[Journal]\n\t ForwardToSyslog \t=\t Yes \t\nStorage=persistent\n# tail\n' > "$FW_MAIN"; review; }
@test "6233 etc dropin overrides main" { config "$FW_MAIN" no; config "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf" yes; review; }
@test "6233 later vendor filename overrides earlier admin filename" { config "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf" yes; config "$RLCH_CIS_6_2_3_3_ROOT/usr/lib/systemd/journald.conf.d/90-fw.conf" no; expect 1; }
@test "6233 same basename etc wins run local vendor" { for dir in run usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_3_3_ROOT/$dir/systemd/journald.conf.d/20-fw.conf" no; done; config "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf" yes; review; }
@test "6233 same basename run wins local vendor" { for dir in usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_3_3_ROOT/$dir/systemd/journald.conf.d/20-fw.conf" no; done; config "$RLCH_CIS_6_2_3_3_ROOT/run/systemd/journald.conf.d/20-fw.conf" yes; review; }
@test "6233 same basename local wins vendor" { config "$RLCH_CIS_6_2_3_3_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" no; config "$RLCH_CIS_6_2_3_3_ROOT/usr/local/lib/systemd/journald.conf.d/20-fw.conf" yes; review; }
@test "6233 dev null mask suppresses vendor forwarding without reading target" { config "$RLCH_CIS_6_2_3_3_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" no; ln -s /dev/null "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; review; }
@test "6233 empty admin dropin overrides vendor same basename" { config "$RLCH_CIS_6_2_3_3_ROOT/usr/lib/systemd/journald.conf.d/20-fw.conf" no; touch "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; review; }
@test "6233 file boundary resets section ERROR instead of inheriting Journal" { printf 'ForwardToSyslog=yes\n' > "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 selected vendor main ambiguous daemon version ERROR" { mv "$FW_MAIN" "$RLCH_CIS_6_2_3_3_ROOT/usr/lib/systemd/journald.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 incomplete continuation ERROR" { printf '[Journal]\nForwardToSyslog=yes\\\n' > "$FW_MAIN"; expect 2; }
@test "6233 malformed section ERROR" { printf '[Journal\nForwardToSyslog=yes\n' > "$FW_MAIN"; expect 2; }
@test "6233 assignment before section ERROR" { printf 'ForwardToSyslog=yes\n' > "$FW_MAIN"; expect 2; }
@test "6233 unknown malformed line inside Journal ERROR" { printf '[Journal]\nForwardToSyslog=yes\nmalformed\n' > "$FW_MAIN"; expect 2; }
@test "6233 inaccessible directory ERROR including root readable mode check" { chmod 0000 "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6233 inaccessible file ERROR" { chmod 0000 "$FW_MAIN"; expect 2; }
@test "6233 FIFO configuration ERROR no block" { rm "$FW_MAIN"; mkfifo "$FW_MAIN"; expect 2; }
@test "6233 directory at configuration path ERROR" { rm "$FW_MAIN"; mkdir "$FW_MAIN"; expect 2; }
@test "6233 symlink configuration ERROR except dev null mask" { mv "$FW_MAIN" "$FW_STATE/target"; ln -s "$FW_STATE/target" "$FW_MAIN"; expect 2; }
@test "6233 symlink directory ERROR" { mv "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d" "$FW_STATE/directory"; ln -s "$FW_STATE/directory" "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6233 unsafe root ERROR" { RLCH_CIS_6_2_3_3_ROOT="$RLCH_CIS_6_2_3_3_ROOT/../root"; expect 2; }
@test "6233 malicious provenance filename ERROR" { touch "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/"$'bad\n.conf'; expect 2; }
@test "6233 header shaped comment ERROR before cat-config" { printf '# /etc/systemd/fake.conf\n' >> "$FW_MAIN"; expect 2; [ ! -e "$FW_CALLS" ]; }
@test "6233 raw file NUL rejected before Bash substitution" { printf '\0' >> "$FW_MAIN"; expect 2; }
@test "6233 raw program NUL ERROR" { touch "$FW_STATE/nul"; expect 2; }
@test "6233 oversized program ERROR" { touch "$FW_STATE/large"; expect 2; }
@test "6233 oversized input line ERROR" { printf '%9000s\n' x >> "$FW_MAIN"; expect 2; }
@test "6233 unavailable command ERROR redacted" { touch "$FW_STATE/error"; expect 2; }
@test "6233 second observation command failure ERROR" { touch "$FW_STATE/second-error"; expect 2; }
@test "6233 missing binary ERROR" { RLCH_CIS_6_2_3_3_ANALYZE="$FW_STATE/missing"; expect 2; }
@test "6233 nonexecutable binary ERROR" { chmod 0644 "$RLCH_CIS_6_2_3_3_ANALYZE"; expect 2; }
@test "6233 content drift even same policy ERROR" { touch "$FW_STATE/drift"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6233 inventory addition during observation ERROR" { touch "$FW_STATE/add"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6233 forged untracked program header ERROR" { printf '# %s\n[Journal]\nForwardToSyslog=yes\n' "$FW_STATE/untracked.conf" > "$FW_STATE/program"; expect 2; }
@test "6233 repeated program header ERROR" { for repeat in 1 2; do printf '# %s\n[Journal]\nForwardToSyslog=yes\n' "$FW_MAIN"; done > "$FW_STATE/program"; expect 2; }
@test "6233 config text without provenance ERROR" { printf '[Journal]\nForwardToSyslog=yes\n' > "$FW_STATE/program"; expect 2; }
@test "6233 check and validate repeatable same result for disabled enabled absent" {
    for value in yes no; do config "$FW_MAIN" "$value"; for repeat in 1 2; do run check; code=$status; diagnostic=$output; run validate; [ "$status" -eq "$code" ]; [ "$output" = "$diagnostic" ]; [ "$code" -ne 0 ]; done; done
    rm "$FW_MAIN"; expect 1; run validate; [ "$status" -eq 1 ]
}
@test "6233 apply repeated ERROR guidance no artificial change even enabled" { for value in yes no; do config "$FW_MAIN" "$value"; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; done; [ ! -e "$FW_STATE/mutation" ]; }
@test "6233 rollback repeatable SUCCESS without command or query" { rm "$RLCH_CIS_6_2_3_3_ANALYZE"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$FW_CALLS" ]; }
@test "6233 all APIs preserve admin files directories symlinks permissions and prior controls" {
    set -o pipefail
    mkdir -p "$RLCH_CIS_6_2_3_3_ROOT"/{etc/pki/private,var/lib/rlch,var/lib/rsyslog,var/log/journal,run/log/journal,etc/rsyslog.d,run/systemd/system,previous}
    for file in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/pki/private/key.pem etc/rsyslog.conf previous/62211 previous/62212 previous/62213 previous/62214 previous/6222 previous/6223 previous/6224 previous/6231 previous/6232 var/lib/rlch/admin-state var/lib/rsyslog/admin-queue var/log/journal/synthetic.journal run/log/journal/synthetic.journal etc/rsyslog.d/admin.conf; do printf 'SECRET-PRIVATE\n' > "$RLCH_CIS_6_2_3_3_ROOT/$file"; done
    ln -s /dev/null "$RLCH_CIS_6_2_3_3_ROOT/etc/systemd/journald.conf.d/admin-mask.conf"
    chmod 0600 "$RLCH_CIS_6_2_3_3_ROOT/etc/pki/private/key.pem"
    ln -s /dev/null "$RLCH_CIS_6_2_3_3_ROOT/run/systemd/system/rsyslog.service"
    before=$(find "$RLCH_CIS_6_2_3_3_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$RLCH_CIS_6_2_3_3_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in systemctl rpm dnf yum rsyslogd journalctl logger openssl curl wget chmod chown rm cp ln sed tee; do printf '#!/usr/bin/env bash\ntouch "$FW_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for state in enabled disabled error; do
        case "$state" in enabled) config "$FW_MAIN" yes;; disabled) config "$FW_MAIN" no;; error) config "$FW_MAIN" INVALID;; esac
        before=$(find "$RLCH_CIS_6_2_3_3_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
        inventory=$(find "$RLCH_CIS_6_2_3_3_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
        for repeat in 1 2; do for api in check validate apply rollback; do
            expected=2
            [[ "$api" != rollback ]] || expected=0
            if [[ "$state" == disabled && ( "$api" == check || "$api" == validate ) ]]; then expected=1; fi
            run "$api"; [ "$status" -eq "$expected" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RLCH_CIS_6_2_3_3_ROOT"* ]]
        done; done
        [ "$(find "$RLCH_CIS_6_2_3_3_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
        [ "$(find "$RLCH_CIS_6_2_3_3_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
    done
    export PATH="$saved_path"
    [ ! -e "$FW_STATE/mutation" ]
}
@test "6233 helper direct normalized scalar origin value" { run rows; [ "$status" -eq 0 ]; [ "$output" = "ForwardToSyslog|$FW_MAIN|2|yes" ]; }
@test "6233 helper direct absent scalar row" { rm "$FW_MAIN"; run rows; [ "$status" -eq 0 ]; [ "$output" = 'ForwardToSyslog|||' ]; }
@test "6233 helper direct unsupported relative path rejected before command" { run rlch_sdconf_snapshot "$RLCH_CIS_6_2_3_3_ROOT" "$RLCH_CIS_6_2_3_3_ANALYZE" systemd/../journald.conf; [ "$status" -eq 2 ]; [ ! -e "$FW_CALLS" ]; }
@test "6233 helper direct malformed provenance fails" { run rlch_sdconf_scalars "$RLCH_CIS_6_2_3_3_ROOT" systemd/journald.conf Journal ForwardToSyslog <<< $'===program===\n# /untracked.conf\n[Journal]\nForwardToSyslog=yes'; [ "$status" -eq 2 ]; }
@test "6233 enabled boolean yes technical observation requires review" { config "$FW_MAIN" yes; review; }
@test "6233 enabled boolean y technical observation requires review" { config "$FW_MAIN" y; review; }
@test "6233 enabled boolean true technical observation requires review" { config "$FW_MAIN" true; review; }
@test "6233 enabled boolean t technical observation requires review" { config "$FW_MAIN" t; review; }
@test "6233 enabled boolean on technical observation requires review" { config "$FW_MAIN" on; review; }
@test "6233 enabled boolean 1 technical observation requires review" { config "$FW_MAIN" 1; review; }
@test "6233 enabled boolean YES technical observation requires review" { config "$FW_MAIN" YES; review; }
@test "6233 enabled boolean True technical observation requires review" { config "$FW_MAIN" True; review; }
@test "6233 enabled boolean ON technical observation requires review" { config "$FW_MAIN" ON; review; }
@test "6233 disabled boolean no NON COMPLIANT" { config "$FW_MAIN" no; expect 1; }
@test "6233 disabled boolean n NON COMPLIANT" { config "$FW_MAIN" n; expect 1; }
@test "6233 disabled boolean false NON COMPLIANT" { config "$FW_MAIN" false; expect 1; }
@test "6233 disabled boolean f NON COMPLIANT" { config "$FW_MAIN" f; expect 1; }
@test "6233 disabled boolean off NON COMPLIANT" { config "$FW_MAIN" off; expect 1; }
@test "6233 disabled boolean 0 NON COMPLIANT" { config "$FW_MAIN" 0; expect 1; }
@test "6233 disabled boolean NO NON COMPLIANT" { config "$FW_MAIN" NO; expect 1; }
@test "6233 disabled boolean False NON COMPLIANT" { config "$FW_MAIN" False; expect 1; }
@test "6233 disabled boolean OFF NON COMPLIANT" { config "$FW_MAIN" OFF; expect 1; }
@test "6233 malformed final value empty ERROR" { config "$FW_MAIN" ''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value quoted ERROR" { config "$FW_MAIN" '"yes"'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value singlequoted ERROR" { config "$FW_MAIN" ''\''yes'\'''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value inlinecomment ERROR" { config "$FW_MAIN" 'yes # comment'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value unknown ERROR" { config "$FW_MAIN" 'auto'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value negative ERROR" { config "$FW_MAIN" '-1'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value multiple ERROR" { config "$FW_MAIN" 'yes no'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value pipe ERROR" { config "$FW_MAIN" 'yes|no'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 malformed final value percent ERROR" { config "$FW_MAIN" '%s'; expect 2; [[ "$output" == *unsupported* ]]; }

@test "6233 empty main no policy NON COMPLIANT" { : > "$FW_MAIN"; expect 1; }
@test "6233 absent dropin directories main enabled review" { for dir in etc run usr/local/lib usr/lib; do rmdir "$RLCH_CIS_6_2_3_3_ROOT/$dir/systemd/journald.conf.d"; done; review; }
@test "6233 all config absent no fabricated NOT APPLICABLE" { rm "$FW_MAIN"; for dir in etc run usr/local/lib usr/lib; do rmdir "$RLCH_CIS_6_2_3_3_ROOT/$dir/systemd/journald.conf.d"; done; expect 1; }
@test "6233 continuation enabled recognized manual review" { printf '[Journal]\nForwardToSyslog=\\\nyes\n' > "$FW_MAIN"; review; }
@test "6233 final invalid does not inherit earlier enabled" { printf '[Journal]\nForwardToSyslog=yes\nForwardToSyslog=INVALID\n' > "$FW_MAIN"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6233 earlier invalid overwritten still never SUCCESS" { printf '[Journal]\nForwardToSyslog=INVALID\nForwardToSyslog=yes\n' > "$FW_MAIN"; review; }
@test "6233 validate fresh after administrator disables forwarding" { review; config "$FW_MAIN" no; run validate; [ "$status" -eq 1 ]; }
@test "6233 CR raw file ERROR" { printf '\r\n' >> "$FW_MAIN"; expect 2; }
@test "6233 DEL raw file ERROR" { printf '\177\n' >> "$FW_MAIN"; expect 2; }
@test "6233 BOM raw file ERROR" { printf '\357\273\277' >> "$FW_MAIN"; expect 2; }
@test "6233 oversize scalar ERROR" { printf '[Journal]\nForwardToSyslog=%300s\n' x > "$FW_MAIN"; expect 2; }
@test "6233 empty root rejected" { saved_root="$RLCH_CIS_6_2_3_3_ROOT"; RLCH_CIS_6_2_3_3_ROOT=''; run check; RLCH_CIS_6_2_3_3_ROOT="$saved_root"; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* ]]; }
@test "6233 configured true never claims reception" { review; [[ "$output" == *'rsyslog reception'* && "$output" == *'kernel overrides'* && "$output" == *namespaces* ]]; }
@test "6233 no package service config parser socket prerequisite or logging probe" {
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in rpm dnf systemctl rsyslogd journalctl logger; do printf '#!/usr/bin/env bash\nprintf mutation >> "$FW_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    review
    export PATH="$saved_path"
    [ ! -e "$FW_STATE/mutation" ]
}
@test "6233 absent parameter all APIs idempotent exact results" { printf '[Journal]\n' > "$FW_MAIN"; for repeat in 1 2; do expect 1; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$FW_STATE/mutation" ]; }
@test "6233 guidance reconciles earlier opposite control without changing it" { run apply; [ "$status" -eq 2 ]; [[ "$output" == *'CIS 6.2.2.2'* && "$output" == *'imuxsock/imjournal'* && "$output" == *'exact rollback'* ]]; }
@test "6233 helper direct bool enabled technical observation" { run rlch_6_2_3_3_value "ForwardToSyslog|$FW_MAIN|2|yes"; [ "$status" -eq 0 ]; [ -z "$output" ]; }
@test "6233 helper direct bool disabled technical observation" { run rlch_6_2_3_3_value "ForwardToSyslog|$FW_MAIN|2|no"; [ "$status" -eq 1 ]; [ -z "$output" ]; }
@test "6233 helper direct wrong requested key ERROR" { run rlch_6_2_3_3_value "Compress|$FW_MAIN|2|yes"; [ "$status" -eq 2 ]; }
@test "6233 helper direct multiple rows ERROR" { run rlch_6_2_3_3_value $'ForwardToSyslog|||\nForwardToSyslog|||'; [ "$status" -eq 2 ]; }
@test "6233 helper direct invalid boolean ERROR" { run rlch_6_2_3_3_value "ForwardToSyslog|$FW_MAIN|2|INVALID"; [ "$status" -eq 2 ]; }
@test "6233 helper direct unsafe file snapshot fails before command" { chmod 0000 "$FW_MAIN"; run rlch_sdconf_snapshot "$RLCH_CIS_6_2_3_3_ROOT" "$RLCH_CIS_6_2_3_3_ANALYZE" systemd/journald.conf; [ "$status" -eq 2 ]; [ ! -e "$FW_CALLS" ]; }
