#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_3_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_2_3_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export CP_STATE="$BATS_TEST_TMPDIR/state" CP_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$CP_STATE" "$RLCH_CIS_6_2_2_3_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journald.conf.d
    export CP_MAIN="$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf"
    config "$CP_MAIN" yes
    cat > "$RLCH_CIS_6_2_2_3_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CP_CALLS"
[[ "$#" == 4 && "$1" == --no-pager && "$2" == "--root=$RLCH_CIS_6_2_2_3_ROOT" && "$3" == cat-config && "$4" == systemd/journald.conf ]] || { touch "$CP_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_PAGER" == cat && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 ]] || exit 3
if [[ -e "$CP_STATE/error" ]]; then echo SECRET-ERROR >&2; exit 1; fi
if [[ $(wc -l < "$CP_CALLS") -ge 2 && -e "$CP_STATE/second-error" ]]; then exit 1; fi
if [[ -e "$CP_STATE/nul" ]]; then printf '# %s\n[Journal]\nCompress=yes\0\n' "$CP_MAIN"; exit; fi
if [[ -e "$CP_STATE/large" ]]; then printf '%9000s\n' x; exit; fi
if [[ -e "$CP_STATE/program" ]]; then cat "$CP_STATE/program"; exit; fi
/usr/bin/systemd-analyze "$@" || exit
if [[ -e "$CP_STATE/drift" ]]; then printf '# changed\n' >> "$CP_MAIN"; fi
if [[ -e "$CP_STATE/add" ]]; then printf '[Journal]\nCompress=yes\n' > "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/new.conf"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_2_3_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/3/module.sh"
}
config() { printf '[Journal]\nCompress=%s\n' "$2" > "$1"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RLCH_CIS_6_2_2_3_ROOT"* ]]; }
compliant() { expect 0; [ -z "$output" ]; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_3_ROOT" "$RLCH_CIS_6_2_2_3_ANALYZE" systemd/journald.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_2_3_ROOT" systemd/journald.conf Journal Compress <<< "$snapshot"
}
teardown() {
    if [[ -d "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d" && ! -L "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d" ]]; then chmod u+rwx "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d"; fi
}
@test "6223 official metadata exact mapped rule Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.3 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure journald Compress is configured' ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_journald_compress ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6223 documentation exact automated CAS mapping and RHEL9 CCE" {
    run sed -n '/^## CIS 6.2.2.3 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: automated'* && "$output" == *'rules: journald_compress'* && "$output" == *'CCE-85931-4'* && "$output" == *'no related_rules:'* ]]
}
@test "6223 explicit literal yes SUCCESS for disk configuration" { compliant; }
@test "6223 only native cat-config twice no service or journal action" { compliant; [ "$(wc -l < "$CP_CALLS")" -eq 2 ]; [ ! -e "$CP_STATE/mutation" ]; }
@test "6223 absent main explicit etc dropin SUCCESS" { rm "$CP_MAIN"; config "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf" yes; compliant; }
@test "6223 main duplicates last yes wins" { printf '[Journal]\nCompress=no\nCompress=yes\n' > "$CP_MAIN"; compliant; }
@test "6223 main duplicates last no NON COMPLIANT" { printf '[Journal]\nCompress=yes\nCompress=no\n' > "$CP_MAIN"; expect 1; }
@test "6223 repeated Journal section last explicit yes wins" { printf '[Journal]\nCompress=no\n[Upload]\nCompress=no\n[Journal]\nCompress=yes\n' > "$CP_MAIN"; compliant; }
@test "6223 whitespace comments unrelated settings preserved" { printf ' # comment\n[Journal]\n\t Compress \t=\t yes \t\nStorage=persistent\n# tail\n' > "$CP_MAIN"; compliant; }
@test "6223 main literal yes overridden by later no NON COMPLIANT even OVAL main may pass" { config "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/90-cp.conf" no; expect 1; }
@test "6223 etc dropin yes overrides main no" { config "$CP_MAIN" no; config "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf" yes; compliant; }
@test "6223 later vendor filename no overrides earlier admin yes" { config "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf" yes; config "$RLCH_CIS_6_2_2_3_ROOT/usr/lib/systemd/journald.conf.d/90-cp.conf" no; expect 1; }
@test "6223 same basename etc wins run local vendor" { for dir in run usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_3_ROOT/$dir/systemd/journald.conf.d/20-cp.conf" no; done; config "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf" yes; compliant; }
@test "6223 same basename run wins local vendor" { for dir in usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_3_ROOT/$dir/systemd/journald.conf.d/20-cp.conf" no; done; config "$RLCH_CIS_6_2_2_3_ROOT/run/systemd/journald.conf.d/20-cp.conf" yes; compliant; }
@test "6223 same basename local wins vendor" { config "$RLCH_CIS_6_2_2_3_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" no; config "$RLCH_CIS_6_2_2_3_ROOT/usr/local/lib/systemd/journald.conf.d/20-cp.conf" yes; compliant; }
@test "6223 dev null admin mask suppresses vendor no" { config "$RLCH_CIS_6_2_2_3_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" no; ln -s /dev/null "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf"; compliant; }
@test "6223 empty admin dropin suppresses vendor same basename" { config "$RLCH_CIS_6_2_2_3_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" no; touch "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-cp.conf"; compliant; }
@test "6223 CAS correct quoted value fail fixture never PASS" { config "$CP_MAIN" "'yes'"; expect 2; }
@test "6223 CAS correct master pass fixture simulated" { compliant; }
@test "6223 CAS correct dropin with spaces pass fixture simulated" { rm "$CP_MAIN"; printf '[Journal]\nCompress = yes\n' > "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/ssg.conf"; compliant; }
@test "6223 CAS commented correct value bad active fixture ERROR" { printf '[Journal]\nCompress=badval\n#Compress=yes\n' > "$CP_MAIN"; expect 2; }
@test "6223 CASE namespace configs not default-instance proof or read" { printf '[Journal]\nCompress=no\n' > "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald@admin.conf"; compliant; }
@test "6223 prior numeric threshold then yes no invented CIS threshold predicate" { printf '[Journal]\nCompress=1M\nCompress=yes\n' > "$CP_MAIN"; compliant; }
@test "6223 continuation assembled yes supported" { printf '[Journal]\nCompress=\\\n yes\n' > "$CP_MAIN"; compliant; }
@test "6223 missing setting NON COMPLIANT even implicit disabled default" { printf '[Journal]\n' > "$CP_MAIN"; expect 1; }
@test "6223 commented setting not explicit NON COMPLIANT" { printf '[Journal]\n#Compress=no\n;Compress=no\n' > "$CP_MAIN"; expect 1; }
@test "6223 absent main and all dropins NON COMPLIANT" { rm "$CP_MAIN"; expect 1; }
@test "6223 wrong section not policy NON COMPLIANT" { printf '[Upload]\nCompress=no\n' > "$CP_MAIN"; expect 1; }
@test "6223 section names case sensitive" { printf '[journal]\nCompress=no\n' > "$CP_MAIN"; expect 1; }
@test "6223 key names case sensitive" { printf '[Journal]\nforwardtosyslog=no\n' > "$CP_MAIN"; expect 1; }
@test "6223 file boundary resets section ERROR instead of inheriting Journal" { printf 'Compress=no\n' > "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected vendor main ambiguous daemon version ERROR" { mv "$CP_MAIN" "$RLCH_CIS_6_2_2_3_ROOT/usr/lib/systemd/journald.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 incomplete continuation ERROR" { printf '[Journal]\nCompress=no\\\n' > "$CP_MAIN"; expect 2; }
@test "6223 malformed section ERROR" { printf '[Journal\nCompress=no\n' > "$CP_MAIN"; expect 2; }
@test "6223 assignment before section ERROR" { printf 'Compress=no\n' > "$CP_MAIN"; expect 2; }
@test "6223 unknown malformed line inside Journal ERROR" { printf '[Journal]\nCompress=no\nmalformed\n' > "$CP_MAIN"; expect 2; }
@test "6223 inaccessible directory ERROR including root readable mode check" { chmod 0000 "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6223 inaccessible file ERROR" { chmod 0000 "$CP_MAIN"; expect 2; }
@test "6223 FIFO configuration ERROR no block" { rm "$CP_MAIN"; mkfifo "$CP_MAIN"; expect 2; }
@test "6223 directory at configuration path ERROR" { rm "$CP_MAIN"; mkdir "$CP_MAIN"; expect 2; }
@test "6223 symlink configuration ERROR except dev null mask" { mv "$CP_MAIN" "$CP_STATE/target"; ln -s "$CP_STATE/target" "$CP_MAIN"; expect 2; }
@test "6223 symlink directory ERROR" { mv "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d" "$CP_STATE/directory"; ln -s "$CP_STATE/directory" "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6223 unsafe root ERROR" { RLCH_CIS_6_2_2_3_ROOT="$RLCH_CIS_6_2_2_3_ROOT/../root"; expect 2; }
@test "6223 malicious provenance filename ERROR" { touch "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/"$'bad\n.conf'; expect 2; }
@test "6223 header shaped comment ERROR before cat-config" { printf '# /etc/systemd/fake.conf\n' >> "$CP_MAIN"; expect 2; [ ! -e "$CP_CALLS" ]; }
@test "6223 raw file NUL rejected before Bash substitution" { printf '\0' >> "$CP_MAIN"; expect 2; }
@test "6223 raw program NUL ERROR" { touch "$CP_STATE/nul"; expect 2; }
@test "6223 oversized program ERROR" { touch "$CP_STATE/large"; expect 2; }
@test "6223 oversized input line ERROR" { printf '%9000s\n' x >> "$CP_MAIN"; expect 2; }
@test "6223 unavailable command ERROR redacted" { touch "$CP_STATE/error"; expect 2; }
@test "6223 second observation command failure ERROR" { touch "$CP_STATE/second-error"; expect 2; }
@test "6223 missing binary ERROR" { RLCH_CIS_6_2_2_3_ANALYZE="$CP_STATE/missing"; expect 2; }
@test "6223 nonexecutable binary ERROR" { chmod 0644 "$RLCH_CIS_6_2_2_3_ANALYZE"; expect 2; }
@test "6223 content drift even same policy ERROR" { touch "$CP_STATE/drift"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6223 inventory addition during observation ERROR" { touch "$CP_STATE/add"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6223 forged untracked program header ERROR" { printf '# %s\n[Journal]\nCompress=no\n' "$CP_STATE/untracked.conf" > "$CP_STATE/program"; expect 2; }
@test "6223 repeated program header ERROR" { for repeat in 1 2; do printf '# %s\n[Journal]\nCompress=no\n' "$CP_MAIN"; done > "$CP_STATE/program"; expect 2; }
@test "6223 config text without provenance ERROR" { printf '[Journal]\nCompress=no\n' > "$CP_STATE/program"; expect 2; }
@test "6223 rollback repeatable SUCCESS without command or query" { rm "$RLCH_CIS_6_2_2_3_ANALYZE"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$CP_CALLS" ]; }
@test "6223 helper direct normalized scalar origin value" { run rows; [ "$status" -eq 0 ]; [ "$output" = "Compress|$CP_MAIN|2|yes" ]; }
@test "6223 helper direct absent scalar row" { rm "$CP_MAIN"; run rows; [ "$status" -eq 0 ]; [ "$output" = 'Compress|||' ]; }
@test "6223 helper direct unsupported relative path rejected before command" { run rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_3_ROOT" "$RLCH_CIS_6_2_2_3_ANALYZE" systemd/../journald.conf; [ "$status" -eq 2 ]; [ ! -e "$CP_CALLS" ]; }
@test "6223 helper direct malformed provenance fails" { run rlch_sdconf_scalars "$RLCH_CIS_6_2_2_3_ROOT" systemd/journald.conf Journal Compress <<< $'===program===\n# /untracked.conf\n[Journal]\nCompress=no'; [ "$status" -eq 2 ]; }
@test "6223 check validate idempotent SUCCESS NON COMPLIANT ERROR" {
    for value in yes no auto; do
        config "$CP_MAIN" "$value"
        case "$value" in yes) expected=0;; no) expected=1;; auto) expected=2;; esac
        for repeat in 1 2; do run check; [ "$status" -eq "$expected" ]; diagnostic=$output; run validate; [ "$status" -eq "$expected" ]; [ "$output" = "$diagnostic" ]; done
    done
}
@test "6223 apply already compliant repeated SUCCESS no changes" { for repeat in 1 2; do run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$CP_STATE/mutation" ]; }
@test "6223 apply disabled absent malformed repeated ERROR manual guidance" { for value in no auto; do config "$CP_MAIN" "$value"; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; done; rm "$CP_MAIN"; run apply; [ "$status" -eq 2 ]; [ ! -e "$CP_STATE/mutation" ]; }
@test "6223 apply observer failure ERROR no sensitive diagnostics" { touch "$CP_STATE/error"; run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; }
@test "6223 all APIs preserve config keys journal content admin attributes and prior controls" {
    set -o pipefail
    mkdir -p "$RLCH_CIS_6_2_2_3_ROOT"/{etc/pki/private,var/lib/rlch,previous,var/log/journal}
    for file in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/systemd/journald@admin.conf etc/pki/private/key.pem etc/rsyslog.conf previous/62211 previous/62212 previous/62213 previous/62214 previous/6222 var/lib/rlch/admin-state var/log/journal/synthetic.journal; do printf 'SECRET-PRIVATE\n' > "$RLCH_CIS_6_2_2_3_ROOT/$file"; done
    ln -s /dev/null "$RLCH_CIS_6_2_2_3_ROOT/etc/systemd/journald.conf.d/admin-mask.conf"
    before=$(find "$RLCH_CIS_6_2_2_3_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$RLCH_CIS_6_2_2_3_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in systemctl journalctl rpm dnf yum openssl curl wget chmod chown rm cp ln sed tee; do printf '#!/usr/bin/env bash\ntouch "$CP_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for repeat in 1 2; do for api in check validate apply rollback; do run "$api"; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]; done; done
    export PATH="$saved_path"
    [ "$(find "$RLCH_CIS_6_2_2_3_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
    [ "$(find "$RLCH_CIS_6_2_2_3_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
    [ ! -e "$CP_STATE/mutation" ]
}
@test "6223 disabled boolean no NON COMPLIANT" { config "$CP_MAIN" no; expect 1; }
@test "6223 disabled boolean n NON COMPLIANT" { config "$CP_MAIN" n; expect 1; }
@test "6223 disabled boolean false NON COMPLIANT" { config "$CP_MAIN" false; expect 1; }
@test "6223 disabled boolean f NON COMPLIANT" { config "$CP_MAIN" f; expect 1; }
@test "6223 disabled boolean off NON COMPLIANT" { config "$CP_MAIN" off; expect 1; }
@test "6223 disabled boolean 0 NON COMPLIANT" { config "$CP_MAIN" 0; expect 1; }
@test "6223 disabled boolean NO NON COMPLIANT" { config "$CP_MAIN" NO; expect 1; }
@test "6223 disabled boolean False NON COMPLIANT" { config "$CP_MAIN" False; expect 1; }
@test "6223 disabled boolean OFF NON COMPLIANT" { config "$CP_MAIN" OFF; expect 1; }
@test "6223 enabled alias y CAS literal discordance ERROR" { config "$CP_MAIN" y; expect 2; }
@test "6223 enabled alias true CAS literal discordance ERROR" { config "$CP_MAIN" true; expect 2; }
@test "6223 enabled alias t CAS literal discordance ERROR" { config "$CP_MAIN" t; expect 2; }
@test "6223 enabled alias on CAS literal discordance ERROR" { config "$CP_MAIN" on; expect 2; }
@test "6223 enabled alias 1 CAS literal discordance ERROR" { config "$CP_MAIN" 1; expect 2; }
@test "6223 enabled alias YES CAS literal discordance ERROR" { config "$CP_MAIN" YES; expect 2; }
@test "6223 enabled alias Yes CAS literal discordance ERROR" { config "$CP_MAIN" Yes; expect 2; }
@test "6223 enabled alias True CAS literal discordance ERROR" { config "$CP_MAIN" True; expect 2; }
@test "6223 enabled alias ON CAS literal discordance ERROR" { config "$CP_MAIN" ON; expect 2; }
@test "6223 selected unsupported value empty ERROR manual review" { config "$CP_MAIN" ''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value quoted ERROR manual review" { config "$CP_MAIN" '"yes"'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value singlequoted ERROR manual review" { config "$CP_MAIN" ''\''yes'\'''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value inlinecomment ERROR manual review" { config "$CP_MAIN" 'yes # comment'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value unknown ERROR manual review" { config "$CP_MAIN" 'auto'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value negative ERROR manual review" { config "$CP_MAIN" '-1'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value multiple ERROR manual review" { config "$CP_MAIN" 'yes no'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value pipe ERROR manual review" { config "$CP_MAIN" 'yes|no'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value percent ERROR manual review" { config "$CP_MAIN" '%s'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value threshold512 ERROR manual review" { config "$CP_MAIN" '512'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value threshold1K ERROR manual review" { config "$CP_MAIN" '1K'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value threshold1M ERROR manual review" { config "$CP_MAIN" '1M'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value thresholdzero ERROR manual review" { config "$CP_MAIN" '0B'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value thresholdmax ERROR manual review" { config "$CP_MAIN" '18446744073709551615'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6223 selected unsupported value infinity ERROR manual review" { config "$CP_MAIN" 'infinity'; expect 2; [[ "$output" == *unsupported* ]]; }
