#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_4_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_2_4_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export CP_STATE="$BATS_TEST_TMPDIR/state" CP_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$CP_STATE" "$RLCH_CIS_6_2_2_4_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journald.conf.d
    export CP_MAIN="$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf"
    config "$CP_MAIN" persistent
    cat > "$RLCH_CIS_6_2_2_4_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CP_CALLS"
[[ "$#" == 4 && "$1" == --no-pager && "$2" == "--root=$RLCH_CIS_6_2_2_4_ROOT" && "$3" == cat-config && "$4" == systemd/journald.conf ]] || { touch "$CP_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_PAGER" == cat && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 ]] || exit 3
if [[ -e "$CP_STATE/error" ]]; then echo SECRET-ERROR >&2; exit 1; fi
if [[ $(wc -l < "$CP_CALLS") -ge 2 && -e "$CP_STATE/second-error" ]]; then exit 1; fi
if [[ -e "$CP_STATE/nul" ]]; then printf '# %s\n[Journal]\nStorage=persistent\0\n' "$CP_MAIN"; exit; fi
if [[ -e "$CP_STATE/large" ]]; then printf '%9000s\n' x; exit; fi
if [[ -e "$CP_STATE/program" ]]; then cat "$CP_STATE/program"; exit; fi
/usr/bin/systemd-analyze "$@" || exit
if [[ -e "$CP_STATE/drift" ]]; then printf '# changed\n' >> "$CP_MAIN"; fi
if [[ -e "$CP_STATE/add" ]]; then printf '[Journal]\nStorage=persistent\n' > "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/new.conf"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_2_4_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/4/module.sh"
}
config() { printf '[Journal]\nStorage=%s\n' "$2" > "$1"; }
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$RLCH_CIS_6_2_2_4_ROOT"* ]]; }
compliant() { expect 0; [ -z "$output" ]; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_4_ROOT" "$RLCH_CIS_6_2_2_4_ANALYZE" systemd/journald.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_2_4_ROOT" systemd/journald.conf Journal Storage <<< "$snapshot"
}
teardown() {
    if [[ -d "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d" && ! -L "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d" ]]; then chmod u+rwx "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d"; fi
}
@test "6224 official metadata exact mapped rule Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.4 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure journald Storage is configured' ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_journald_storage ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6224 documentation exact automated CAS mapping and RHEL9 CCE" {
    run sed -n '/^## CIS 6.2.2.4 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: automated'* && "$output" == *'rules: journald_storage'* && "$output" == *'CCE-86046-0'* && "$output" == *'no related_rules:'* ]]
}
@test "6224 explicit literal persistent SUCCESS for disk configuration" { compliant; }
@test "6224 only native cat-config twice no service or journal action" { compliant; [ "$(wc -l < "$CP_CALLS")" -eq 2 ]; [ ! -e "$CP_STATE/mutation" ]; }
@test "6224 absent main explicit etc dropin SUCCESS" { rm "$CP_MAIN"; config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf" persistent; compliant; }
@test "6224 main duplicates last persistent wins" { printf '[Journal]\nStorage=volatile\nStorage=persistent\n' > "$CP_MAIN"; compliant; }
@test "6224 main duplicates last volatile NON COMPLIANT" { printf '[Journal]\nStorage=persistent\nStorage=volatile\n' > "$CP_MAIN"; expect 1; }
@test "6224 repeated Journal section last explicit persistent wins" { printf '[Journal]\nStorage=volatile\n[Upload]\nStorage=volatile\n[Journal]\nStorage=persistent\n' > "$CP_MAIN"; compliant; }
@test "6224 whitespace comments unrelated settings preserved" { printf ' # comment\n[Journal]\n\t Storage \t=\t persistent \t\nCompress=yes\n# tail\n' > "$CP_MAIN"; compliant; }
@test "6224 main literal persistent overridden by later volatile NON COMPLIANT even OVAL main may pass" { config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/90-cp.conf" volatile; expect 1; }
@test "6224 etc dropin persistent overrides main volatile" { config "$CP_MAIN" volatile; config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf" persistent; compliant; }
@test "6224 later vendor filename volatile overrides earlier admin persistent" { config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf" persistent; config "$RLCH_CIS_6_2_2_4_ROOT/usr/lib/systemd/journald.conf.d/90-cp.conf" volatile; expect 1; }
@test "6224 same basename etc wins run local vendor" { for dir in run usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_4_ROOT/$dir/systemd/journald.conf.d/20-cp.conf" volatile; done; config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf" persistent; compliant; }
@test "6224 same basename run wins local vendor" { for dir in usr/local/lib usr/lib; do config "$RLCH_CIS_6_2_2_4_ROOT/$dir/systemd/journald.conf.d/20-cp.conf" volatile; done; config "$RLCH_CIS_6_2_2_4_ROOT/run/systemd/journald.conf.d/20-cp.conf" persistent; compliant; }
@test "6224 same basename local wins vendor" { config "$RLCH_CIS_6_2_2_4_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" volatile; config "$RLCH_CIS_6_2_2_4_ROOT/usr/local/lib/systemd/journald.conf.d/20-cp.conf" persistent; compliant; }
@test "6224 dev null admin mask suppresses vendor volatile" { config "$RLCH_CIS_6_2_2_4_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" volatile; ln -s /dev/null "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf"; compliant; }
@test "6224 empty admin dropin suppresses vendor same basename" { config "$RLCH_CIS_6_2_2_4_ROOT/usr/lib/systemd/journald.conf.d/20-cp.conf" volatile; touch "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-cp.conf"; compliant; }
@test "6224 CAS correct quoted value fail fixture never PASS" { config "$CP_MAIN" "'persistent'"; expect 2; }
@test "6224 CAS correct master pass fixture simulated" { compliant; }
@test "6224 CAS correct dropin with spaces pass fixture simulated" { rm "$CP_MAIN"; printf '[Journal]\nStorage = persistent\n' > "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/ssg.conf"; compliant; }
@test "6224 CAS commented correct value bad active fixture ERROR" { printf '[Journal]\nStorage=badval\n#Storage=persistent\n' > "$CP_MAIN"; expect 2; }
@test "6224 CASE namespace configs not default-instance proof or read" { printf '[Journal]\nStorage=volatile\n' > "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald@admin.conf"; compliant; }
@test "6224 earlier invalid numeric value then persistent last scalar wins" { printf '[Journal]\nStorage=1M\nStorage=persistent\n' > "$CP_MAIN"; compliant; }
@test "6224 continuation assembled persistent supported" { printf '[Journal]\nStorage=\\\n persistent\n' > "$CP_MAIN"; compliant; }
@test "6224 missing setting NON COMPLIANT even implicit auto default" { printf '[Journal]\n' > "$CP_MAIN"; expect 1; }
@test "6224 commented setting not explicit NON COMPLIANT" { printf '[Journal]\n#Storage=volatile\n;Storage=volatile\n' > "$CP_MAIN"; expect 1; }
@test "6224 absent main and all dropins NON COMPLIANT" { rm "$CP_MAIN"; expect 1; }
@test "6224 wrong section not policy NON COMPLIANT" { printf '[Upload]\nStorage=volatile\n' > "$CP_MAIN"; expect 1; }
@test "6224 section names case sensitive" { printf '[journal]\nStorage=volatile\n' > "$CP_MAIN"; expect 1; }
@test "6224 key names case sensitive" { printf '[Journal]\nstorage=volatile\n' > "$CP_MAIN"; expect 1; }
@test "6224 file boundary resets section ERROR instead of inheriting Journal" { printf 'Storage=volatile\n' > "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/20-fw.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 selected vendor main ambiguous daemon version ERROR" { mv "$CP_MAIN" "$RLCH_CIS_6_2_2_4_ROOT/usr/lib/systemd/journald.conf"; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 incomplete continuation ERROR" { printf '[Journal]\nStorage=volatile\\\n' > "$CP_MAIN"; expect 2; }
@test "6224 malformed section ERROR" { printf '[Journal\nStorage=volatile\n' > "$CP_MAIN"; expect 2; }
@test "6224 assignment before section ERROR" { printf 'Storage=volatile\n' > "$CP_MAIN"; expect 2; }
@test "6224 unknown malformed line inside Journal ERROR" { printf '[Journal]\nStorage=volatile\nmalformed\n' > "$CP_MAIN"; expect 2; }
@test "6224 inaccessible directory ERROR including root readable mode check" { chmod 0000 "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6224 inaccessible file ERROR" { chmod 0000 "$CP_MAIN"; expect 2; }
@test "6224 FIFO configuration ERROR no block" { rm "$CP_MAIN"; mkfifo "$CP_MAIN"; expect 2; }
@test "6224 directory at configuration path ERROR" { rm "$CP_MAIN"; mkdir "$CP_MAIN"; expect 2; }
@test "6224 symlink configuration ERROR except dev null mask" { mv "$CP_MAIN" "$CP_STATE/target"; ln -s "$CP_STATE/target" "$CP_MAIN"; expect 2; }
@test "6224 symlink directory ERROR" { mv "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d" "$CP_STATE/directory"; ln -s "$CP_STATE/directory" "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d"; expect 2; }
@test "6224 unsafe root ERROR" { RLCH_CIS_6_2_2_4_ROOT="$RLCH_CIS_6_2_2_4_ROOT/../root"; expect 2; }
@test "6224 malicious provenance filename ERROR" { touch "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/"$'bad\n.conf'; expect 2; }
@test "6224 header shaped comment ERROR before cat-config" { printf '# /etc/systemd/fake.conf\n' >> "$CP_MAIN"; expect 2; [ ! -e "$CP_CALLS" ]; }
@test "6224 raw file NUL rejected before Bash substitution" { printf '\0' >> "$CP_MAIN"; expect 2; }
@test "6224 raw program NUL ERROR" { touch "$CP_STATE/nul"; expect 2; }
@test "6224 oversized program ERROR" { touch "$CP_STATE/large"; expect 2; }
@test "6224 oversized input line ERROR" { printf '%9000s\n' x >> "$CP_MAIN"; expect 2; }
@test "6224 unavailable command ERROR redacted" { touch "$CP_STATE/error"; expect 2; }
@test "6224 second observation command failure ERROR" { touch "$CP_STATE/second-error"; expect 2; }
@test "6224 missing binary ERROR" { RLCH_CIS_6_2_2_4_ANALYZE="$CP_STATE/missing"; expect 2; }
@test "6224 nonexecutable binary ERROR" { chmod 0644 "$RLCH_CIS_6_2_2_4_ANALYZE"; expect 2; }
@test "6224 content drift even same policy ERROR" { touch "$CP_STATE/drift"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6224 inventory addition during observation ERROR" { touch "$CP_STATE/add"; expect 2; [[ "$output" == *unstable* ]]; }
@test "6224 forged untracked program header ERROR" { printf '# %s\n[Journal]\nStorage=volatile\n' "$CP_STATE/untracked.conf" > "$CP_STATE/program"; expect 2; }
@test "6224 repeated program header ERROR" { for repeat in 1 2; do printf '# %s\n[Journal]\nStorage=volatile\n' "$CP_MAIN"; done > "$CP_STATE/program"; expect 2; }
@test "6224 config text without provenance ERROR" { printf '[Journal]\nStorage=volatile\n' > "$CP_STATE/program"; expect 2; }
@test "6224 rollback repeatable SUCCESS without command or query" { rm "$RLCH_CIS_6_2_2_4_ANALYZE"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$CP_CALLS" ]; }
@test "6224 helper direct normalized scalar origin value" { run rows; [ "$status" -eq 0 ]; [ "$output" = "Storage|$CP_MAIN|2|persistent" ]; }
@test "6224 helper direct absent scalar row" { rm "$CP_MAIN"; run rows; [ "$status" -eq 0 ]; [ "$output" = 'Storage|||' ]; }
@test "6224 helper direct unsupported relative path rejected before command" { run rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_4_ROOT" "$RLCH_CIS_6_2_2_4_ANALYZE" systemd/../journald.conf; [ "$status" -eq 2 ]; [ ! -e "$CP_CALLS" ]; }
@test "6224 helper direct malformed provenance fails" { run rlch_sdconf_scalars "$RLCH_CIS_6_2_2_4_ROOT" systemd/journald.conf Journal Storage <<< $'===program===\n# /untracked.conf\n[Journal]\nStorage=volatile'; [ "$status" -eq 2 ]; }
@test "6224 check validate idempotent SUCCESS NON COMPLIANT ERROR" {
    for value in persistent volatile unsupported; do
        config "$CP_MAIN" "$value"
        case "$value" in persistent) expected=0;; volatile) expected=1;; unsupported) expected=2;; esac
        for repeat in 1 2; do run check; [ "$status" -eq "$expected" ]; diagnostic=$output; run validate; [ "$status" -eq "$expected" ]; [ "$output" = "$diagnostic" ]; done
    done
}
@test "6224 apply already compliant repeated SUCCESS no changes" { for repeat in 1 2; do run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$CP_STATE/mutation" ]; }
@test "6224 apply nonpersistent absent malformed repeated ERROR manual guidance" { for value in volatile unsupported; do config "$CP_MAIN" "$value"; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; done; rm "$CP_MAIN"; run apply; [ "$status" -eq 2 ]; [ ! -e "$CP_STATE/mutation" ]; }
@test "6224 apply observer failure ERROR no sensitive diagnostics" { touch "$CP_STATE/error"; run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; }
@test "6224 all APIs preserve config keys journal content admin attributes and prior controls" {
    set -o pipefail
    mkdir -p "$RLCH_CIS_6_2_2_4_ROOT"/{etc/pki/private,var/lib/rlch,previous,var/log/journal,run/log/journal}
    for file in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/systemd/journald@admin.conf etc/pki/private/key.pem etc/rsyslog.conf previous/62211 previous/62212 previous/62213 previous/62214 previous/6222 previous/6223 var/lib/rlch/admin-state var/log/journal/synthetic.journal run/log/journal/synthetic.journal; do printf 'SECRET-PRIVATE\n' > "$RLCH_CIS_6_2_2_4_ROOT/$file"; done
    ln -s /dev/null "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald.conf.d/admin-mask.conf"
    before=$(find "$RLCH_CIS_6_2_2_4_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$RLCH_CIS_6_2_2_4_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in systemctl journalctl rpm dnf yum openssl curl wget chmod chown rm cp ln sed tee; do printf '#!/usr/bin/env bash\ntouch "$CP_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for value in persistent volatile unsupported; do
        config "$CP_MAIN" "$value"
        before=$(find "$RLCH_CIS_6_2_2_4_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
        inventory=$(find "$RLCH_CIS_6_2_2_4_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
        for repeat in 1 2; do for api in check validate apply rollback; do
            expected=0
            if [[ "$api" != rollback && "$value" != persistent ]]; then expected=2; [[ "$api" == apply || "$value" != volatile ]] || expected=1; fi
            run "$api"; [ "$status" -eq "$expected" ]; [[ "$output" != *SECRET* ]]
        done; done
        [ "$(find "$RLCH_CIS_6_2_2_4_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
        [ "$(find "$RLCH_CIS_6_2_2_4_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
    done
    export PATH="$saved_path"
    [ "$(find "$RLCH_CIS_6_2_2_4_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
    [ "$(find "$RLCH_CIS_6_2_2_4_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
    [ ! -e "$CP_STATE/mutation" ]
}
@test "6224 native enum auto NON COMPLIANT" { config "$CP_MAIN" auto; expect 1; }
@test "6224 native enum volatile NON COMPLIANT" { config "$CP_MAIN" volatile; expect 1; }
@test "6224 native enum none NON COMPLIANT" { config "$CP_MAIN" none; expect 1; }
@test "6224 unsupported value empty ERROR manual review" { config "$CP_MAIN" ''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value quoted ERROR manual review" { config "$CP_MAIN" '"persistent"'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value singlequoted ERROR manual review" { config "$CP_MAIN" ''"'"'persistent'"'"''; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value inlinecomment ERROR manual review" { config "$CP_MAIN" 'persistent # comment'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value unknown ERROR manual review" { config "$CP_MAIN" unsupported; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value negative ERROR manual review" { config "$CP_MAIN" -1; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value multiple ERROR manual review" { config "$CP_MAIN" 'persistent volatile'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value pipe ERROR manual review" { config "$CP_MAIN" 'persistent|none'; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value percent ERROR manual review" { config "$CP_MAIN" %s; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value number ERROR manual review" { config "$CP_MAIN" 512; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value boolean ERROR manual review" { config "$CP_MAIN" yes; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value booleanfalse ERROR manual review" { config "$CP_MAIN" false; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value zero ERROR manual review" { config "$CP_MAIN" 0; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value one ERROR manual review" { config "$CP_MAIN" 1; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value upper ERROR manual review" { config "$CP_MAIN" PERSISTENT; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value mixed ERROR manual review" { config "$CP_MAIN" Persistent; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value upperauto ERROR manual review" { config "$CP_MAIN" AUTO; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 unsupported value infinity ERROR manual review" { config "$CP_MAIN" infinity; expect 2; [[ "$output" == *unsupported* ]]; }
@test "6224 auto with existing persistent journal directory still NON COMPLIANT" { mkdir -p "$RLCH_CIS_6_2_2_4_ROOT/var/log/journal"; config "$CP_MAIN" auto; expect 1; }
@test "6224 persistent without journal directories SUCCESS configuration only no creation" { compliant; [ ! -e "$RLCH_CIS_6_2_2_4_ROOT/var/log/journal" ]; [ ! -e "$RLCH_CIS_6_2_2_4_ROOT/run/log/journal" ]; }
@test "6224 volatile persistent directory and synthetic records unchanged" { mkdir -p "$RLCH_CIS_6_2_2_4_ROOT/var/log/journal"; printf 'PRIVATE\n' > "$RLCH_CIS_6_2_2_4_ROOT/var/log/journal/fake.journal"; config "$CP_MAIN" volatile; expect 1; [ "$(cat "$RLCH_CIS_6_2_2_4_ROOT/var/log/journal/fake.journal")" = PRIVATE ]; }
@test "6224 validate fresh observation after administrator change" { compliant; config "$CP_MAIN" none; run validate; [ "$status" -eq 1 ]; }
@test "6224 missing setting not proved by namespace persistent" { printf '[Journal]\n' > "$CP_MAIN"; config "$RLCH_CIS_6_2_2_4_ROOT/etc/systemd/journald@admin.conf" persistent; expect 1; }
@test "6224 earlier invalid enum overridden by final persistent last scalar subset" { printf '[Journal]\nStorage=badval\nStorage=persistent\n' > "$CP_MAIN"; compliant; }
