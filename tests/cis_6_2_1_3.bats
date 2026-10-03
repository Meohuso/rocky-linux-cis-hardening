#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_1_3_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_1_3_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export JR_STATE="$BATS_TEST_TMPDIR/state" JR_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$JR_STATE" "$RLCH_CIS_6_2_1_3_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journald.conf.d
    export JR_MAIN="$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf"
    complete "$JR_MAIN"
    cat > "$RLCH_CIS_6_2_1_3_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$JR_CALLS"
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 && "$1" == --no-pager ]] || exit 3
case "$2" in
--root=*)
    [[ "$2" == "--root=$RLCH_CIS_6_2_1_3_ROOT" && "$3" == cat-config && "$4" == systemd/journald.conf && $# == 4 ]] || exit 3
    [[ ! -e "$JR_STATE/query-error" ]] || { echo SECRET >&2; exit 1; }
    if [[ -e "$JR_STATE/nul" ]]; then printf '# %s\n[Journal]\nSystemMaxUse=1G\0\n' "$JR_MAIN"; exit; fi
    if [[ -e "$JR_STATE/large" ]]; then printf '%9000s\n' x; exit; fi
    if [[ -e "$JR_STATE/program" ]]; then cat "$JR_STATE/program"; exit; fi
    /usr/bin/systemd-analyze "$@" || exit
    if [[ -e "$JR_STATE/drift" ]]; then printf '# changed\n' >> "$JR_MAIN"; fi
    ;;
timespan)
    [[ "$3" == -- && $# == 4 ]] || exit 3
    [[ ! -e "$JR_STATE/time-error" ]] || { echo SECRET >&2; exit 1; }
    if [[ -e "$JR_STATE/time-output" ]]; then cat "$JR_STATE/time-output"; exit; fi
    /usr/bin/systemd-analyze "$@"
    ;;
*) exit 3;;
esac
MOCK
    chmod 0755 "$RLCH_CIS_6_2_1_3_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/3/module.sh"
}
complete() {
    cat > "$1" <<'INI'
[Journal]
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
INI
}
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
setting() { sed -i "s/^$1=.*/$1=$2/" "$JR_MAIN"; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_1_3_ROOT" "$RLCH_CIS_6_2_1_3_ANALYZE" systemd/journald.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_1_3_ROOT" systemd/journald.conf Journal 'SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec' <<< "$snapshot"
}
teardown() {
    if [[ -d "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d" && ! -L "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d" ]]; then chmod u+rwx "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d"; fi
}
@test "6213 metadata manual exact Level 1 no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.1.3 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
}
@test "6213 example complete main configuration ERROR site policy review never false PASS" {
    expect 2; [[ "$output" == *'five explicit technically valid'* ]]; [[ "$output" == *'no supplied site policy'* ]]; [[ "$output" == *SystemMaxUse=1073741824B* ]]
}
@test "6213 third party example also manual without numeric CIS thresholds" {
    setting SystemMaxUse 10M; setting SystemKeepFree 100G; setting RuntimeMaxUse 10M; setting RuntimeKeepFree 100G
    expect 2; [[ "$output" == *'five explicit technically valid'* ]]
}
@test "6213 arbitrary valid different values manual not numeric NON COMPLIANT" {
    setting SystemMaxUse 7T; setting SystemKeepFree 0; setting RuntimeMaxUse 17K; setting RuntimeKeepFree 123456; setting MaxFileSec 2h
    expect 2; [[ "$output" == *'five explicit technically valid'* ]]
}
@test "6213 missing each expected explicit parameter NON COMPLIANT" {
    for key in SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec; do complete "$JR_MAIN"; sed -i "/^$key=/d" "$JR_MAIN"; expect 1; [[ "$output" == *"$key=implicit-default-not-explicit"* ]]; done
}
@test "6213 implicit defaults all missing NON COMPLIANT" {
    printf '[Journal]\n#MaxFileSec=1month\n' > "$JR_MAIN"; expect 1;
}
@test "6213 no main and no dropins NON COMPLIANT" {
    rm "$JR_MAIN"; expect 1;
}
@test "6213 vendor dropin alone explicit values manual" {
    complete "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-rotation.conf"; rm "$JR_MAIN"; expect 2; [[ "$output" == *'five explicit technically valid'* ]];
}
@test "6213 etc dropin alone explicit values manual" {
    complete "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-rotation.conf"; rm "$JR_MAIN"; expect 2; [[ "$output" == *'five explicit technically valid'* ]];
}
@test "6213 selected main rows preserve explicit provenance" {
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *"SystemMaxUse|$JR_MAIN|2|1G"* ]];
}
@test "6213 dropins override main" {
    printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|2G'* ]]
}
@test "6213 etc same basename overrides vendor" {
    printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    printf '[Journal]\nSystemMaxUse=3G\n' > "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|3G'* ]]; [[ "$output" != *'|2|2G'* ]]
}
@test "6213 run same basename overrides vendor" {
    printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    printf '[Journal]\nSystemMaxUse=4G\n' > "$RLCH_CIS_6_2_1_3_ROOT/run/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|4G'* ]]
}
@test "6213 local lib overrides vendor same basename" {
    printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    printf '[Journal]\nSystemMaxUse=5G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/local/lib/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|5G'* ]]
}
@test "6213 etc overrides run and local lib same basename" {
    for prefix in run usr/local/lib; do printf '[Journal]\nSystemMaxUse=4G\n' > "$RLCH_CIS_6_2_1_3_ROOT/$prefix/systemd/journald.conf.d/20-size.conf"; done
    printf '[Journal]\nSystemMaxUse=6G\n' > "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|6G'* ]]
}
@test "6213 lexically later vendor filename overrides earlier etc filename" {
    printf '[Journal]\nSystemMaxUse=3G\n' > "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/10-size.conf"
    printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/90-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|2G'* ]]
}
@test "6213 last assignment same file and repeated Journal section" {
    printf 'SystemMaxUse=2G\n[Other]\nSystemMaxUse=9G\n[Journal]\nSystemMaxUse=3G\n' >> "$JR_MAIN"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|11|3G'* ]]
}
@test "6213 wrong section ignored" {
    sed -i 's/\[Journal\]/[Other]/' "$JR_MAIN"; expect 1;
}
@test "6213 sections do not carry between separate dropins" {
    printf 'SystemMaxUse=3G\n' > "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-size.conf"; expect 2; [[ "$output" == *unsupported* ]]
}
@test "6213 comments semicolons blanks whitespace tabs accepted" {
    printf '  # note\n; note\n\n[Journal]\n SystemMaxUse \t=\t 1G \nSystemKeepFree=500M\nRuntimeMaxUse=200M\nRuntimeKeepFree=50M\nMaxFileSec=1month\n' > "$JR_MAIN"
    expect 2; [[ "$output" == *'five explicit technically valid'* ]]
}
@test "6213 commented required line remains absent" {
    sed -i 's/^SystemMaxUse=/#SystemMaxUse=/' "$JR_MAIN"; expect 1;
}
@test "6213 continuation and interposed comments native semantics" {
    setting MaxFileSec '1h'; printf 'MaxFileSec=1h \\\n# ignored continuation comment\n; ignored too\n 30m\n' >> "$JR_MAIN"
    expect 2; [[ "$output" == *MaxFileSec=5400000000us* ]]
}
@test "6213 incomplete continuation ERROR" {
    printf 'MaxFileSec=1h \\' >> "$JR_MAIN"; expect 2;
}
@test "6213 malformed section ERROR" {
    printf '[Journal\nSystemMaxUse=2G\n' >> "$JR_MAIN"; expect 2;
}
@test "6213 assignment outside section ERROR" {
    printf 'SystemMaxUse=2G\n' > "$JR_MAIN"; expect 2;
}
@test "6213 malformed Journal line ERROR" {
    printf 'SystemMaxUse 2G\n' >> "$JR_MAIN"; expect 2;
}
@test "6213 explicit empty values ERROR not generic reset or implicit conformant default" {
    for key in SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec; do complete "$JR_MAIN"; setting "$key" ''; expect 2; [[ "$output" == *unsupported* ]]; done
}
@test "6213 invalid last assignment ERROR despite earlier valid value" {
    printf 'SystemMaxUse=invalid\n' >> "$JR_MAIN"; expect 2;
}
@test "6213 earlier invalid value superseded by known final valid assignment" {
    printf '[Journal]\nSystemMaxUse=invalid\n' > "$JR_MAIN"; complete "$JR_STATE/valid"; cat "$JR_STATE/valid" >> "$JR_MAIN"; expect 2; [[ "$output" == *'five explicit technically valid'* ]];
}
@test "6213 inline comments are value data and not silently stripped" {
    setting SystemMaxUse '1G # comment'; expect 2;
}
@test "6213 quoted size not supported ERROR" {
    setting SystemMaxUse '"1G"'; expect 2;
}
@test "6213 extra options impose no additional CIS criteria" {
    printf 'MaxRetentionSec=bogus\nSystemMaxFileSize=bogus\nRuntimeMaxFileSize=bogus\nSystemMaxFiles=bogus\nRuntimeMaxFiles=bogus\nStorage=bogus\n' >> "$JR_MAIN"; expect 2; [[ "$output" == *'five explicit technically valid'* ]];
}
@test "6213 namespace configuration outside default scope" {
    complete "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald@custom.conf"; sed -i '/^SystemMaxUse=/d' "$JR_MAIN"; expect 1;
}
@test "6213 dev null dropin mask preserves main value" {
    printf '[Journal]\nSystemMaxUse=9G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    ln -s /dev/null "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|1G'* ]]; [[ "$output" != *9G* ]]
}
@test "6213 dev null main is explicit masking and missing settings" {
    rm "$JR_MAIN"; ln -s /dev/null "$JR_MAIN"; expect 1;
}
@test "6213 non etc main selection requires version reconciliation ERROR" {
    mv "$JR_MAIN" "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf"; expect 2;
}
@test "6213 integer sizes and uppercase K M G T P E B exact" {
    for pair in '0:0' '00010:10' '1234:1234' '10B:10' '1K:1024' '10M:10485760' '1G:1073741824' '1T:1099511627776' '1P:1125899906842624' '1E:1152921504606846976' '8E:9223372036854775808' '15E:17293822569102704640' '18446744073709551615:18446744073709551615'; do run rlch_sdconf_size "${pair%:*}"; [ "$status" -eq 0 ]; [ "$output" = "${pair#*:}" ]; done
}
@test "6213 size internal suffix whitespace supported" {
    run rlch_sdconf_size '10 M'; [ "$status" -eq 0 ]; [ "$output" = 10485760 ];
}
@test "6213 size invalid suffix case signs negative empty text ERROR" {
    for value in '' -1 +1 -0 1m 1g 1KiB 1MB infinity text 0x10; do run rlch_sdconf_size "$value"; [ "$status" -eq 2 ]; done
}
@test "6213 valid native fraction and compound size forms intentionally manual unsupported" {
    for value in 1.5G '1G 500M' 10.M; do run rlch_sdconf_size "$value"; [ "$status" -eq 2 ]; done;
}
@test "6213 size overflow uint64 ERROR" {
    for value in 18446744073709551616 16E 999999999999999999999999 20000000T; do run rlch_sdconf_size "$value"; [ "$status" -eq 2 ]; done;
}
@test "6213 zero sizes recorded without inventing CIS failure threshold" {
    for key in SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree; do setting "$key" 0; done; expect 2; [[ "$output" == *'five explicit technically valid'* ]]; [[ "$output" == *SystemMaxUse=0B* ]];
}
@test "6213 maximum size sentinel distinguished from computed runtime value" {
    setting SystemMaxUse 18446744073709551615; expect 2; [[ "$output" == *uint64-default-sentinel* ]];
}
@test "6213 native duration seconds minute hour day week month year combinations" {
    for pair in '60:60000000' '2m:120000000' '2h:7200000000' '1day:86400000000' '1week:604800000000' '1month:2629800000000' '1year:31557600000000' '1h 30m:5400000000' '0.5s:500000' '250ms:250000'; do run rlch_sdconf_duration "$RLCH_CIS_6_2_1_3_ANALYZE" "${pair%:*}"; [ "$status" -eq 0 ]; [ "$output" = "${pair#*:}" ]; done
}
@test "6213 zero time rotation disabled remains site review not universal failure" {
    setting MaxFileSec 0; expect 2; [[ "$output" == *'time-rotation-disabled'* ]]; [[ "$output" == *'five explicit technically valid'* ]];
}
@test "6213 infinity time has no finite limit and requires site review" {
    setting MaxFileSec infinity; expect 2; [[ "$output" == *no-finite-time-limit* ]];
}
@test "6213 native invalid durations ERROR" {
    for value in '' -1 -0 xyz 1fortnight '1month # bad' '9999999999999999999999year'; do run rlch_sdconf_duration "$RLCH_CIS_6_2_1_3_ANALYZE" "$value"; [ "$status" -eq 2 ]; done;
}
@test "6213 duration overflow ERROR" {
    setting MaxFileSec 18446744073709551615; expect 2;
}
@test "6213 duration parser failure and error text hidden" {
    touch "$JR_STATE/time-error"; expect 2;
}
@test "6213 malformed native timespan output ERROR" {
    for text in '' 'Original: 1month' 'Original: 1month\nus: abc\nHuman: 1month' 'Original: other\nus: 1\nHuman: 1month' 'Original: 1month\nus: 1\nus: 2\nHuman: 1month'; do printf '%b\n' "$text" > "$JR_STATE/time-output"; expect 2; done
}
@test "6213 duration normalized observation drift ERROR" {
    cat > "$RLCH_CIS_6_2_1_3_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
if [[ "$2" == timespan ]]; then
 if [[ -e "$JR_STATE/time-seen" ]]; then n=2; else n=1;touch "$JR_STATE/time-seen";fi
 printf 'Original: %s\nus: %s\nHuman: 1month\n' "$4" "$n"
else /usr/bin/systemd-analyze "$@";fi
MOCK
    expect 2; [[ "$output" == *unstable* ]]
}
@test "6213 command failure and missing executable ERROR" {
    touch "$JR_STATE/query-error"; expect 2; rm "$JR_STATE/query-error"; RLCH_CIS_6_2_1_3_ANALYZE=/missing; expect 2;
}
@test "6213 query NUL and excessive line ERROR" {
    touch "$JR_STATE/nul"; expect 2; rm "$JR_STATE/nul"; touch "$JR_STATE/large"; expect 2;
}
@test "6213 query output unknown file header ERROR" {
    printf '# /etc/unknown.conf\n[Journal]\nSystemMaxUse=1G\n' > "$JR_STATE/program"; expect 2;
}
@test "6213 query flat headerless values ERROR" {
    cat "$JR_MAIN" > "$JR_STATE/program"; expect 2;
}
@test "6213 forged native header comment in source file ERROR" {
    printf '# %s\n' "$JR_MAIN" >> "$JR_MAIN"; expect 2;
}
@test "6213 content changes during observation ERROR" {
    touch "$JR_STATE/drift"; expect 2;
}
@test "6213 effective output alone changes ERROR" {
    eval "$(declare -f rlch_sdconf_snapshot | sed '1s/rlch_sdconf_snapshot/jr_original_snapshot/')"
    rlch_sdconf_snapshot() {
        jr_original_snapshot "$@" || return 2
        if [[ -e "$JR_STATE/seen" ]]; then printf '# extra observed output\n'; else touch "$JR_STATE/seen"; fi
    }
    expect 2
}
@test "6213 inode replaced between full observations ERROR" {
    eval "$(declare -f rlch_sdconf_snapshot | sed '1s/rlch_sdconf_snapshot/jr_original_snapshot/')"
    rlch_sdconf_snapshot() {
        jr_original_snapshot "$@" || return 2
        if [[ ! -e "$JR_STATE/replaced" ]]; then mv "$JR_MAIN" "$JR_STATE/old"; cp "$JR_STATE/old" "$JR_MAIN"; touch "$JR_STATE/replaced"; fi
    }
    expect 2
}
@test "6213 new dropin appears between observations ERROR" {
    eval "$(declare -f rlch_sdconf_snapshot | sed '1s/rlch_sdconf_snapshot/jr_original_snapshot/')"
    rlch_sdconf_snapshot() { jr_original_snapshot "$@" || return 2; printf '[Journal]\nSystemMaxUse=2G\n' > "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/new.conf"; }
    expect 2
}
@test "6213 existing dropin disappears between observations ERROR" {
    complete "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/remove.conf"
    eval "$(declare -f rlch_sdconf_snapshot | sed '1s/rlch_sdconf_snapshot/jr_original_snapshot/')"
    rlch_sdconf_snapshot() { jr_original_snapshot "$@" || return 2; rm -f "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/remove.conf"; }
    expect 2
}
@test "6213 identity drift before descriptor open ERROR" {
    eval "$(declare -f rlch_journal_config_file | sed '1s/rlch_journal_config_file/jr_original_stamp/')"
    rlch_journal_config_file() { jr_original_stamp "$1" || return 2; chmod 0600 "$1"; }
    expect 2
}
@test "6213 hostile main symlink ERROR" {
    mv "$JR_MAIN" "$JR_STATE/outside"; ln -s "$JR_STATE/outside" "$JR_MAIN"; expect 2;
}
@test "6213 hostile dropin symlink ERROR even shadowed" {
    ln -s "$JR_MAIN" "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-bad.conf"; expect 2;
}
@test "6213 parent symlink ERROR" {
    mv "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d" "$JR_STATE/directory"; ln -s "$JR_STATE/directory" "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d"; expect 2;
}
@test "6213 FIFO configuration ERROR without opening" {
    rm "$JR_MAIN"; mkfifo "$JR_MAIN"; expect 2;
}
@test "6213 nonregular configuration directory ERROR" {
    mkdir "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/bad.conf"; expect 2;
}
@test "6213 unreadable file mode ERROR even privileged" {
    chmod 0000 "$JR_MAIN"; expect 2;
}
@test "6213 inaccessible dropin directory ERROR" {
    chmod 0000 "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d"; expect 2;
}
@test "6213 oversized configuration ERROR" {
    truncate -s 1048577 "$JR_MAIN"; expect 2;
}
@test "6213 physical long line ERROR" {
    printf '%9000s\n' x >> "$JR_MAIN"; expect 2;
}
@test "6213 raw file NUL CR escape controls ERROR" {
    for bytes in '\0' '\r' '\033'; do complete "$JR_MAIN"; printf '%b\n' "$bytes" >> "$JR_MAIN"; expect 2; done;
}
@test "6213 control byte filename ERROR" {
    touch "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/"$'bad\n.conf'; expect 2;
}
@test "6213 BOM unsupported ERROR" {
    printf '\357\273\277[Journal]\n' > "$JR_MAIN"; expect 2;
}
@test "6213 path traversal root and config name ERROR" {
    RLCH_CIS_6_2_1_3_ROOT="$RLCH_CIS_6_2_1_3_ROOT/../root"; expect 2; run rlch_sdconf_snapshot / /usr/bin/systemd-analyze systemd/../journald.conf; [ "$status" -eq 2 ];
}
@test "6213 unsupported value bounds ERROR" {
    printf 'SystemMaxUse=%300s\n' x >> "$JR_MAIN"; expect 2;
}
@test "6213 check validate repeated identical classification" {
    for n in 1 2; do run check; [ "$status" -eq 2 ]; run validate; [ "$status" -eq 2 ]; done; sed -i '/^SystemMaxUse=/d' "$JR_MAIN"; run validate; [ "$status" -eq 1 ];
}
@test "6213 apply repeated ERROR manual rollback repeated SUCCESS unchanged" {
    before="$(sha256sum "$JR_MAIN")"
    for n in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]; run rollback; [ "$status" -eq 0 ]; done
    [ "$(sha256sum "$JR_MAIN")" = "$before" ]; [ "$(stat -c %a "$JR_MAIN")" = 644 ]
}
@test "6213 missing settings apply ERROR remains unchanged" {
    sed -i '/^MaxFileSec=/d' "$JR_MAIN"; before="$(sha256sum "$JR_MAIN")"; run apply; [ "$status" -eq 2 ]; [ "$(sha256sum "$JR_MAIN")" = "$before" ];
}
@test "6213 previous controls journal content ACL tmpfiles AIDE cron service state untouched" {
    mkdir -p "$RLCH_CIS_6_2_1_3_ROOT"/{etc/tmpfiles.d,etc/aide,etc/cron.d,var/lib/aide,var/lib/rlch,var/log/journal,etc/systemd/system}
    for path in etc/tmpfiles.d/systemd.conf etc/aide/aide.conf etc/cron.d/aide var/lib/aide/aide.db var/lib/rlch/6.1.3.state var/lib/rlch/6.2.1.1.state var/log/journal/system.journal etc/systemd/system/journald.service; do echo preserved > "$RLCH_CIS_6_2_1_3_ROOT/$path"; done
    chmod 0000 "$RLCH_CIS_6_2_1_3_ROOT/var/log/journal/system.journal"
    before="$(find "$RLCH_CIS_6_2_1_3_ROOT" -type f ! -name '*.journal' -exec sha256sum {} + | sort)"
    run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; [ "$(find "$RLCH_CIS_6_2_1_3_ROOT" -type f ! -name '*.journal' -exec sha256sum {} + | sort)" = "$before" ]; [ "$(stat -c %a "$RLCH_CIS_6_2_1_3_ROOT/var/log/journal/system.journal")" = 0 ]
    ! rg --quiet -- 'restart|reload|rotate|vacuum|create|clean|remove|systemctl|journalctl|tmpfiles|dnf' "$JR_CALLS"
}
@test "6213 duplicate file headers are ambiguous ERROR" {
    printf '# %s\n' "$JR_MAIN" > "$JR_STATE/program"; cat "$JR_MAIN" >> "$JR_STATE/program"; printf '# %s\n' "$JR_MAIN" >> "$JR_STATE/program"; expect 2
}
@test "6213 main selection run prefix requires daemon version review" {
    mv "$JR_MAIN" "$RLCH_CIS_6_2_1_3_ROOT/run/systemd/journald.conf"; expect 2
}
@test "6213 duration output control bytes and excessive output ERROR" {
    printf 'Original: 1month\nus: 1\0\nHuman: 1month\n' > "$JR_STATE/time-output"; expect 2
    printf '%9000s\n' x > "$JR_STATE/time-output"; expect 2
}
@test "6213 missing explicit value and invalid present value prioritizes observation ERROR" {
    sed -i '/^SystemMaxUse=/d' "$JR_MAIN"; setting MaxFileSec bad; expect 2
}
@test "6213 native query and scalar extraction do not evaluate shell content" {
    printf 'SystemMaxUse=$(touch %s/owned)\n' "$JR_STATE" >> "$JR_MAIN"; expect 2; [ ! -e "$JR_STATE/owned" ]
}
@test "6213 empty higher priority dropin masks same named vendor content" {
    printf '[Journal]\nSystemMaxUse=9G\n' > "$RLCH_CIS_6_2_1_3_ROOT/usr/lib/systemd/journald.conf.d/20-size.conf"
    touch "$RLCH_CIS_6_2_1_3_ROOT/etc/systemd/journald.conf.d/20-size.conf"
    run rows; [ "$status" -eq 0 ]; [[ "$output" == *'|2|1G'* ]]
}
