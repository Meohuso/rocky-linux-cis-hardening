#!/usr/bin/env bats
# Neighbor CAS service fixtures provide technical context, not mapped CIS tests.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_3_2_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl"
    export RS_STATE="$BATS_TEST_TMPDIR/observations" RS_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$RS_STATE"
    cat > "$RLCH_CIS_6_2_3_2_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RS_CALLS"
[[ "$#" == 6 && "$1" == --system && "$2" == --no-pager && "$3" == show && "$4" == --property=Id,LoadState,ActiveState,UnitFileState,StateChangeTimestampMonotonic && "$5" == -- && "$6" == rsyslog.service ]] || { touch "$RS_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_PAGER" == cat ]] || exit 3
if [[ -e "$RS_STATE/error" ]]; then echo SECRET-DBUS-ERROR >&2; exit 1; fi
if [[ -e "$RS_STATE/nul" ]]; then printf 'Id=rsyslog.service\0\n'; exit; fi
if [[ -e "$RS_STATE/oversized" ]]; then printf '%140000s\n' x; exit; fi
if [[ $(wc -l < "$RS_CALLS") -ge 2 && -e "$RS_STATE/second-error" ]]; then echo SECRET-SECOND >&2; exit 1; fi
if [[ $(wc -l < "$RS_CALLS") -ge 2 && -e "$RS_STATE/second" ]]; then cat "$RS_STATE/second"; else cat "$RS_STATE/current"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_3_2_SYSTEMCTL"
    runtime loaded active enabled
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/2/module.sh"
}
runtime() { printf 'Id=rsyslog.service\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\nStateChangeTimestampMonotonic=100\n' "$1" "$2" "$3" > "$RS_STATE/current"; }
expect() { rm -f "$RS_CALLS"; run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *PEM* ]]; }
helper() { rlch_systemd_properties "$RLCH_CIS_6_2_3_2_SYSTEMCTL" rsyslog.service runtime; }
second() { cp "$RS_STATE/current" "$RS_STATE/second"; sed -i "$1" "$RS_STATE/second"; }
@test "6232 metadata exact applicable unmapped Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/3/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.3.2 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure rsyslog service is enabled and active' ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "6232 exact pinned supported mapping context only documented" {
    run sed -n '/^## CIS 6.2.3.2 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: supported'* && "$output" == *'no rules:'* && "$output" == *'related_rules: [service_rsyslog_enabled]'* && "$output" == *'CCE-83989-4'* && "$output" == *'context only'* && "$output" == *'NOT an official CIS mapping'* ]]
}
@test "6232 informative neighbor enabled active fixture SUCCESS" { expect 0; [ -z "$output" ]; }
@test "6232 informative neighbor disabled inactive fixture NON COMPLIANT" { runtime loaded inactive disabled; expect 1; }
@test "6232 enabled inactive NON COMPLIANT" { runtime loaded inactive enabled; expect 1; }
@test "6232 enabled failed NON COMPLIANT" { runtime loaded failed enabled; expect 1; }
@test "6232 disabled active NON COMPLIANT" { runtime loaded active disabled; expect 1; }
@test "6232 missing coherent unit NON COMPLIANT not package SKIPPED" { runtime not-found inactive ''; expect 1; }
@test "6232 masked inactive NON COMPLIANT" { runtime masked inactive masked; expect 1; }
@test "6232 runtime masked active NON COMPLIANT" { runtime masked active masked-runtime; expect 1; }
@test "6232 activation transition ambiguous ERROR" { runtime loaded activating enabled; expect 2; }
@test "6232 deactivation transition ambiguous ERROR" { runtime loaded deactivating enabled; expect 2; }
@test "6232 reloading state unsupported ERROR" { runtime loaded reloading enabled; expect 2; }
@test "6232 missing tool ERROR" { RLCH_CIS_6_2_3_2_SYSTEMCTL="$RS_STATE/no-tool"; expect 2; }
@test "6232 nonexecutable tool ERROR" { chmod 0644 "$RLCH_CIS_6_2_3_2_SYSTEMCTL"; expect 2; }
@test "6232 manager failure ERROR raw diagnostic redacted" { touch "$RS_STATE/error"; expect 2; }
@test "6232 second observation failure ERROR" { touch "$RS_STATE/second-error"; expect 2; }
@test "6232 empty property response ERROR" { : > "$RS_STATE/current"; expect 2; }
@test "6232 unknown property ERROR" { printf 'Secret=SECRET-PEM\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 duplicate property ERROR" { printf 'ActiveState=active\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 properties may be reordered" { sort -r "$RS_STATE/current" -o "$RS_STATE/current"; expect 0; }
@test "6232 raw NUL rejected before shell substitution" { touch "$RS_STATE/nul"; expect 2; }
@test "6232 control byte ERROR no leak" { printf 'Secret=SECRET\001\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 oversized command response ERROR" { touch "$RS_STATE/oversized"; expect 2; }
@test "6232 primary alias identity ERROR even enabled active" { sed -i 's/rsyslog.service/alias.service/' "$RS_STATE/current"; expect 2; }
@test "6232 wrong unit suffix ERROR" { sed -i 's/rsyslog.service/rsyslog.socket/' "$RS_STATE/current"; expect 2; }
@test "6232 whitespace state not normalized" { sed -i 's/active$/active /' "$RS_STATE/current"; expect 2; }
@test "6232 timestamp drift ERROR" { second 's/100/101/'; expect 2; }
@test "6232 active state drift ERROR" { second 's/active/inactive/'; expect 2; }
@test "6232 unit file state drift ERROR" { second 's/enabled/disabled/'; expect 2; }
@test "6232 unit identity drift ERROR" { second 's/rsyslog.service/alias.service/'; expect 2; }
@test "6232 load state drift ERROR" { second 's/loaded/not-found/'; expect 2; }
@test "6232 order only difference stable" { cp "$RS_STATE/current" "$RS_STATE/second"; sort -r "$RS_STATE/second" -o "$RS_STATE/second"; expect 0; }
@test "6232 check validate repeated identical stable results" {
    for state in compliant noncompliant error; do
        runtime loaded active enabled; rm -f "$RS_STATE/error"
        case "$state" in noncompliant) runtime loaded inactive disabled;; error) touch "$RS_STATE/error";; esac
        run check; code=$status; text=$output; run validate; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]; run check; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]
    done
}
@test "6232 apply repeated compliant SUCCESS unchanged" { for repeat in 1 2; do run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 apply repeated noncompliant ERROR guidance no enable start" { runtime loaded inactive disabled; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 apply manager failure ERROR without raw stderr" { touch "$RS_STATE/error"; run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 rollback repeatable SUCCESS without observer no query" { rm "$RLCH_CIS_6_2_3_2_SYSTEMCTL"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$RS_CALLS" ]; }
@test "6232 preservation all APIs exact results content attributes administrator state" {
    set -o pipefail
    root="$BATS_TEST_TMPDIR/preserve"
    mkdir -p "$root"/{etc/rsyslog.d,etc/systemd/system/rsyslog.service.d,run/systemd/system,etc/pki/private,var/log/journal,run/log/journal,var/lib/rsyslog,var/lib/rlch,previous,usr/lib/systemd/system}
    for name in etc/rsyslog.conf etc/rsyslog.d/admin.conf etc/systemd/system/rsyslog.service.d/admin.conf usr/lib/systemd/system/rsyslog.service etc/journald.conf etc/journal-upload.conf etc/journal-remote.conf etc/pki/private/key.pem var/log/journal/synthetic.journal run/log/journal/synthetic.journal var/lib/rsyslog/admin-queue var/lib/rlch/admin-state previous/6211 previous/6212 previous/6213 previous/6214 previous/62211 previous/62212 previous/62213 previous/62214 previous/6222 previous/6223 previous/6224 previous/6231; do printf 'SECRET-PRIVATE-PEM\n' > "$root/$name"; done
    chmod 0600 "$root/etc/pki/private/key.pem"
    ln -s /dev/null "$root/run/systemd/system/rsyslog.service"
    ln -s /dev/null "$root/etc/rsyslog.d/admin-mask.conf"
    ln -s ../../../usr/lib/systemd/system/rsyslog.service "$root/etc/systemd/system/admin.service"
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in rpm dnf yum service journalctl rsyslogd openssl curl wget chmod chown rm cp ln tee sed; do
        printf '#!/usr/bin/env bash\nprintf mutation >> "$RS_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"
        chmod +x "$BATS_TEST_TMPDIR/bin/$command"
    done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for state in compliant noncompliant error; do
        runtime loaded active enabled
        case "$state" in noncompliant) runtime loaded inactive disabled;; error) printf '' > "$RS_STATE/error";; esac
        before=$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)
        inventory=$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
        observation=$(sha256sum "$RS_STATE/current")
        for repeat in 1 2; do for api in check validate apply rollback; do
            expected=0
            if [[ "$api" != rollback && "$state" != compliant ]]; then
                expected=2
                [[ "$api" == apply || "$state" != noncompliant ]] || expected=1
            fi
            run "$api"; [ "$status" -eq "$expected" ]
            [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *"$root"* ]]
        done; done
        [ "$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
        [ "$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]
        [ "$(sha256sum "$RS_STATE/current")" = "$observation" ]
    done
    export PATH="$saved_path"
    [ ! -e "$RS_STATE/mutation" ]
}
@test "6232 query scope exact service twice no socket graph RPM PKI" { expect 0; [ "$(wc -l < "$RS_CALLS")" -eq 2 ]; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 helper direct normalized stable machine fields" { run helper; [ "$status" -eq 0 ]; [ "$output" = 'rsyslog.service|loaded|active|enabled|100' ]; }
@test "6232 helper direct malformed unit rejected without query" { run rlch_systemd_properties "$RLCH_CIS_6_2_3_2_SYSTEMCTL" 'bad;SECRET.service' runtime; [ "$status" -eq 2 ]; [ ! -e "$RS_CALLS" ]; }
@test "6232 helper direct unknown kind rejected without query" { run rlch_systemd_properties "$RLCH_CIS_6_2_3_2_SYSTEMCTL" rsyslog.service unknown; [ "$status" -eq 2 ]; [ ! -e "$RS_CALLS" ]; }
@test "6232 active enabled-runtime not persistent enabled NON COMPLIANT" { runtime loaded active enabled-runtime; expect 1; }
@test "6232 active static not persistent enabled NON COMPLIANT" { runtime loaded active static; expect 1; }
@test "6232 active indirect not persistent enabled NON COMPLIANT" { runtime loaded active indirect; expect 1; }
@test "6232 active generated not persistent enabled NON COMPLIANT" { runtime loaded active generated; expect 1; }
@test "6232 active transient not persistent enabled NON COMPLIANT" { runtime loaded active transient; expect 1; }
@test "6232 active alias not persistent enabled NON COMPLIANT" { runtime loaded active alias; expect 1; }
@test "6232 active linked not persistent enabled NON COMPLIANT" { runtime loaded active linked; expect 1; }
@test "6232 active linked-runtime not persistent enabled NON COMPLIANT" { runtime loaded active linked-runtime; expect 1; }
@test "6232 missing Id ERROR" { sed -i "/^Id=/d" "$RS_STATE/current"; expect 2; }
@test "6232 missing LoadState ERROR" { sed -i "/^LoadState=/d" "$RS_STATE/current"; expect 2; }
@test "6232 missing ActiveState ERROR" { sed -i "/^ActiveState=/d" "$RS_STATE/current"; expect 2; }
@test "6232 missing UnitFileState ERROR" { sed -i "/^UnitFileState=/d" "$RS_STATE/current"; expect 2; }
@test "6232 missing StateChangeTimestampMonotonic ERROR" { sed -i "/^StateChangeTimestampMonotonic=/d" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent bad-load ERROR" { sed -i "s/loaded/error/" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent bad-unit-file ERROR" { sed -i "s/enabled/unknown/" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent bad-timestamp ERROR" { sed -i "s/100/-1/" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent empty-timestamp ERROR" { sed -i "s/100//" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent loaded-masked ERROR" { sed -i "s/enabled/masked/" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent missing-active ERROR" { sed -i "s/loaded/not-found/" "$RS_STATE/current"; expect 2; }
@test "6232 incoherent empty-loaded-file ERROR" { sed -i "s/enabled//" "$RS_STATE/current"; expect 2; }

@test "6232 masked failed remains NON COMPLIANT" { runtime masked failed masked; expect 1; }
@test "6232 persistent masked active remains NON COMPLIANT" { runtime masked active masked; expect 1; }
@test "6232 runtime masked inactive remains NON COMPLIANT" { runtime masked inactive masked-runtime; expect 1; }
@test "6232 bad-setting config LoadState ERROR" { runtime bad-setting inactive disabled; expect 2; }
@test "6232 unknown runtime state ERROR" { runtime loaded unknown enabled; expect 2; }
@test "6232 empty identity ERROR" { sed -i 's/Id=rsyslog.service/Id=/' "$RS_STATE/current"; expect 2; }
@test "6232 incoherent missing enabled unit ERROR" { runtime not-found inactive enabled; expect 2; }
@test "6232 incoherent mask disabled ERROR" { runtime masked inactive disabled; expect 2; }
@test "6232 timestamp zero accepted stable" { sed -i 's/100/0/' "$RS_STATE/current"; expect 0; }
@test "6232 CR rejected" { printf '\r\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 TAB rejected" { printf '\t\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 DEL rejected" { printf '\177\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 interior blank row rejected" { sed -i '2i\\' "$RS_STATE/current"; expect 2; }
@test "6232 malformed property without equals rejected" { printf 'SECRET\n' >> "$RS_STATE/current"; expect 2; }
@test "6232 validate rereads after administrator disables service" { expect 0; runtime loaded inactive disabled; run validate; [ "$status" -eq 1 ]; }
@test "6232 socket activity cannot substitute inactive service" { printf 'active\n' > "$RS_STATE/rsyslog.socket"; runtime loaded inactive enabled; expect 1; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 missing service never inferred from installed package" { printf 'rsyslog\n' > "$RS_STATE/installed-package"; runtime not-found inactive ''; expect 1; }
@test "6232 malformed state apply ERROR guidance and no mutation" { runtime bad-setting inactive disabled; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* && "$output" == *'logging architecture'* && "$output" == *SELinux* ]]; [ ! -e "$RS_STATE/mutation" ]; }
@test "6232 helper direct missing unit normalized" { runtime not-found inactive ''; run helper; [ "$status" -eq 0 ]; [ "$output" = 'rsyslog.service|not-found|inactive||100' ]; }
@test "6232 helper direct masked unit normalized" { runtime masked inactive masked-runtime; run helper; [ "$status" -eq 0 ]; [ "$output" = 'rsyslog.service|masked|inactive|masked-runtime|100' ]; }
@test "6232 helper direct incoherent state rejected" { runtime loaded active masked; run helper; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "6232 helper direct manager failure rejected redacted" { touch "$RS_STATE/error"; run helper; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; }
@test "6232 helper direct NUL rejected" { touch "$RS_STATE/nul"; run helper; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "6232 exact query locale environment forced" { export LC_ALL=C.UTF-8 SYSTEMD_PAGER=wrong SYSTEMD_COLORS=1; expect 0; }
@test "6232 no package binary config socket prerequisite for narrow service criterion" {
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in rpm dnf rsyslogd journalctl stat; do
        printf '#!/usr/bin/env bash\nprintf mutation >> "$RS_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"
        chmod +x "$BATS_TEST_TMPDIR/bin/$command"
    done
    saved_path="$PATH"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    expect 0
    export PATH="$saved_path"
    [ ! -e "$RS_STATE/mutation" ]
}
