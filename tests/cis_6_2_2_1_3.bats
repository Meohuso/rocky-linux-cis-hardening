#!/usr/bin/env bats
# Neighbor CAS service fixtures provide technical context, not mapped CIS tests.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_1_3_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl"
    export UP_STATE="$BATS_TEST_TMPDIR/observations" UP_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$UP_STATE"
    cat > "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$UP_CALLS"
[[ "$#" == 6 && "$1" == --system && "$2" == --no-pager && "$3" == show && "$4" == --property=Id,LoadState,ActiveState,UnitFileState,StateChangeTimestampMonotonic && "$5" == -- && "$6" == systemd-journal-upload.service ]] || { touch "$UP_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_PAGER" == cat ]] || exit 3
if [[ -e "$UP_STATE/error" ]]; then echo SECRET-DBUS-ERROR >&2; exit 1; fi
if [[ -e "$UP_STATE/nul" ]]; then printf 'Id=systemd-journal-upload.service\0\n'; exit; fi
if [[ -e "$UP_STATE/oversized" ]]; then printf '%140000s\n' x; exit; fi
if [[ $(wc -l < "$UP_CALLS") -ge 2 && -e "$UP_STATE/second-error" ]]; then echo SECRET-SECOND >&2; exit 1; fi
if [[ $(wc -l < "$UP_CALLS") -ge 2 && -e "$UP_STATE/second" ]]; then cat "$UP_STATE/second"; else cat "$UP_STATE/current"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL"
    runtime loaded active enabled
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/3/module.sh"
}
runtime() { printf 'Id=systemd-journal-upload.service\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\nStateChangeTimestampMonotonic=100\n' "$1" "$2" "$3" > "$UP_STATE/current"; }
expect() { rm -f "$UP_CALLS"; run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *PEM* ]]; }
helper() { rlch_systemd_properties "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" systemd-journal-upload.service runtime; }
second() { cp "$UP_STATE/current" "$UP_STATE/second"; sed -i "$1" "$UP_STATE/second"; }
@test "62213 metadata exact applicable unmapped Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.1.3 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure systemd-journal-upload is enabled and active' ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "62213 exact pinned pending mapping documented no invented RHEL9 CCE" {
    run sed -n '/^## CIS 6.2.2.1.3 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: pending'* && "$output" == *'no rules:'* && "$output" == *'no related_rules:'* && "$output" == *'No RHEL9 CCE'* && "$output" == *'NOT mapped'* ]]
}
@test "62213 informative neighbor enabled active fixture SUCCESS" { expect 0; [ -z "$output" ]; }
@test "62213 informative neighbor disabled inactive fixture NON COMPLIANT" { runtime loaded inactive disabled; expect 1; }
@test "62213 enabled inactive NON COMPLIANT" { runtime loaded inactive enabled; expect 1; }
@test "62213 enabled failed NON COMPLIANT" { runtime loaded failed enabled; expect 1; }
@test "62213 disabled active NON COMPLIANT" { runtime loaded active disabled; expect 1; }
@test "62213 missing coherent unit NON COMPLIANT not package SKIPPED" { runtime not-found inactive ''; expect 1; }
@test "62213 masked inactive NON COMPLIANT" { runtime masked inactive masked; expect 1; }
@test "62213 runtime masked active NON COMPLIANT" { runtime masked active masked-runtime; expect 1; }
@test "62213 activation transition ambiguous ERROR" { runtime loaded activating enabled; expect 2; }
@test "62213 deactivation transition ambiguous ERROR" { runtime loaded deactivating enabled; expect 2; }
@test "62213 reloading state unsupported ERROR" { runtime loaded reloading enabled; expect 2; }
@test "62213 missing tool ERROR" { RLCH_CIS_6_2_2_1_3_SYSTEMCTL="$UP_STATE/no-tool"; expect 2; }
@test "62213 nonexecutable tool ERROR" { chmod 0644 "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL"; expect 2; }
@test "62213 manager failure ERROR raw diagnostic redacted" { touch "$UP_STATE/error"; expect 2; }
@test "62213 second observation failure ERROR" { touch "$UP_STATE/second-error"; expect 2; }
@test "62213 empty property response ERROR" { : > "$UP_STATE/current"; expect 2; }
@test "62213 unknown property ERROR" { printf 'Secret=SECRET-PEM\n' >> "$UP_STATE/current"; expect 2; }
@test "62213 duplicate property ERROR" { printf 'ActiveState=active\n' >> "$UP_STATE/current"; expect 2; }
@test "62213 properties may be reordered" { sort -r "$UP_STATE/current" -o "$UP_STATE/current"; expect 0; }
@test "62213 raw NUL rejected before shell substitution" { touch "$UP_STATE/nul"; expect 2; }
@test "62213 control byte ERROR no leak" { printf 'Secret=SECRET\001\n' >> "$UP_STATE/current"; expect 2; }
@test "62213 oversized command response ERROR" { touch "$UP_STATE/oversized"; expect 2; }
@test "62213 primary alias identity ERROR even enabled active" { sed -i 's/systemd-journal-upload.service/alias.service/' "$UP_STATE/current"; expect 2; }
@test "62213 wrong unit suffix ERROR" { sed -i 's/systemd-journal-upload.service/systemd-journal-upload.socket/' "$UP_STATE/current"; expect 2; }
@test "62213 whitespace state not normalized" { sed -i 's/active$/active /' "$UP_STATE/current"; expect 2; }
@test "62213 timestamp drift ERROR" { second 's/100/101/'; expect 2; }
@test "62213 active state drift ERROR" { second 's/active/inactive/'; expect 2; }
@test "62213 unit file state drift ERROR" { second 's/enabled/disabled/'; expect 2; }
@test "62213 unit identity drift ERROR" { second 's/systemd-journal-upload.service/alias.service/'; expect 2; }
@test "62213 load state drift ERROR" { second 's/loaded/not-found/'; expect 2; }
@test "62213 order only difference stable" { cp "$UP_STATE/current" "$UP_STATE/second"; sort -r "$UP_STATE/second" -o "$UP_STATE/second"; expect 0; }
@test "62213 check validate repeated identical stable results" {
    for state in compliant noncompliant error; do
        runtime loaded active enabled; rm -f "$UP_STATE/error"
        case "$state" in noncompliant) runtime loaded inactive disabled;; error) touch "$UP_STATE/error";; esac
        run check; code=$status; text=$output; run validate; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]; run check; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]
    done
}
@test "62213 apply repeated compliant SUCCESS unchanged" { for repeat in 1 2; do run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$UP_STATE/mutation" ]; }
@test "62213 apply repeated noncompliant ERROR guidance no enable start" { runtime loaded inactive disabled; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; [ ! -e "$UP_STATE/mutation" ]; }
@test "62213 apply manager failure ERROR without raw stderr" { touch "$UP_STATE/error"; run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; [ ! -e "$UP_STATE/mutation" ]; }
@test "62213 rollback repeatable SUCCESS without observer no query" { rm "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$UP_CALLS" ]; }
@test "62213 no CHANGED or package service config key trust prior-control mutation" {
    set -o pipefail
    root="$BATS_TEST_TMPDIR/preserve"; mkdir -p "$root"/{etc/systemd/system,etc/pki/private,etc/pki/ca-trust,run/systemd/system,var/lib/rlch,previous}
    for name in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/systemd/system/upload.service etc/systemd/system/remote.socket etc/pki/private/key.pem etc/pki/ca-trust/admin.pem previous/6214 previous/62211 previous/62212; do printf 'SECRET-PRIVATE-PEM\n' > "$root/$name"; done
    ln -s ../etc/systemd/system/upload.service "$root/previous/admin-link"
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in rpm dnf yum openssl curl wget chmod chown; do printf '#!/usr/bin/env bash\ntouch "$UP_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    before=$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    for state in enabled disabled; do runtime loaded active "$state"; for repeat in 1 2; do for api in check validate apply rollback; do run "$api"; [ "$status" -ne 4 ]; [[ "$output" != *SECRET* ]]; done; done; done
    [ "$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]; [ "$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]; [ ! -e "$UP_STATE/mutation" ]
}
@test "62213 query scope exact service twice no socket graph RPM PKI" { expect 0; [ "$(wc -l < "$UP_CALLS")" -eq 2 ]; [ ! -e "$UP_STATE/mutation" ]; }
@test "62213 helper direct normalized stable machine fields" { run helper; [ "$status" -eq 0 ]; [ "$output" = 'systemd-journal-upload.service|loaded|active|enabled|100' ]; }
@test "62213 helper direct malformed unit rejected without query" { run rlch_systemd_properties "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" 'bad;SECRET.service' runtime; [ "$status" -eq 2 ]; [ ! -e "$UP_CALLS" ]; }
@test "62213 helper direct unknown kind rejected without query" { run rlch_systemd_properties "$RLCH_CIS_6_2_2_1_3_SYSTEMCTL" systemd-journal-upload.service unknown; [ "$status" -eq 2 ]; [ ! -e "$UP_CALLS" ]; }
@test "62213 active enabled-runtime not persistent enabled NON COMPLIANT" { runtime loaded active enabled-runtime; expect 1; }
@test "62213 active static not persistent enabled NON COMPLIANT" { runtime loaded active static; expect 1; }
@test "62213 active indirect not persistent enabled NON COMPLIANT" { runtime loaded active indirect; expect 1; }
@test "62213 active generated not persistent enabled NON COMPLIANT" { runtime loaded active generated; expect 1; }
@test "62213 active transient not persistent enabled NON COMPLIANT" { runtime loaded active transient; expect 1; }
@test "62213 active alias not persistent enabled NON COMPLIANT" { runtime loaded active alias; expect 1; }
@test "62213 active linked not persistent enabled NON COMPLIANT" { runtime loaded active linked; expect 1; }
@test "62213 active linked-runtime not persistent enabled NON COMPLIANT" { runtime loaded active linked-runtime; expect 1; }
@test "62213 missing Id ERROR" { sed -i "/^Id=/d" "$UP_STATE/current"; expect 2; }
@test "62213 missing LoadState ERROR" { sed -i "/^LoadState=/d" "$UP_STATE/current"; expect 2; }
@test "62213 missing ActiveState ERROR" { sed -i "/^ActiveState=/d" "$UP_STATE/current"; expect 2; }
@test "62213 missing UnitFileState ERROR" { sed -i "/^UnitFileState=/d" "$UP_STATE/current"; expect 2; }
@test "62213 missing StateChangeTimestampMonotonic ERROR" { sed -i "/^StateChangeTimestampMonotonic=/d" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent bad-load ERROR" { sed -i "s/loaded/error/" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent bad-unit-file ERROR" { sed -i "s/enabled/unknown/" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent bad-timestamp ERROR" { sed -i "s/100/-1/" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent empty-timestamp ERROR" { sed -i "s/100//" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent loaded-masked ERROR" { sed -i "s/enabled/masked/" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent missing-active ERROR" { sed -i "s/loaded/not-found/" "$UP_STATE/current"; expect 2; }
@test "62213 incoherent empty-loaded-file ERROR" { sed -i "s/enabled//" "$UP_STATE/current"; expect 2; }
