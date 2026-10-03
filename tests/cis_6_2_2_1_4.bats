#!/usr/bin/env bats
# Mapped pinned CAS socket_disabled template fixtures are simulated only.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_1_4_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl"
    export REMOTE_STATE="$BATS_TEST_TMPDIR/observations" REMOTE_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$REMOTE_STATE"
    cat > "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$REMOTE_CALLS"
[[ "$#" == 6 && "$1" == --system && "$2" == --no-pager && "$3" == show && "$4" == --property=Id,LoadState,ActiveState,UnitFileState,StateChangeTimestampMonotonic && "$5" == -- && "$6" == systemd-journal-remote.socket ]] || { touch "$REMOTE_STATE/mutation"; exit 99; }
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_PAGER" == cat ]] || exit 3
if [[ -e "$REMOTE_STATE/error" ]]; then echo SECRET-DBUS-ERROR >&2; exit 1; fi
if [[ -e "$REMOTE_STATE/nul" ]]; then printf 'Id=systemd-journal-remote.socket\0\n'; exit; fi
if [[ -e "$REMOTE_STATE/oversized" ]]; then printf '%140000s\n' x; exit; fi
if [[ $(wc -l < "$REMOTE_CALLS") -ge 2 && -e "$REMOTE_STATE/second-error" ]]; then echo SECRET-SECOND >&2; exit 1; fi
if [[ $(wc -l < "$REMOTE_CALLS") -ge 2 && -e "$REMOTE_STATE/second" ]]; then cat "$REMOTE_STATE/second"; else cat "$REMOTE_STATE/current"; fi
MOCK
    chmod +x "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL"
    runtime masked inactive masked
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/4/module.sh"
}
runtime() { printf 'Id=systemd-journal-remote.socket\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\nStateChangeTimestampMonotonic=100\n' "$1" "$2" "$3" > "$REMOTE_STATE/current"; }
expect() { rm -f "$REMOTE_CALLS"; run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *PEM* ]]; }
helper() { rlch_systemd_properties "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" systemd-journal-remote.socket runtime; }
second() { cp "$REMOTE_STATE/current" "$REMOTE_STATE/second"; sed -i "$1" "$REMOTE_STATE/second"; }
@test "62214 exact metadata official mapped rule Level 1" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.1.4 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure systemd-journal-remote service is not in use' ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled ]
}
@test "62214 documented pinned automated mapping RHEL9 CCE and OVAL scope" {
    run sed -n '/^## CIS 6.2.2.1.4 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [[ "$output" == *'status: automated'* && "$output" == *'CCE-87606-0'* && "$output" == *'LoadState=masked'* && "$output" == *'no related_rules:'* ]]
}
@test "62214 official template socket_disabled pass fixture simulated" { expect 0; [ -z "$output" ]; }
@test "62214 official template socket_enabled fail fixture simulated" { runtime loaded active enabled; expect 1; }
@test "62214 disabled inactive alone does not satisfy OVAL mask" { runtime loaded inactive disabled; expect 1; }
@test "62214 active masked socket OVAL pass but OCIL discordance requires ERROR" { runtime masked active masked; expect 2; }
@test "62214 failed masked socket not OCIL inactive requires ERROR" { runtime masked failed masked; expect 2; }
@test "62214 runtime mask OVAL pass but SCE OCIL discordance requires ERROR" { runtime masked inactive masked-runtime; expect 2; }
@test "62214 runtime mask active discordant requires ERROR" { runtime masked active masked-runtime; expect 2; }
@test "62214 coherent absent socket OCIL OVAL interpretation requires review ERROR" { runtime not-found inactive ''; expect 2; }
@test "62214 aliases to different socket ERROR" { sed -i 's/systemd-journal-remote.socket/other.socket/' "$REMOTE_STATE/current"; expect 2; }
@test "62214 service substitution ERROR" { sed -i 's/systemd-journal-remote.socket/systemd-journal-remote.service/' "$REMOTE_STATE/current"; expect 2; }
@test "62214 only exact receiver socket queried twice no service upload RPM PKI graph" { expect 0; [ "$(wc -l < "$REMOTE_CALLS")" -eq 2 ]; [ ! -e "$REMOTE_STATE/mutation" ]; }
@test "62214 manager unavailable ERROR diagnostic redacted" { touch "$REMOTE_STATE/error"; expect 2; }
@test "62214 second command fails ERROR" { touch "$REMOTE_STATE/second-error"; expect 2; }
@test "62214 absent observation command ERROR" { RLCH_CIS_6_2_2_1_4_SYSTEMCTL="$REMOTE_STATE/missing"; expect 2; }
@test "62214 nonexecutable command ERROR" { chmod 0644 "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL"; expect 2; }
@test "62214 empty observation ERROR" { : > "$REMOTE_STATE/current"; expect 2; }
@test "62214 missing separator ERROR" { printf 'malformed SECRET\n' >> "$REMOTE_STATE/current"; expect 2; }
@test "62214 duplicate field ERROR" { printf 'LoadState=masked\n' >> "$REMOTE_STATE/current"; expect 2; }
@test "62214 unknown field ERROR" { printf 'Unknown=SECRET\n' >> "$REMOTE_STATE/current"; expect 2; }
@test "62214 NUL rejected before shell substitution" { touch "$REMOTE_STATE/nul"; expect 2; }
@test "62214 raw control bytes ERROR" { printf 'Unknown=SECRET\001\n' >> "$REMOTE_STATE/current"; expect 2; }
@test "62214 output size bound ERROR" { touch "$REMOTE_STATE/oversized"; expect 2; }
@test "62214 property order harmless normalized" { sort -r "$REMOTE_STATE/current" -o "$REMOTE_STATE/current"; expect 0; }
@test "62214 order difference between observations harmless" { cp "$REMOTE_STATE/current" "$REMOTE_STATE/second"; sort -r "$REMOTE_STATE/second" -o "$REMOTE_STATE/second"; expect 0; }
@test "62214 timestamp drift ERROR" { second 's/100/101/'; expect 2; }
@test "62214 runtime drift ERROR despite still masked" { second 's/inactive/active/'; expect 2; }
@test "62214 file mask drift ERROR despite still masked" { second 's/UnitFileState=masked/UnitFileState=masked-runtime/'; expect 2; }
@test "62214 mask appearance ERROR instead of transient PASS" { runtime loaded inactive disabled; second 's/loaded/masked/;s/disabled/masked/'; expect 2; }
@test "62214 mask disappearance ERROR instead of transient failure" { second 's/masked/loaded/;s/UnitFileState=loaded/UnitFileState=disabled/'; expect 2; }
@test "62214 identity drift ERROR" { second 's/systemd-journal-remote.socket/other.socket/'; expect 2; }
@test "62214 check validate repeated identical all stable states" {
    for state in compliant noncompliant error; do
        runtime masked inactive masked; rm -f "$REMOTE_STATE/error"
        case "$state" in noncompliant) runtime loaded active enabled;; error) touch "$REMOTE_STATE/error";; esac
        run check; code=$status; text=$output; run validate; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]; run check; [ "$status" -eq "$code" ]; [ "$output" = "$text" ]
    done
}
@test "62214 apply compliant repeated SUCCESS no mutation" { for repeat in 1 2; do run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$REMOTE_STATE/mutation" ]; }
@test "62214 apply unmasked repeated ERROR guidance no stop mask disable" { runtime loaded active enabled; for repeat in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]; done; [ ! -e "$REMOTE_STATE/mutation" ]; }
@test "62214 apply unsafe ERROR no raw stderr" { touch "$REMOTE_STATE/error"; run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; [ ! -e "$REMOTE_STATE/mutation" ]; }
@test "62214 rollback repeatable SUCCESS unavailable tool no query" { rm "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL"; for repeat in 1 2; do run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done; [ ! -e "$REMOTE_CALLS" ]; }
@test "62214 all APIs preserve configs credentials masks state prior controls never CHANGED" {
    set -o pipefail
    root="$BATS_TEST_TMPDIR/preserve"; mkdir -p "$root"/{etc/systemd/system,etc/pki/private,etc/pki/ca-trust,run/systemd/system,var/lib/rlch,previous}
    for name in etc/systemd/journal-upload.conf etc/systemd/journal-remote.conf etc/systemd/system/upload.service etc/systemd/system/remote.service etc/pki/private/key.pem etc/pki/ca-trust/admin.pem previous/62211 previous/62212 previous/62213; do printf 'SECRET-PRIVATE-PEM\n' > "$root/$name"; done
    ln -s /dev/null "$root/etc/systemd/system/systemd-journal-remote.socket"
    ln -s /dev/null "$root/run/systemd/system/systemd-journal-remote.socket"
    mkdir "$BATS_TEST_TMPDIR/bin"
    for command in rpm dnf yum openssl curl wget chmod chown rm cp ln; do printf '#!/usr/bin/env bash\ntouch "$REMOTE_STATE/mutation"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"; done
    preserve_path="$PATH"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    before=$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    for state in masked loaded; do if [ "$state" = masked ]; then runtime masked inactive masked; else runtime loaded active enabled; fi; for repeat in 1 2; do for api in check validate apply rollback; do run "$api"; [ "$status" -ne 4 ]; [[ "$output" != *SECRET* ]]; done; done; done
    export PATH="$preserve_path"
    [ "$(find "$root" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]; [ "$(find "$root" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]; [ ! -e "$REMOTE_STATE/mutation" ]
}
@test "62214 helper direct masked socket normalized property row" { run helper; [ "$status" -eq 0 ]; [ "$output" = 'systemd-journal-remote.socket|masked|inactive|masked|100' ]; }
@test "62214 helper direct invalid socket name rejected before query" { run rlch_systemd_properties "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" 'bad;SECRET.socket' runtime; [ "$status" -eq 2 ]; [ ! -e "$REMOTE_CALLS" ]; }
@test "62214 helper direct unknown observation kind rejected before query" { run rlch_systemd_properties "$RLCH_CIS_6_2_2_1_4_SYSTEMCTL" systemd-journal-remote.socket unknown; [ "$status" -eq 2 ]; [ ! -e "$REMOTE_CALLS" ]; }
@test "62214 loaded inactive enabled not masked NON COMPLIANT" { runtime loaded inactive enabled; expect 1; }
@test "62214 loaded inactive enabled-runtime not masked NON COMPLIANT" { runtime loaded inactive enabled-runtime; expect 1; }
@test "62214 loaded inactive disabled not masked NON COMPLIANT" { runtime loaded inactive disabled; expect 1; }
@test "62214 loaded inactive static not masked NON COMPLIANT" { runtime loaded inactive static; expect 1; }
@test "62214 loaded inactive indirect not masked NON COMPLIANT" { runtime loaded inactive indirect; expect 1; }
@test "62214 loaded inactive generated not masked NON COMPLIANT" { runtime loaded inactive generated; expect 1; }
@test "62214 loaded inactive transient not masked NON COMPLIANT" { runtime loaded inactive transient; expect 1; }
@test "62214 loaded inactive alias not masked NON COMPLIANT" { runtime loaded inactive alias; expect 1; }
@test "62214 loaded inactive linked not masked NON COMPLIANT" { runtime loaded inactive linked; expect 1; }
@test "62214 loaded inactive linked-runtime not masked NON COMPLIANT" { runtime loaded inactive linked-runtime; expect 1; }
@test "62214 missing Id ERROR" { sed -i "/^Id=/d" "$REMOTE_STATE/current"; expect 2; }
@test "62214 missing LoadState ERROR" { sed -i "/^LoadState=/d" "$REMOTE_STATE/current"; expect 2; }
@test "62214 missing ActiveState ERROR" { sed -i "/^ActiveState=/d" "$REMOTE_STATE/current"; expect 2; }
@test "62214 missing UnitFileState ERROR" { sed -i "/^UnitFileState=/d" "$REMOTE_STATE/current"; expect 2; }
@test "62214 missing StateChangeTimestampMonotonic ERROR" { sed -i "/^StateChangeTimestampMonotonic=/d" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent bad-load ERROR" { sed -i "s/LoadState=masked/LoadState=error/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent bad-file ERROR" { sed -i "s/UnitFileState=masked/UnitFileState=unknown/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent loaded-masked ERROR" { sed -i "s/LoadState=masked/LoadState=loaded/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent masked-disabled ERROR" { sed -i "s/UnitFileState=masked/UnitFileState=disabled/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent bad-time ERROR" { sed -i "s/100/-1/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent empty-time ERROR" { sed -i "s/100//" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent transition ERROR" { sed -i "s/inactive/activating/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent deactivating ERROR" { sed -i "s/inactive/deactivating/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent reloading ERROR" { sed -i "s/inactive/reloading/" "$REMOTE_STATE/current"; expect 2; }
@test "62214 unsupported or incoherent state-whitespace ERROR" { sed -i "s/LoadState=masked/LoadState=masked /" "$REMOTE_STATE/current"; expect 2; }
