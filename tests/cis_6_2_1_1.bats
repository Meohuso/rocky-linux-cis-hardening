#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_1_1_RPM="$BATS_TEST_TMPDIR/rpm"
    export RLCH_CIS_6_2_1_1_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl"
    export JOURNAL_FIXTURE="$BATS_TEST_TMPDIR/units"
    export JOURNAL_CALLS="$BATS_TEST_TMPDIR/calls"
    export JOURNAL_RPM_STATE="$BATS_TEST_TMPDIR/rpm-state"
    mkdir "$JOURNAL_FIXTURE"
    echo installed > "$JOURNAL_RPM_STATE"
    cat > "$RLCH_CIS_6_2_1_1_RPM" <<'MOCK'
#!/usr/bin/env bash
printf 'rpm %s\n' "$*" >> "$JOURNAL_CALLS"
[[ "$1" == -q && "$2" == --qf && "$4" == systemd ]] || exit 3
case "$(cat "$JOURNAL_RPM_STATE")" in
installed) echo systemd;;
absent) echo 'package systemd is not installed'; exit 1;;
duplicate) printf 'systemd\nsystemd\n';;
error) echo 'SECRET RPM error'; exit 2;;
corrupt) echo 'SECRET RPM corrupt'; exit 1;;
wrong) echo other;;
empty) exit 0;;
esac
MOCK
    cat > "$RLCH_CIS_6_2_1_1_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$JOURNAL_CALLS"
[[ "$1" == --system && "$2" == --no-pager && "$3" == show && "$5" == -- ]] || { echo mutation >> "$JOURNAL_FIXTURE/mutations"; exit 3; }
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 ]] || exit 3
[[ ! -e "$JOURNAL_FIXTURE/error" ]] || { echo 'SECRET D-Bus inaccessible' >&2; exit 1; }
unit="${@: -1}"
[[ -e "$JOURNAL_FIXTURE/$unit" ]] || exit 1
cat "$JOURNAL_FIXTURE/$unit"
MOCK
    chmod 0755 "$RLCH_CIS_6_2_1_1_RPM" "$RLCH_CIS_6_2_1_1_SYSTEMCTL"
    runtime systemd-journald.service active static
    runtime systemd-journald.socket active static
    target multi-user.target 'systemd-journald.service' ''
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/1/module.sh"
    dnf_install_package() { echo install >> "$JOURNAL_FIXTURE/mutations"; return 1; }
    dnf_remove_package() { echo remove >> "$JOURNAL_FIXTURE/mutations"; return 1; }
}
runtime() {
    printf 'Id=%s\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\nStateChangeTimestampMonotonic=100\n' "$1" "${4:-loaded}" "$2" "$3" > "$JOURNAL_FIXTURE/$1"
}
target() {
    printf 'Id=%s\nLoadState=loaded\nRequires=%s\nWants=%s\n' "$1" "$2" "$3" > "$JOURNAL_FIXTURE/$1"
}
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
@test "metadata exact primary mapping Level 1 enabled no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.1.1 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled ]
}
@test "installed active static units and service dependency PASS" {
    expect 0;
}
@test "absent systemd NON COMPLIANT apply manual ERROR without systemctl" {
    echo absent > "$JOURNAL_RPM_STATE"; expect 1; run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]
    ! rg --quiet systemctl "$JOURNAL_CALLS"; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
}
@test "RPM errors malformed success and unavailable executable ERROR" {
    for value in error corrupt wrong empty; do echo "$value" > "$JOURNAL_RPM_STATE"; expect 2; done
    RLCH_CIS_6_2_1_1_RPM="$BATS_TEST_TMPDIR/missing"; expect 2
}
@test "duplicate installed RPM instances accepted" {
    echo duplicate > "$JOURNAL_RPM_STATE"; expect 0;
}
@test "service active socket inactive accepted" {
    runtime systemd-journald.socket inactive static; expect 0;
}
@test "service inactive socket active accepted" {
    runtime systemd-journald.service inactive static; expect 0;
}
@test "service failed socket active accepted by OVAL OR" {
    runtime systemd-journald.service failed static; expect 0;
}
@test "both inactive NON COMPLIANT" {
    runtime systemd-journald.service inactive static; runtime systemd-journald.socket inactive static; expect 1;
}
@test "failed service and inactive socket NON COMPLIANT" {
    runtime systemd-journald.service failed static; runtime systemd-journald.socket inactive static; expect 1;
}
@test "socket-only startup dependency PASS" {
    target multi-user.target '' 'systemd-journald.socket'; expect 0;
}
@test "both startup dependencies PASS" {
    target multi-user.target 'systemd-journald.service' 'systemd-journald.socket'; expect 0;
}
@test "active units without startup dependency NON COMPLIANT" {
    target multi-user.target '' ''; expect 1;
}
@test "enabled does not substitute for missing dependency" {
    runtime systemd-journald.service active enabled; runtime systemd-journald.socket active enabled
    target multi-user.target '' ''; expect 1
}
@test "static disabled indirect generated transient alias linked states do not imply failure" {
    for state in static disabled indirect enabled enabled-runtime generated transient alias linked linked-runtime; do runtime systemd-journald.service active "$state"; expect 0; done
}
@test "masked inactive service with active relevant socket may PASS" {
    runtime systemd-journald.service inactive masked masked; expect 0;
}
@test "both masked inactive NON COMPLIANT" {
    runtime systemd-journald.service inactive masked masked; runtime systemd-journald.socket inactive masked-runtime masked; expect 1;
}
@test "mask applied to running service does not erase runtime OVAL activity" {
    runtime systemd-journald.service active masked masked; runtime systemd-journald.socket inactive static; expect 0
}
@test "not-found optional socket with active service still PASS" {
    runtime systemd-journald.socket inactive '' not-found; expect 0;
}
@test "both units safely reported not-found NON COMPLIANT" {
    runtime systemd-journald.service inactive '' not-found; runtime systemd-journald.socket inactive '' not-found; expect 1;
}
@test "incoherent not-found active or loaded masked metadata ERROR" {
    runtime systemd-journald.service active '' not-found; expect 2
    runtime systemd-journald.service active masked loaded; expect 2
}
@test "activating deactivating reloading refreshing maintenance unknown states ERROR" {
    for state in activating deactivating reloading refreshing maintenance UNKNOWN; do runtime systemd-journald.service "$state" static; expect 2; done
}
@test "unknown or error LoadState ERROR" {
    for state in error bad-setting stub merged UNKNOWN; do runtime systemd-journald.service inactive static "$state"; expect 2; done
}
@test "unknown UnitFileState or missing loaded UnitFileState ERROR" {
    runtime systemd-journald.service active UNKNOWN; expect 2; runtime systemd-journald.service active ''; expect 2;
}
@test "systemctl failure D-Bus unavailable and offline ERROR" {
    touch "$JOURNAL_FIXTURE/error"; expect 2; run apply; [ "$status" -eq 2 ]; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
}
@test "offline container success text is unexpected ERROR" {
    printf 'systemd not running in container\n' > "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2;
}
@test "missing systemctl executable ERROR" {
    RLCH_CIS_6_2_1_1_SYSTEMCTL="$BATS_TEST_TMPDIR/missing"; expect 2;
}
@test "empty output missing duplicate extra malformed properties ERROR" {
    cp "$JOURNAL_FIXTURE/systemd-journald.service" "$BATS_TEST_TMPDIR/saved"
    for value in empty missing duplicate extra malformed; do
        cp "$BATS_TEST_TMPDIR/saved" "$JOURNAL_FIXTURE/systemd-journald.service"
        case "$value" in empty) : > "$JOURNAL_FIXTURE/systemd-journald.service";; missing) sed -i '/ActiveState=/d' "$JOURNAL_FIXTURE/systemd-journald.service";; duplicate) echo ActiveState=active >> "$JOURNAL_FIXTURE/systemd-journald.service";; extra) echo SECRET=bad >> "$JOURNAL_FIXTURE/systemd-journald.service";; malformed) echo '=SECRET' >> "$JOURNAL_FIXTURE/systemd-journald.service";; esac
        expect 2
    done
}
@test "property order irrelevant and aliases with same suffix observable" {
    sort -r "$JOURNAL_FIXTURE/systemd-journald.service" > "$BATS_TEST_TMPDIR/reordered"; mv "$BATS_TEST_TMPDIR/reordered" "$JOURNAL_FIXTURE/systemd-journald.service"; expect 0
    sed -i 's/Id=systemd-journald.service/Id=journal-alias.service/' "$JOURNAL_FIXTURE/systemd-journald.service"; expect 0
}
@test "wrong Id suffix ERROR" {
    sed -i 's/Id=systemd-journald.service/Id=SECRET.socket/' "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2;
}
@test "invalid timestamp or control character ERROR" {
    sed -i 's/Monotonic=100/Monotonic=SECRET/' "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2; runtime systemd-journald.service active static; printf '\r\n' >> "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2;
}
@test "direct Requires and Wants each reproduce startup dependency" {
    target multi-user.target '' systemd-journald.service; expect 0; target multi-user.target systemd-journald.socket ''; expect 0;
}
@test "transitive target chain reproduces probe traversal" {
    target multi-user.target basic.target ''; target basic.target sysinit.target ''; target sysinit.target '' systemd-journald.service; expect 0
}
@test "socket under sockets target reproduced" {
    target multi-user.target basic.target ''; target basic.target '' sockets.target; target sockets.target '' systemd-journald.socket; expect 0;
}
@test "dependencies of non-target service are deliberately not recursed" {
    target multi-user.target other.service ''; printf 'Requires=systemd-journald.service\n' > "$JOURNAL_FIXTURE/other.service"; expect 1
    ! rg --quiet -- 'show .* -- other.service' "$JOURNAL_CALLS"
}
@test "Requisite BindsTo and ordering are not accepted as Requires Wants" {
    target multi-user.target '' ''; expect 1;
}
@test "cycles duplicate edges normalized without infinite traversal" {
    target multi-user.target 'basic.target basic.target' ''; target basic.target multi-user.target 'systemd-journald.socket systemd-journald.socket'; expect 0
}
@test "missing transitive target observation ERROR even if another edge qualifies" {
    target multi-user.target missing.target systemd-journald.service; expect 2
}
@test "malformed dependencies extra fields and unavailable root target ERROR" {
    target multi-user.target 'SECRET*' ''; expect 2
    target multi-user.target systemd-journald.service ''; echo Requisite=other.service >> "$JOURNAL_FIXTURE/multi-user.target"; expect 2
    rm "$JOURNAL_FIXTURE/multi-user.target"; expect 2
}
@test "root target masked not-loaded ERROR" {
    sed -i 's/LoadState=loaded/LoadState=masked/' "$JOURNAL_FIXTURE/multi-user.target"; expect 2;
}
@test "root mount escaped unit names allowed as inert dependencies" {
    target multi-user.target '-.mount dev-disk-by\\x2duuid.mount' systemd-journald.socket; expect 0;
}
@test "dev-log and audit sockets alone never substitute for required socket" {
    runtime systemd-journald.service inactive static; runtime systemd-journald.socket inactive static
    runtime systemd-journald-dev-log.socket active static; runtime systemd-journald-audit.socket active enabled
    target multi-user.target '' 'systemd-journald-dev-log.socket systemd-journald-audit.socket'; expect 1
    ! rg --quiet -- 'show .* -- systemd-journald-(dev-log|audit).socket' "$JOURNAL_CALLS"
}
@test "specific CAS service_disabled FAIL state replayed without stopping logging" {
    runtime systemd-journald.socket inactive static; runtime systemd-journald-dev-log.socket inactive static; runtime systemd-journald.service inactive disabled
    expect 1; run apply; [ "$status" -eq 2 ]; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
}
@test "generic template PASS state replayed without executing unmask start enable" {
    runtime systemd-journald.service active enabled; expect 0; run apply; [ "$status" -eq 0 ]; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
}
@test "ActiveState drift between observations ERROR" {
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; runtime systemd-journald.service inactive static; }; expect 2
}
@test "dependency drift between observations ERROR" {
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; target multi-user.target '' systemd-journald.socket; }; expect 2
}
@test "transitive target drift detected even with qualifying direct edge" {
    target multi-user.target basic.target systemd-journald.service; target basic.target '' ''
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; target basic.target '' other.service; }; expect 2
}
@test "mask UnitFileState drift between observations ERROR" {
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; runtime systemd-journald.service active masked masked; }; expect 2
}
@test "timestamp changes detect observed transition returning to same ActiveState" {
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; sed -i 's/Monotonic=100/Monotonic=200/' "$JOURNAL_FIXTURE/systemd-journald.service"; }; expect 2
}
@test "RPM changed during snapshot ERROR" {
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; echo absent > "$JOURNAL_RPM_STATE"; }; expect 2
}
@test "absent package changes to installed on second query ERROR" {
    echo absent > "$JOURNAL_RPM_STATE"
    eval "$(declare -f rlch_systemd_package_status | sed '1s/rlch_systemd_package_status/original_package/')"
    rlch_systemd_package_status() { local result=0; original_package "$@" || result=$?; echo installed > "$JOURNAL_RPM_STATE"; return "$result"; }; expect 2
}
@test "dependency ordering changes alone do not create false race" {
    target multi-user.target 'other.service systemd-journald.service' ''
    eval "$(declare -f rlch_6_2_1_1_snapshot | sed '1s/rlch_6_2_1_1_snapshot/original_snapshot/')"
    rlch_6_2_1_1_snapshot() { original_snapshot; target multi-user.target 'systemd-journald.service other.service' ''; }; expect 0
}
@test "validate uses identical observation semantics" {
    run validate; [ "$status" -eq 0 ]; target multi-user.target '' ''; run validate; [ "$status" -eq 1 ];
}
@test "compliant repeated apply no mutation journal or write" {
    before="$(find "$JOURNAL_FIXTURE" -type f -exec sha256sum {} +)"
    run apply; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(find "$JOURNAL_FIXTURE" -type f -exec sha256sum {} +)" ]; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
}
@test "noncompliant repeated apply manual ERROR rollback no-op idempotent" {
    target multi-user.target '' ''; before="$(find "$JOURNAL_FIXTURE" -type f -exec sha256sum {} +)"
    run apply; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(find "$JOURNAL_FIXTURE" -type f -exec sha256sum {} +)" ]
}
@test "AIDE config databases cron state and journald.conf entirely untouched" {
    mkdir "$BATS_TEST_TMPDIR/preserved"
    for f in aide.conf aide.db.gz aide.db.new.gz rlch-aide-check 612-journal 613-state journald.conf; do echo "$f SECRET" > "$BATS_TEST_TMPDIR/preserved/$f"; done
    export RLCH_CIS_6_1_1_CONFIG="$BATS_TEST_TMPDIR/preserved/aide.conf"
    export RLCH_CIS_6_1_2_CRON_D="$BATS_TEST_TMPDIR/preserved"
    export RLCH_CIS_6_1_3_CONFIG="$BATS_TEST_TMPDIR/preserved/aide.conf"
    before="$(find "$BATS_TEST_TMPDIR/preserved" -type f -exec sha256sum {} +)"
    expect 0; run apply; [ "$status" -eq 0 ]; target multi-user.target '' ''; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(find "$BATS_TEST_TMPDIR/preserved" -type f -exec sha256sum {} +)" ]; [ ! -e "$JOURNAL_FIXTURE/mutations" ]
    ! rg --quiet -- 'unmask| enable | start | stop |\.conf|cron\.d|aide --' "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/1/module.sh"
}
@test "NUL unexpected systemctl output rejected before substitution strips it" {
    printf 'ActiveState=ac\000tive\n' > "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2
}
@test "bounded systemctl output rejects oversized observations" {
    printf 'Id=%0140000d\n' 0 > "$JOURNAL_FIXTURE/systemd-journald.service"; expect 2
}
@test "target graph target-count bound enforced with safe cycle handling" {
    rlch_systemd_properties() {
        local number=0 next
        if [[ "$2" == multi-user.target ]]; then next=n1.target
        else number="${2#n}"; number="${number%.target}"; next="n$((number+1)).target"; fi
        printf '%s|loaded|%s|\n' "$2" "$next"
    }
    run rlch_systemd_target_graph "$RLCH_CIS_6_2_1_1_SYSTEMCTL" multi-user.target
    [ "$status" -eq 2 ]
}
@test "nonzero systemctl with apparently valid stdout still ERROR" {
    cat > "$RLCH_CIS_6_2_1_1_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
cat "$JOURNAL_FIXTURE/${@: -1}"
exit 1
MOCK
    expect 2
}
