#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_1_4_SYSTEMCTL="$BATS_TEST_TMPDIR/systemctl"
    export LOG_UNITS="$BATS_TEST_TMPDIR/units" LOG_CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir "$LOG_UNITS"
    cat > "$RLCH_CIS_6_2_1_4_SYSTEMCTL" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$LOG_CALLS"
[[ "$#" == 6 && "$1" == --system && "$2" == --no-pager && "$3" == show && "$4" == --property=Id,LoadState,ActiveState,UnitFileState,StateChangeTimestampMonotonic && "$5" == -- ]] || { touch "$LOG_UNITS/mutation"; exit 3; }
[[ "$LC_ALL" == C && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_PAGER" == cat ]] || exit 3
[[ ! -e "$LOG_UNITS/error" ]] || { echo 'SECRET D-Bus offline failure' >&2; exit 1; }
u="$6"
n=0; if [[ -f "$LOG_UNITS/$u.count" ]]; then read -r n < "$LOG_UNITS/$u.count"; fi
n=$((n + 1)); echo "$n" > "$LOG_UNITS/$u.count"
if [[ "$n" -ge 2 && -e "$LOG_UNITS/$u.second" ]]; then cat "$LOG_UNITS/$u.second"; else cat "$LOG_UNITS/$u"; fi
MOCK
    chmod 0755 "$RLCH_CIS_6_2_1_4_SYSTEMCTL"
    runtime rsyslog.service inactive enabled
    runtime systemd-journald.service active static
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/4/module.sh"
}
runtime() {
    printf 'Id=%s\nLoadState=%s\nActiveState=%s\nUnitFileState=%s\nStateChangeTimestampMonotonic=100\n' "$1" "${4:-loaded}" "$2" "$3" > "$LOG_UNITS/$1"
}
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
second() { cp "$LOG_UNITS/$1" "$LOG_UNITS/$1.second"; sed -i "$2" "$LOG_UNITS/$1.second"; }

@test "6214 upstream both_active.fail.sh" {
    runtime systemd-journald.service active static; runtime rsyslog.service active disabled; expect 1
}

@test "6214 upstream none_active.fail.sh" {
    runtime systemd-journald.service inactive static; runtime rsyslog.service inactive disabled; expect 1
}

@test "6214 upstream only_journald.pass.sh" {
    runtime systemd-journald.service active static; runtime rsyslog.service inactive disabled; expect 0
}

@test "6214 upstream only_rsyslog.pass.sh" {
    runtime systemd-journald.service inactive static; runtime rsyslog.service active disabled; expect 0
}

@test "6214 metadata exact automated unique primary mapping" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.1.4 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure only one logging system is in use' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_ensure_journald_and_rsyslog_not_active_together ]
    [ "$(grep -Rl '^RLCH_MODULE_OPENSCAP_RULE="xccdf_org.ssgproject.content_rule_ensure_journald_and_rsyslog_not_active_together"$' "$BATS_TEST_DIRNAME/../modules" | wc -l)" -eq 1 ]
}

@test "6214 rsyslog.service active enabled counts by runtime" {
    runtime rsyslog.service active enabled; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active enabled-runtime counts by runtime" {
    runtime rsyslog.service active enabled-runtime; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active disabled counts by runtime" {
    runtime rsyslog.service active disabled; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active static counts by runtime" {
    runtime rsyslog.service active static; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active indirect counts by runtime" {
    runtime rsyslog.service active indirect; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active generated counts by runtime" {
    runtime rsyslog.service active generated; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active transient counts by runtime" {
    runtime rsyslog.service active transient; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active alias counts by runtime" {
    runtime rsyslog.service active alias; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active linked counts by runtime" {
    runtime rsyslog.service active linked; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service active linked-runtime counts by runtime" {
    runtime rsyslog.service active linked-runtime; runtime systemd-journald.service inactive enabled; expect 0
}

@test "6214 rsyslog.service masked active remains active masked" {
    runtime rsyslog.service active masked masked; runtime systemd-journald.service inactive static; expect 0
}

@test "6214 rsyslog.service masked active remains active masked-runtime" {
    runtime rsyslog.service active masked-runtime masked; runtime systemd-journald.service inactive static; expect 0
}

@test "6214 rsyslog.service failed counts non-active" {
    runtime rsyslog.service failed disabled; runtime systemd-journald.service active static; expect 0
}

@test "6214 rsyslog.service coherent not-found non-active" {
    runtime rsyslog.service inactive "" not-found; runtime systemd-journald.service active static; expect 0
}

@test "6214 rsyslog.service incoherent not-found active file empty" {
    runtime rsyslog.service active "" not-found; expect 2
}

@test "6214 rsyslog.service incoherent not-found failed file empty" {
    runtime rsyslog.service failed "" not-found; expect 2
}

@test "6214 rsyslog.service incoherent not-found inactive file enabled" {
    runtime rsyslog.service inactive "enabled" not-found; expect 2
}

@test "6214 rsyslog.service transitional or unknown activating" {
    runtime rsyslog.service activating static; expect 2
}

@test "6214 rsyslog.service transitional or unknown deactivating" {
    runtime rsyslog.service deactivating static; expect 2
}

@test "6214 rsyslog.service transitional or unknown reloading" {
    runtime rsyslog.service reloading static; expect 2
}

@test "6214 rsyslog.service transitional or unknown maintenance" {
    runtime rsyslog.service maintenance static; expect 2
}

@test "6214 rsyslog.service transitional or unknown refreshing" {
    runtime rsyslog.service refreshing static; expect 2
}

@test "6214 rsyslog.service transitional or unknown UNKNOWN" {
    runtime rsyslog.service UNKNOWN static; expect 2
}

@test "6214 rsyslog.service drift timestamp returns ERROR" {
    runtime rsyslog.service active static; second rsyslog.service "s/Monotonic=100/Monotonic=101/"; expect 2
}

@test "6214 rsyslog.service drift active returns ERROR" {
    runtime rsyslog.service active static; second rsyslog.service "s/ActiveState=active/ActiveState=inactive/"; expect 2
}

@test "6214 rsyslog.service drift file returns ERROR" {
    runtime rsyslog.service active static; second rsyslog.service "s/UnitFileState=static/UnitFileState=disabled/"; expect 2
}

@test "6214 rsyslog.service drift load returns ERROR" {
    runtime rsyslog.service active static; second rsyslog.service "s/LoadState=loaded/LoadState=masked/;s/UnitFileState=static/UnitFileState=masked/"; expect 2
}

@test "6214 rsyslog.service wrong service alias identity rejected" {
    sed -i 's/Id=rsyslog.service/Id=other.service/' "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 rsyslog.service wrong type identity rejected" {
    sed -i 's/Id=rsyslog.service/Id=other.socket/' "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 systemd-journald.service active enabled counts by runtime" {
    runtime systemd-journald.service active enabled; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active enabled-runtime counts by runtime" {
    runtime systemd-journald.service active enabled-runtime; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active disabled counts by runtime" {
    runtime systemd-journald.service active disabled; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active static counts by runtime" {
    runtime systemd-journald.service active static; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active indirect counts by runtime" {
    runtime systemd-journald.service active indirect; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active generated counts by runtime" {
    runtime systemd-journald.service active generated; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active transient counts by runtime" {
    runtime systemd-journald.service active transient; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active alias counts by runtime" {
    runtime systemd-journald.service active alias; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active linked counts by runtime" {
    runtime systemd-journald.service active linked; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service active linked-runtime counts by runtime" {
    runtime systemd-journald.service active linked-runtime; runtime rsyslog.service inactive enabled; expect 0
}

@test "6214 systemd-journald.service masked active remains active masked" {
    runtime systemd-journald.service active masked masked; runtime rsyslog.service inactive static; expect 0
}

@test "6214 systemd-journald.service masked active remains active masked-runtime" {
    runtime systemd-journald.service active masked-runtime masked; runtime rsyslog.service inactive static; expect 0
}

@test "6214 systemd-journald.service failed counts non-active" {
    runtime systemd-journald.service failed disabled; runtime rsyslog.service active static; expect 0
}

@test "6214 systemd-journald.service coherent not-found non-active" {
    runtime systemd-journald.service inactive "" not-found; runtime rsyslog.service active static; expect 0
}

@test "6214 systemd-journald.service incoherent not-found active file empty" {
    runtime systemd-journald.service active "" not-found; expect 2
}

@test "6214 systemd-journald.service incoherent not-found failed file empty" {
    runtime systemd-journald.service failed "" not-found; expect 2
}

@test "6214 systemd-journald.service incoherent not-found inactive file enabled" {
    runtime systemd-journald.service inactive "enabled" not-found; expect 2
}

@test "6214 systemd-journald.service transitional or unknown activating" {
    runtime systemd-journald.service activating static; expect 2
}

@test "6214 systemd-journald.service transitional or unknown deactivating" {
    runtime systemd-journald.service deactivating static; expect 2
}

@test "6214 systemd-journald.service transitional or unknown reloading" {
    runtime systemd-journald.service reloading static; expect 2
}

@test "6214 systemd-journald.service transitional or unknown maintenance" {
    runtime systemd-journald.service maintenance static; expect 2
}

@test "6214 systemd-journald.service transitional or unknown refreshing" {
    runtime systemd-journald.service refreshing static; expect 2
}

@test "6214 systemd-journald.service transitional or unknown UNKNOWN" {
    runtime systemd-journald.service UNKNOWN static; expect 2
}

@test "6214 systemd-journald.service drift timestamp returns ERROR" {
    runtime systemd-journald.service active static; second systemd-journald.service "s/Monotonic=100/Monotonic=101/"; expect 2
}

@test "6214 systemd-journald.service drift active returns ERROR" {
    runtime systemd-journald.service active static; second systemd-journald.service "s/ActiveState=active/ActiveState=inactive/"; expect 2
}

@test "6214 systemd-journald.service drift file returns ERROR" {
    runtime systemd-journald.service active static; second systemd-journald.service "s/UnitFileState=static/UnitFileState=disabled/"; expect 2
}

@test "6214 systemd-journald.service drift load returns ERROR" {
    runtime systemd-journald.service active static; second systemd-journald.service "s/LoadState=loaded/LoadState=masked/;s/UnitFileState=static/UnitFileState=masked/"; expect 2
}

@test "6214 systemd-journald.service wrong service alias identity rejected" {
    sed -i 's/Id=systemd-journald.service/Id=other.service/' "$LOG_UNITS/systemd-journald.service"; expect 2
}

@test "6214 systemd-journald.service wrong type identity rejected" {
    sed -i 's/Id=systemd-journald.service/Id=other.socket/' "$LOG_UNITS/systemd-journald.service"; expect 2
}

@test "6214 both failed are noncompliant" {
    runtime rsyslog.service failed disabled; runtime systemd-journald.service failed static; expect 1
}

@test "6214 both absent are noncompliant" {
    runtime rsyslog.service inactive "" not-found; runtime systemd-journald.service inactive "" not-found; expect 1
}

@test "6214 masked inactive and enabled inactive do not substitute activity" {
    runtime rsyslog.service inactive masked masked; runtime systemd-journald.service inactive enabled; expect 1
}

@test "6214 unsupported LoadState error" {
    runtime rsyslog.service inactive disabled error; expect 2
}

@test "6214 unsupported LoadState bad-setting" {
    runtime rsyslog.service inactive disabled bad-setting; expect 2
}

@test "6214 unsupported LoadState stub" {
    runtime rsyslog.service inactive disabled stub; expect 2
}

@test "6214 unsupported LoadState merged" {
    runtime rsyslog.service inactive disabled merged; expect 2
}

@test "6214 unsupported LoadState UNKNOWN" {
    runtime rsyslog.service inactive disabled UNKNOWN; expect 2
}

@test "6214 incoherent loaded UnitFileState UNKNOWN" {
    runtime rsyslog.service inactive "UNKNOWN"; expect 2
}

@test "6214 incoherent loaded UnitFileState empty" {
    runtime rsyslog.service inactive ""; expect 2
}

@test "6214 incoherent loaded UnitFileState masked" {
    runtime rsyslog.service inactive "masked"; expect 2
}

@test "6214 missing Id" {
    sed -i "/^Id=/d" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 duplicate Id" {
    grep "^Id=" "$LOG_UNITS/rsyslog.service" >> "$BATS_TEST_TMPDIR/duplicate"; cat "$BATS_TEST_TMPDIR/duplicate" >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 missing LoadState" {
    sed -i "/^LoadState=/d" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 duplicate LoadState" {
    grep "^LoadState=" "$LOG_UNITS/rsyslog.service" >> "$BATS_TEST_TMPDIR/duplicate"; cat "$BATS_TEST_TMPDIR/duplicate" >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 missing ActiveState" {
    sed -i "/^ActiveState=/d" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 duplicate ActiveState" {
    grep "^ActiveState=" "$LOG_UNITS/rsyslog.service" >> "$BATS_TEST_TMPDIR/duplicate"; cat "$BATS_TEST_TMPDIR/duplicate" >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 missing UnitFileState" {
    sed -i "/^UnitFileState=/d" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 duplicate UnitFileState" {
    grep "^UnitFileState=" "$LOG_UNITS/rsyslog.service" >> "$BATS_TEST_TMPDIR/duplicate"; cat "$BATS_TEST_TMPDIR/duplicate" >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 missing StateChangeTimestampMonotonic" {
    sed -i "/^StateChangeTimestampMonotonic=/d" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 duplicate StateChangeTimestampMonotonic" {
    grep "^StateChangeTimestampMonotonic=" "$LOG_UNITS/rsyslog.service" >> "$BATS_TEST_TMPDIR/duplicate"; cat "$BATS_TEST_TMPDIR/duplicate" >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 empty output" {
    : > "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 malformed text" {
    echo SECRET > "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 unknown key" {
    echo SECRET=bad >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 empty key" {
    echo =SECRET >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 invalid timestamp" {
    sed -i "s/Monotonic=100/Monotonic=-1/" "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 NUL byte" {
    printf '\0' >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 control carriage return" {
    printf '\r\n' >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 control tab" {
    printf '\t\n' >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 bounded output" {
    head -c 131073 /dev/zero | tr "\000" x >> "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 offline successful human text" {
    echo "systemd not running in container" > "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 failed query or DBus offline" {
    touch "$LOG_UNITS/error"; expect 2
}

@test "6214 missing executable" {
    RLCH_CIS_6_2_1_4_SYSTEMCTL="$BATS_TEST_TMPDIR/missing"; expect 2
}

@test "6214 missing unit output" {
    rm "$LOG_UNITS/rsyslog.service"; expect 2
}

@test "6214 property ordering irrelevant" {
    sort -r "$LOG_UNITS/rsyslog.service" > "$BATS_TEST_TMPDIR/sorted"; mv "$BATS_TEST_TMPDIR/sorted" "$LOG_UNITS/rsyslog.service"; expect 0
}

@test "6214 pair activity inversion with unchanged count is ERROR" {
    second rsyslog.service "s/ActiveState=inactive/ActiveState=active/"; second systemd-journald.service "s/ActiveState=active/ActiveState=inactive/"; expect 2
}

@test "6214 activity round trip detected by timestamp" {
    second systemd-journald.service "s/Monotonic=100/Monotonic=102/"; expect 2
}

@test "6214 two full observations include inactive side" {
    expect 0; [ "$(wc -l < "$LOG_CALLS")" -eq 4 ]; [ "$(cat "$LOG_UNITS/rsyslog.service.count")" -eq 2 ]; [ "$(cat "$LOG_UNITS/systemd-journald.service.count")" -eq 2 ]
}

@test "6214 OCIL grep substring counts inactive and does not govern result" {
    [ "$(printf 'active\ninactive\n' | grep -c active)" -eq 2 ]; expect 0
    [ "$(printf 'inactive\ninactive\n' | grep -c active)" -eq 2 ]; runtime systemd-journald.service inactive static; expect 1
}

@test "6214 repeated API active" {
    runtime systemd-journald.service active static; for i in 1 2; do expect 0; run validate; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 repeated API inactive" {
    runtime systemd-journald.service inactive static; for i in 1 2; do expect 1; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 repeated API activating" {
    runtime systemd-journald.service activating static; for i in 1 2; do expect 2; run validate; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; done; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 both active apply manual unchanged ERROR" {
    runtime rsyslog.service active enabled; run apply; [ "$status" -eq 2 ]; [[ "$output" == *architectural* && "$output" == *both* && "$output" == *neither* ]]; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 rollback makes no queries even without manager" {
    RLCH_CIS_6_2_1_4_SYSTEMCTL="$BATS_TEST_TMPDIR/missing"; run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]; [ ! -e "$LOG_CALLS" ]
}

@test "6214 commands only named-property show no package socket or mutations" {
    for action in check validate apply rollback; do run "$action"; [ "$status" -eq 0 ]; done
    [ "$(wc -l < "$LOG_CALLS")" -eq 12 ]; ! grep -Eq 'is-active|is-enabled|start|stop|enable |disable|mask|unmask|socket|rpm|dnf' "$LOG_CALLS"; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 prior AIDE cron tmpfiles ACL journal configuration and state preserved" {
    mkdir -p "$BATS_TEST_TMPDIR/preserve/etc" "$BATS_TEST_TMPDIR/preserve/state"
    for file in aide.conf crontab tmpfiles.conf acl journal.bin journald.conf rotation.conf rsyslog.conf ForwardToSyslog 6.2.1.1 6.2.1.2 6.2.1.3; do printf 'sentinel %s\n' "$file" > "$BATS_TEST_TMPDIR/preserve/etc/$file"; done
    before="$(find "$BATS_TEST_TMPDIR/preserve" -printf '%p %m %u %g\n'; sha256sum "$BATS_TEST_TMPDIR/preserve/etc/"*)"
    for state in active inactive activating; do runtime systemd-journald.service "$state" static; for action in check validate apply rollback; do run "$action"; [ "$status" -ne 4 ]; done; done
    after="$(find "$BATS_TEST_TMPDIR/preserve" -printf '%p %m %u %g\n'; sha256sum "$BATS_TEST_TMPDIR/preserve/etc/"*)"
    [ "$before" = "$after" ]; [ -z "$(ls -A "$BATS_TEST_TMPDIR/preserve/state")" ]; [ ! -e "$LOG_UNITS/mutation" ]
}

@test "6214 rsyslog-only PASS independent of 6211 service socket criterion" {
    runtime rsyslog.service active disabled; runtime systemd-journald.service inactive static; expect 0
    runtime systemd-journald.socket inactive static
    printf 'Id=multi-user.target\nLoadState=loaded\nRequires=systemd-journald.service\nWants=\n' > "$LOG_UNITS/multi-user.target"
    cat > "$BATS_TEST_TMPDIR/cross-systemctl" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == --system && "$2" == --no-pager && "$3" == show ]] || exit 3
cat "$LOG_UNITS/${@: -1}"
MOCK
    printf '#!/usr/bin/env bash\necho systemd\n' > "$BATS_TEST_TMPDIR/rpm"
    chmod +x "$BATS_TEST_TMPDIR/cross-systemctl" "$BATS_TEST_TMPDIR/rpm"
    RLCH_CIS_6_2_1_1_SYSTEMCTL="$BATS_TEST_TMPDIR/cross-systemctl" RLCH_CIS_6_2_1_1_RPM="$BATS_TEST_TMPDIR/rpm"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/1/module.sh"
    run check; [ "$status" -eq 1 ]
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/1/4/module.sh"
    expect 0
}
