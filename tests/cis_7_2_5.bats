#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats isolates tests; run sets status/output.
# shellcheck disable=SC2016 # Literal artificial credential sentinels.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_5_GROUP="$BATS_TEST_TMPDIR/group"
    export RLCH_CIS_7_2_5_RPM="$BATS_TEST_TMPDIR/rpm"
    export PACKAGES="$BATS_TEST_TMPDIR/packages" FLAG="$BATS_TEST_TMPDIR/flag" COUNT="$BATS_TEST_TMPDIR/count"
    G="$RLCH_CIS_7_2_5_GROUP"; N="$BATS_TEST_TMPDIR/nsswitch.conf"
    printf 'root:x:0:\n' > "$G"; printf 'passwd: files\ngroup: files\n' > "$N"; chmod 0644 "$G" "$N"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\n' > "$PACKAGES"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_5_RPM"; chmod 0700 "$RLCH_CIS_7_2_5_RPM"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/5/module.sh"
}
dup() { printf 'other:x:0:\n' >> "$G"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.5 exact metadata Level 1 enabled no reboot and public API" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/5/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.5 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_group_unique_id ]
    validate_loaded_module_metadata 7.2.5; validate_loaded_module_functions
}
@test "7.2.5 framework loads after previous control without inheriting NSS policy" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/4"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/5"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.5 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 unique root system and other local GIDs comply" {
    printf 'daemon:x:1:\nservice:x:999:\nuser:x:1000:\nnobody:x:65534:\n' >> "$G"
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.5 two groups sharing one capture are NON_COMPLIANT" {
    dup; run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 selected local group entries have 1 distinct'* ]]
}
@test "7.2.5 three groups sharing one capture are counted" {
    dup; printf 'third:x:0:\n' >> "$G"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 selected local group entries have 1 distinct'* ]]
}
@test "7.2.5 multiple nonadjacent duplicate sets are counted globally" {
    printf 'a:x:42:\nb:x:7:\nc:x:42:\nd:x:7:\n' >> "$G"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'5 selected local group entries have 3 distinct'* ]]
}
@test "7.2.5 GID zero has no exemption" {
    dup; run check; [ "$status" -eq 1 ]
}
@test "7.2.5 system groups and arbitrary GID thresholds have no exemption" {
    for gid in 1 999 1000 65534; do printf 'a:x:%s:\nb:x:%s:\n' "$gid" "$gid" > "$G"; run check; [ "$status" -eq 1 ]; done
}
@test "7.2.5 42 and 0042 are distinct text captures" {
    printf 'a:x:42:\nb:x:0042:\n' > "$G"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 repeated 0042 is a duplicate without canonicalizing it" {
    printf 'a:x:0042:\nb:x:42:\nc:x:0042:\n' > "$G"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 selected local group entries have 2 distinct'* ]]
}
@test "7.2.5 zero and multiple zero spellings remain distinct" {
    printf 'a:x:0:\nb:x:00:\nc:x:000:\n' > "$G"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 decimal captures exceeding native GID range are not converted" {
    printf 'a:x:4294967295:\nb:x:18446744073709551616:\nc:x:0004294967295:\n' > "$G"
    run check; [ "$status" -eq 0 ]; printf 'd:x:18446744073709551616:\n' >> "$G"; run check; [ "$status" -eq 1 ]
}
@test "7.2.5 very long decimal captures remain exact and noncolliding" {
    zeros="$(printf '%1000s' '' | tr ' ' 0)"; printf 'a:x:%s42:\nb:x:42:\n' "$zeros" > "$G"
    run check; [ "$status" -eq 0 ]; printf 'c:x:%s42:\n' "$zeros" >> "$G"; run check; [ "$status" -eq 1 ]
}
@test "7.2.5 repeated names with distinct captured GIDs are not a name policy" {
    printf 'same:x:42:\nsame:x:7:\n' > "$G"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 identical records preserve instances and reveal duplicate captures" {
    printf 'root:x:0:\n' >> "$G"; run check; [ "$status" -eq 1 ]
}
@test "7.2.5 empty first or second field excludes a row from OVAL selection" {
    printf ':x:0:PRIVATE_MEMBER\nempty::0:\n::0:\n' >> "$G"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 nonempty whitespace fields match dot plus without trimming" {
    printf ' : :0:\n' >> "$G"; run check; [ "$status" -eq 1 ]
}
@test "7.2.5 nondecimal signed empty and padded GIDs do not match digit capture" {
    for gid in BAD '' -1 +42 '42 ' ' 42' 1.0; do printf 'excluded:x:%s:\n' "$gid" >> "$G"; done
    run check; [ "$status" -eq 0 ]
}
@test "7.2.5 zero selected captures abstains rather than certifying empty-domain parity" {
    printf ':x:0:\na::42:\nb:x:BAD:\n' > "$G"; uncertain
}
@test "7.2.5 names authentication markers and members do not add selection filters" {
    printf '+:PRIVATE_HASH:0:PRIVATE_MEMBER\n' >> "$G"; run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.5 missing group source is ERROR" { rm "$G"; uncertain; }
@test "7.2.5 empty group source is ERROR" { : > "$G"; uncertain; }
@test "7.2.5 unreadable mode is ERROR even for privileged test reader" { chmod 0000 "$G"; uncertain; }
@test "7.2.5 unsafe writable permissions are ERROR" {
    for mode in 0666 0664; do chmod "$mode" "$G"; uncertain; done
}
@test "7.2.5 malformed short or extra-field record takes priority over duplicate" {
    dup; printf 'BROKEN_PRIVATE\n' >> "$G"; uncertain
    printf 'a:x:0:PRIVATE:extra\n' > "$G"; uncertain
}
@test "7.2.5 blank comments and unsupported file syntax fail closed" {
    printf '# PRIVATE_COMMENT\n' >> "$G"; uncertain
    printf '\n' > "$G"; uncertain
}
@test "7.2.5 symlink rejected" {
    mv "$G" "$G.real"; ln -s "$G.real" "$G"; uncertain
}
@test "7.2.5 symlink ancestor rejected" {
    mkdir "$BATS_TEST_TMPDIR/real"; mv "$G" "$BATS_TEST_TMPDIR/real/group"; ln -s real "$BATS_TEST_TMPDIR/alias"
    RLCH_CIS_7_2_5_GROUP="$BATS_TEST_TMPDIR/alias/group"; uncertain
}
@test "7.2.5 hardlink rejected" { ln "$G" "$G.alias"; uncertain; }
@test "7.2.5 directory and FIFO rejected without reading bodies" {
    rm "$G"; mkdir "$G"; uncertain; rmdir "$G"; mkfifo "$G"; uncertain
}
@test "7.2.5 complete-row silent truncation cannot hide duplicate" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.5 identical complete-row truncations cannot establish completeness" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain; uncertain
}
@test "7.2.5 mid-record and zero-byte truncation are ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 5; }; uncertain
    rlch_identity_stream() { :; }; uncertain
}
@test "7.2.5 producer failure discards complete prefix before finding" {
    dup; rlch_identity_stream() { /usr/bin/cat; return 87; }; uncertain
}
@test "7.2.5 producer stderr is withheld and invalidates observation" {
    dup; rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SENTINEL\n' >&2; }; uncertain
}
@test "7.2.5 appended producer records and forged terminal frame are ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:x:7:\n'; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; uncertain
}
@test "7.2.5 missing final newline invalidates evidence" {
    printf 'root:x:0:' > "$G"; uncertain
}
@test "7.2.5 NUL control and tab bytes invalidate supported observation" {
    printf 'root:PRIVATE\000:0:\n' > "$G"; uncertain
    printf 'root:x:0:PRIVATE\r\n' > "$G"; uncertain
    printf 'root:\t:0:\n' > "$G"; uncertain
}
@test "7.2.5 line count and aggregate byte bounds are enforced" {
    printf 'a:%17000s:0:\n' X > "$G"; uncertain
    awk 'BEGIN{for(i=0;i<65537;i++) print "g"i":x:42:"}' > "$G"; uncertain
    awk 'BEGIN{for(i=0;i<500;i++){printf "g%d:",i;for(j=0;j<10000;j++)printf "x";print ":42:"}}' > "$G"; uncertain
}
@test "7.2.5 maximum supported record count preserves every duplicate" {
    awk 'BEGIN{for(i=0;i<65536;i++) print "g"i":x:0042:"}' > "$G"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'65536 selected local group entries have 1 distinct'* ]]
}
@test "7.2.5 content mutation during reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:7:\n' >> "$G"; }; uncertain
}
@test "7.2.5 pathname replacement during reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; cp "$G" "$G.new"; mv "$G.new" "$G"; }; uncertain
}
@test "7.2.5 hardlink added during reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; ln "$G" "$G.alias"; }; uncertain
}
@test "7.2.5 second observation failure overrides first duplicate finding" {
    dup
    rlch_identity_gid_fields() { if [[ -f "$FLAG" ]]; then return 2; fi; touch "$FLAG"; printf 'PRESENT|PRESENT|NA|0\nPRESENT|PRESENT|NA|0\n'; }; uncertain
}
@test "7.2.5 changed projection across observations is ERROR" {
    rlch_identity_gid_fields() { if [[ -f "$FLAG" ]]; then printf 'PRESENT|PRESENT|NA|7\n'; else touch "$FLAG"; printf 'PRESENT|PRESENT|NA|0\n'; fi; }; uncertain
}
@test "7.2.5 exactly two real group projections are required" {
    rlch_identity_stream() { printf 'read\n' >> "$COUNT"; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]; [ "$(wc -l < "$COUNT")" -eq 2 ]
}
@test "7.2.5 invalid forged projection and oversized output cannot become findings" {
    for BAD in 'PRIVATE_SENTINEL' 'PRESENT|PRESENT|NA|-1' 'PRESENT|PRESENT|OTHER|42' 'PRESENT|PRESENT|NA|42|EXTRA'; do
        export BAD; rlch_identity_gid_fields() { printf '%s\n' "$BAD"; }; uncertain
    done
    rlch_identity_gid_fields() { printf '%6300000s\n' X; }; uncertain
}
@test "7.2.5 oversized projection row and row count are ERROR" {
    rlch_identity_gid_fields() { printf 'PRESENT|PRESENT|NA|%16500s\n' 0; }; uncertain
    rlch_identity_gid_fields() { awk 'BEGIN{for(i=0;i<65537;i++)print "PRESENT|PRESENT|NA|0"}'; }; uncertain
}
@test "7.2.5 files mixed and external NSS do not alter local conformity" {
    for src in files 'files sss' 'sss files' ldap compat; do
        printf 'passwd: %s\ngroup: %s\n' "$src" "$src" > "$N"
        run check; [ "$status" -eq 0 ]; [ -z "$output" ]
    done
}
@test "7.2.5 duplicate local captures remain findings independently of NSS" {
    dup
    for src in files 'files sss' ldap; do printf 'group: %s\n' "$src" > "$N"; run check; [ "$status" -eq 1 ]; done
}
@test "7.2.5 missing ambiguous or unreadable NSS is outside the local rule" {
    printf 'group: files\ngroup: sss\n' > "$N"; run check; [ "$status" -eq 0 ]
    chmod 0000 "$N"; run check; [ "$status" -eq 0 ]; rm "$N"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 no NSS enumeration or historical identity projection is invoked" {
    for cmd in getent getgrent rlch_identity_rows rlch_identity_uid_values; do
        eval "${cmd}"'() { printf forbidden > "$FLAG"; return 99; }'
    done
    printf 'group: files sss\n' > "$N"; check; [ ! -e "$FLAG" ]
}
@test "7.2.5 real identity reader opens only selected local group fixture" {
    rlch_identity_stream() { [[ "$(readlink /proc/self/fd/0)" == "$G" ]] || return 99; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]
}
@test "7.2.5 local uncertainty still takes priority with external NSS" {
    printf 'group: sss\n' > "$N"; dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.5 RPM absence proves NOT_APPLICABLE without group access" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; rm "$G"
    run check; [ "$status" -eq 3 ]; [ -z "$output" ]; run apply; [ "$status" -eq 3 ]
}
@test "7.2.5 failed empty malformed and noisy RPM inventories are ERROR" {
    : > "$PACKAGES"; uncertain; printf 'PRIVATE_BROKEN\n' > "$PACKAGES"; uncertain
    printf '#!/usr/bin/env bash\nexit 1\n' > "$RLCH_CIS_7_2_5_RPM"; uncertain
    printf '#!/usr/bin/env bash\nprintf PRIVATE_SENTINEL >&2\n' > "$RLCH_CIS_7_2_5_RPM"; uncertain
}
@test "7.2.5 applicability change across observation is ERROR" {
    rlch_rpm_package_status() { if [[ -f "$FLAG" ]]; then return 1; fi; touch "$FLAG"; return 0; }; uncertain
}
@test "7.2.5 kernel-bearing bootc is applicable without a container heuristic" {
    printf 'RPM1|2|bootc|0|1|1|x86_64|END\n' >> "$PACKAGES"; run check; [ "$status" -eq 0 ]
}
@test "7.2.5 check and validate observe fresh evidence without cached result" {
    check; dup; run validate; [ "$status" -eq 1 ]
    printf 'root:x:0:\n' > "$G"; run check; [ "$status" -eq 0 ]; rm "$G"; uncertain
}
@test "7.2.5 apply succeeds only for already conforming or inapplicable state" {
    run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; dup
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.5 apply preserves uncertainty and never claims CHANGED" {
    rm "$G"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.5 rollback silent idempotent with missing sources" {
    rm "$G" "$N" "$PACKAGES"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.5 all public operations preserve content mode ownership and file set" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$G" "$N" "$PACKAGES")"; data="$(sha256sum "$G" "$N" "$PACKAGES")"
    files="$(find "$BATS_TEST_TMPDIR" -type f | sort)"
    check; validate; apply; rollback; check
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$G" "$N" "$PACKAGES")" ]; [ "$data" = "$(sha256sum "$G" "$N" "$PACKAGES")" ]
    [ "$files" = "$(find "$BATS_TEST_TMPDIR" -type f | sort)" ]
}
@test "7.2.5 findings and manual guidance preserve duplicate fixtures" {
    dup; before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$G")"; data="$(cat "$G")"
    run check; [ "$status" -eq 1 ]; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; rollback
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$G")" ]; [ "$data" = "$(cat "$G")" ]
}
@test "7.2.5 group and ownership administration must never execute" {
    for cmd in groupmod groupdel groupadd usermod userdel chown chgrp chmod setfacl; do
        eval "${cmd}"'() { printf forbidden > "$FLAG"; return 99; }'
    done
    check; validate; apply; rollback; [ ! -e "$FLAG" ]
}
@test "7.2.5 diagnostics disclose neither names GIDs hashes nor members" {
    printf 'PRIVATE_GROUP:$6$PRIVATE_SALT$PRIVATE_HASH:424242:PRIVATE_MEMBER\nPRIVATE_OTHER:PRIVATE_MARKER:424242:\n' > "$G"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *424242* ]]; [ "${#output}" -lt 200 ]
    run apply; [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* && "$output" != *424242* ]]; [ "${#output}" -lt 400 ]
}
@test "7.2.5 aggregate diagnostics stay bounded for large duplicate sets" {
    awk 'BEGIN{for(i=0;i<1000;i++)print "PRIVATE_"i":PRIVATE_HASH:424242:PRIVATE_MEMBER"}' > "$G"
    run check; [ "$status" -eq 1 ]; [ "${#output}" -lt 200 ]; [[ "$output" != *PRIVATE* && "$output" != *424242* ]]
}
@test "7.2.5 shell traces do not expose raw identity or credential fields" {
    printf 'PRIVATE_GROUP:$6$PRIVATE_SALT$PRIVATE_HASH:42:PRIVATE_MEMBER\n' > "$G"
    run bash -c 'source "$1"; source "$2"; set -x; check' bash "$BATS_TEST_DIRNAME/../lib/module_api.sh" "$BATS_TEST_DIRNAME/../modules/cis/7/2/5/module.sh"
    # Inherited xtrace is producer stderr: the strict reader abstains.
    [ "$status" -eq 2 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.5 unexpected observer status is normalized to ERROR" {
    rlch_7_2_5_observe() { return 99; }; uncertain
}
