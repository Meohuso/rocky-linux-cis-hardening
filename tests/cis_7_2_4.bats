#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats isolates test state.
# shellcheck disable=SC2016 # Literal artificial credentials and shell stubs.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_4_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_7_2_4_NSS="$BATS_TEST_TMPDIR/nsswitch.conf"
    export RLCH_CIS_7_2_4_RPM="$BATS_TEST_TMPDIR/rpm"
    export PACKAGES="$BATS_TEST_TMPDIR/packages"
    P="$RLCH_CIS_7_2_4_PASSWD"; N="$RLCH_CIS_7_2_4_NSS"
    export FLAG="$BATS_TEST_TMPDIR/flag" COUNT="$BATS_TEST_TMPDIR/count"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\n' > "$PACKAGES"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_4_RPM"; chmod 0700 "$RLCH_CIS_7_2_4_RPM"
    printf 'root:x:0:0::/:/bin/false\n' > "$P"; printf 'passwd: files\n' > "$N"; chmod 0644 "$P" "$N"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/4/module.sh"
}
dup() { printf 'other:x:0:7::/:/bin/bash\n' >> "$P"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.4 metadata exact rule enabled Level 1 no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.4 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_account_unique_id ]
    validate_loaded_module_metadata 7.2.4; validate_loaded_module_functions
}
@test "7.2.4 framework loads after prior control" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/3"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/4"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.4 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.4 unique root system and user IDs comply" {
    printf 'daemon:x:2:2::/:/sbin/nologin\nuser:x:1000:1000::/:/bin/bash\n' >> "$P"
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.4 two accounts sharing UID are NON_COMPLIANT" {
    dup; run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 local account entries have 1 distinct'* ]]
}
@test "7.2.4 three accounts sharing UID are NON_COMPLIANT" {
    dup; printf 'third:x:0:8::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 local account entries have 1 distinct'* ]]
}
@test "7.2.4 multiple duplicate sets counted globally" {
    dup; printf 'a:x:42:7::/:/bin/false\nb:x:42:8::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'4 local account entries have 2 distinct'* ]]
}
@test "7.2.4 root UID zero has no exemption" {
    dup; run check; [ "$status" -eq 1 ]
}
@test "7.2.4 no system or interactive threshold or shell filter" {
    for uid in 1 999 1000 65534; do
     printf 'service:x:%s:7::/:/sbin/nologin\nuser:x:%s:8::/:/bin/false\n' "$uid" "$uid" > "$P"
     run check; [ "$status" -eq 1 ]
    done
}
@test "7.2.4 42 and 0042 are one numeric UID" {
    printf 'a:x:42:7::/:/bin/false\nb:x:0042:8::/:/bin/bash\n' > "$P"
    run check; [ "$status" -eq 1 ]
}
@test "7.2.4 zero prefixed unique IDs remain unique" {
    printf 'a:x:000:7::/:/bin/false\nb:x:0042:8::/:/bin/bash\n' > "$P"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.4 maximum supported UID stays distinct from zero" {
    printf 'last:x:4294967294:7::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.4 empty authentication field does not exclude duplicate" {
    printf 'other::0:7::/:/bin/false\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.4 duplicate names are uncertain not a separate uniqueness policy" {
    printf 'root:x:42:7::/:/bin/false\n' >> "$P"; uncertain
}
@test "7.2.4 nondecimal empty reserved and oversized UIDs are ERROR" {
    for uid in BAD '' -1 4294967295 9999999999999999999; do
     printf 'fixture:x:%s:7::/:/bin/false\n' "$uid" > "$P"; uncertain
    done
}
@test "7.2.4 invalid GID or framing makes proof unusable" {
    printf 'fixture:x:42:BAD::/:/bin/false\n' > "$P"; uncertain
    printf 'fixture:x:42:7\n' > "$P"; uncertain
}
@test "7.2.4 files source with spaces tabs and comment can establish coverage" {
    printf 'hosts: files dns\n  passwd:	files  # local\ngroup: files sss\n' > "$N"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.4 SSSD LDAP compat altfiles and conditional sources never imply completeness" {
    for src in 'files sss' 'sss files' ldap compat altfiles 'files [SUCCESS=return]' 'files files'; do
     printf 'passwd: %s\n' "$src" > "$N"; uncertain
    done
}
@test "7.2.4 external source has ERROR priority over local duplicate" {
    dup; printf 'passwd: files sss\n' > "$N"; uncertain
}
@test "7.2.4 absent duplicate or ambiguous passwd source is ERROR" {
    for body in 'group: files' 'passwd:' 'passwd : files'; do printf '%s\n' "$body" > "$N"; uncertain; done
    printf 'passwd: files\npasswd: sss\n' > "$N"; uncertain
}
@test "7.2.4 empty passwd or NSS cannot prove vacuous conformity" {
    for file in "$P" "$N"; do saved="$(cat "$file")"; : > "$file"; uncertain; printf '%s\n' "$saved" > "$file"; done
}
@test "7.2.4 missing or unreadable sources are ERROR" {
    chmod 0000 "$P"; uncertain; chmod 0644 "$P"; rm "$N"; uncertain
}
@test "7.2.4 symlinks rejected" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; uncertain
}
@test "7.2.4 hardlinks rejected for either source" {
    ln "$N" "$N.alias"; uncertain; rm "$N.alias"; ln "$P" "$P.alias"; uncertain
}
@test "7.2.4 unsafe modes are ERROR" {
    chmod 0666 "$N"; uncertain
}
@test "7.2.4 whole-record passwd truncation cannot hide duplicate" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.4 whole-record NSS truncation cannot hide later external declaration" {
    printf 'passwd: sss\n' >> "$N"; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.4 mid-record and zero-byte truncation ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; uncertain
    rlch_identity_stream() { :; }; uncertain
}
@test "7.2.4 I/O failure and stderr discard findings privately" {
    dup; rlch_identity_stream() { /usr/bin/cat; return 88; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SENTINEL\n' >&2; }; uncertain
}
@test "7.2.4 missing newline and control bytes ERROR" {
    printf 'root:x:0:0::/:/bin/false' > "$P"; uncertain
    printf 'root:PRIVATE\r:0:0::/:/bin/false\n' > "$P"; uncertain
}
@test "7.2.4 malformed later entry takes priority over duplicate" {
    dup; printf 'BROKEN:PRIVATE_SENTINEL:BAD\n' >> "$P"; uncertain
}
@test "7.2.4 oversized line and entry count ERROR" {
    printf 'root:%17000s:0:0::/:/bin/false\n' X > "$P"; uncertain
    awk 'BEGIN{for(i=0;i<65537;i++)print "u"i":x:42:7::/:/bin/false"}' > "$P"; uncertain
}
@test "7.2.4 source mutation while reading ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf '# changed\n' >> "$N"; }; uncertain
}
@test "7.2.4 second snapshot failure has priority over finding" {
    dup
    rlch_identity_uid_values() { if [[ -f "$FLAG" ]]; then return 2; fi; touch "$FLAG"; printf 'SOURCE|FILES\nUID|0\nUID|0\n'; }
    uncertain
}
@test "7.2.4 changed UID snapshot is ERROR" {
    rlch_identity_uid_values() { if [[ -f "$FLAG" ]]; then printf 'SOURCE|FILES\nUID|42\n'; else touch "$FLAG"; printf 'SOURCE|FILES\nUID|0\n'; fi; }; uncertain
}
@test "7.2.4 changed source snapshot is ERROR" {
    rlch_identity_uid_values() { if [[ -f "$FLAG" ]]; then printf 'SOURCE|OTHER\nUID|0\n'; else touch "$FLAG"; printf 'SOURCE|FILES\nUID|0\n'; fi; }; uncertain
}
@test "7.2.4 two complete observations are required" {
    rlch_identity_uid_values() { printf 'called\n' >> "$COUNT"; printf 'SOURCE|FILES\nUID|0\n'; }
    run check; [ "$status" -eq 0 ]; [ "$(wc -l < "$COUNT")" -eq 2 ]
}
@test "7.2.4 malformed projections and extra source rows are ERROR" {
    for BAD in $'SOURCE|FILES\nUID|0042' $'SOURCE|FILES\nUID|-1' $'SOURCE|FILES\nUID|4294967295' $'SOURCE|FILES\nUID|0\nSOURCE|FILES' $'SOURCE|FILES' $'UID|0'; do
     export BAD; rlch_identity_uid_values() { printf '%s\n' "$BAD"; }; uncertain
    done
}
@test "7.2.4 RPM absence proves NOT_APPLICABLE without opening account sources" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; rm "$P" "$N"
    run check; [ "$status" -eq 3 ]; [ -z "$output" ]; run apply; [ "$status" -eq 3 ]
}
@test "7.2.4 RPM query errors cannot prove container absence" {
    printf '#!/usr/bin/env bash\nexit 1\n' > "$RLCH_CIS_7_2_4_RPM"; uncertain
}
@test "7.2.4 RPM empty inventory cannot prove container absence" {
    : > "$PACKAGES"; uncertain
}
@test "7.2.4 RPM stderr invalidates applicability" {
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\nprintf PRIVATE_SENTINEL >&2\n' > "$RLCH_CIS_7_2_4_RPM"; uncertain
}
@test "7.2.4 kernel-core presence covers kernel-bearing bootc without container heuristic" {
    printf 'RPM1|2|bootc|0|1|1|x86_64|END\n' >> "$PACKAGES"; run check; [ "$status" -eq 0 ]
}
@test "7.2.4 applicability change across observation is ERROR" {
    rlch_rpm_package_status() { if [[ -f "$FLAG" ]]; then return 1; fi; touch "$FLAG"; return 0; }; uncertain
}
@test "7.2.4 check and validate are fresh without cached compliance" {
    check; dup; run validate; [ "$status" -eq 1 ]
    printf 'root:x:0:0::/:/bin/false\n' > "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.4 fresh source coverage rechecked" {
    check; printf 'passwd: files sss\n' > "$N"; uncertain
}
@test "7.2.4 apply returns success only if already compliant" {
    run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; dup
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.4 apply preserves ERROR and never claims CHANGED" {
    rm "$P"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.4 rollback silent idempotent even with missing sources" {
    rm "$P" "$N"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.4 all public functions preserve fixtures mode ownership and content" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N")"; data="$(cat "$P" "$N")"
    check; validate; apply; rollback; check; [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N")" ]; [ "$data" = "$(cat "$P" "$N")" ]
}
@test "7.2.4 findings disclose neither names nor numeric IDs nor authentication fields" {
    printf 'PRIVATE_A:$6$PRIVATE_SALT$PRIVATE_HASH:424242:7::/PRIVATE_HOME:/bin/false\nPRIVATE_B:PRIVATE_VALUE:0424242:8::/:/bin/bash\n' > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *424242* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.4 untrusted source text never reaches diagnostic" {
    printf 'passwd: PRIVATE_SENTINEL\n' > "$N"; uncertain
}
@test "7.2.4 large findings aggregate into bounded diagnostics" {
    awk 'BEGIN{for(i=0;i<1000;i++) print "PRIVATE_"i":PRIVATE_VALUE:42:7::/:/bin/false"}' > "$P"
    run check; [ "$status" -eq 1 ]; [ "${#output}" -lt 200 ]; [[ "$output" != *PRIVATE* ]]
}
@test "7.2.4 identity administration and getent pwck must never execute" {
    for cmd in getent pwck usermod userdel chown; do eval "${cmd}"'() { printf forbidden > "$FLAG"; return 99; }'; done
    check; [ ! -e "$FLAG" ]
}
@test "7.2.4 unexpected observer status is normalized to ERROR" {
    rlch_7_2_4_observe() { return 99; }; uncertain
}

@test "7.2.4 native comments are not accounts and leading spaces preserve numeric duplicate" {
    printf '\n# PRIVATE_COMMENT:x:0:7::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 0 ]
    printf '  spaced:x:0000:7::/:/bin/false\n' >> "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *spaced* ]]
}
