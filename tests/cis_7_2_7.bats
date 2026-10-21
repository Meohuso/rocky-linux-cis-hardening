#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats isolates tests; run sets status/output.
# shellcheck disable=SC2016 # Literal artificial credentials and inert names.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_7_GROUP="$BATS_TEST_TMPDIR/group"
    export RLCH_CIS_7_2_7_RPM="$BATS_TEST_TMPDIR/rpm"
    export PACKAGES="$BATS_TEST_TMPDIR/packages" FLAG="$BATS_TEST_TMPDIR/flag" COUNT="$BATS_TEST_TMPDIR/count"
    P="$RLCH_CIS_7_2_7_GROUP"; N="$BATS_TEST_TMPDIR/nsswitch.conf"
    printf 'root:x:0:\n' > "$P"; printf 'group: files\n' > "$N"; chmod 0644 "$P" "$N"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\n' > "$PACKAGES"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$PACKAGES"\n' > "$RLCH_CIS_7_2_7_RPM"; chmod 0700 "$RLCH_CIS_7_2_7_RPM"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/7/module.sh"
}
dup() { printf 'root:x:42:\n' >> "$P"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.7 exact metadata Level 1 enabled no reboot and public functions" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.7 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_group_unique_name ]
    validate_loaded_module_metadata 7.2.7; validate_loaded_module_functions
}
@test "7.2.7 framework loads after previous control" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/6"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/7"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.7 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 missing and empty source are ERROR" { rm "$P"; uncertain; : > "$P"; uncertain; }
@test "7.2.7 unreadable and unsafe permission modes are ERROR" {
    for mode in 0000 0666 0664; do chmod "$mode" "$P"; uncertain; done
}
@test "7.2.7 invalid UTF-8 cannot produce SUCCESS" {
    printf 'PRIVATE\377:x:1:7::/:/bin/false\n' >> "$P"; uncertain
}
@test "7.2.7 symlink ancestor symlink and hardlink rejected" {
    mv "$P" "$P.real"; ln -s "$P.real" "$P"; uncertain; rm "$P"; mv "$P.real" "$P"
    ln "$P" "$P.alias"; uncertain; rm "$P.alias"
    mkdir "$BATS_TEST_TMPDIR/real"; mv "$P" "$BATS_TEST_TMPDIR/real/passwd"; ln -s real "$BATS_TEST_TMPDIR/alias"
    RLCH_CIS_7_2_7_GROUP="$BATS_TEST_TMPDIR/alias/passwd"; uncertain
}
@test "7.2.7 directory and FIFO rejected without reading bodies" {
    rm "$P"; mkdir "$P"; uncertain; rmdir "$P"; mkfifo "$P"; uncertain
}
@test "7.2.7 complete-row truncation cannot hide duplicate name" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.7 mid-record and zero-byte truncation are ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 5; }; uncertain; rlch_identity_stream() { :; }; uncertain
}
@test "7.2.7 producer failure and stderr discard prefix privately" {
    dup; rlch_identity_stream() { /usr/bin/cat; return 87; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf PRIVATE_SENTINEL >&2; }; uncertain
}
@test "7.2.7 appended data and forged frame invalidate observation" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:1:\n'; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf 'RLCH-IDENTITY-END\n'; }; uncertain
}
@test "7.2.7 missing newline NUL and controls are ERROR" {
    printf 'root:x:0:' > "$P"; uncertain
    printf 'root:PRIVATE\000:0:0::/:/bin/false\n' > "$P"; uncertain
    printf 'root:x:0:0:PRIVATE\r:/:/bin/false\n' > "$P"; uncertain
}
@test "7.2.7 line entry and aggregate byte bounds are enforced" {
    printf '%17000s:x:1:7::/:/bin/false\n' X > "$P"; uncertain
    awk 'BEGIN{for(i=0;i<65537;i++)print "same:x:1:"}' > "$P"; uncertain
    awk 'BEGIN{for(i=0;i<500;i++){printf "same:";for(j=0;j<10000;j++)printf "x";print ":1:7::/:/bin/false"}}' > "$P"; uncertain
}
@test "7.2.7 maximum supported count preserves all duplicates" {
    awk 'BEGIN{for(i=0;i<65536;i++)print "same:x:1:"}' > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'65536 selected local group entries have 1 distinct'* ]]
}
@test "7.2.7 content mutation during read is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'later:x:1:\n' >> "$P"; }; uncertain
}
@test "7.2.7 pathname replacement or link creation during read is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; cp "$P" "$P.new"; mv "$P.new" "$P"; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; ln "$P" "$P.alias"; }; uncertain
}
@test "7.2.7 two real strict observations are required" {
    rlch_identity_stream() { printf 'read\n' >> "$COUNT"; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]; [ "$(wc -l < "$COUNT")" -eq 2 ]
}
@test "7.2.7 files mixed and external NSS do not alter local conformity" {
    for src in files 'files sss' 'sss files' ldap compat; do printf 'group: %s\n' "$src" > "$N"; run check; [ "$status" -eq 0 ]; done
}
@test "7.2.7 local duplicate remains finding independently of NSS" {
    dup; for src in files 'files sss' ldap; do printf 'group: %s\n' "$src" > "$N"; run check; [ "$status" -eq 1 ]; done
}
@test "7.2.7 absent ambiguous and unreadable NSS do not add prerequisites" {
    printf 'group: files\ngroup: sss\n' > "$N"; run check; [ "$status" -eq 0 ]
    chmod 0000 "$N"; run check; [ "$status" -eq 0 ]; rm "$N"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 no external enumeration or historical projection invoked" {
    getent() { touch "$FLAG"; return 99; }
    getgrent() { touch "$FLAG"; return 99; }
    rlch_identity_rows() { touch "$FLAG"; return 99; }
    rlch_identity_uid_values() { touch "$FLAG"; return 99; }
    rlch_identity_user_names() { touch "$FLAG"; return 99; }
    check; [ ! -e "$FLAG" ]
}
@test "7.2.7 identity reader opens only selected local group fixture" {
    rlch_identity_stream() { [[ "$(readlink /proc/self/fd/0)" == "$P" ]] || return 99; /usr/bin/cat; }
    run check; [ "$status" -eq 0 ]
}
@test "7.2.7 local uncertainty overrides finding with external NSS" {
    dup; printf 'group: sss\n' > "$N"; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.7 RPM absence proves NOT_APPLICABLE without group access" {
    printf 'RPM1|1|bash|0|1|1|x86_64|END\n' > "$PACKAGES"; rm "$P"
    run check; [ "$status" -eq 3 ]; [ -z "$output" ]; run apply; [ "$status" -eq 3 ]
}
@test "7.2.7 failed empty malformed and noisy RPM inventory is ERROR" {
    : > "$PACKAGES"; uncertain; printf 'PRIVATE_BROKEN\n' > "$PACKAGES"; uncertain
    printf '#!/usr/bin/env bash\nexit 1\n' > "$RLCH_CIS_7_2_7_RPM"; uncertain
    printf '#!/usr/bin/env bash\nprintf PRIVATE_SENTINEL >&2\n' > "$RLCH_CIS_7_2_7_RPM"; uncertain
}
@test "7.2.7 applicability change across observation is ERROR" {
    rlch_rpm_package_status() { if [[ -f "$FLAG" ]]; then return 1; fi; touch "$FLAG"; return 0; }; uncertain
}
@test "7.2.7 kernel-bearing bootc is applicable without container heuristic" {
    printf 'RPM1|2|bootc|0|1|1|x86_64|END\n' >> "$PACKAGES"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 check and validate are fresh without cached result" {
    check; dup; run validate; [ "$status" -eq 1 ]; printf 'root:x:0:\n' > "$P"; run check; [ "$status" -eq 0 ]
    rm "$P"; uncertain
}
@test "7.2.7 apply succeeds only for already conforming or inapplicable state" {
    run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; dup
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.7 apply preserves uncertainty and never claims CHANGED" {
    rm "$P"; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.7 rollback silent idempotent with missing source files" {
    rm "$P" "$N" "$PACKAGES"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.7 all public functions preserve fixtures metadata contents and file set" {
    before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N" "$PACKAGES")"; data="$(sha256sum "$P" "$N" "$PACKAGES")"; files="$(find "$BATS_TEST_TMPDIR" -type f | sort)"
    check; validate; apply; rollback; check
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P" "$N" "$PACKAGES")" ]; [ "$data" = "$(sha256sum "$P" "$N" "$PACKAGES")" ]
    [ "$files" = "$(find "$BATS_TEST_TMPDIR" -type f | sort)" ]
}
@test "7.2.7 findings and apply manual guidance preserve duplicate source" {
    dup; before="$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")"; data="$(cat "$P")"
    run check; [ "$status" -eq 1 ]; run validate; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; rollback
    [ "$before" = "$(stat -c '%i:%a:%u:%g:%Y:%Z:%s' "$P")" ]; [ "$data" = "$(cat "$P")" ]
}
@test "7.2.7 group account ownership ACL administration never invoked" {
    usermod() { touch "$FLAG"; return 99; }
    userdel() { touch "$FLAG"; return 99; }
    useradd() { touch "$FLAG"; return 99; }
    groupmod() { touch "$FLAG"; return 99; }
    groupdel() { touch "$FLAG"; return 99; }
    groupadd() { touch "$FLAG"; return 99; }
    chown() { touch "$FLAG"; return 99; }
    chgrp() { touch "$FLAG"; return 99; }
    chmod() { touch "$FLAG"; return 99; }
    setfacl() { touch "$FLAG"; return 99; }
    check; validate; apply; rollback; [ ! -e "$FLAG" ]
}
@test "7.2.7 unexpected observer status is normalized to ERROR" {
    rlch_7_2_7_observe() { return 99; }; uncertain
}
@test "7.2.7 unique root system and user captures are SUCCESS" {
    printf 'daemon:x:1:\nuser:x:1000:\n' >> "$P"; run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.7 identical capture with different GID is NON_COMPLIANT" {
    dup; run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 selected local group entries have 1 distinct OVAL captures'* ]]
}
@test "7.2.7 three identical captures counted without deduplication" {
    dup; printf 'root:x:1000:\n' >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 selected local group entries have 1 distinct'* ]]
}
@test "7.2.7 nonadjacent multiple duplicate sets are NON_COMPLIANT" {
    printf 'a:x:1:\nb:x:2:\na:x:3:\nb:x:4:\n' >> "$P"; run check; [ "$status" -eq 1 ]; [[ "$output" == *'5 selected local group entries have 3 distinct'* ]]
}
@test "7.2.7 same group name with distinct captures is SUCCESS under pinned OVAL" {
    printf 'alpha:x:42:member\nalpha:x:43:member\n' > "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 differing member field does not change greedy capture" {
    printf 'alpha:x:42:one\nalpha:x:42:two\n' > "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.7 no authentication GID range system threshold or name filter" {
    printf '+::BAD:\n-:PRIVATE:999999999999999999999:\n#system:x:-1:\n :x:0:\n' > "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 case and spaces preserve exact string distinctions" {
    printf 'Alpha:x\nalpha:x\n alpha:x\nalpha :x\na  b:x\n' > "$P"; run check; [ "$status" -eq 0 ]
    printf 'alpha :y\n' >> "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.7 Unicode and numeric spellings are not normalized" {
    printf 'é:x\ne\314\201:x\n01:x\n1:x\nalpha:x:42:m\nalpha:x:0042:m\n' > "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 empty fields match exact greedy pattern rather than first-field parser" {
    printf ':x:42:\n:x:43:\n' > "$P"; run check; [ "$status" -eq 1 ]
    printf 'alpha::42:\nalpha::43:\n' > "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.7 nonmatching blank comment and malformed lines are ignored by selection" {
    printf '\n# PRIVATE_NONMATCH\nalpha:\n:x\nnot-a-group\n' >> "$P"; run check; [ "$status" -eq 0 ]
}
@test "7.2.7 matching malformed field counts remain selected by exact pattern" {
    printf 'alpha:x\nalpha:y\n' > "$P"; run check; [ "$status" -eq 1 ]
}
@test "7.2.7 nonempty source with no captures is conservative ERROR" {
    printf '\nalpha:\n:x\n# PRIVATE\n' > "$P"; uncertain
}
@test "7.2.7 structural safety error overrides duplicate prefix" {
    dup; printf 'PRIVATE_BAD\r\n' >> "$P"; uncertain
}
@test "7.2.7 repeated identical complete-row truncations cannot produce SUCCESS" {
    dup; rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain; uncertain
}
@test "7.2.7 real second observation failure overrides initially valid duplicate evidence" {
    dup
    rlch_identity_stream() { if [[ -f "$FLAG" ]]; then /usr/bin/head -n 1; else touch "$FLAG"; /usr/bin/cat; fi; }
    uncertain; [ -f "$FLAG" ]
}
@test "7.2.7 real mutation between observations overrides equal aggregate counts" {
    rlch_identity_stream() { /usr/bin/cat; if [[ ! -f "$FLAG" ]]; then touch "$FLAG"; sed -i s/root/other/ "$P"; fi; }; uncertain
}
@test "7.2.7 changed counts and second API error override finding" {
    rlch_identity_group_name_counts() { if [[ -f "$FLAG" ]]; then printf 'COUNTS|1|1\n'; else touch "$FLAG"; printf 'COUNTS|2|1\n'; fi; }; uncertain
    rm "$FLAG"
    rlch_identity_group_name_counts() { if [[ -f "$FLAG" ]]; then return 2; fi; touch "$FLAG"; printf 'COUNTS|2|1\n'; }; uncertain
}
@test "7.2.7 defensive decoder rejects malformed out-of-range and inconsistent counts" {
    for BAD in PRIVATE_SENTINEL 'COUNTS|0|0' 'COUNTS|01|1' 'COUNTS|1|0' 'COUNTS|1|2' 'COUNTS|65537|1' 'COUNTS|1|1|PRIVATE' $'COUNTS|2|1\nPRIVATE'; do
        export BAD; rlch_identity_group_name_counts() { printf '%s\n' "$BAD"; }; uncertain
    done
}
@test "7.2.7 outer metadata change overrides matching counts" {
    rlch_identity_stamp() { if [[ -f "$FLAG" ]]; then printf after; else touch "$FLAG"; printf before; fi; }; uncertain
}
@test "7.2.7 long captures remain complete and nonadjacent duplicates detected" {
    long="$(printf '%16000s' '' | tr ' ' a)"; printf '%s:x\nother:x\n%s:y\n' "$long" "$long" > "$P"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 selected local group entries have 2 distinct'* ]]
}
@test "7.2.7 metacharacters in captures are inert and never evaluated" {
    name='$(touch "$FLAG")|a[$(touch "$FLAG")]'
    printf '%s:x\n%s:y\n' "$name" "$name" > "$P"; run check; [ "$status" -eq 1 ]; [ ! -e "$FLAG" ]
}
@test "7.2.7 success finding and ERROR diagnostics never expose captures or fields" {
    for mode in success finding error; do
        printf 'PRIVATE_NAME:$6$PRIVATE_SALT$PRIVATE_HASH:424242:PRIVATE_MEMBER\n' > "$P"; expected=0
        if [[ "$mode" == finding ]]; then printf 'PRIVATE_NAME:$6$PRIVATE_SALT$PRIVATE_HASH:424242:OTHER_MEMBER\n' >> "$P"; expected=1; fi
        if [[ "$mode" == error ]]; then printf 'PRIVATE_BAD\377\n' >> "$P"; expected=2; fi
        run check; [ "$status" -eq "$expected" ]; [[ "$output" != *PRIVATE* && "$output" != *424242* ]]; [ "${#output}" -lt 300 ]
        run apply; [[ "$status" -eq 0 || "$status" -eq 2 ]]; [[ "$output" != *PRIVATE* ]]; [ "${#output}" -lt 500 ]
    done
}
@test "7.2.7 xtrace hides captures and preserves caller tracing on all result paths" {
    for mode in success finding error; do
        printf 'PRIVATE_NAME:PRIVATE_AUTH:1:PRIVATE_MEMBER\n' > "$P"; expected=0
        if [[ "$mode" == finding ]]; then printf 'PRIVATE_NAME:PRIVATE_AUTH:1:OTHER_MEMBER\n' >> "$P"; expected=1; fi
        if [[ "$mode" == error ]]; then printf 'PRIVATE\377\n' >> "$P"; expected=2; fi
        run bash -c 'source "$1"; source "$2"; set -x; rc=0; check || rc=$?; [[ $- == *x* ]] || exit 99; exit "$rc"' bash "$BATS_TEST_DIRNAME/../lib/module_api.sh" "$BATS_TEST_DIRNAME/../modules/cis/7/2/7/module.sh"
        [ "$status" -eq "$expected" ]; [[ "$output" != *PRIVATE* ]]
    done
}
@test "7.2.7 aggregate diagnostics remain bounded for large duplicate sets" {
    awk 'BEGIN{for(i=0;i<1000;i++)print "PRIVATE_NAME:PRIVATE_AUTH:"i":"}' > "$P"
    run check; [ "$status" -eq 1 ]; [ "${#output}" -lt 200 ]; [[ "$output" != *PRIVATE* ]]
}
