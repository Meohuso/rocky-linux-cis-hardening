#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced API.
# shellcheck disable=SC2016 # Artificial password strings contain literal dollars.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_1_PASSWD="$BATS_TEST_TMPDIR/passwd"
    printf 'root:x:0:0::/root:/bin/false\n' > "$RLCH_CIS_7_2_1_PASSWD"
    chmod 0644 "$RLCH_CIS_7_2_1_PASSWD"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/1/module.sh"
}
entry() { printf 'fixture:%s:1001:1001::/fixture:/bin/false\n' "$1" > "$RLCH_CIS_7_2_1_PASSWD"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *SENTINEL* && "$output" != *PRIVATE* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.1 metadata exact primary rule Level 1 no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.1 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed ]
    validate_loaded_module_metadata 7.2.1; validate_loaded_module_functions
}
@test "7.2.1 loads through framework" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/1"; [ "$RLCH_CURRENT_MODULE_ID" = 7.2.1 ]
}
@test "7.2.1 x complies across public observation APIs" {
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]
    run validate; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]
}
@test "7.2.1 asterisk complies" {
    entry '*'; run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.1 single exclamation does not match pinned OVAL" {
    entry '!'; run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 1'* && "$output" != *hash* ]]
}
@test "7.2.1 empty field does not match and is not called a hash" {
    entry ''; run check; [ "$status" -eq 1 ]; [[ "$output" != *hash* ]]
}
@test "7.2.1 lock strings are not marker exceptions" {
    for value in '!!' '!*' '!x' '*LK*' '!$6$FAKE$SENTINEL'; do
        entry "$value"; run check; [ "$status" -eq 1 ]; [[ "$output" != *SENTINEL* ]]
    done
}
@test "7.2.1 artificial traditional hash-like string fails privately" {
    entry 'FAKEtraditionalSENTINEL'; run check; [ "$status" -eq 1 ]; [[ "$output" != *SENTINEL* ]]
}
@test "7.2.1 artificial modern hash-like strings fail privately" {
    for value in '$6$FAKE$SENTINEL' '$y$FAKE$SENTINEL' '$1$FAKE$SENTINEL'; do
        entry "$value"; run check; [ "$status" -eq 1 ]; [[ "$output" != *SENTINEL* ]]
    done
}
@test "7.2.1 anchored pattern rejects unknown prefixes suffixes and case" {
    for value in X xx '**' xSENTINEL SENTINELx ' x' 'x '; do
        entry "$value"; run check; [ "$status" -eq 1 ]; [[ "$output" != *SENTINEL* ]]
    done
}
@test "7.2.1 root system and ordinary accounts have no exemptions" {
    for uid in 0 500 1001; do
        printf 'root:SENTINEL:%s:0::/:/sbin/nologin\n' "$uid" > "$RLCH_CIS_7_2_1_PASSWD"
        run check; [ "$status" -eq 1 ]; [[ "$output" != *SENTINEL* ]]
    done
}
@test "7.2.1 multiple compliant accounts and ID aliases pass" {
    printf 'service:*:0:0::/:/sbin/nologin\nuser:x:1001:1001::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.1 one deficient entry among compliant entries fails" {
    printf 'SECRETNAME:SENTINEL:1001:1001::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 2'* && "$output" != *SECRETNAME* && "$output" != *SENTINEL* ]]
}
@test "7.2.1 several deficits yield a bounded aggregate diagnostic" {
    printf 'a:!:1:1::/:/bin/false\nb::2:2::/:/bin/false\nc:SENTINEL:3:3::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'3 of 4'* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.1 malformed field counts are ERROR" {
    for row in 'bad:SENTINEL:1:1' 'bad:SENTINEL:1:1::/:/bin/false:extra'; do
        printf '%s\n' "$row" > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
    done
}
@test "7.2.1 invalid UID or GID is ERROR" {
    for value in bad -1 4294967295; do
        printf 'bad:x:%s:1::/:/bin/false\n' "$value" > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
        printf 'bad:x:1:%s::/:/bin/false\n' "$value" > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
    done
}
@test "7.2.1 duplicate names are ambiguous" {
    printf 'root:x:1:1::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 compat inclusion is not silently ignored" {
    printf '+::::::\n' >> "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 empty database is ERROR" {
    : > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 absent database is ERROR" {
    rm "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 unreadable or writable database is ERROR" {
    for mode in 0000 0664 0666; do chmod "$mode" "$RLCH_CIS_7_2_1_PASSWD"; uncertain; done
}
@test "7.2.1 directory and special object rejected" {
    rm "$RLCH_CIS_7_2_1_PASSWD"; mkdir "$RLCH_CIS_7_2_1_PASSWD"; uncertain
    rmdir "$RLCH_CIS_7_2_1_PASSWD"; mkfifo "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 symlink rejected" {
    mv "$RLCH_CIS_7_2_1_PASSWD" "$RLCH_CIS_7_2_1_PASSWD.real"
    ln -s "$RLCH_CIS_7_2_1_PASSWD.real" "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 hardlinked database rejected" {
    ln "$RLCH_CIS_7_2_1_PASSWD" "$RLCH_CIS_7_2_1_PASSWD.alias"; uncertain
}
@test "7.2.1 missing final newline is ERROR" {
    printf 'root:x:0:0::/:/bin/false' > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 embedded control and NUL are ERROR" {
    printf 'root:x:0:0::/\000:/bin/false\n' > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
    entry $'SENTINEL\r'; uncertain
}
@test "7.2.1 I/O failure is ERROR with no partial result" {
    rlch_identity_stream() { /usr/bin/cat; return 93; }; uncertain
}
@test "7.2.1 producer stderr is invalid even with exit zero" {
    rlch_identity_stream() { /usr/bin/cat; printf 'SENTINEL\n' >&2; }; uncertain
}
@test "7.2.1 complete-row silent truncation cannot pass" {
    printf 'u:SENTINEL:1:1::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.1 mid-row truncation is ERROR" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; uncertain
}
@test "7.2.1 mutation while reading invalidates evidence" {
    rlch_identity_stream() { /usr/bin/cat; printf 'u:x:1:1::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"; }; uncertain
}
@test "7.2.1 pathname replacement invalidates evidence" {
    rlch_identity_stream() { /usr/bin/cat; cp "$RLCH_CIS_7_2_1_PASSWD" "$BATS_TEST_TMPDIR/new"; mv "$BATS_TEST_TMPDIR/new" "$RLCH_CIS_7_2_1_PASSWD"; }; uncertain
}
@test "7.2.1 malformed later entry overrides established deficit" {
    entry SENTINEL; printf 'MALFORMED\n' >> "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 failure on second complete observation overrides deficit" {
    entry SENTINEL
    rlch_identity_password_markers() {
        if [[ -e "$BATS_TEST_TMPDIR/seen" ]]; then return 2; fi
        touch "$BATS_TEST_TMPDIR/seen"; printf 'OTHER\n'
    }
    uncertain
}
@test "7.2.1 conflicting projections cannot produce a verdict" {
    rlch_identity_password_markers() {
        if [[ -e "$BATS_TEST_TMPDIR/seen" ]]; then printf 'STAR\n'; else touch "$BATS_TEST_TMPDIR/seen"; printf 'X\n'; fi
    }
    uncertain
}
@test "7.2.1 invalid dependency output and empty output fail closed" {
    for value in '' 'INVALID-SENTINEL' $'X\n\nOTHER'; do
        export MARKER_TEST_VALUE="$value"
        rlch_identity_password_markers() { printf '%s' "$MARKER_TEST_VALUE"; }
        uncertain
    done
}
@test "7.2.1 dependency stamp failure is ERROR" {
    rlch_identity_stamp() { return 75; }; uncertain
}
@test "7.2.1 line length bound fails closed" {
    awk 'BEGIN {printf "u:x:1:1:"; for(i=0;i<16400;i++) printf "a"; print ":/:/bin/false"}' > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 line count bound fails closed" {
    awk 'BEGIN {for(i=0;i<65537;i++) print "u"i":x:1:1::/:/bin/false"}' > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 aggregate byte bound fails closed" {
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:x:1:1:",i; for(j=0;j<10000;j++) printf "a"; print ":/:/bin/false"}}' > "$RLCH_CIS_7_2_1_PASSWD"; uncertain
}
@test "7.2.1 check is fresh across changes" {
    run check; [ "$status" -eq 0 ]; entry '!'; run check; [ "$status" -eq 1 ]; entry '*'; run check; [ "$status" -eq 0 ]
}
@test "7.2.1 validate independently observes current data" {
    run check; [ "$status" -eq 0 ]; entry '!'; run validate; [ "$status" -eq 1 ]; entry '*'; run validate; [ "$status" -eq 0 ]
}
@test "7.2.1 apply never invents CHANGED on a deficit" {
    entry SENTINEL; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* && "$output" != *SENTINEL* ]]
}
@test "7.2.1 apply reobserves compliant data and fails on unreadable data" {
    run apply; [ "$status" -eq 0 ]; rm "$RLCH_CIS_7_2_1_PASSWD"; run apply; [ "$status" -eq 2 ]
}
@test "7.2.1 rollback silent idempotent even when database is absent" {
    rm "$RLCH_CIS_7_2_1_PASSWD"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
    run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.1 no mutation across all public functions" {
    entry '$6$FAKE$SENTINEL'
    before="$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_7_2_1_PASSWD")"
    content="$(cat "$RLCH_CIS_7_2_1_PASSWD")"
    for action in check validate apply rollback check; do run "$action"; [[ "$status" == 0 || "$status" == 1 || "$status" == 2 ]]; done
    [ "$content" = "$(cat "$RLCH_CIS_7_2_1_PASSWD")" ]
    [ "$before" = "$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_7_2_1_PASSWD")" ]
}
@test "7.2.1 no raw secret on either output channel" {
    entry '$y$FAKE$SENTINEL'
    for action in check validate apply; do
        result=0; "$action" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
        [[ "$result" == 1 || "$result" == 2 ]]; [ ! -s "$BATS_TEST_TMPDIR/out" ]
        [[ "$(cat "$BATS_TEST_TMPDIR/err")" != *SENTINEL* ]]; [ "$(wc -c < "$BATS_TEST_TMPDIR/err")" -lt 500 ]
    done
}
@test "7.2.1 does not consult shadow or run account remediation" {
    pwconv() { printf 'UNEXPECTED\n'; return 99; }
    passwd() { printf 'UNEXPECTED\n'; return 99; }
    chpasswd() { printf 'UNEXPECTED\n'; return 99; }
    entry '*'; run apply; [ "$status" -eq 0 ]; [ -z "$output" ]
    entry '!'; run apply; [ "$status" -eq 2 ]; [[ "$output" != *UNEXPECTED* ]]
}
@test "7.2.1 metadata change between observations is ERROR" {
    rlch_identity_password_markers() {
        if [[ ! -e "$BATS_TEST_TMPDIR/seen" ]]; then
            touch "$BATS_TEST_TMPDIR/seen"
            printf 'extra:x:1:1::/:/bin/false\n' >> "$RLCH_CIS_7_2_1_PASSWD"
        fi
        printf 'X\n'
    }
    uncertain
}
@test "7.2.1 symlink ancestor is ERROR" {
    mkdir "$BATS_TEST_TMPDIR/dir"; mv "$RLCH_CIS_7_2_1_PASSWD" "$BATS_TEST_TMPDIR/dir/passwd"
    ln -s "$BATS_TEST_TMPDIR/dir" "$BATS_TEST_TMPDIR/alias"
    RLCH_CIS_7_2_1_PASSWD="$BATS_TEST_TMPDIR/alias/passwd"; uncertain
}
@test "7.2.1 dependency classification count cannot exceed bound" {
    rlch_identity_password_markers() { /usr/bin/awk 'BEGIN {for(i=0;i<65537;i++) print "X"}'; }
    uncertain
}
@test "7.2.1 repeat noncompliance has deterministic diagnostics" {
    entry SENTINEL; run check; [ "$status" -eq 1 ]; first_output="$output"
    run validate; [ "$status" -eq 1 ]; [ "$output" = "$first_output" ]
}
