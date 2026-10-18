#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats test isolation; run sets status/output.
# shellcheck disable=SC2016 # Literal artificial credential sentinels.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_3_PASSWD="$BATS_TEST_TMPDIR/passwd" RLCH_CIS_7_2_3_GROUP="$BATS_TEST_TMPDIR/group"
    printf 'root:x:11111:42::/fixture:/bin/false\n' > "$RLCH_CIS_7_2_3_PASSWD"
    printf 'first:x:42:\n' > "$RLCH_CIS_7_2_3_GROUP"; chmod 0644 "$RLCH_CIS_7_2_3_PASSWD" "$RLCH_CIS_7_2_3_GROUP"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/3/module.sh"
}
passwd_row() { printf 'fixture:%s:%s:%s::/fixture:/bin/false\n' "$1" "$2" "$3" > "$RLCH_CIS_7_2_3_PASSWD"; }
group_row() { printf 'first:%s:%s:PRIVATE_MEMBER\n' "$1" "$2" > "$RLCH_CIS_7_2_3_GROUP"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.3 metadata exact primary mapping Level 1 no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.3 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_gid_passwd_group_same ]
    validate_loaded_module_metadata 7.2.3; validate_loaded_module_functions
}
@test "7.2.3 framework loads after previous module" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/2"; load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/3"
    [ "$RLCH_CURRENT_MODULE_ID" = 7.2.3 ]; run check; [ "$status" -eq 0 ]
}
@test "7.2.3 matching primary GID passes independently of UID" {
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.3 existing UID cannot substitute for missing primary GID" {
    group_row x 11111; run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 1'* ]]
}
@test "7.2.3 canonical GID and zero match exactly" {
    for gid in 0 42 123456; do passwd_row x 11111 "$gid"; group_row x "$gid"; run check; [ "$status" -eq 0 ]; done
}
@test "7.2.3 equal leading-zero captures match without normalization" {
    passwd_row x 11111 0042; group_row x 0042; run check; [ "$status" -eq 0 ]
}
@test "7.2.3 0042 against 42 fails pinned string equality" {
    passwd_row x 11111 0042; run check; [ "$status" -eq 1 ]; [[ "$output" != *0042* ]]
}
@test "7.2.3 42 against 0042 fails pinned string equality" {
    group_row x 0042; run check; [ "$status" -eq 1 ]
}
@test "7.2.3 zero against double zero differs" {
    passwd_row x 11111 0; group_row x 00; run check; [ "$status" -eq 1 ]
}
@test "7.2.3 large decimal strings follow captures not UID bounds" {
    passwd_row x 9999999999999999999 18446744073709551616; group_row x 18446744073709551616
    run check; [ "$status" -eq 0 ]
}
@test "7.2.3 several users sharing one GID pass" {
    printf 'service:x:1:42::/:/sbin/nologin\nuser:x:2:42::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.3 several groups and aliases preserve exact membership" {
    printf 'alias:x:42:\nother:x:0042:\n' >> "$RLCH_CIS_7_2_3_GROUP"
    printf 'service:x:1:0042::/:/sbin/nologin\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.3 repeated names and duplicate records do not impose uniqueness" {
    printf 'root:x:11111:42::/fixture:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    printf 'first:x:42:\n' >> "$RLCH_CIS_7_2_3_GROUP"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.3 system accounts have no shell or UID exemption" {
    printf 'service:x:1:99::/:/sbin/nologin\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 2'* ]]
}
@test "7.2.3 multiple missing references yield bounded aggregate finding" {
    printf 'a:x:1:98::/:/bin/false\nb:x:2:99::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 of 3'* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.3 empty passwd second field is excluded by pinned pattern" {
    printf 'excluded::1:99::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"; run check; [ "$status" -eq 0 ]
}
@test "7.2.3 zero or artificial credential second fields are nonempty captures" {
    for value in 0 '$6$PRIVATE_SALT$PRIVATE_SENTINEL'; do passwd_row "$value" 11111 42; run check; [ "$status" -eq 0 ]; [ -z "$output" ]; done
}
@test "7.2.3 empty group second field cannot define a captured GID" {
    printf 'excluded::99:\n' >> "$RLCH_CIS_7_2_3_GROUP"
    passwd_row x 11111 99; run check; [ "$status" -eq 1 ]
}
@test "7.2.3 empty names and nondecimal IDs are excluded not silently normalized" {
    printf ':x:1:99::/:/bin/false\nemptyuid:x::99::/:/bin/false\nnondecimal:x:PRIVATE_UID:99::/:/bin/false\nnondecimalgid:x:2:+42::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    printf ':x:99:\nexcluded:x:+42:\n' >> "$RLCH_CIS_7_2_3_GROUP"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.3 name plus is a literal local capture not an NSS inclusion" {
    printf '+:x:1:42::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"; run check; [ "$status" -eq 0 ]
}
@test "7.2.3 no selected passwd object fails all_exist instead of vacuous success" {
    passwd_row '' 11111 42; run check; [ "$status" -eq 1 ]; [[ "$output" == *'all_exist'* ]]
}
@test "7.2.3 no group capture means unavailable OVAL state variable ERROR" {
    group_row '' 42; uncertain
}
@test "7.2.3 no passwd captures still fails existence when group variable empty" {
    passwd_row '' 11111 42; group_row '' 42
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'all_exist'* ]]
}
@test "7.2.3 structurally malformed passwd is ERROR" {
    printf 'bad:PRIVATE_SENTINEL:1\n' >> "$RLCH_CIS_7_2_3_PASSWD"; uncertain
}
@test "7.2.3 structurally malformed group is ERROR" {
    printf 'bad:PRIVATE_SENTINEL:42::extra\n' >> "$RLCH_CIS_7_2_3_GROUP"; uncertain
}
@test "7.2.3 either empty file is insufficient evidence" {
    : > "$RLCH_CIS_7_2_3_PASSWD"; uncertain; passwd_row x 11111 42
    : > "$RLCH_CIS_7_2_3_GROUP"; uncertain
}
@test "7.2.3 absent passwd and group return ERROR" {
    rm "$RLCH_CIS_7_2_3_PASSWD"; uncertain; passwd_row x 11111 42; rm "$RLCH_CIS_7_2_3_GROUP"; uncertain
}
@test "7.2.3 unsafe modes and no read bits return ERROR" {
    chmod 0666 "$RLCH_CIS_7_2_3_PASSWD"; uncertain; chmod 0644 "$RLCH_CIS_7_2_3_PASSWD"
    chmod 0000 "$RLCH_CIS_7_2_3_GROUP"; uncertain; chmod 0644 "$RLCH_CIS_7_2_3_GROUP"
}
@test "7.2.3 symlink files rejected for both sources" {
    mv "$RLCH_CIS_7_2_3_PASSWD" "$RLCH_CIS_7_2_3_PASSWD.real"; ln -s "$RLCH_CIS_7_2_3_PASSWD.real" "$RLCH_CIS_7_2_3_PASSWD"; uncertain
    rm "$RLCH_CIS_7_2_3_PASSWD"; mv "$RLCH_CIS_7_2_3_PASSWD.real" "$RLCH_CIS_7_2_3_PASSWD"
    mv "$RLCH_CIS_7_2_3_GROUP" "$RLCH_CIS_7_2_3_GROUP.real"; ln -s "$RLCH_CIS_7_2_3_GROUP.real" "$RLCH_CIS_7_2_3_GROUP"; uncertain
}
@test "7.2.3 hardlinked inputs rejected" {
    ln "$RLCH_CIS_7_2_3_PASSWD" "$BATS_TEST_TMPDIR/p.alias"; uncertain
    rm "$BATS_TEST_TMPDIR/p.alias"; ln "$RLCH_CIS_7_2_3_GROUP" "$BATS_TEST_TMPDIR/g.alias"; uncertain
}
@test "7.2.3 directories and FIFO rejected without body read" {
    rm "$RLCH_CIS_7_2_3_PASSWD"; mkdir "$RLCH_CIS_7_2_3_PASSWD"; uncertain
    rmdir "$RLCH_CIS_7_2_3_PASSWD"; mkfifo "$RLCH_CIS_7_2_3_PASSWD"; uncertain
}
@test "7.2.3 missing newline and NUL are ERROR" {
    printf 'first:x:42:' > "$RLCH_CIS_7_2_3_GROUP"; uncertain; group_row x 42
    printf 'root:PRIVATE\000:1:42::/:/bin/false\n' > "$RLCH_CIS_7_2_3_PASSWD"; uncertain
}
@test "7.2.3 complete-row passwd truncation cannot hide a missing reference" {
    printf 'other:x:2:99::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.3 complete-row group truncation invalidates evidence" {
    printf 'other:x:99:\n' >> "$RLCH_CIS_7_2_3_GROUP"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.3 producer failure and stderr are withheld" {
    rlch_identity_stream() { /usr/bin/cat; return 91; }; uncertain
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SALT_SENTINEL\n' >&2; }; uncertain
}
@test "7.2.3 mutation of passwd detected" {
    rlch_identity_stream() { /usr/bin/cat; printf 'other:x:2:99::/:/bin/false\n' >> "$RLCH_CIS_7_2_3_PASSWD"; }; uncertain
}
@test "7.2.3 mutation of group detected" {
    rlch_identity_stream() { /usr/bin/cat; printf 'other:x:99:\n' >> "$RLCH_CIS_7_2_3_GROUP"; }; uncertain
}
@test "7.2.3 same-projection metadata mutation between observations is ERROR" {
    rlch_identity_gid_fields() {
        if [[ "$2" == passwd ]]; then
            if [[ ! -e "$BATS_TEST_TMPDIR/seen" ]]; then touch "$BATS_TEST_TMPDIR/seen"; passwd_row x 11111 42; fi
            printf 'PRESENT|PRESENT|DECIMAL|42\n'
        else printf 'PRESENT|PRESENT|NA|42\n'; fi
    }
    uncertain
}
@test "7.2.3 both sources compared across complete independent observations" {
    rlch_identity_gid_fields() {
        if [[ -e "$BATS_TEST_TMPDIR/$2.seen" ]]; then
            if [[ "$2" == group ]]; then printf 'PRESENT|PRESENT|NA|99\n'; else printf 'PRESENT|PRESENT|DECIMAL|42\n'; fi
        else touch "$BATS_TEST_TMPDIR/$2.seen"
            if [[ "$2" == group ]]; then printf 'PRESENT|PRESENT|NA|42\n'; else printf 'PRESENT|PRESENT|DECIMAL|42\n'; fi
        fi
    }
    uncertain
}
@test "7.2.3 second observation failure overrides first finding" {
    passwd_row x 11111 99
    rlch_identity_gid_fields() {
        if [[ -e "$BATS_TEST_TMPDIR/$2.seen" ]]; then return 2; fi
        touch "$BATS_TEST_TMPDIR/$2.seen"
        if [[ "$2" == group ]]; then printf 'PRESENT|PRESENT|NA|42\n'; else printf 'PRESENT|PRESENT|DECIMAL|99\n'; fi
    }
    uncertain
}
@test "7.2.3 invalid later proof row overrides a missing GID" {
    rlch_identity_gid_fields() {
        if [[ "$2" == group ]]; then printf 'PRESENT|PRESENT|NA|42\n'; else printf 'PRESENT|PRESENT|DECIMAL|99\nPRIVATE_SENTINEL\n'; fi
    }
    uncertain
}
@test "7.2.3 unexpected or empty group projection fails closed" {
    rlch_identity_gid_fields() { if [[ "$2" == passwd ]]; then printf 'PRESENT|PRESENT|DECIMAL|42\n'; else printf ''; fi; }; uncertain
}
@test "7.2.3 dependency failures propagate ERROR" {
    rlch_identity_gid_fields() { return 72; }; uncertain
}
@test "7.2.3 raw extra separators cannot form a valid projection" {
    rlch_identity_gid_fields() { printf 'PRESENT|PRESENT|NA|42|\n'; }; uncertain
}
@test "7.2.3 limits on physical line row count and aggregate bytes are ERROR" {
    awk 'BEGIN {printf "name:x:1:";for(i=0;i<16400;i++) printf "0";print "::/:/bin/false"}' > "$RLCH_CIS_7_2_3_PASSWD"; uncertain
    passwd_row x 11111 42
    awk 'BEGIN {for(i=0;i<65537;i++) print "same:x:42:"}' > "$RLCH_CIS_7_2_3_GROUP"; uncertain
    awk 'BEGIN {for(i=0;i<500;i++) {printf "g%d:x:42:",i;for(j=0;j<10000;j++) printf "a";print ""}}' > "$RLCH_CIS_7_2_3_GROUP"; uncertain
}
@test "7.2.3 check freshly observes both sources" {
    run check; [ "$status" -eq 0 ]; group_row x 99; run check; [ "$status" -eq 1 ]; group_row x 42; run check; [ "$status" -eq 0 ]
}
@test "7.2.3 validate independently observes current data" {
    run check; [ "$status" -eq 0 ]; passwd_row x 11111 99; run validate; [ "$status" -eq 1 ]; group_row x 99; run validate; [ "$status" -eq 0 ]
}
@test "7.2.3 apply is fresh observation-only and never CHANGED" {
    run apply; [ "$status" -eq 0 ]; passwd_row x 11111 99; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.3 apply invalid evidence is ERROR" {
    rm "$RLCH_CIS_7_2_3_GROUP"; run apply; [ "$status" -eq 2 ]
}
@test "7.2.3 rollback silent idempotent without either source" {
    rm "$RLCH_CIS_7_2_3_PASSWD" "$RLCH_CIS_7_2_3_GROUP"
    run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.3 public functions preserve both artificial files" {
    before="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RLCH_CIS_7_2_3_PASSWD" "$RLCH_CIS_7_2_3_GROUP")"
    p="$(cat "$RLCH_CIS_7_2_3_PASSWD")"; g="$(cat "$RLCH_CIS_7_2_3_GROUP")"
    for action in check validate apply rollback check; do run "$action"; [ "$status" -eq 0 ]; done
    [ "$before" = "$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RLCH_CIS_7_2_3_PASSWD" "$RLCH_CIS_7_2_3_GROUP")" ]
    [ "$p" = "$(cat "$RLCH_CIS_7_2_3_PASSWD")" ]; [ "$g" = "$(cat "$RLCH_CIS_7_2_3_GROUP")" ]
}
@test "7.2.3 no secret name UID member list or GID on diagnostics" {
    passwd_row '$6$PRIVATE_SALT$PRIVATE_SENTINEL' 11111 0042
    for action in check validate apply; do
        result=0; "$action" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || result=$?
        [[ "$result" -eq 1 || "$result" -eq 2 ]]; [ ! -s "$BATS_TEST_TMPDIR/out" ]
        diagnostic="$(cat "$BATS_TEST_TMPDIR/err")"
        [[ "$diagnostic" != *PRIVATE* && "$diagnostic" != *11111* && "$diagnostic" != *0042* ]]; [ "${#diagnostic}" -lt 500 ]
    done
}
@test "7.2.3 aggregate diagnostics remain bounded for many missing references" {
    awk 'BEGIN {for(i=0;i<2000;i++) print "u"i":x:1:99::/:/bin/false"}' > "$RLCH_CIS_7_2_3_PASSWD"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'2000 of 2000'* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.3 no identity mutation utility NSS resolver or pwck invoked" {
    groupadd() { printf UNEXPECTED; return 99; }; usermod() { printf UNEXPECTED; return 99; }
    pwck() { printf UNEXPECTED; return 99; }; getent() { printf UNEXPECTED; return 99; }
    run check; [ "$status" -eq 0 ]; [ -z "$output" ]; passwd_row x 11111 99
    run apply; [ "$status" -eq 2 ]; [[ "$output" != *UNEXPECTED* ]]
}
@test "7.2.3 existing framework codes are respected" {
    [ "$(module_status_from_result 0)" = compliant ]; [ "$(module_status_from_result 1)" = non_compliant ]; [ "$(module_status_from_result 2)" = error ]
}
