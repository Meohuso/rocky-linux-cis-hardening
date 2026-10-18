#!/usr/bin/env bats
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2317 # Fault injection through sourced APIs.
# shellcheck disable=SC2030,SC2031 # Bats isolates test state; run sets status/output.
# shellcheck disable=SC2016 # Literal artificial password/salt sentinels.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/common.sh"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_7_2_2_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_7_2_2_RPM="$BATS_TEST_TMPDIR/rpm"
    export CIS722_RPM_BODY="$BATS_TEST_TMPDIR/packages"
    printf 'RPM1|1|kernel-core|0|1|1|x86_64|END\nRPM1|2|bash|0|1|1|x86_64|END\n' > "$CIS722_RPM_BODY"
    printf '#!/usr/bin/env bash\n/usr/bin/cat "$CIS722_RPM_BODY"\n' > "$RLCH_CIS_7_2_2_RPM"
    chmod 0700 "$RLCH_CIS_7_2_2_RPM"
    printf 'root:!:20000:0:99999:7:::\n' > "$RLCH_CIS_7_2_2_SHADOW"; chmod 0600 "$RLCH_CIS_7_2_2_SHADOW"
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/2/module.sh"
}
entry() { printf 'fixture:%s:20000:0:99999:7:::\n' "$1" > "$RLCH_CIS_7_2_2_SHADOW"; }
uncertain() {
    run check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot reliably evaluate'* ]]
    [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 300 ]
}
@test "7.2.2 metadata exact selected rule Level 1 enabled no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/7/2/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 7.2.2 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow ]
    validate_loaded_module_metadata 7.2.2; validate_loaded_module_functions
}
@test "7.2.2 framework load after 7.2.1 preserves behavior" {
    source "$BATS_TEST_DIRNAME/../lib/modules.sh"
    RLCH_MODULE_ROOT="$BATS_TEST_DIRNAME/../modules"; RLCH_MODULE_NAMESPACE=cis
    RLCH_MODULE_METADATA_FILENAME=metadata.conf; RLCH_MODULE_IMPLEMENTATION_FILENAME=module.sh
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/1"
    load_module "$BATS_TEST_DIRNAME/../modules/cis/7/2/2"; [ "$RLCH_CURRENT_MODULE_ID" = 7.2.2 ]
    run check; [ "$status" -eq 0 ]
}
@test "7.2.2 lock markers satisfy presence only" {
    for value in '!' '*' '!!'; do entry "$value"; run check; [ "$status" -eq 0 ]; [ -z "$output" ]; done
}
@test "7.2.2 zero satisfies OVAL regardless of OCIL truthiness" {
    for value in 0 00 0.0; do entry "$value"; run check; [ "$status" -eq 0 ]; done
}
@test "7.2.2 nonempty arbitrary values are not hash validation" {
    for value in ';' ' ' x 'ARTIFICIAL_SENTINEL'; do entry "$value"; run check; [ "$status" -eq 0 ]; [ -z "$output" ]; done
}
@test "7.2.2 artificial traditional and modern hash-like fields remain private" {
    for value in 'FAKEtraditionalSENTINEL' '$6$PRIVATE_SALT$PRIVATE_SENTINEL' '$y$PRIVATE_SALT$PRIVATE_SENTINEL'; do
        entry "$value"; run check; [ "$status" -eq 0 ]; [ -z "$output" ]
    done
}
@test "7.2.2 empty field is NON_COMPLIANT" {
    entry ''; run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 1'* && "$output" != *fixture* ]]
}
@test "7.2.2 several nonempty entries comply" {
    printf 'service:*:20000:0:99999:7:::\nuser:0:20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"
    run check; [ "$status" -eq 0 ]
}
@test "7.2.2 one empty field among nonempty entries fails" {
    printf 'PRIVATE_NAME::20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'1 of 2'* && "$output" != *PRIVATE* ]]
}
@test "7.2.2 several empty fields aggregate without identity disclosure" {
    printf 'service::20000:0:99999:7:::\nuser::20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'2 of 3'* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.2 root system user names and age policy create no exemption" {
    for name in root service user; do printf '%s::20000:0:99999:7:::\n' "$name" > "$RLCH_CIS_7_2_2_SHADOW"; run check; [ "$status" -eq 1 ]; done
}
@test "7.2.2 malformed field counts are ERROR" {
    for row in 'bad:!:1:0:99:7::' 'bad:!:1:0:99:7::::extra'; do printf '%s\n' "$row" > "$RLCH_CIS_7_2_2_SHADOW"; uncertain; done
}
@test "7.2.2 uninterpretable numeric fields are ERROR not policy findings" {
    printf 'fixture:!:BAD:0:99999:7:::\n' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 duplicate and compat entries cannot pass" {
    printf 'root::20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"; uncertain
    printf '+:::::::0:\n' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 empty file is insufficient evidence" {
    : > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 missing file is ERROR" {
    rm "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 unsafe writable permissions ERROR" {
    chmod 0666 "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 mode zero is evaluated only with actual read permission" {
    chmod 0000 "$RLCH_CIS_7_2_2_SHADOW"
    if [[ -r "$RLCH_CIS_7_2_2_SHADOW" ]]; then run check; [ "$status" -eq 0 ]; else uncertain; fi
    chmod 0600 "$RLCH_CIS_7_2_2_SHADOW"
}
@test "7.2.2 symlink rejected" {
    mv "$RLCH_CIS_7_2_2_SHADOW" "$RLCH_CIS_7_2_2_SHADOW.real"; ln -s "$RLCH_CIS_7_2_2_SHADOW.real" "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 ancestor symlink rejected" {
    mkdir "$BATS_TEST_TMPDIR/dir"; mv "$RLCH_CIS_7_2_2_SHADOW" "$BATS_TEST_TMPDIR/dir/shadow"
    ln -s "$BATS_TEST_TMPDIR/dir" "$BATS_TEST_TMPDIR/link"; RLCH_CIS_7_2_2_SHADOW="$BATS_TEST_TMPDIR/link/shadow"; uncertain
}
@test "7.2.2 hardlink rejected" {
    ln "$RLCH_CIS_7_2_2_SHADOW" "$RLCH_CIS_7_2_2_SHADOW.alias"; uncertain
}
@test "7.2.2 directory and FIFO rejected without reading bodies" {
    rm "$RLCH_CIS_7_2_2_SHADOW"; mkdir "$RLCH_CIS_7_2_2_SHADOW"; uncertain
    rmdir "$RLCH_CIS_7_2_2_SHADOW"; mkfifo "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 missing newline and control bytes rejected" {
    printf 'root:!:20000:0:99999:7:::' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
    entry $'PRIVATE\r'; uncertain
    printf 'root:PRIVATE\000:20000:0:99999:7:::\n' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 I/O failure discards partial findings" {
    entry ''; rlch_identity_stream() { /usr/bin/cat; return 93; }; uncertain
}
@test "7.2.2 dependency stderr never escapes" {
    rlch_identity_stream() { /usr/bin/cat; printf 'PRIVATE_SALT_SENTINEL\n' >&2; }; uncertain
}
@test "7.2.2 mid-record truncation fails closed" {
    rlch_identity_stream() { /usr/bin/head -c 10; }; uncertain
}
@test "7.2.2 full-record silent truncation fails closed" {
    printf 'second::20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"
    rlch_identity_stream() { /usr/bin/head -n 1; }; uncertain
}
@test "7.2.2 later malformed record overrides empty finding" {
    entry ''; printf 'MALFORMED_PRIVATE_SENTINEL\n' >> "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 concurrent mutation while reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'extra:!:20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"; }; uncertain
}
@test "7.2.2 substitution while reading is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; cp "$RLCH_CIS_7_2_2_SHADOW" "$BATS_TEST_TMPDIR/new"; mv "$BATS_TEST_TMPDIR/new" "$RLCH_CIS_7_2_2_SHADOW"; }; uncertain
}
@test "7.2.2 same-class mutation between observations detected by outer metadata" {
    rlch_identity_shadow_password_presence() {
        if [[ ! -e "$BATS_TEST_TMPDIR/seen" ]]; then touch "$BATS_TEST_TMPDIR/seen"; entry '!'; fi
        printf 'NONEMPTY\n'
    }
    uncertain
}
@test "7.2.2 conflicting classifications are ERROR" {
    rlch_identity_shadow_password_presence() {
        if [[ -e "$BATS_TEST_TMPDIR/seen" ]]; then printf 'EMPTY\n'; else touch "$BATS_TEST_TMPDIR/seen"; printf 'NONEMPTY\n'; fi
    }
    uncertain
}
@test "7.2.2 second observation failure overrides first empty classification" {
    rlch_identity_shadow_password_presence() {
        if [[ -e "$BATS_TEST_TMPDIR/seen" ]]; then return 2; fi
        touch "$BATS_TEST_TMPDIR/seen"; printf 'EMPTY\n'
    }
    uncertain
}
@test "7.2.2 malformed or absent classification tokens are ERROR" {
    for value in '' 'PRIVATE_SENTINEL' $'EMPTY\n\nNONEMPTY'; do
        export SHADOW_CLASS_TEST_VALUE="$value"
        rlch_identity_shadow_password_presence() { printf '%s' "$SHADOW_CLASS_TEST_VALUE"; }; uncertain
    done
}
@test "7.2.2 returned entry count bounded independently" {
    rlch_identity_shadow_password_presence() { /usr/bin/awk 'BEGIN {for(i=0;i<65537;i++) print "NONEMPTY"}'; }; uncertain
}
@test "7.2.2 line byte and record limits are ERROR" {
    awk 'BEGIN {printf "root:";for(i=0;i<16400;i++) printf "a";print ":20000:0:99999:7:::"}' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
    awk 'BEGIN {for(i=0;i<65537;i++) print "u"i":!:20000:0:99999:7:::"}' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
    awk 'BEGIN {for(i=0;i<500;i++) {printf "u%d:",i;for(j=0;j<10000;j++) printf "a";print ":20000:0:99999:7:::"}}' > "$RLCH_CIS_7_2_2_SHADOW"; uncertain
}
@test "7.2.2 check and validate are fresh" {
    run check; [ "$status" -eq 0 ]; entry ''; run validate; [ "$status" -eq 1 ]; entry '!'; run check; [ "$status" -eq 0 ]
}
@test "7.2.2 apply succeeds if already compliant without CHANGED" {
    run apply; [ "$status" -eq 0 ]; [ -z "$output" ]; run apply; [ "$status" -eq 0 ]
}
@test "7.2.2 apply deficit requires manual remediation without mutation" {
    entry ''; run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* ]]
}
@test "7.2.2 apply reevaluates and propagates unsafe evidence as ERROR" {
    run apply; [ "$status" -eq 0 ]; rm "$RLCH_CIS_7_2_2_SHADOW"; run apply; [ "$status" -eq 2 ]
}
@test "7.2.2 rollback silent and idempotent when database absent" {
    rm "$RLCH_CIS_7_2_2_SHADOW"; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]
}
@test "7.2.2 API actions preserve artificial data metadata and account access" {
    entry '$6$PRIVATE_SALT$PRIVATE_SENTINEL'; before="$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RLCH_CIS_7_2_2_SHADOW")"
    content="$(cat "$RLCH_CIS_7_2_2_SHADOW")"
    for action in check validate apply rollback; do run "$action"; [ "$status" -eq 0 ]; done
    [ "$content" = "$(cat "$RLCH_CIS_7_2_2_SHADOW")" ]; [ "$before" = "$(stat -c '%d:%i:%a:%u:%g:%s:%y:%z' "$RLCH_CIS_7_2_2_SHADOW")" ]
}
@test "7.2.2 no salt hash field or identity on either output channel" {
    entry '$y$PRIVATE_SALT$PRIVATE_SENTINEL'
    for action in check validate apply; do
        "$action" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err"; [ ! -s "$BATS_TEST_TMPDIR/out" ]; [ ! -s "$BATS_TEST_TMPDIR/err" ]
    done
    printf 'PRIVATE_NAME::20000:0:99999:7:::\n' >> "$RLCH_CIS_7_2_2_SHADOW"; run check
    [ "$status" -eq 1 ]; [[ "$output" != *PRIVATE* && "$output" != *SENTINEL* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.2 diagnostic bounded for many empty entries" {
    awk 'BEGIN {for(i=0;i<2000;i++) print "u"i"::20000:0:99999:7:::"}' > "$RLCH_CIS_7_2_2_SHADOW"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'2000 of 2000'* ]]; [ "${#output}" -lt 200 ]
}
@test "7.2.2 no account-changing utility invoked" {
    passwd() { printf 'UNEXPECTED'; return 99; }; pwconv() { printf 'UNEXPECTED'; return 99; }; chpasswd() { printf 'UNEXPECTED'; return 99; }
    entry ''; run apply; [ "$status" -eq 2 ]; [[ "$output" != *UNEXPECTED* ]]
}
@test "7.2.2 classic container scope absent kernel-core gives NOT_APPLICABLE without shadow read" {
    printf 'RPM1|2|bash|0|1|1|x86_64|END\n' > "$CIS722_RPM_BODY"; rm "$RLCH_CIS_7_2_2_SHADOW"
    for action in check validate apply; do run "$action"; [ "$status" -eq 3 ]; [ -z "$output" ]; done
}
@test "7.2.2 kernel-bearing bootc scope follows technical CAS predicate" {
    export container=oci; run check; [ "$status" -eq 0 ]; entry ''; run check; [ "$status" -eq 1 ]
}
@test "7.2.2 empty RPM inventory is insufficient not NOT_APPLICABLE" {
    : > "$CIS722_RPM_BODY"; uncertain
}
@test "7.2.2 missing or failed RPM dependency is ERROR" {
    rm "$RLCH_CIS_7_2_2_RPM"; uncertain
}
@test "7.2.2 RPM stderr or malformed inventory is ERROR" {
    printf '#!/usr/bin/env bash\nprintf "PRIVATE_SENTINEL\\n" >&2\n/usr/bin/cat "$CIS722_RPM_BODY"\n' > "$RLCH_CIS_7_2_2_RPM"; uncertain
    printf '#!/usr/bin/env bash\nprintf "INVALID\\n"\n' > "$RLCH_CIS_7_2_2_RPM"; uncertain
}
@test "7.2.2 changed applicability during evaluation is ERROR" {
    rlch_identity_stream() { /usr/bin/cat; printf 'RPM1|2|bash|0|1|1|x86_64|END\n' > "$CIS722_RPM_BODY"; }; uncertain
}
@test "7.2.2 framework maps statuses with existing codes" {
    [ "$(module_status_from_result 0)" = compliant ]; [ "$(module_status_from_result 1)" = non_compliant ]
    [ "$(module_status_from_result 2)" = error ]; [ "$(module_status_from_result 3)" = not_applicable ]
}
