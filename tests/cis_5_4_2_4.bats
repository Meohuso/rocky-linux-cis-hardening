#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_4_SHADOW="$BATS_TEST_TMPDIR/shadow"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/4/module.sh"
    shadow_password '$y$j9T$salt$SECRET'
}
shadow_password() { printf 'root:%s:20000:0:99999:7:::\n' "$1" > "$RLCH_CIS_5_4_2_4_SHADOW"; }

@test "5.4.2.4 metadata exact Level 1 CAS rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/4/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.4 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_ensure_root_password_configured ]
}
@test "yescrypt SHA512 SHA256 MD5 bcrypt numeric CAS formats succeed" {
    for password in '$y$j9T$salt$SECRET' '$6$salt$SECRET' '$5$salt$SECRET' '$1$salt$SECRET' '$2b$12$SECRET' '$9custom$SECRET' '$y$'; do
        shadow_password "$password"
        run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "empty and all lock representations are noncompliant without secret disclosure" {
    for password in '' '!' '!!' '!*' '*' '!locked' '!$6$salt$SECRET' '$gy$salt$SECRET' 'traditionalSECRET' '$6$SECRET'; do
        shadow_password "$password"
        run check; [ "$status" -eq 1 ]; [[ "$output" != *SECRET* ]]
        run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation'* && "$output" != *SECRET* ]]
    done
}
@test "observation apply validate rollback are idempotent without backup state" {
    before="$(sha256sum "$RLCH_CIS_5_4_2_4_SHADOW")"
    run apply; [ "$status" -eq 0 ]
    run validate; [ "$status" -eq 0 ]
    run rollback; [ "$status" -eq 0 ]
    shadow_password '!$6$salt$SECRET'
    locked="$(sha256sum "$RLCH_CIS_5_4_2_4_SHADOW")"
    run apply; [ "$status" -eq 2 ]
    run rollback; [ "$status" -eq 0 ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_4_SHADOW")" = "$locked" ]
    shadow_password '$y$j9T$salt$SECRET'
    [ "$(sha256sum "$RLCH_CIS_5_4_2_4_SHADOW")" = "$before" ]
    [ "$(find "$BATS_TEST_TMPDIR" -type f | wc -l)" -eq 1 ]
}
@test "absent duplicate root and malformed rows are errors" {
    printf 'user:!:20000:0:99999:7:::\n' > "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
    shadow_password '$y$SECRET'
    cat "$RLCH_CIS_5_4_2_4_SHADOW" >> "$BATS_TEST_TMPDIR/duplicate"
    cat "$BATS_TEST_TMPDIR/duplicate" >> "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    shadow_password '$y$SECRET'
    printf 'broken:SECRET\n' >> "$RLCH_CIS_5_4_2_4_SHADOW"
    run apply; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
}
@test "missing directory FIFO and symlink files are errors" {
    rm "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
    mkdir "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
    rmdir "$RLCH_CIS_5_4_2_4_SHADOW"
    mkfifo "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
    rm "$RLCH_CIS_5_4_2_4_SHADOW"
    ln -s /etc/shadow "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
}
@test "unreadable permissions and failed read are errors" {
    chmod 000 "$RLCH_CIS_5_4_2_4_SHADOW"
    run check; [ "$status" -eq 2 ]
    chmod 600 "$RLCH_CIS_5_4_2_4_SHADOW"
    awk() { return 2; }
    run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
}
@test "parent symlink and concurrent file change are errors" {
    ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/alias"
    export RLCH_CIS_5_4_2_4_SHADOW="$BATS_TEST_TMPDIR/alias/shadow"
    run check; [ "$status" -eq 2 ]
    export RLCH_CIS_5_4_2_4_SHADOW="$BATS_TEST_TMPDIR/shadow"
    awk() { command awk "$@"; printf 'user:!:20000:0:99999:7:::\n' >> "$RLCH_CIS_5_4_2_4_SHADOW"; }
    run check; [ "$status" -eq 2 ]
}
