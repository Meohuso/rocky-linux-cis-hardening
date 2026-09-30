#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_1_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_1_SHADOW="$BATS_TEST_TMPDIR/shadow"
    printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > "$RLCH_CIS_5_4_2_1_PASSWD"
    printf 'root:$y$secret:20000:0:365:7:45::\nalice:$6$secret:20000:0:365:7:45::\n' > "$RLCH_CIS_5_4_2_1_SHADOW"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/1/module.sh"
}

@test "metadata uses the exact automated Level 1 rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.1 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure root is the only UID 0 account' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero ]
}

@test "root alone has UID zero and no mutation or state" {
    before="$(sha256sum "$RLCH_CIS_5_4_2_1_PASSWD" "$RLCH_CIS_5_4_2_1_SHADOW")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_1_PASSWD" "$RLCH_CIS_5_4_2_1_SHADOW")" = "$before" ]
}

@test "root nonzero UID is noncompliant, missing root is an error" {
    sed -i '1s/:0:0:/:1:0:/' "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '1d' "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "nonroot unlocked UID zero requires manual remediation without exposing hash" {
    sed -i '2s/:1000:1000:/:0:1000:/' "$RLCH_CIS_5_4_2_1_PASSWD"
    before="$(sha256sum "$RLCH_CIS_5_4_2_1_PASSWD" "$RLCH_CIS_5_4_2_1_SHADOW")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *'alice has UID 0 and is not locked'* && "$output" != *'$6$secret'* ]]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'manual remediation'* ]]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_1_PASSWD" "$RLCH_CIS_5_4_2_1_SHADOW")" = "$before" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "OVAL accepts every leading lock marker, including prefixed hash" {
    sed -i '2s/:1000:1000:/:0:1000:/' "$RLCH_CIS_5_4_2_1_PASSWD"
    for password in '!' '!!' '!*' '*' '!locked' '!$6$secret' '*LK*'; do
        sed -i "2s@:[^:]*:20000:@:$password:20000:@" "$RLCH_CIS_5_4_2_1_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
}

@test "multiple UID zero accounts are all inspected and numeric leading zero is handled" {
    printf 'bob:x:000:1000::/home/bob:/bin/bash\n' >> "$RLCH_CIS_5_4_2_1_PASSWD"
    printf 'bob:!:20000:0:365:7:45::\n' >> "$RLCH_CIS_5_4_2_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i '2s/:1000:1000:/:0:1000:/' "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *alice* && "$output" != *bob* ]]
}

@test "missing or malformed shadow and duplicate identities are errors" {
    rm "$RLCH_CIS_5_4_2_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'root:$y$secret:20000:0:365:7:45::\nalice:!\n' > "$RLCH_CIS_5_4_2_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'root:$y$secret:20000:0:365:7:45::\nalice:!:20000:0:365:7:45::\nalice:!:20000:0:365:7:45::\n' > "$RLCH_CIS_5_4_2_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_1_SHADOW"
    printf 'alice:x:0:1000::/home/alice:/bin/bash\n' >> "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "missing, symlinked, nonregular and malformed passwd are errors" {
    printf 'bad:row\n' >> "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_1_PASSWD"
    mv "$RLCH_CIS_5_4_2_1_PASSWD" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    mkdir "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "unmatched UID-zero account shadow entry is an error, ordinary accounts need no shadow entry" {
    sed -i '/^alice:/d' "$RLCH_CIS_5_4_2_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i '2s/:1000:1000:/:0:1000:/' "$RLCH_CIS_5_4_2_1_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}
