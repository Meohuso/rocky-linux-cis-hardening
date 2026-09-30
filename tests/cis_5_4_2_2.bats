#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_2_PASSWD="$BATS_TEST_TMPDIR/passwd"
    printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > "$RLCH_CIS_5_4_2_2_PASSWD"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/2/module.sh"
}

@test "metadata identifies the exact RHEL9 rule and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.2 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure root is the only GID 0 account' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_root_gid_zero ]
}

@test "root GID zero and unrelated accounts comply without mutation" {
    before="$(sha256sum "$RLCH_CIS_5_4_2_2_PASSWD")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_2_PASSWD")" = "$before" ]
}

@test "root primary GID nonzero fails; missing root is error" {
    sed -i '1s/:0:0:/:0:1:/' "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '1d' "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "other accounts with primary GID zero fail even when their UID is nonzero" {
    sed -i '2s/:1000:1000:/:1000:0:/' "$RLCH_CIS_5_4_2_2_PASSWD"
    before="$(sha256sum "$RLCH_CIS_5_4_2_2_PASSWD")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *alice* ]]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'manually'* ]]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_2_PASSWD")" = "$before" ]
}

@test "RHEL OVAL excludes exactly sync shutdown halt operator" {
    for account in sync shutdown halt operator; do
        printf '%s:x:1:0::/nonexistent:/sbin/nologin\n' "$account" >> "$RLCH_CIS_5_4_2_2_PASSWD"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'operators:x:1:0::/nonexistent:/sbin/nologin\n' >> "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *operators* && "$output" != *'operator has'* ]]
}

@test "multiple offenders, leading zeros and UID-zero distinction" {
    printf 'bob:x:0:000::/home/bob:/bin/bash\ncarol:x:2000:0::/home/carol:/bin/bash\n' >> "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *bob* && "$output" == *carol* ]]
    sed -i 's/^bob:x:0:000:/bob:x:0:1:/' "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" != *bob* ]]
}

@test "malformed and duplicate entries return error" {
    printf 'bad:row\n' >> "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_2_PASSWD"
    printf 'alice:x:2000:0::/home/alice:/bin/bash\n' >> "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_2_PASSWD"
    sed -i '2s/:1000:1000:/:bad:0:/' "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "unsafe and missing passwd paths return error" {
    mv "$RLCH_CIS_5_4_2_2_PASSWD" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_4_2_2_PASSWD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    mkdir "$RLCH_CIS_5_4_2_2_PASSWD"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}
