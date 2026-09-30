#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_3_GROUP="$BATS_TEST_TMPDIR/group"
    printf 'root:x:0:\nusers:x:100:\n' > "$RLCH_CIS_5_4_2_3_GROUP"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/3/module.sh"
}

@test "metadata declares exact Level 1 rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.3 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure group root is the only GID 0 group' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_groups_no_zero_gid_except_root ]
}

@test "root only GID zero succeeds with no mutation" {
    before="$(sha256sum "$RLCH_CIS_5_4_2_3_GROUP")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_3_GROUP")" = "$before" ]
}

@test "root nonzero GID is noncompliant; missing root is an error" {
    sed -i '1s/:0:/:10:/' "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '1d' "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "other GID zero and multiple groups fail; name rootlike is not root" {
    printf 'rootlike:x:0:\nother:x:000:\n' >> "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *rootlike* && "$output" == *other* ]]
    before="$(sha256sum "$RLCH_CIS_5_4_2_3_GROUP")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'manually'* ]]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_3_GROUP")" = "$before" ]
}

@test "malformed, duplicate and invalid GID entries are errors" {
    printf 'bad:row\n' >> "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_3_GROUP"
    printf 'root:x:0:\n' >> "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_2_3_GROUP"
    sed -i '2s/:100:/:bogus:/' "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "missing, symlinked and nonregular group file are errors" {
    mv "$RLCH_CIS_5_4_2_3_GROUP" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_4_2_3_GROUP"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    mkdir "$RLCH_CIS_5_4_2_3_GROUP"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}
