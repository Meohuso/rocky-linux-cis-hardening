#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_1_6_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_5_4_1_6_DATE="$BATS_TEST_TMPDIR/date"
    printf 'root:$6$hash:20000:0:365:7:45::\nsystem:oldhash:20001:0:365:7:45::\n' > "$RLCH_CIS_5_4_1_6_SHADOW"
    # Fixed epoch: midnight of day 20001, plus one second.
    printf '#!/bin/sh\n[ "$1" = +%%s ] || exit 2\necho 1728086401\n' > "$RLCH_CIS_5_4_1_6_DATE"
    chmod +x "$RLCH_CIS_5_4_1_6_DATE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/6/module.sh"
}

@test "metadata maps the sole exact Level 1 OpenSCAP rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/6/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.1.6 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure all users last password change date is in the past' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past ]
}

@test "yesterday today and epoch day zero comply at day boundary" {
    for day in 0 19999 20000 20001; do
        sed -i -E "1s/:[0-9]+:0:365:/:$day:0:365:/" "$RLCH_CIS_5_4_1_6_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
}

@test "tomorrow and distant future are noncompliant; diagnostic only names accounts" {
    for day in 20002 900000; do
        sed -i -E "1s/:[0-9]+:0:365:/:$day:0:365:/" "$RLCH_CIS_5_4_1_6_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        [[ "$output" == *'root: last password change date is in the future'* ]]
        [[ "$output" != *'$6$hash'* ]]
    done
}

@test "multiple users, including system accounts, are checked without passwd shell filter" {
    printf 'daemon:oldhash:20002:0:365:7:45::\nother:$y$hash:20003:0:365:7:45::\n' >> "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *daemon* && "$output" == *other* ]]
    [[ "$output" != *root* ]]
}

@test "OVAL excludes exactly five password values, but not empty or !hash" {
    local n=0
    for value in '!' '!!' '!*' '*' '!locked'; do
        printf 'locked%s:%s:20002:0:365:7:45::\n' "$n" "$value" >> "$RLCH_CIS_5_4_1_6_SHADOW"
        n=$((n + 1))
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'empty::20002:0:365:7:45::\n' >> "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *empty* && "$output" != *locked0* ]]
    sed -i '/^empty:/d' "$RLCH_CIS_5_4_1_6_SHADOW"
    printf 'prefixed:!$6$hash:20002:0:365:7:45::\n' >> "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [[ "$output" == *prefixed* ]]
}

@test "empty negative malformed and overflowing change days are errors" {
    for day in '' -1 junk 99999999999; do
        sed -i -E "1s/:[^:]*:0:365:/:$day:0:365:/" "$RLCH_CIS_5_4_1_6_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
}

@test "malformed duplicate and unsafe shadow or date source are errors" {
    printf 'bad:row\n' >> "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_1_6_SHADOW"
    printf 'root:$6$other:20000:0:365:7:45::\n' >> "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_4_1_6_SHADOW"
    mv "$RLCH_CIS_5_4_1_6_SHADOW" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_4_1_6_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\necho invalid\n' > "$RLCH_CIS_5_4_1_6_DATE"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "compliant apply validate rollback are all read-only and idempotent" {
    before="$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW")"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW")" = "$before" ]
    [ ! -e "$BATS_TEST_TMPDIR/state" ]
}

@test "future date apply refuses auto-remediation without shadow mutation or state" {
    sed -i '1s/:20000:/:20002:/' "$RLCH_CIS_5_4_1_6_SHADOW"
    before="$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'manual remediation required'* ]]
    [ "$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW")" = "$before" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW")" = "$before" ]
}

@test "other password-aging controls and hashing defaults remain unchanged by observation" {
    export RLCH_CIS_5_4_1_1_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    export RLCH_CIS_5_4_1_3_LOGIN_DEFS="$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    export RLCH_CIS_5_4_1_4_LOGIN_DEFS="$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    export RLCH_CIS_5_4_1_1_SHADOW="$RLCH_CIS_5_4_1_6_SHADOW"
    export RLCH_CIS_5_4_1_3_SHADOW="$RLCH_CIS_5_4_1_6_SHADOW"
    export RLCH_CIS_5_4_1_5_SHADOW="$RLCH_CIS_5_4_1_6_SHADOW"
    export RLCH_CIS_5_4_1_5_USERADD="$BATS_TEST_TMPDIR/useradd"
    export RLCH_CIS_5_4_1_4_RPM="$BATS_TEST_TMPDIR/rpm"
    printf 'PASS_MAX_DAYS 365\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    printf 'INACTIVE=45\n' > "$RLCH_CIS_5_4_1_5_USERADD"
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_4_1_4_RPM"
    chmod +x "$RLCH_CIS_5_4_1_4_RPM"
    before="$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW" "$RLCH_CIS_5_4_1_1_LOGIN_DEFS" "$RLCH_CIS_5_4_1_5_USERADD")"
    for section in 1 3 4 5; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/$section/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/6/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(sha256sum "$RLCH_CIS_5_4_1_6_SHADOW" "$RLCH_CIS_5_4_1_1_LOGIN_DEFS" "$RLCH_CIS_5_4_1_5_USERADD")" = "$before" ]
}
