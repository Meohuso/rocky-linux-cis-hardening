#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_4_2_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_4_2_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    mkdir -p "$RLCH_CIS_5_3_3_4_2_PAM_DIR"
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password sufficient pam_unix.so sha512 shadow use_authtok\npassword requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_4_2_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/2/module.sh"
}

@test "metadata has exact Level 1 OpenSCAP mapping" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.4.2 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_no_remember ]
}

@test "clean pam_unix stacks comply without changing pam_pwhistory" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "all present remember numeric values on pam_unix fail including zero" {
    for value in 0 1 5 24 400; do
        printf 'password sufficient pam_unix.so sha512 remember=%s use_authtok\n' "$value" >> "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        sed -i '$d' "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
    done
}

@test "second applicable hook and password-auth cannot hide remember" {
    printf 'password required pam_unix.so remember=24\n' >> "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    before="$(cat "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth")" = "$before" ]
}

@test "malformed and duplicate remember options are ERROR" {
    for option in remember=bad remember=-1 remember= remember=999999999999 'remember=5 remember=24'; do
        printf 'password required pam_unix.so %s\n' "$option" >> "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        sed -i '$d' "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
    done
}

@test "comments, similar tokens, other modules and PAM types are distinct" {
    printf '# password required pam_unix.so remember=5\npassword required pam_unix.so remembered=5 # remember=24\nauth required pam_unix.so remember=5\npassword required pam_pwhistory.so remember=24\n' >> "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "authselect failure and unsafe path prevent mutation" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    mv "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_3_3_4_2_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "remediation requires reviewed standard or custom authselect profile" {
    for profile in sssd custom/site; do
        printf '#!/bin/sh\n[ "$1" = check ]\n' > "$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
        printf 'password requisite pam_unix.so remember=5 sha512 shadow use_authtok\n' >> "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth"
        before="$(cat "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth")"
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [ "$(cat "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth")" = "$before" ]
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        sed -i '$d' "$RLCH_CIS_5_3_3_4_2_PAM_DIR/password-auth"
    done
}

@test "independence from nullok and pwhistory remember configuration" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4"
    RLCH_CIS_5_3_3_4_1_AUTHSELECT="$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    RLCH_CIS_5_3_3_4_1_PAM_DIR="$RLCH_CIS_5_3_3_4_2_PAM_DIR"
    mkdir -p "${BATS_TEST_TMPDIR}/security"
    RLCH_CIS_5_3_3_3_1_CONF="${BATS_TEST_TMPDIR}/security/pwhistory.conf"
    RLCH_CIS_5_3_3_3_1_PAM_DIR="$RLCH_CIS_5_3_3_4_2_PAM_DIR"
    RLCH_CIS_5_3_3_3_1_AUTHSELECT="$RLCH_CIS_5_3_3_4_2_AUTHSELECT"
    printf 'remember = 24\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    source "$path/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "$path/2/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_1_CONF")" = 'remember = 24' ]
}
