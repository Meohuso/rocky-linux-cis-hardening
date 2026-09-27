#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_4_1_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_4_1_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    mkdir -p "$RLCH_CIS_5_3_3_4_1_PAM_DIR"
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_1_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_4_1_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'auth sufficient pam_unix.so try_first_pass\npassword sufficient pam_unix.so sha512 shadow use_authtok\n' > "$RLCH_CIS_5_3_3_4_1_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/1/module.sh"
}

@test "metadata has exact Level 1 no_empty_passwords rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.4.1 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_no_empty_passwords ]
}

@test "both clean stacks comply without mutation" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "nullok in system-auth auth or password hook is noncompliant" {
    for line in 'auth sufficient pam_unix.so nullok try_first_pass' 'password requisite pam_unix.so sha512 nullok shadow'; do
        printf '%s\n' "$line" >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        sed -i '$d' "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    done
}

@test "nullok in password-auth and a second applicable hook cannot be hidden" {
    printf 'password required pam_unix.so nullok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(tail -1 "$RLCH_CIS_5_3_3_4_1_PAM_DIR/password-auth")" = 'password required pam_unix.so nullok' ]
}

@test "comment, inline comment and token containing nullok are not the exact option" {
    printf '# password required pam_unix.so nullok\npassword required pam_unix.so nullok_secure # nullok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "CAS rule also flags exact nullok on another active PAM module" {
    printf 'auth required pam_example.so nullok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "extended PAM control syntax is parsed and relevant nullok detected" {
    printf ' auth [success=1 default=bad] pam_unix.so try_first_pass nullok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "unsafe syntax, symlink and invalid authselect return ERROR" {
    printf 'auth required nullok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '$d' "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_4_1_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_1_AUTHSELECT"
    mv "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "standard or custom profile needs reviewed source correction; no rollback state" {
    for profile in sssd custom/site; do
        printf '#!/bin/sh\n[ "$1" = check ]\n' > "$RLCH_CIS_5_3_3_4_1_AUTHSELECT"
        printf 'password required pam_unix.so shadow nullok sha512 use_authtok\n' >> "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
        before="$(cat "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth")"
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [ "$(cat "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth")" = "$before" ]
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        sed -i '$d' "$RLCH_CIS_5_3_3_4_1_PAM_DIR/system-auth"
    done
}
