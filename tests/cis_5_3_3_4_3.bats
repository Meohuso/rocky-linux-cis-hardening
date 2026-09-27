#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_4_3_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_4_3_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    mkdir -p "$RLCH_CIS_5_3_3_4_3_PAM_DIR"
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password sufficient pam_unix.so sha512 shadow use_authtok rounds=5000\npassword requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_4_3_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/3/module.sh"
}

@test "metadata represents two primary mappings without a synthetic rule ID" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.4.3 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "both stacks with sole sha512 comply and apply is idempotent" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    before="$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")" = "$before" ]
}

@test "either stack using sha256 violates selected sha512 tailoring" {
    for file in system-auth password-auth; do
        sed -i '1s/sha512/sha256/' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/$file"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
        sed -i '1s/sha256/sha512/' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/$file"
    done
}

@test "missing or alternative algorithms cannot satisfy tailoring" {
    for option in '' sha256 md5 yescrypt blowfish bigcrypt des gost_yescrypt; do
        printf 'password required pam_unix.so %s shadow\n' "$option" > "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
}

@test "conflicting or duplicated algorithms fail even with sha512" {
    for option in 'sha512 sha256' 'yescrypt sha512' 'sha512 sha512' 'sha512 md5'; do
        printf 'password required pam_unix.so %s shadow\n' "$option" > "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
}

@test "every relevant hook must specify sha512" {
    printf 'password required pam_unix.so sha256\n' >> "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '$d' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    printf 'password required pam_unix.so sha512\n' >> "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "comments, other modules, other PAM types and similar options do not count" {
    printf '# password sufficient pam_unix.so sha256\nauth required pam_unix.so md5\npassword required pam_pwhistory.so sha256 use_authtok\npassword required pam_other.so yescrypt\n' >> "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'password sufficient pam_unix.so sha512-ish\n' >> "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "missing hook, unsafe path and invalid authselect fail safely" {
    printf '# password sufficient pam_unix.so sha512\n' > "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    mv "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "standard and custom profiles require reviewed correction without touching other state" {
    for profile in sssd custom/site; do
        sed -i '1s/sha512/yescrypt/' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth"
        before="$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth")"
        printf 'ENCRYPT_METHOD SHA512\n' > "$BATS_TEST_TMPDIR/login.defs"
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [ "$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth")" = "$before" ]
        [ "$(cat "$BATS_TEST_TMPDIR/login.defs")" = 'ENCRYPT_METHOD SHA512' ]
        run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        sed -i '1s/yescrypt/sha512/' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/password-auth"
    done
}

@test "coexistence of nullok and remember findings never rewrites unrelated options" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/4"
    RLCH_CIS_5_3_3_4_1_AUTHSELECT="$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    RLCH_CIS_5_3_3_4_1_PAM_DIR="$RLCH_CIS_5_3_3_4_3_PAM_DIR"
    RLCH_CIS_5_3_3_4_2_AUTHSELECT="$RLCH_CIS_5_3_3_4_3_AUTHSELECT"
    RLCH_CIS_5_3_3_4_2_PAM_DIR="$RLCH_CIS_5_3_3_4_3_PAM_DIR"
    sed -i '1s/sha512/sha256 nullok remember=5/' "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth"
    original="$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")"
    source "$path/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    source "$path/2/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    source "$path/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_4_3_PAM_DIR/system-auth")" = "$original" ]
}
