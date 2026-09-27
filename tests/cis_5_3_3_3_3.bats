#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_3_3_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_3_3_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    mkdir -p "$RLCH_CIS_5_3_3_3_3_PAM_DIR"
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/3/module.sh"
}

@test "metadata uses manual for RHEL9 partial control without exact primary rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.3.3 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "both system-auth and password-auth comply with exact use_authtok" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "required and requisite control flags are both valid" {
    sed -i 's/requisite/required/' "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/requisite/optional/' "$RLCH_CIS_5_3_3_3_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "missing option in either or both stacks is NON_COMPLIANT" {
    sed -i 's/ use_authtok//' "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i 's/ use_authtok//' "$RLCH_CIS_5_3_3_3_3_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth")" = 'password requisite pam_pwhistory.so' ]
}

@test "use_authok typo and forms with values are not accepted" {
    for option in use_authok use_authtok=1 use_authtok=0 use_authok=1; do
        printf 'password requisite pam_pwhistory.so %s\n' "$option" > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
}

@test "duplicate, partial token and wrong module do not satisfy the hook" {
    printf 'password requisite pam_pwhistory.so use_authtok use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'password requisite pam_pwhistory.so use_auth\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'password requisite pam_pwhistory.so\npassword required pam_unix.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "commented, wrong PAM type and multiple hooks cannot masquerade as compliance" {
    printf '# password requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'auth requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'password requisite pam_pwhistory.so use_authtok\npassword required pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "authselect invalid or unsafe symlink is ERROR without mutation" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    mv "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "standard and custom authselect profiles are inspected, never edited" {
    for profile in sssd custom/site; do
        cat > "$RLCH_CIS_5_3_3_3_3_AUTHSELECT" <<EOF
#!/bin/sh
[ "\$1" = check ] && [ -n "$profile" ]
EOF
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        sed -i 's/ use_authtok//' "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
        before="$(cat "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth")"
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        [ "$(cat "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth")" = "$before" ]
        printf 'password requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_3_PAM_DIR/system-auth"
    done
}

@test "pwhistory enablement and both previous history properties remain intact" {
    local path="${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3" control
    export RLCH_CIS_5_3_3_3_1_CONF="${BATS_TEST_TMPDIR}/security/pwhistory.conf"
    export RLCH_CIS_5_3_3_3_1_PAM_DIR="$RLCH_CIS_5_3_3_3_3_PAM_DIR"
    export RLCH_CIS_5_3_3_3_1_AUTHSELECT="$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    export RLCH_CIS_5_3_3_3_1_STATE="${BATS_TEST_TMPDIR}/state-1"
    export RLCH_CIS_5_3_3_3_2_CONF="$RLCH_CIS_5_3_3_3_1_CONF"
    export RLCH_CIS_5_3_3_3_2_PAM_DIR="$RLCH_CIS_5_3_3_3_3_PAM_DIR"
    export RLCH_CIS_5_3_3_3_2_AUTHSELECT="$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    export RLCH_CIS_5_3_3_3_2_STATE="${BATS_TEST_TMPDIR}/state-2"
    mkdir -p "${BATS_TEST_TMPDIR}/security"
    for control in 1 2; do
        source "$path/$control/module.sh"
        result=0; apply || result=$?
        [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    done
    RLCH_CIS_5_3_2_4_PAM_DIR="$RLCH_CIS_5_3_3_3_3_PAM_DIR"
    RLCH_CIS_5_3_2_4_AUTHSELECT="$RLCH_CIS_5_3_3_3_3_AUTHSELECT"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/2/4/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    for control in 1 2 3; do
        source "$path/$control/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "$path/2/module.sh"
    result=0; rollback || result=$?
    source "$path/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "$path/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "$path/2/module.sh"
    result=0; apply || result=$?
    source "$path/1/module.sh"
    result=0; rollback || result=$?
    source "$path/2/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "$path/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}
