#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_3_3_3_1_CONF="${BATS_TEST_TMPDIR}/security/pwhistory.conf"
    export RLCH_CIS_5_3_3_3_1_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export RLCH_CIS_5_3_3_3_1_AUTHSELECT="${BATS_TEST_TMPDIR}/authselect"
    export RLCH_CIS_5_3_3_3_1_STATE="${BATS_TEST_TMPDIR}/state"
    mkdir -p "${BATS_TEST_TMPDIR}/security" "$RLCH_CIS_5_3_3_3_1_PAM_DIR"
    printf '#!/bin/sh\nexit "${RLCH_TEST_AUTHSELECT_EXIT:-0}"\n' > "$RLCH_CIS_5_3_3_3_1_AUTHSELECT"
    chmod +x "$RLCH_CIS_5_3_3_3_1_AUTHSELECT"
    for file in system-auth password-auth; do
        printf 'password requisite pam_pwhistory.so use_authtok\n' > "$RLCH_CIS_5_3_3_3_1_PAM_DIR/$file"
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/1/module.sh"
}

@test "metadata is manual for two exact rules and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/3/3/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.3.3.1 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "absent, commented and below 24 fail; 24 through 400 pass unchanged" {
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    for value in 0 1 23 24 25 30 400; do
        printf '# remember = 24\nremember = %s\n' "$value" > "$RLCH_CIS_5_3_3_3_1_CONF"
        run check
        if [ "$value" -lt 24 ]; then [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]; else
            [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
            run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
            [ "$(tail -1 "$RLCH_CIS_5_3_3_3_1_CONF")" = "remember = $value" ]
        fi
    done
}

@test "negative malformed oversized and duplicate values are errors" {
    for value in -1 invalid 401 99999999999999; do
        printf 'remember = %s\n' "$value" > "$RLCH_CIS_5_3_3_3_1_CONF"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
    printf 'remember = 24\nremember = 25\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "required and requisite are accepted in both stacks" {
    printf 'remember = 24\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    sed -i 's/requisite/required/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/requisite/optional/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "inline on both stacks can comply when configuration has no remember" {
    for file in system-auth password-auth; do
        printf 'password required pam_pwhistory.so remember=30 use_authtok\n' > "$RLCH_CIS_5_3_3_3_1_PAM_DIR/$file"
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i 's/remember=30/remember=23/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "one inline stack or duplicated config and inline are not compliant" {
    sed -i 's/use_authtok/remember=24 use_authtok/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'remember = 24\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "custom conf, malformed inline and duplicate hook fail safely" {
    sed -i 's/use_authtok/conf=\/custom use_authtok/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's@conf=/custom@remember=bad@' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i 's/remember=bad/remember=24 remember=25/' "$RLCH_CIS_5_3_3_3_1_PAM_DIR/system-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'password requisite pam_pwhistory.so\n' >> "$RLCH_CIS_5_3_3_3_1_PAM_DIR/password-auth"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "authselect failure and unsafe config path prevent mutation" {
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_3_3_3_1_AUTHSELECT"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '#!/bin/sh\nexit 0\n' > "$RLCH_CIS_5_3_3_3_1_AUTHSELECT"
    ln -s /missing "$RLCH_CIS_5_3_3_3_1_CONF"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply repairs weak value, preserves other settings and metadata, rollback restores just remember" {
    printf '# keep\nremember = 23 # old\nenforce_for_root\nretry = 3\nfile = /tmp/history\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    chmod 0600 "$RLCH_CIS_5_3_3_3_1_CONF"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_3_1_CONF")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_3_3_3_1_CONF")" = "$before" ]
    printf 'other = value\n' >> "$RLCH_CIS_5_3_3_3_1_CONF"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_1_CONF")" = "$(printf '# keep\nremember = 23 # old\nenforce_for_root\nretry = 3\nfile = /tmp/history\nother = value')" ]
}

@test "rollback detects concurrent remember edit and retains state" {
    result=0; apply || result=$?
    printf 'remember = 30\n' >> "$RLCH_CIS_5_3_3_3_1_CONF"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -f "$RLCH_CIS_5_3_3_3_1_STATE/original" ]
}

@test "created file is deleted only if no independent data follows" {
    result=0; apply || result=$?
    result=0; rollback || result=$?
    [ ! -e "$RLCH_CIS_5_3_3_3_1_CONF" ]
    result=0; apply || result=$?
    printf 'enforce_for_root\n' >> "$RLCH_CIS_5_3_3_3_1_CONF"
    result=0; rollback || result=$?
    [ "$(cat "$RLCH_CIS_5_3_3_3_1_CONF")" = enforce_for_root ]
}

@test "post-write validation failure restores prior state immediately" {
    printf 'remember = 23\n' > "$RLCH_CIS_5_3_3_3_1_CONF"
    cat > "$RLCH_CIS_5_3_3_3_1_AUTHSELECT" <<'EOF'
#!/bin/sh
file="${RLCH_CIS_5_3_3_3_1_STATE}.calls"
count=0
if [ -f "$file" ]; then count="$(cat "$file")"; fi
count=$((count + 1)); printf '%s\n' "$count" > "$file"
[ "$count" -lt 2 ]
EOF
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(cat "$RLCH_CIS_5_3_3_3_1_CONF")" = 'remember = 23' ]
    [ ! -e "$RLCH_CIS_5_3_3_3_1_STATE" ]
}
