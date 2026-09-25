#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_TEST_RPM_LOG="${BATS_TEST_TMPDIR}/rpm.log"
    export RLCH_TEST_DNF_LOG="${BATS_TEST_TMPDIR}/dnf.log"
    export RLCH_CIS_5_3_1_1_RPM="${BATS_TEST_TMPDIR}/rpm"
    export RLCH_CIS_5_3_1_1_DNF="${BATS_TEST_TMPDIR}/dnf5"
    cat > "${RLCH_CIS_5_3_1_1_RPM}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RLCH_TEST_RPM_LOG"
exit "${RLCH_TEST_RPM_EXIT:-0}"
EOF
    cat > "${RLCH_CIS_5_3_1_1_DNF}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$RLCH_TEST_DNF_LOG"
if [[ " $* " == *' repoquery '* ]]; then
    [[ "${RLCH_TEST_DNF_EXIT:-0}" == 0 ]] || exit "$RLCH_TEST_DNF_EXIT"
    printf '%s\n' "${RLCH_TEST_DNF_AVAILABLE-pam}"
    exit 0
fi
exit "${RLCH_TEST_DNF_CHECK_EXIT:-0}"
EOF
    chmod +x "${RLCH_CIS_5_3_1_1_RPM}" "${RLCH_CIS_5_3_1_1_DNF}"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/1/1/module.sh"
}

@test "installed current PAM is compliant after a refreshed repository check" {
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(cat "$RLCH_TEST_RPM_LOG")" = '-q pam' ]
    [ "$(cat "$RLCH_TEST_DNF_LOG")" = $'--refresh --setopt=skip_if_unavailable=False repoquery --available --queryformat=%{name} pam\n--refresh --setopt=skip_if_unavailable=False check-upgrade pam' ]
}

@test "absent PAM is noncompliant without querying repositories" {
    export RLCH_TEST_RPM_EXIT=1
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    [ ! -e "$RLCH_TEST_DNF_LOG" ]
}

@test "an available PAM update is noncompliant" {
    export RLCH_TEST_DNF_CHECK_EXIT=100
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "unavailable repositories produce an error rather than a false compliant result" {
    export RLCH_TEST_DNF_EXIT=1
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "no PAM in enabled repositories cannot prove latest version" {
    export RLCH_TEST_DNF_AVAILABLE=''
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(wc -l < "$RLCH_TEST_DNF_LOG")" -eq 1 ]
}

@test "other DNF errors also produce an error" {
    export RLCH_TEST_DNF_EXIT=4
    run check
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "compliant apply is idempotent and starts no transaction" {
    run apply
    [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(wc -l < "$RLCH_TEST_DNF_LOG")" -eq 2 ]
}

@test "apply refuses an upgrade without a safe system rollback" {
    export RLCH_TEST_DNF_CHECK_EXIT=100
    run apply
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [[ "$output" == *'system snapshot and recovery path'* ]]
    [ "$(wc -l < "$RLCH_TEST_DNF_LOG")" -eq 2 ]
}

@test "apply refuses to install absent PAM automatically" {
    export RLCH_TEST_RPM_EXIT=1
    run apply
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_TEST_DNF_LOG" ]
}

@test "apply propagates repository errors without a transaction" {
    export RLCH_TEST_DNF_EXIT=1
    run apply
    [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(wc -l < "$RLCH_TEST_DNF_LOG")" -eq 1 ]
}

@test "validate checks freshness and rollback makes no package changes" {
    export RLCH_TEST_DNF_CHECK_EXIT=100
    run validate; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(wc -l < "$RLCH_TEST_DNF_LOG")" -eq 2 ]
}

@test "metadata is Level 1 and manual because ComplianceAsCode has no exact rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/3/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.3.1.1 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
