#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_1_1_LOGIN_DEFS="${BATS_TEST_TMPDIR}/login.defs"
    export RLCH_CIS_5_4_1_1_SHADOW="${BATS_TEST_TMPDIR}/shadow"
    export RLCH_CIS_5_4_1_1_CHAGE="${BATS_TEST_TMPDIR}/chage"
    export RLCH_CIS_5_4_1_1_STATE="${BATS_TEST_TMPDIR}/state"
    printf '# keep\nPASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    printf 'alice:$6$hash:20000:0:365:7:::\nlocked:!$6$hash:20000:0:99999:0:::\nnohash::20000:0:99999:0:::\n' > "$RLCH_CIS_5_4_1_1_SHADOW"
    cat > "$RLCH_CIS_5_4_1_1_CHAGE" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == -M ]] || exit 2
value="$2" account="$3"
if [[ "${RLCH_TEST_FAIL_ACCOUNT:-}" == "$account" ]]; then exit 1; fi
[[ "$value" != -1 ]] || value=''
temp="${RLCH_CIS_5_4_1_1_SHADOW}.new"
awk -F: -v OFS=: -v account="$account" -v value="$value" '$1==account {$5=value; found=1} {print} END {if (!found) exit 1}' "$RLCH_CIS_5_4_1_1_SHADOW" > "$temp" || exit 1
mv "$temp" "$RLCH_CIS_5_4_1_1_SHADOW"
EOF
    chmod +x "$RLCH_CIS_5_4_1_1_CHAGE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
}

id() {
    if [[ "${1:-}" == -u ]]; then printf '%s\n' "${RLCH_TEST_EUID:-0}"
    else command id "$@"; fi
}

@test "metadata records composite Level 1 mapping" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.1.1 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "compliant maximums including zero and more restrictive values are untouched" {
    for value in 0 1 30 60 90 365 009; do
        sed -i -E "s/^PASS_MAX_DAYS [0-9]+/PASS_MAX_DAYS $value/" "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
}

@test "missing and excessive default age and existing account are noncompliant" {
    sed -i '/^PASS_MAX_DAYS/d' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'PASS_MAX_DAYS 366\n' >> "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '1s/:365:/:99999:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "active account empty age fails; locked and passwordless accounts are excluded" {
    sed -i '1s/:365:/: :/' "$RLCH_CIS_5_4_1_1_SHADOW"
    sed -i '1s/: :/::/' "$RLCH_CIS_5_4_1_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    printf 'alice:$6$hash:20000:0:365:7:::\nlocked:!$6$hash:20000:0:99999:0:::\nnohash::20000:0:99999:0:::\n' > "$RLCH_CIS_5_4_1_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
}

@test "invalid negative nonnumeric duplicate and oversized values are errors" {
    for value in -1 bad 999999999999999; do
        sed -i "s/^PASS_MAX_DAYS .*/PASS_MAX_DAYS $value/" "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
    printf 'PASS_MAX_DAYS 365\nPASS_MAX_DAYS 365\n' > "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf '# PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 365\n' > "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    sed -i '1s/:365:/:bad:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply changes only default and selected accounts, then rollback restores them" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999 # old/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    sed -i '1s/:365:/:99999:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    printf 'bob:$6$hash:20000:0::7:::\n' >> "$RLCH_CIS_5_4_1_1_SHADOW"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS")" = "$before" ]
    [ "$(awk -F: '$1=="locked" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" = 99999 ]
    [ "$(awk -F: '$1=="nohash" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" = 99999 ]
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(awk -F: '$1=="alice" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" = 99999 ]
    [ -z "$(awk -F: '$1=="bob" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" ]
    [ "$(sed -n '2p' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS")" = 'PASS_MAX_DAYS 99999 # old' ]
    [ ! -e "$RLCH_CIS_5_4_1_1_STATE" ]
}

@test "rollback preserves independent login.defs edits and refuses managed property edit" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    printf 'UMASK 077\n' >> "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    sed -i 's/^PASS_MAX_DAYS 365 # rlch/PASS_MAX_DAYS 30 # rlch/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -d "$RLCH_CIS_5_4_1_1_STATE" ]
    sed -i 's/^PASS_MAX_DAYS 30 # rlch/PASS_MAX_DAYS 365 # rlch/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^UMASK 077$' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
}

@test "rollback refuses a concurrent account maximum change without undoing default" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    sed -i '1s/:365:/:99999:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    sed -i '1s/:365:/:30:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^PASS_MAX_DAYS 365 # rlch-cis-5.4.1.1$' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
}

@test "failure on second account rolls back prior changes and leaves no state" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    sed -i '1s/:365:/:99999:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    printf 'bob:$6$hash:20000:0:99999:7:::\n' >> "$RLCH_CIS_5_4_1_1_SHADOW"
    export RLCH_TEST_FAIL_ACCOUNT=bob
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ "$(awk -F: '$1=="alice" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" = 99999 ]
    grep -q '^PASS_MAX_DAYS 99999$' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    [ ! -e "$RLCH_CIS_5_4_1_1_STATE" ]
}

@test "failed post-write validation immediately restores both properties" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    sed -i '1s/:365:/:99999:/' "$RLCH_CIS_5_4_1_1_SHADOW"
    eval "$(declare -f check | sed '1s/check/real_check/')"
    RLCH_TEST_CHECK_COUNT=0
    check() {
        RLCH_TEST_CHECK_COUNT=$((RLCH_TEST_CHECK_COUNT + 1))
        if [ "$RLCH_TEST_CHECK_COUNT" -eq 2 ]; then return "$RLCH_MODULE_RESULT_ERROR"; fi
        real_check
    }
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^PASS_MAX_DAYS 99999$' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    [ "$(awk -F: '$1=="alice" {print $5}' "$RLCH_CIS_5_4_1_1_SHADOW")" = 99999 ]
    [ ! -e "$RLCH_CIS_5_4_1_1_STATE" ]
}

@test "unsafe paths fail without changes" {
    mv "$RLCH_CIS_5_4_1_1_SHADOW" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_1_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply refuses non-root without creating state" {
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    RLCH_TEST_EUID=1000
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_4_1_1_STATE" ]
    grep -q '^PASS_MAX_DAYS 99999$' "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
}
