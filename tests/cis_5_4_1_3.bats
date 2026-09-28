#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_1_3_LOGIN_DEFS="${BATS_TEST_TMPDIR}/login.defs"
    export RLCH_CIS_5_4_1_3_SHADOW="${BATS_TEST_TMPDIR}/shadow"
    export RLCH_CIS_5_4_1_3_CHAGE="${BATS_TEST_TMPDIR}/chage"
    export RLCH_CIS_5_4_1_3_STATE="${BATS_TEST_TMPDIR}/state-warn"
    printf '# keep\nPASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    printf 'alice:$6$hash:20000:1:365:7:::\nlegacy:oldhash:20000:1:365:14:::\nlocked:!$6$hash:20000:1:365:0:::\nstar:*:20000:1:365:0:::\nnohash::20000:1:365:0:::\n' > "$RLCH_CIS_5_4_1_3_SHADOW"
    cat > "$RLCH_CIS_5_4_1_3_CHAGE" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == --warndays ]] || exit 2
value="$2" account="$3"
if [[ "${RLCH_TEST_FAIL_ACCOUNT:-}" == "$account" ]]; then exit 1; fi
[[ "$value" != -1 ]] || value=''
temp="${RLCH_CIS_5_4_1_3_SHADOW}.new"
awk -F: -v OFS=: -v account="$account" -v value="$value" '$1==account {$6=value; found=1} {print} END {if (!found) exit 1}' "$RLCH_CIS_5_4_1_3_SHADOW" > "$temp" || exit 1
mv "$temp" "$RLCH_CIS_5_4_1_3_SHADOW"
EOF
    chmod +x "$RLCH_CIS_5_4_1_3_CHAGE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
}

id() { if [[ "${1:-}" == -u ]]; then printf '%s\n' "${RLCH_TEST_EUID:-0}"; else command id "$@"; fi; }

@test "metadata is manual for both Level 1 OpenSCAP rules" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.1.3 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "default 7, 8 and 14 and stronger account warnings comply" {
    for value in 7 8 14 007; do
        sed -i -E "s/^PASS_WARN_AGE [0-9]+/PASS_WARN_AGE $value/" "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
}

@test "missing default, zero, one and six fail; comments do not satisfy" {
    for value in 0 1 6; do
        sed -i "s/^PASS_WARN_AGE .*/PASS_WARN_AGE $value/" "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    printf '# PASS_WARN_AGE 7\nPASS_MAX_DAYS 365\n' > "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "negative malformed duplicate and unsafe default are errors" {
    for value in -1 broken 999999999999999; do
        sed -i "s/^PASS_WARN_AGE .*/PASS_WARN_AGE $value/" "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
    printf 'PASS_WARN_AGE 7\nPASS_WARN_AGE 8\n' > "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    mv "$RLCH_CIS_5_4_1_3_LOGIN_DEFS" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "active modular and traditional hashes are covered; empty and locked are excluded" {
    sed -i '1s/:7:/:6:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '1s/:6:/:7:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    sed -i '2s/:14:/:0:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    sed -i '2s/:0:/:14:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'daemon:$6$hash:20000:0:365::::\n' >> "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "malformed active account warning is an error" {
    sed -i '1s/:7:/:bad:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply changes only warning, preserves stronger settings and rollback restores" {
    sed -i 's/PASS_WARN_AGE 7/PASS_WARN_AGE 6 # old/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    sed -i '1s/:7:/:0:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    printf 'bob:$6$hash:20000:1:365::::\n' >> "$RLCH_CIS_5_4_1_3_SHADOW"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS")"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS")" = "$before" ]
    [ "$(awk -F: '$1=="legacy" {print $6}' "$RLCH_CIS_5_4_1_3_SHADOW")" = 14 ]
    [ "$(awk -F: '$1=="locked" {print $6}' "$RLCH_CIS_5_4_1_3_SHADOW")" = 0 ]
    printf 'UMASK 077\n' >> "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    result=0; rollback || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^PASS_WARN_AGE 6 # old$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    grep -q '^PASS_MAX_DAYS 365$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    grep -q '^PASS_MIN_DAYS 1$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    grep -q '^UMASK 077$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    [ "$(awk -F: '$1=="alice" {print $6}' "$RLCH_CIS_5_4_1_3_SHADOW")" = 0 ]
    [ -z "$(awk -F: '$1=="bob" {print $6}' "$RLCH_CIS_5_4_1_3_SHADOW")" ]
}

@test "concurrent default and account changes block rollback and preserve state" {
    sed -i 's/PASS_WARN_AGE 7/PASS_WARN_AGE 0/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    sed -i '1s/:7:/:0:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    result=0; apply || result=$?
    [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    sed -i '1s/:7:/:14:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^PASS_WARN_AGE 7 # rlch' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    sed -i '1s/:14:/:7:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    sed -i 's/^PASS_WARN_AGE 7 # rlch/PASS_WARN_AGE 8 # rlch/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -d "$RLCH_CIS_5_4_1_3_STATE" ]
}

@test "failure on second account restores default and first account" {
    sed -i 's/PASS_WARN_AGE 7/PASS_WARN_AGE 0/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    sed -i '1s/:7:/:0:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    printf 'bob:$6$hash:20000:1:365:0:::\n' >> "$RLCH_CIS_5_4_1_3_SHADOW"
    export RLCH_TEST_FAIL_ACCOUNT=bob
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^PASS_WARN_AGE 0$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    [ "$(awk -F: '$1=="alice" {print $6}' "$RLCH_CIS_5_4_1_3_SHADOW")" = 0 ]
    [ ! -e "$RLCH_CIS_5_4_1_3_STATE" ]
}

@test "post-write validation failure restores original warning" {
    sed -i 's/PASS_WARN_AGE 7/PASS_WARN_AGE 0/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    eval "$(declare -f check | sed '1s/check/real_check/')"
    RLCH_TEST_CHECK_COUNT=0
    check() { RLCH_TEST_CHECK_COUNT=$((RLCH_TEST_CHECK_COUNT + 1)); if [ "$RLCH_TEST_CHECK_COUNT" -eq 2 ]; then return "$RLCH_MODULE_RESULT_ERROR"; fi; real_check; }
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^PASS_WARN_AGE 0$' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    [ ! -e "$RLCH_CIS_5_4_1_3_STATE" ]
}

@test "non-root and unsafe shadow refuse mutation" {
    sed -i 's/PASS_WARN_AGE 7/PASS_WARN_AGE 0/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    RLCH_TEST_EUID=1000
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_4_1_3_STATE" ]
    mv "$RLCH_CIS_5_4_1_3_SHADOW" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_3_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "max-age and warning-age controls apply and roll back independently" {
    RLCH_CIS_5_4_1_1_LOGIN_DEFS="$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    RLCH_CIS_5_4_1_1_SHADOW="$RLCH_CIS_5_4_1_3_SHADOW"
    RLCH_CIS_5_4_1_1_CHAGE="$BATS_TEST_TMPDIR/chage-max"
    RLCH_CIS_5_4_1_1_STATE="$BATS_TEST_TMPDIR/state-max"
    sed -i 's/PASS_MAX_DAYS 365/PASS_MAX_DAYS 99999/;s/PASS_WARN_AGE 7/PASS_WARN_AGE 0/' "$RLCH_CIS_5_4_1_3_LOGIN_DEFS"
    sed -i '1s/:365:7:/:99999:0:/' "$RLCH_CIS_5_4_1_3_SHADOW"
    sed 's/--warndays/-M/;s/\$6=/\$5=/' "$RLCH_CIS_5_4_1_3_CHAGE" > "$RLCH_CIS_5_4_1_1_CHAGE"
    chmod +x "$RLCH_CIS_5_4_1_1_CHAGE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
}
