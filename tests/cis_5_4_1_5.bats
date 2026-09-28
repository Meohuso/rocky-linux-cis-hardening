#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_1_5_USERADD="${BATS_TEST_TMPDIR}/useradd"
    export RLCH_CIS_5_4_1_5_SHADOW="${BATS_TEST_TMPDIR}/shadow"
    export RLCH_CIS_5_4_1_5_CHAGE="${BATS_TEST_TMPDIR}/chage"
    export RLCH_CIS_5_4_1_5_STATE="${BATS_TEST_TMPDIR}/state-inactive"
    printf '# keep\nGROUP=100\nINACTIVE=45\nSHELL=/bin/bash\n' > "$RLCH_CIS_5_4_1_5_USERADD"
    printf 'alice:$6$hash:20000:1:365:7:45::\nlegacy:oldhash:20000:1:365:7:30::\nlocked:!$6$hash:20000:1:365:7:90::\nstar:*:20000:1:365:7:90::\nnohash::20000:1:365:7:90::\n' > "$RLCH_CIS_5_4_1_5_SHADOW"
    cat > "$RLCH_CIS_5_4_1_5_CHAGE" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == --inactive ]] || exit 2
value="$2" account="$3"
if [[ "${RLCH_TEST_FAIL_ACCOUNT:-}" == "$account" ]]; then exit 1; fi
[[ "$value" != -1 ]] || value=''
temp="${RLCH_CIS_5_4_1_5_SHADOW}.new"
awk -F: -v OFS=: -v account="$account" -v value="$value" '$1==account {$7=value; found=1} {print} END {if (!found) exit 1}' "$RLCH_CIS_5_4_1_5_SHADOW" > "$temp" || exit 1
mv "$temp" "$RLCH_CIS_5_4_1_5_SHADOW"
EOF
    chmod +x "$RLCH_CIS_5_4_1_5_CHAGE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/module.sh"
}

id() { if [[ "${1:-}" == -u ]]; then printf '%s\n' "${RLCH_TEST_EUID:-0}"; else command id "$@"; fi; }

@test "metadata identifies the two-rule Level 1 control without composite rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.1.5 ]
    [ "$RLCH_MODULE_TITLE" = 'Ensure inactive password lock is configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]
    [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}

@test "default and accounts accept zero through 45 unchanged" {
    for value in 0 1 30 44 45; do
        sed -i -E "s/^INACTIVE=.*/INACTIVE=$value/" "$RLCH_CIS_5_4_1_5_USERADD"
        sed -i -E "1s/:7:[0-9]+:/:7:$value:/" "$RLCH_CIS_5_4_1_5_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
        [ ! -e "$RLCH_CIS_5_4_1_5_STATE" ]
    done
}

@test "default missing, disabled, 46 and 90 are noncompliant; comments ignored" {
    for value in -1 46 90; do
        sed -i "s/^INACTIVE=.*/INACTIVE=$value/" "$RLCH_CIS_5_4_1_5_USERADD"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    printf '# INACTIVE=45\nGROUP=100\n' > "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    [ "$(grep -c '^INACTIVE=' "$RLCH_CIS_5_4_1_5_USERADD")" -eq 0 ]
}

@test "whitespace and comment preservation; duplicate and malformed defaults error" {
    sed -i 's/^INACTIVE=45/  INACTIVE = 46 # old/' "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^  INACTIVE = 46 # old$' "$RLCH_CIS_5_4_1_5_USERADD"
    sed -i 's/^  INACTIVE.*/INACTIVE=45 # old/' "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^INACTIVE=45 # old$' "$RLCH_CIS_5_4_1_5_USERADD"
    for value in broken 9999999999999 -2; do
        sed -i "s/^INACTIVE.*/INACTIVE=$value/" "$RLCH_CIS_5_4_1_5_USERADD"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    done
    printf 'INACTIVE=45\nINACTIVE=46\n' > "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "unsafe default path, missing file and unsafe shadow are errors" {
    mv "$RLCH_CIS_5_4_1_5_USERADD" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rm "$RLCH_CIS_5_4_1_5_USERADD"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    mkdir "$RLCH_CIS_5_4_1_5_USERADD"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    rmdir "$RLCH_CIS_5_4_1_5_USERADD"
    mv "$RLCH_CIS_5_4_1_5_SHADOW" "$BATS_TEST_TMPDIR/real-shadow"
    ln -s "$BATS_TEST_TMPDIR/real-shadow" "$RLCH_CIS_5_4_1_5_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "active traditional and system accounts covered; empty and locked excluded" {
    local n=0
    for password in '!' '!!' '!*' '*' '!locked' '!$6$old'; do
        printf 'system%s:%s:20000:1:365:7:90::\n' "$n" "$password" >> "$RLCH_CIS_5_4_1_5_SHADOW"
        n=$((n + 1))
    done
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    printf 'daemon:oldhash:20000:0:365:7:90::\n' >> "$RLCH_CIS_5_4_1_5_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
}

@test "empty, minus one, 46, 90 account inactivity fails, malformed errors" {
    for value in '' -1 46 90; do
        sed -i -E "1s/:7:[^:]*:/:7:$value:/" "$RLCH_CIS_5_4_1_5_SHADOW"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_NON_COMPLIANT" ]
    done
    sed -i '1s/:7:90:/:7:broken:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    printf 'malformed:row\n' >> "$RLCH_CIS_5_4_1_5_SHADOW"
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
}

@test "apply changes only inactive and preserves stronger account, unrelated defaults and metadata" {
    sed -i 's/INACTIVE=45/INACTIVE=90 # old/' "$RLCH_CIS_5_4_1_5_USERADD"
    sed -i '1s/:7:45:/:7::/' "$RLCH_CIS_5_4_1_5_SHADOW"
    printf 'bob:$6$hash:20000:1:365:7:90::\n' >> "$RLCH_CIS_5_4_1_5_SHADOW"
    before="$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_5_USERADD")"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    [ "$(stat -c '%u:%g:%a' "$RLCH_CIS_5_4_1_5_USERADD")" = "$before" ]
    [ "$(awk -F: '$1=="legacy" {print $7}' "$RLCH_CIS_5_4_1_5_SHADOW")" = 30 ]
    printf 'SKEL=/etc/skel\n' >> "$RLCH_CIS_5_4_1_5_USERADD"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    grep -q '^INACTIVE=90 # old$' "$RLCH_CIS_5_4_1_5_USERADD"
    grep -q '^GROUP=100$' "$RLCH_CIS_5_4_1_5_USERADD"
    grep -q '^SKEL=/etc/skel$' "$RLCH_CIS_5_4_1_5_USERADD"
    [ -z "$(awk -F: '$1=="alice" {print $7}' "$RLCH_CIS_5_4_1_5_SHADOW")" ]
    [ "$(awk -F: '$1=="bob" {print $7}' "$RLCH_CIS_5_4_1_5_SHADOW")" = 90 ]
}

@test "concurrent account or default changes refuse rollback and retain state" {
    sed -i 's/INACTIVE=45/INACTIVE=90/' "$RLCH_CIS_5_4_1_5_USERADD"
    sed -i '1s/:7:45:/:7:90:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    sed -i '1s/:7:45:/:7:44:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    sed -i '1s/:7:44:/:7:45:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    sed -i 's/^INACTIVE=45$/INACTIVE=44/' "$RLCH_CIS_5_4_1_5_USERADD"
    run rollback; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ -d "$RLCH_CIS_5_4_1_5_STATE" ]
}

@test "partial chage failure immediately restores prior changes" {
    sed -i 's/INACTIVE=45/INACTIVE=-1/' "$RLCH_CIS_5_4_1_5_USERADD"
    sed -i '1s/:7:45:/:7:90:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    printf 'bob:$6$hash:20000:1:365:7:90::\n' >> "$RLCH_CIS_5_4_1_5_SHADOW"
    export RLCH_TEST_FAIL_ACCOUNT=bob
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^INACTIVE=-1$' "$RLCH_CIS_5_4_1_5_USERADD"
    [ "$(awk -F: '$1=="alice" {print $7}' "$RLCH_CIS_5_4_1_5_SHADOW")" = 90 ]
    [ ! -e "$RLCH_CIS_5_4_1_5_STATE" ]
}

@test "nonroot and post-write validation error never report partial success" {
    sed -i 's/INACTIVE=45/INACTIVE=90/' "$RLCH_CIS_5_4_1_5_USERADD"
    RLCH_TEST_EUID=1000
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    [ ! -e "$RLCH_CIS_5_4_1_5_STATE" ]
    RLCH_TEST_EUID=0
    eval "$(declare -f check | sed '1s/check/real_check/')"
    RLCH_TEST_CHECK_COUNT=0
    check() { RLCH_TEST_CHECK_COUNT=$((RLCH_TEST_CHECK_COUNT + 1)); if [ "$RLCH_TEST_CHECK_COUNT" -eq 2 ]; then return "$RLCH_MODULE_RESULT_ERROR"; fi; real_check; }
    run apply; [ "$status" -eq "$RLCH_MODULE_RESULT_ERROR" ]
    grep -q '^INACTIVE=90$' "$RLCH_CIS_5_4_1_5_USERADD"
    [ ! -e "$RLCH_CIS_5_4_1_5_STATE" ]
}

@test "max, warning, inactive and hashing defaults remain independently managed" {
    export RLCH_CIS_5_4_1_1_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    export RLCH_CIS_5_4_1_3_LOGIN_DEFS="$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    export RLCH_CIS_5_4_1_4_LOGIN_DEFS="$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    export RLCH_CIS_5_4_1_1_SHADOW="$RLCH_CIS_5_4_1_5_SHADOW"
    export RLCH_CIS_5_4_1_3_SHADOW="$RLCH_CIS_5_4_1_5_SHADOW"
    export RLCH_CIS_5_4_1_1_STATE="$BATS_TEST_TMPDIR/state-max"
    export RLCH_CIS_5_4_1_3_STATE="$BATS_TEST_TMPDIR/state-warn"
    export RLCH_CIS_5_4_1_1_CHAGE="$BATS_TEST_TMPDIR/chage-max"
    export RLCH_CIS_5_4_1_3_CHAGE="$BATS_TEST_TMPDIR/chage-warn"
    export RLCH_CIS_5_4_1_4_RPM="$BATS_TEST_TMPDIR/rpm"
    printf 'PASS_MAX_DAYS 99999\nPASS_WARN_AGE 0\nENCRYPT_METHOD SHA512\n' > "$RLCH_CIS_5_4_1_1_LOGIN_DEFS"
    printf '#!/bin/sh\nexit 1\n' > "$RLCH_CIS_5_4_1_4_RPM"
    chmod +x "$RLCH_CIS_5_4_1_4_RPM"
    sed -i 's/INACTIVE=45/INACTIVE=90/' "$RLCH_CIS_5_4_1_5_USERADD"
    sed -i '1s/:365:7:45:/:99999:0:90:/' "$RLCH_CIS_5_4_1_5_SHADOW"
    sed 's/--inactive/-M/;s/\$7=/\$5=/' "$RLCH_CIS_5_4_1_5_CHAGE" > "$RLCH_CIS_5_4_1_1_CHAGE"
    sed 's/--inactive/--warndays/;s/\$7=/\$6=/' "$RLCH_CIS_5_4_1_5_CHAGE" > "$RLCH_CIS_5_4_1_3_CHAGE"
    chmod +x "$RLCH_CIS_5_4_1_1_CHAGE" "$RLCH_CIS_5_4_1_3_CHAGE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    for section in 1 3 5 4; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/$section/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    for section in 1 3 4; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/$section/module.sh"
        run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    done
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/module.sh"
    result=0; apply || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/1/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/3/module.sh"
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/1/5/module.sh"
    run check; [ "$status" -eq "$RLCH_MODULE_RESULT_SUCCESS" ]
    result=0; rollback || result=$?; [ "$result" -eq "$RLCH_MODULE_RESULT_CHANGED" ]
}
