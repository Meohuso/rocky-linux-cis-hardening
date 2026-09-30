#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/5/module.sh"
    mkdir -p "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/sbin"
    chmod 755 "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/sbin"
    test_path="$BATS_TEST_TMPDIR/bin:$BATS_TEST_TMPDIR/sbin"
    # CI runs as an ordinary user. Substitute only observed UID; preserve actual
    # filesystem metadata and permissions. Production helpers use trusted paths.
    rlch_5_4_2_5_uid() { printf '0\n'; }
    rlch_5_4_2_5_stat() {
        local info device inode owner mode rest
        info="$(/usr/bin/stat -L -c '%d:%i:%u:%a:%f:%y:%z' -- "$1")" || return 2
        IFS=: read -r device inode owner mode rest <<< "$info"
        owner=0
        [[ "${wrong_owner:-}" != "$1" ]] || owner=1000
        printf '%s:%s:%s:%s:%s\n' "$device" "$inode" "$owner" "$mode" "$rest"
    }
}
with_test_path() { local PATH="$test_path"; "$@"; }

@test "5.4.2.5 metadata uses manual four-rule Level 1 mapping" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/5/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.5 ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "normal absolute root PATH and duplicate components succeed" {
    run with_test_path check; [ "$status" -eq 0 ]
    test_path="$test_path:$BATS_TEST_TMPDIR/bin"
    run with_test_path validate; [ "$status" -eq 0 ]
    run with_test_path apply; [ "$status" -eq 0 ]
}
@test "dot and relative components fail without executing entries" {
    for entry in . ./bin bin ../bin; do
        test_path="$BATS_TEST_TMPDIR/bin:$entry"
        run with_test_path check; [ "$status" -eq 1 ]
    done
}
@test "empty PATH initial final and doubled colon fail" {
    for value in '' ":$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/bin:" "$BATS_TEST_TMPDIR/bin::$BATS_TEST_TMPDIR/sbin" ':'; do
        test_path="$value"
        run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'empty component'* ]]
    done
}
@test "CAS double periods and final period are rejected even in absolute names" {
    mkdir "$BATS_TEST_TMPDIR/bin..name" "$BATS_TEST_TMPDIR/bin."
    for entry in "$BATS_TEST_TMPDIR/bin..name" "$BATS_TEST_TMPDIR/bin." "$BATS_TEST_TMPDIR/bin/../sbin"; do
        test_path="$entry"
        run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'period pattern'* ]]
    done
}
@test "missing directory and regular file are noncompliant" {
    test_path="$BATS_TEST_TMPDIR/missing/child"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'does not exist'* ]]
    touch "$BATS_TEST_TMPDIR/file"
    test_path="$BATS_TEST_TMPDIR/file"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'not a directory'* ]]
}
@test "non-root owner group-write and world-write fail independently" {
    wrong_owner="$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'not owned by root'* ]]
    unset wrong_owner
    chmod 775 "$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *group-writable* ]]
    chmod 757 "$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *world-writable* ]]
    chmod 700 "$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 0 ]
}
@test "all simultaneous anomalies are diagnosed by index without raw PATH" {
    wrong_owner="$BATS_TEST_TMPDIR/bin"
    chmod 777 "$BATS_TEST_TMPDIR/bin"
    test_path=".:$BATS_TEST_TMPDIR/bin::$BATS_TEST_TMPDIR/SECRET"
    run with_test_path check; [ "$status" -eq 1 ]
    [[ "$output" == *'dot denotes'* && "$output" == *group-writable* && "$output" == *world-writable* && "$output" == *'not owned by root'* && "$output" == *'empty component'* && "$output" == *'does not exist'* ]]
    [[ "$output" != *SECRET* && "$output" != *"$BATS_TEST_TMPDIR"* ]]
}
@test "safe symlink target passes unsafe target fails dangling or file target fails" {
    ln -s "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/link"
    test_path="$BATS_TEST_TMPDIR/link"
    run with_test_path check; [ "$status" -eq 0 ]
    chmod 777 "$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 1 ]
    chmod 755 "$BATS_TEST_TMPDIR/bin"
    wrong_owner="$BATS_TEST_TMPDIR/link"
    run with_test_path check; [ "$status" -eq 1 ]
    unset wrong_owner
    rm "$BATS_TEST_TMPDIR/link"
    ln -s "$BATS_TEST_TMPDIR/absent" "$BATS_TEST_TMPDIR/link"
    run with_test_path check; [ "$status" -eq 1 ]
    rm "$BATS_TEST_TMPDIR/link"
    touch "$BATS_TEST_TMPDIR/file"
    ln -s "$BATS_TEST_TMPDIR/file" "$BATS_TEST_TMPDIR/link"
    run with_test_path check; [ "$status" -eq 1 ]
}
@test "spaces glob shell characters backslash and newline remain literal without disclosure" {
    unusual="$BATS_TEST_TMPDIR/SECRET space * [x] \$(touch SHOULD_NOT_EXIST) \\ line"$'\n'"suffix"
    mkdir "$unusual"
    chmod 755 "$unusual"
    test_path="$unusual:$BATS_TEST_TMPDIR/bin"
    run with_test_path check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    chmod 777 "$unusual"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" != *SECRET* && "$output" != *suffix* ]]
    [ ! -e SHOULD_NOT_EXIST ]
}
@test "backslash before delimiter cannot hide relative component" {
    mkdir "$BATS_TEST_TMPDIR/bin\\"
    chmod 755 "$BATS_TEST_TMPDIR/bin\\"
    test_path="$BATS_TEST_TMPDIR/bin\\:relativeSECRET"
    run with_test_path check; [ "$status" -eq 1 ]; [[ "$output" == *'relative path'* && "$output" != *SECRET* ]]
}
@test "non-root invocation and unavailable PATH return error" {
    rlch_5_4_2_5_uid() { printf '1000\n'; }
    run with_test_path check; [ "$status" -eq 2 ]
    rlch_5_4_2_5_uid() { printf '0\n'; }
    without_path() { unset PATH; check; }
    run without_path; [ "$status" -eq 2 ]
}
@test "inspection errors take precedence over readable noncompliance" {
    rlch_5_4_2_5_stat() { return 2; }
    test_path=".:$BATS_TEST_TMPDIR/bin:$BATS_TEST_TMPDIR/missing"
    run with_test_path check; [ "$status" -eq 2 ]; [[ "$output" == *'cannot safely inspect'* ]]
    run with_test_path apply; [ "$status" -eq 2 ]
}
@test "concurrent directory metadata change is error" {
    rlch_5_4_2_5_stat() {
        /usr/bin/stat -L -c '%d:%i:0:%a:%f:%y:%z' -- "$1"
        /usr/bin/chmod 777 "$1"
    }
    run with_test_path check; [ "$status" -eq 2 ]; [[ "$output" == *'changed during inspection'* ]]
}
@test "concurrent symlink retarget is error" {
    ln -s "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/link"
    test_path="$BATS_TEST_TMPDIR/link"
    rlch_5_4_2_5_realpath() {
        /usr/bin/realpath -e -- "$1"
        /usr/bin/ln -sfn "$BATS_TEST_TMPDIR/sbin" "$BATS_TEST_TMPDIR/link"
    }
    run with_test_path check; [ "$status" -eq 2 ]
}
@test "observation-only apply and rollback do not change any fixture or create state" {
    printf 'profile SECRET\n' > "$BATS_TEST_TMPDIR/profile"
    before="$(find "$BATS_TEST_TMPDIR" -printf '%P %u %g %m %l\n' | sort)"
    checksum="$(sha256sum "$BATS_TEST_TMPDIR/profile")"
    run with_test_path apply; [ "$status" -eq 0 ]
    test_path=".:$test_path"
    run with_test_path apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation'* ]]
    run rollback; [ "$status" -eq 0 ]
    [ "$(find "$BATS_TEST_TMPDIR" -printf '%P %u %g %m %l\n' | sort)" = "$before" ]
    [ "$(sha256sum "$BATS_TEST_TMPDIR/profile")" = "$checksum" ]
}
@test "inspection uses trusted utilities even if PATH contains malicious executables" {
    for tool in id stat realpath; do
        printf '#!/bin/sh\necho SECRET\nexit 1\n' > "$BATS_TEST_TMPDIR/bin/$tool"
        chmod 755 "$BATS_TEST_TMPDIR/bin/$tool"
    done
    run with_test_path check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
}
@test "5.4.2.1 .2 .3 .4 remain independent in both load orders" {
    export RLCH_CIS_5_4_2_1_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_1_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_5_4_2_2_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_3_GROUP="$BATS_TEST_TMPDIR/group"
    export RLCH_CIS_5_4_2_4_SHADOW="$BATS_TEST_TMPDIR/shadow"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$BATS_TEST_TMPDIR/passwd"
    printf 'root:$y$j9T$salt$SECRET:20000:0:99999:7:::\n' > "$BATS_TEST_TMPDIR/shadow"
    printf 'root:x:0:\n' > "$BATS_TEST_TMPDIR/group"
    before="$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,group})"
    for control in 1 2 3 4; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/$control/module.sh"
        run check; [ "$status" -eq 0 ]
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/5/module.sh"
        rlch_5_4_2_5_uid() { printf '0\n'; }
        test_path=".:$BATS_TEST_TMPDIR/bin"
        run with_test_path apply; [ "$status" -eq 2 ]
        run rollback; [ "$status" -eq 0 ]
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/$control/module.sh"
        run apply; [ "$status" -eq 0 ]
        run rollback; [ "$status" -eq 0 ]
    done
    [ "$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,group})" = "$before" ]
}

@test "production stat and realpath helpers inspect a normal system PATH" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/5/module.sh"
    rlch_5_4_2_5_uid() { printf '0\n'; }
    # Hosted runners can customize /usr/local ownership/modes; use base OS dirs.
    test_path=/usr/bin:/bin
    run with_test_path check; [ "$status" -eq 0 ]
}
