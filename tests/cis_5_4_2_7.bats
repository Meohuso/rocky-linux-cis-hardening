#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_7_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_7_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_5_4_2_7_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$RLCH_CIS_5_4_2_7_PASSWD"
    printf 'root:$y$j9T$salt$SECRET:20000:0:99999:7:::\n' > "$RLCH_CIS_5_4_2_7_SHADOW"
    printf 'UID_MIN 1000\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/7/module.sh"
}
add_account() {
    printf '%s:x:%s:100:system:/nonexistent:%s\n' "$1" "$2" "$3" >> "$RLCH_CIS_5_4_2_7_PASSWD"
    printf '%s:%s:20000:0:99999:7:::\n' "$1" "$4" >> "$RLCH_CIS_5_4_2_7_SHADOW"
}
@test "5.4.2.7 Level 1 metadata manual two independent rules" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/7/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.7 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "root and ordinary accounts ignored compliant system account passes" {
    add_account service 500 /sbin/nologin '!'
    add_account user 1000 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]
}
@test "password prefix locks accept every CAS state and old prefixed hash" {
    add_account service 500 /sbin/nologin '!'
    for password in '!' '!!' '!*' '*' '!locked' '!$6$salt$SECRET' '*SECRET'; do
        printf 'root:$y$SECRET:20000:0:99999:7:::\nservice:%s:20000:0:99999:7:::\n' "$password" > "$RLCH_CIS_5_4_2_7_SHADOW"
        run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "active and empty system password fail without secret output" {
    add_account service 500 /sbin/nologin '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *service* && "$output" == *'password authentication'* && "$output" != *SECRET* ]]
    sed -i '2s/:[^:]*/:/' "$RLCH_CIS_5_4_2_7_SHADOW"
    run check; [ "$status" -eq 1 ]
}
@test "interactive shell false empty relative shells fail for RHEL" {
    add_account service 500 /bin/bash '!'
    for shell in /bin/bash /bin/false /usr/bin/false '' relative; do
        sed -i "2s@:[^:]*\$@:$shell@" "$RLCH_CIS_5_4_2_7_PASSWD"
        run check; [ "$status" -eq 1 ]; [[ "$output" == *'login shell'* ]]
    done
}
@test "RHEL nologin and operational shell prefixes follow OVAL" {
    add_account service 500 /sbin/nologin '!'
    for shell in /sbin/nologin /usr/sbin/nologin /bin/sync /sbin/shutdown /sbin/halt /sbin/nologinCASsuffix; do
        sed -i "2s@:[^:]*\$@:$shell@" "$RLCH_CIS_5_4_2_7_PASSWD"
        run check; [ "$status" -eq 0 ]
    done
}
@test "password name exceptions do not suppress the shell sub-rule" {
    for account in sync shutdown halt nfsnobody; do
        add_account "$account" 500 /bin/bash '$6$salt$SECRET'
    done
    run check; [ "$status" -eq 1 ]
    [[ "$output" != *'password authentication'* && "$output" == *sync* && "$output" == *shutdown* && "$output" == *halt* && "$output" == *nfsnobody* && "$output" != *SECRET* ]]
}
@test "root prefix shell exception and exact password exception are independent" {
    add_account rootlike 500 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'password authentication'* && "$output" != *'login shell'* ]]
}
@test "runtime UID_MIN controls shells but compiled threshold controls password" {
    printf 'UID_MIN 2000\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    add_account service 1500 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'login shell'* && "$output" != *'password authentication'* ]]
    printf 'UID_MIN 500\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    run check; [ "$status" -eq 0 ]
    add_account low 700 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'password authentication'* && "$output" != *'login shell'* ]]
}
@test "explicit SYS ranges include reserved and dynamic UIDs with exclusive max" {
    printf 'SYS_UID_MIN 200\nSYS_UID_MAX 800\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    for uid in 0 199 200 799; do add_account "service$uid" "$uid" /bin/bash '!'; done
    add_account boundary 800 /bin/bash '!'
    run check; [ "$status" -eq 1 ]
    [[ "$output" == *service0* && "$output" == *service199* && "$output" == *service200* && "$output" == *service799* && "$output" != *boundary* ]]
}
@test "UID_MIN boundaries and leading zero UID normalization" {
    add_account below 000999 /bin/bash '!'
    add_account atmin 001000 /bin/bash '$6$salt$SECRET'
    add_account above 1001 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *below* && "$output" != *atmin* && "$output" != *above* ]]
}
@test "missing and partial UID policy distinguished from invalid ranges" {
    : > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    run check; [ "$status" -eq 2 ]
    printf 'UID_MIN 1000\nSYS_UID_MIN 200\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    run check; [ "$status" -eq 1 ]
    printf 'SYS_UID_MIN 800\nSYS_UID_MAX 200\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    run check; [ "$status" -eq 2 ]
}
@test "last valid UID declaration wins comments tabs no final newline handled" {
    printf '# UID_MIN 10\nUID_MIN 10\n\tUID_MIN\t2000' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    add_account service 1500 /bin/bash '!'
    run check; [ "$status" -eq 1 ]
}
@test "malformed UID directives and impossible numeric values return error" {
    for value in 'UID_MIN -1' 'UID_MIN badSECRET' 'UID_MIN=1000' 'UID_MIN 1000 # comment' 'SYS_UID_MIN' 'UID_MIN 4294967295'; do
        printf '%s\n' "$value" > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "both dimensions and multiple accounts diagnosed without fields" {
    add_account first 100 /bin/bash '$6$salt$SECRET'
    add_account second 200 /bin/bash ''
    run check; [ "$status" -eq 1 ]
    [[ "$output" == *first* && "$output" == *second* && "$output" == *'login shell'* && "$output" == *'password authentication'* && "$output" != *SECRET* ]]
}
@test "non-x passwd marker skips shell OVAL but not password selection" {
    add_account service 500 /bin/bash '!'
    sed -i '2s/:x:/:!:/' "$RLCH_CIS_5_4_2_7_PASSWD"
    run check; [ "$status" -eq 0 ]
}
@test "passwd malformed duplicate invalid UID GID rejected" {
    baseline="$(cat "$RLCH_CIS_5_4_2_7_PASSWD")"
    for row in 'bad:row' 'root:x:0:0:root:/root:/bin/bash' 'bad:x:no:0::/:/bin/bash' 'bad:x:100:-1::/:/bin/bash'; do
        printf '%s\n%s\n' "$baseline" "$row" > "$RLCH_CIS_5_4_2_7_PASSWD"
        run check; [ "$status" -eq 2 ]
    done
}
@test "shadow malformed duplicate age invalid and NUL rejected without hash" {
    for row in 'root:SECRET' 'root:SECRET:20000:0:99999:7:::' 'bad:SECRET:bogus:0:99999:7:::'; do
        printf 'root:$y$SECRET:20000:0:99999:7:::\n%s\n' "$row" > "$RLCH_CIS_5_4_2_7_SHADOW"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
    printf 'root:$y$SEC\000RET:20000:0:99999:7:::\n' > "$RLCH_CIS_5_4_2_7_SHADOW"
    run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
}
@test "missing required shadow row and orphan shadow row are errors" {
    add_account service 100 /sbin/nologin '!'
    sed -i '2d' "$RLCH_CIS_5_4_2_7_SHADOW"
    run check; [ "$status" -eq 2 ]
    printf 'orphan:!:20000:0:99999:7:::\n' >> "$RLCH_CIS_5_4_2_7_SHADOW"
    run check; [ "$status" -eq 2 ]
}
@test "all files missing symlink nonregular unreadable are errors" {
    for file in "$RLCH_CIS_5_4_2_7_PASSWD" "$RLCH_CIS_5_4_2_7_SHADOW" "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"; do
        mv "$file" "$file.real"
        run check; [ "$status" -eq 2 ]
        ln -s "$file.real" "$file"
        run check; [ "$status" -eq 2 ]
        rm "$file"; mkdir "$file"
        run check; [ "$status" -eq 2 ]
        rmdir "$file"; mv "$file.real" "$file"
        chmod 000 "$file"
        run check; [ "$status" -eq 2 ]
        chmod 600 "$file"
    done
}
@test "observation only apply rollback creates no backup or mutation" {
    add_account service 100 /bin/bash '$6$salt$SECRET'
    before="$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,login.defs})"
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation'* && "$output" != *SECRET* ]]
    run validate; [ "$status" -eq 1 ]
    run rollback; [ "$status" -eq 0 ]
    [ "$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,login.defs})" = "$before" ]
    [ "$(find "$BATS_TEST_TMPDIR" -type f | wc -l)" -eq 3 ]
}
@test "multi-file concurrent change is rejected" {
    eval "$(declare -f rlch_accounts_rows | sed '1s/rlch_accounts_rows/original_rows/')"
    rlch_accounts_rows() {
        original_rows "$@" || return 2
        if [[ "$2" == login_defs ]]; then printf '# concurrent\n' >> "$RLCH_CIS_5_4_2_7_PASSWD"; fi
    }
    run check; [ "$status" -eq 2 ]
}
@test "independence from 5.4.2.1 through .6" {
    export RLCH_CIS_5_4_2_1_PASSWD="$RLCH_CIS_5_4_2_7_PASSWD"
    export RLCH_CIS_5_4_2_1_SHADOW="$RLCH_CIS_5_4_2_7_SHADOW"
    export RLCH_CIS_5_4_2_2_PASSWD="$RLCH_CIS_5_4_2_7_PASSWD"
    export RLCH_CIS_5_4_2_3_GROUP="$BATS_TEST_TMPDIR/group"
    export RLCH_CIS_5_4_2_4_SHADOW="$RLCH_CIS_5_4_2_7_SHADOW"
    export RLCH_CIS_5_4_2_6_BASH_PROFILE="$BATS_TEST_TMPDIR/profile"
    export RLCH_CIS_5_4_2_6_BASHRC="$BATS_TEST_TMPDIR/bashrc"
    printf 'root:x:0:\n' > "$BATS_TEST_TMPDIR/group"
    printf 'umask 027\n' > "$BATS_TEST_TMPDIR/profile"
    printf 'umask 077\n' > "$BATS_TEST_TMPDIR/bashrc"
    before="$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,login.defs,group,profile,bashrc})"
    for control in 1 2 3 4 5 6; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/$control/module.sh"
        if [[ "$control" -eq 5 ]]; then
            rlch_5_4_2_5_uid() { printf '0\n'; }
            normal_path_check() { local PATH=/usr/bin:/bin; check; }
            run normal_path_check; [ "$status" -eq 0 ]
        else run check; [ "$status" -eq 0 ]; fi
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/7/module.sh"
        run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    done
    [ "$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,login.defs,group,profile,bashrc})" = "$before" ]
}
