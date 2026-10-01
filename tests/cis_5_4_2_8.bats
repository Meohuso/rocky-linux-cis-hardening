#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_8_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_8_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_5_4_2_8_SHELLS="$BATS_TEST_TMPDIR/shells"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$RLCH_CIS_5_4_2_8_PASSWD"
    printf 'root:$y$j9T$salt$SECRET:20000:0:99999:7:::\n' > "$RLCH_CIS_5_4_2_8_SHADOW"
    printf '# shells\n/bin/bash\n/usr/bin/bash\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/8/module.sh"
}
add_account() {
    printf '%s:x:%s:100:account:/nonexistent:%s\n' "$1" "$2" "$3" >> "$RLCH_CIS_5_4_2_8_PASSWD"
    printf '%s:%s:20000:0:99999:7:::\n' "$1" "$4" >> "$RLCH_CIS_5_4_2_8_SHADOW"
}
@test "5.4.2.8 exact Level 1 metadata rule" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/8/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.8 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_no_invalid_shell_accounts_unlocked ]
}
@test "listed shell with active password passes independent of UID" {
    add_account low 100 /bin/bash '$6$salt$SECRET'
    add_account high 8000 /usr/bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]
}
@test "invalid shell with strict CAS lock indicators passes including empty password" {
    add_account account 8000 /opt/unlisted '!'
    for password in '!' '!!' '!*' '*' '' ';' '\' ' !*;\' $'\t!\r'; do
        printf 'root:$y$SECRET:20000:0:99999:7:::\naccount:%s:20000:0:99999:7:::\n' "$password" > "$RLCH_CIS_5_4_2_8_SHADOW"
        run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "invalid shell active old prefixed hash and !locked fail strict motif" {
    add_account account 8000 /opt/unlisted '$6$salt$SECRET'
    for password in '$6$salt$SECRET' '!$6$salt$SECRET' '!locked' '*SECRET'; do
        printf 'root:$y$SECRET:20000:0:99999:7:::\naccount:%s:20000:0:99999:7:::\n' "$password" > "$RLCH_CIS_5_4_2_8_SHADOW"
        run check; [ "$status" -eq 1 ]; [[ "$output" == *account* && "$output" != *SECRET* && "$output" != *'!locked'* ]]
    done
}
@test "multiple unlocked invalid-shell accounts all diagnosed" {
    add_account first 10 /opt/unlisted '$6$salt$SECRET'
    add_account second 8000 relativeSECRET '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *first* && "$output" == *second* && "$output" != *SECRET* ]]
}
@test "root nobody nfsnobody exceptions are exact names" {
    for name in nobody nfsnobody; do add_account "$name" 100 /opt/unlisted '$6$salt$SECRET'; done
    sed -i '1s@/bin/bash@/opt/unlisted@' "$RLCH_CIS_5_4_2_8_PASSWD"
    run check; [ "$status" -eq 0 ]
    add_account rootlike 8000 /opt/unlisted '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]; [[ "$output" == *rootlike* && "$output" != *nobody* ]]
}
@test "nologin and false prefixes are excluded before shell-list membership" {
    for shell in /sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false /sbin/nologinSuffix /usr/bin/falseSuffix; do
        printf 'root:x:0:0:root:/root:/bin/bash\naccount:x:8000:100::/nonexistent:%s\n' "$shell" > "$RLCH_CIS_5_4_2_8_PASSWD"
        printf 'root:$y$SECRET:20000:0:99999:7:::\naccount:$6$SECRET:20000:0:99999:7:::\n' > "$RLCH_CIS_5_4_2_8_SHADOW"
        run check; [ "$status" -eq 0 ]
    done
}
@test "empty shell is not captured by the later OVAL shell expression" {
    add_account account 8000 '' '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]
}
@test "relative shell cannot match a slash-leading collected shell" {
    add_account account 8000 relative '$6$salt$SECRET'
    printf 'relative\n/bin/bash\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 1 ]
}
@test "listed nonexistent path accepted; filesystem existence is not CAS requirement" {
    add_account account 8000 "$BATS_TEST_TMPDIR/does-not-exist" '$6$salt$SECRET'
    printf '%s\n' "$BATS_TEST_TMPDIR/does-not-exist" >> "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/does-not-exist" ]
}
@test "shell-list blank comments nonabsolute lines and duplicates follow collection" {
    printf '\n# comment\nrelative\n /bin/bash\n/bin/bash\n/bin/bash\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    add_account account 8000 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]
    printf ' /bin/bash\n/usr/bin/bash\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 1 ]
}
@test "shell-list inline comments are literal and not stripped" {
    add_account account 8000 /bin/bash '$6$salt$SECRET'
    printf '/bin/bash # note\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 1 ]
    sed -i '2s@/bin/bash@/bin/bash # note@' "$RLCH_CIS_5_4_2_8_PASSWD"
    run check; [ "$status" -eq 0 ]
}
@test "custom nologin text is not removed by a state on collector pattern entity" {
    add_account account 8000 /opt/nologin '$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]
    printf '/opt/nologin\n' >> "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 0 ]
}
@test "passwd marker need not be x in this OVAL" {
    add_account account 8000 /opt/unlisted '$6$salt$SECRET'
    sed -i '2s/:x:/:*:/' "$RLCH_CIS_5_4_2_8_PASSWD"
    run check; [ "$status" -eq 1 ]
}
@test "empty or unsafe shell list cannot provide a valid comparison" {
    : > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 2 ]
    printf '/bin/ba\000sh\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 2 ]
    printf '/bin/bash\r\n' > "$RLCH_CIS_5_4_2_8_SHELLS"
    run check; [ "$status" -eq 2 ]
}
@test "malformed duplicate invalid UID GID passwd rows are errors" {
    baseline="$(cat "$RLCH_CIS_5_4_2_8_PASSWD")"
    for row in 'broken' 'root:x:0:0::/:/bin/bash' 'bad:x:invalid:0::/:/bin/bash' 'bad:x:1:-1::/:/bin/bash'; do
        printf '%s\n%s\n' "$baseline" "$row" > "$RLCH_CIS_5_4_2_8_PASSWD"
        run check; [ "$status" -eq 2 ]
    done
}
@test "malformed duplicate and invalid age shadow rows never leak secrets" {
    for row in 'bad:SECRET' 'root:SECRET:20000:0:99999:7:::' 'bad:SECRET:bad:0:99999:7:::'; do
        printf 'root:$y$SECRET:20000:0:99999:7:::\n%s\n' "$row" > "$RLCH_CIS_5_4_2_8_SHADOW"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "missing required shadow and orphan shadow rows are errors" {
    add_account account 8000 /opt/unlisted '$6$salt$SECRET'
    sed -i '2d' "$RLCH_CIS_5_4_2_8_SHADOW"
    run check; [ "$status" -eq 2 ]
    printf 'orphan:!:20000:0:99999:7:::\n' >> "$RLCH_CIS_5_4_2_8_SHADOW"
    run check; [ "$status" -eq 2 ]
}
@test "missing symlink directory FIFO unreadable inputs are errors" {
    for file in "$RLCH_CIS_5_4_2_8_PASSWD" "$RLCH_CIS_5_4_2_8_SHADOW" "$RLCH_CIS_5_4_2_8_SHELLS"; do
        mv "$file" "$file.real"
        run check; [ "$status" -eq 2 ]
        ln -s "$file.real" "$file"
        run check; [ "$status" -eq 2 ]
        rm "$file"; mkdir "$file"
        run check; [ "$status" -eq 2 ]
        rmdir "$file"; mkfifo "$file"
        run check; [ "$status" -eq 2 ]
        rm "$file"; mv "$file.real" "$file"
        chmod 000 "$file"
        run check; [ "$status" -eq 2 ]
        chmod 600 "$file"
    done
}
@test "parent symlink input is unsafe" {
    ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/alias"
    export RLCH_CIS_5_4_2_8_SHELLS="$BATS_TEST_TMPDIR/alias/shells"
    run check; [ "$status" -eq 2 ]
}
@test "observation-only apply and rollback create no state or mutation" {
    add_account account 8000 /opt/unlisted '$6$salt$SECRET'
    before="$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,shells})"
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation'* && "$output" != *SECRET* ]]
    run validate; [ "$status" -eq 1 ]; run rollback; [ "$status" -eq 0 ]
    [ "$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,shells})" = "$before" ]
    [ "$(find "$BATS_TEST_TMPDIR" -type f | wc -l)" -eq 3 ]
}
@test "multi-file concurrent change is error" {
    eval "$(declare -f rlch_accounts_rows | sed '1s/rlch_accounts_rows/original_rows/')"
    rlch_accounts_rows() {
        original_rows "$@" || return 2
        if [[ "$2" == shells ]]; then printf '# concurrent\n' >> "$RLCH_CIS_5_4_2_8_PASSWD"; fi
    }
    run check; [ "$status" -eq 2 ]
}
@test "populations differ explicitly from 5.4.2.7 in both directions" {
    export RLCH_CIS_5_4_2_7_PASSWD="$RLCH_CIS_5_4_2_8_PASSWD"
    export RLCH_CIS_5_4_2_7_SHADOW="$RLCH_CIS_5_4_2_8_SHADOW"
    export RLCH_CIS_5_4_2_7_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    printf 'UID_MIN 1000\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    add_account low 100 /bin/bash '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/7/module.sh"
    run check; [ "$status" -eq 1 ]
    sed -i '2d' "$RLCH_CIS_5_4_2_8_PASSWD" "$RLCH_CIS_5_4_2_8_SHADOW"
    add_account high 8000 /opt/unlisted '$6$salt$SECRET'
    run check; [ "$status" -eq 0 ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/8/module.sh"
    run check; [ "$status" -eq 1 ]
}
@test "lock motifs differ from 5.4.2.7 even for the same UID and password" {
    export RLCH_CIS_5_4_2_7_PASSWD="$RLCH_CIS_5_4_2_8_PASSWD"
    export RLCH_CIS_5_4_2_7_SHADOW="$RLCH_CIS_5_4_2_8_SHADOW"
    export RLCH_CIS_5_4_2_7_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    printf 'UID_MIN 1000\n' > "$RLCH_CIS_5_4_2_7_LOGIN_DEFS"
    add_account low 100 /opt/unlisted '!$6$salt$SECRET'
    run check; [ "$status" -eq 1 ]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/7/module.sh"
    run check; [ "$status" -eq 1 ]; [[ "$output" != *'password authentication'* ]]
    sed -i '2s/:[^:]*/:/' "$RLCH_CIS_5_4_2_8_SHADOW"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'password authentication'* ]]
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/8/module.sh"
    run check; [ "$status" -eq 0 ]
}
