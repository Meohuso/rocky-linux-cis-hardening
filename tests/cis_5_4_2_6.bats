#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_2_6_BASH_PROFILE="$BATS_TEST_TMPDIR/profile"
    export RLCH_CIS_5_4_2_6_BASHRC="$BATS_TEST_TMPDIR/bashrc"
    printf 'umask 027\n' > "$RLCH_CIS_5_4_2_6_BASH_PROFILE"
    printf 'umask 0027\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/6/module.sh"
}
@test "5.4.2.6 Level 1 metadata manual because RHEL9 mapping pending" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/6/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.2.6 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "027 0027 077 and stricter denial bits pass" {
    for value in 027 0027 077 0077 037 0777 27; do
        printf 'umask %s\n' "$value" > "$RLCH_CIS_5_4_2_6_BASHRC"
        run check; [ "$status" -eq 0 ]
    done
}
@test "permissive values and numeric greater values missing denial bits fail" {
    for value in 022 0000 017 026 047 070 0770; do
        printf 'umask %s\n' "$value" > "$RLCH_CIS_5_4_2_6_BASHRC"
        run check; [ "$status" -eq 1 ]
        run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation'* ]]
    done
}
@test "last declaration wins in each file in both orders" {
    printf 'umask 022\numask 077\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 0 ]
    printf 'umask 077\numask 022\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 1 ]
    printf 'umask 022\n' > "$RLCH_CIS_5_4_2_6_BASH_PROFILE"
    printf 'umask 077\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 1 ]
}
@test "comments inline comments whitespace tabs quotes and no final newline" {
    printf '# umask 000\n\t umask\t0027\t # comment SECRET\n\numask "077" # end\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    printf "umask '027'" > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 0 ]
}
@test "complete symbolic assignments model shell allowed permissions" {
    for value in 'u=rwx,g=rx,o=' 'o=,u=rwx,g=' 'u=,g=,o='; do
        printf 'umask %s\n' "$value" > "$RLCH_CIS_5_4_2_6_BASHRC"
        run check; [ "$status" -eq 0 ]
    done
    printf 'umask u=rwx,g=rwx,o=rx\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 1 ]
}
@test "absent empty and comment-only files have no root-specific override" {
    rm "$RLCH_CIS_5_4_2_6_BASH_PROFILE" "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 0 ]
    touch "$RLCH_CIS_5_4_2_6_BASH_PROFILE"
    printf '# umask 022\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 0 ]
}
@test "malformed ambiguous dynamic and partial symbolic forms are errors" {
    for statement in 'umask 888' 'umask badSECRET' 'umask' 'umask "$MASK"' 'umask g-w' 'umask u=rwx,g=rx,g=' 'umask 027; umask 022' 'if true; then umask 027; fi' '. /etc/bashrc' 'eval "umask 027"' 'umask 027#comment' 'echo "umask 022"'; do
        printf '%s\n' "$statement" > "$RLCH_CIS_5_4_2_6_BASHRC"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *badSECRET* ]]
    done
}
@test "NUL content is rejected rather than silently normalized by Bash read" {
    printf 'umask 0\00027\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 2 ]
}
@test "symlink directory FIFO and unreadable files are errors" {
    rm "$RLCH_CIS_5_4_2_6_BASHRC"
    ln -s "$RLCH_CIS_5_4_2_6_BASH_PROFILE" "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 2 ]
    rm "$RLCH_CIS_5_4_2_6_BASHRC"
    mkdir "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 2 ]
    rmdir "$RLCH_CIS_5_4_2_6_BASHRC"
    mkfifo "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 2 ]
    rm "$RLCH_CIS_5_4_2_6_BASHRC"
    printf 'umask 027\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    chmod 000 "$RLCH_CIS_5_4_2_6_BASHRC"
    run check; [ "$status" -eq 2 ]
}
@test "parent symlink cannot hide unsafe root configuration" {
    ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/alias"
    export RLCH_CIS_5_4_2_6_BASHRC="$BATS_TEST_TMPDIR/alias/bashrc"
    run check; [ "$status" -eq 2 ]
    export RLCH_CIS_5_4_2_6_BASHRC="$BATS_TEST_TMPDIR/alias/missing"
    run check; [ "$status" -eq 2 ]
}
@test "check apply validate rollback never modify files or inherited umask" {
    before="$(sha256sum "$RLCH_CIS_5_4_2_6_BASH_PROFILE" "$RLCH_CIS_5_4_2_6_BASHRC")"
    mask_before="$(umask)"
    run apply; [ "$status" -eq 0 ]
    run apply; [ "$status" -eq 0 ]
    run validate; [ "$status" -eq 0 ]
    run rollback; [ "$status" -eq 0 ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_6_BASH_PROFILE" "$RLCH_CIS_5_4_2_6_BASHRC")" = "$before" ]
    [ "$(umask)" = "$mask_before" ]
    printf 'umask 022\n' > "$RLCH_CIS_5_4_2_6_BASHRC"
    bad_before="$(sha256sum "$RLCH_CIS_5_4_2_6_BASHRC")"
    run apply; [ "$status" -eq 2 ]
    run rollback; [ "$status" -eq 0 ]
    [ "$(sha256sum "$RLCH_CIS_5_4_2_6_BASHRC")" = "$bad_before" ]
    [ "$(find "$BATS_TEST_TMPDIR" -type f | wc -l)" -eq 2 ]
}
@test "unsupported commands are never executed" {
    printf 'touch %s/SHOULD_NOT_EXIST\numask 027\n' "$BATS_TEST_TMPDIR" > "$RLCH_CIS_5_4_2_6_BASHRC"
    run apply; [ "$status" -eq 2 ]
    [ ! -e "$BATS_TEST_TMPDIR/SHOULD_NOT_EXIST" ]
}
@test "complete literal symbolic conversion agrees with Bash builtin" {
    for argument in 'u=rwx,g=rx,o=' 'o=,g=,u=rwx' 'u=rw,g=r,o='; do
        actual="$(umask "$argument"; umask)"
        computed="$(rlch_5_4_2_6_mask "$argument")"
        [ "$computed" -eq "$((8#$actual))" ]
    done
}
@test "root umask remains independent from 5.4.2.1 through .5" {
    export RLCH_CIS_5_4_2_1_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_1_SHADOW="$BATS_TEST_TMPDIR/shadow"
    export RLCH_CIS_5_4_2_2_PASSWD="$BATS_TEST_TMPDIR/passwd"
    export RLCH_CIS_5_4_2_3_GROUP="$BATS_TEST_TMPDIR/group"
    export RLCH_CIS_5_4_2_4_SHADOW="$BATS_TEST_TMPDIR/shadow"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$BATS_TEST_TMPDIR/passwd"
    printf 'root:$y$j9T$salt$SECRET:20000:0:99999:7:::\n' > "$BATS_TEST_TMPDIR/shadow"
    printf 'root:x:0:\n' > "$BATS_TEST_TMPDIR/group"
    before="$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,group,profile,bashrc})"
    for control in 1 2 3 4 5; do
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/$control/module.sh"
        if [[ "$control" -eq 5 ]]; then
            rlch_5_4_2_5_uid() { printf '0\n'; }
            ordinary_check() { local PATH=/usr/bin:/bin; check; }
            run ordinary_check; [ "$status" -eq 0 ]
        else
            run check; [ "$status" -eq 0 ]
        fi
        run rollback; [ "$status" -eq 0 ]
        source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/2/6/module.sh"
        run apply; [ "$status" -eq 0 ]
        run rollback; [ "$status" -eq 0 ]
    done
    [ "$(sha256sum "$BATS_TEST_TMPDIR/"{passwd,shadow,group,profile,bashrc})" = "$before" ]
}
