#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_3_3_BASHRC="$BATS_TEST_TMPDIR/bashrc"
    export RLCH_CIS_5_4_3_3_LOGIN_DEFS="$BATS_TEST_TMPDIR/login.defs"
    export RLCH_CIS_5_4_3_3_PROFILE="$BATS_TEST_TMPDIR/profile"
    export RLCH_CIS_5_4_3_3_PROFILE_D="$BATS_TEST_TMPDIR/profile.d"
    export RLCH_CIS_5_4_3_3_STATE="$RLCH_CIS_5_4_3_3_PROFILE_D/.rlch-5.4.3.3"
    export RLCH_CIS_5_4_3_3_ID_COMMAND="$BATS_TEST_TMPDIR/id"
    printf '#!/usr/bin/env bash\necho 0\n' > "$RLCH_CIS_5_4_3_3_ID_COMMAND"; chmod 0755 "$RLCH_CIS_5_4_3_3_ID_COMMAND"
    mkdir "$RLCH_CIS_5_4_3_3_PROFILE_D"
    printf 'umask 027\n' > "$RLCH_CIS_5_4_3_3_BASHRC"
    printf 'UMASK 027\n' > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"
    printf '# default profile\n' > "$RLCH_CIS_5_4_3_3_PROFILE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/3/3/module.sh"
}
setting() { printf '%s\n' "$1" > "$RLCH_CIS_5_4_3_3_PROFILE"; }
created() { local code=0; apply || code=$?; [ "$code" -eq 4 ]; }
@test "manual composite Level 1 metadata" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/3/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.3.3 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "027 037 077 177 777 denial bits pass all dimensions unchanged" {
    for value in 027 037 077 177 777; do
        printf 'umask %s\n' "$value" > "$RLCH_CIS_5_4_3_3_BASHRC"
        printf 'UMASK %s\n' "$value" > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"
        setting "umask $value"
        before=$(sha256sum "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE")
        run check; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]
        [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE")" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
    done
}
@test "022 002 000 047 777 numeric ordering cannot replace bit test" {
    for value in 022 002 000 047; do
        setting "umask $value"; run check; [ "$status" -eq 1 ]
        printf 'umask %s\n' "$value" > "$RLCH_CIS_5_4_3_3_BASHRC"; setting 'umask 027'; run check; [ "$status" -eq 1 ]
        printf 'umask 027\n' > "$RLCH_CIS_5_4_3_3_BASHRC"; printf 'UMASK %s\n' "$value" > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"; run check; [ "$status" -eq 1 ]
        printf 'UMASK 027\n' > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"
    done
}
@test "duplicates stricter pass and earlier weak declaration cannot be masked" {
    setting $'umask 027\numask 077'; run check; [ "$status" -eq 0 ]
    for lines in $'umask 022\numask 077' $'umask 077\numask 022'; do setting "$lines"; run check; [ "$status" -eq 1 ]; done
    setting 'umask 077'; printf 'UMASK 027\nUMASK 000\n' > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"; run check; [ "$status" -eq 1 ]
}
@test "whitespace comments and no final newline follow distinct OVAL patterns" {
    printf '\tumask\t027  ' > "$RLCH_CIS_5_4_3_3_BASHRC"
    printf ' UMASK 037 # SECRET\n' > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"
    setting $'# umask 000\n  umask 077 # SECRET'; run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
    printf 'umask 027 # comment\n' > "$RLCH_CIS_5_4_3_3_BASHRC"; run check; [ "$status" -eq 1 ]
}
@test "no declaration in each required dimension is non compliant" {
    setting 'umask 027'
    for file in "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE"; do
        cp "$file" "$BATS_TEST_TMPDIR/saved"; printf '# missing\n' > "$file"; run check; [ "$status" -eq 1 ]; cp "$BATS_TEST_TMPDIR/saved" "$file"
    done
}
@test "non octal short long quoted symbolic negative variable values are errors" {
    for value in 888 078 27 0027 027022 -1 SECRET '$SECRET' 'u=rwx,g=rx,o=' '"027"'; do
        setting "umask $value"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
    setting 'umask 027'; printf 'UMASK abc\n' > "$RLCH_CIS_5_4_3_3_LOGIN_DEFS"; run check; [ "$status" -eq 2 ]
}
@test "bashrc prefixes suffixes and dynamic contexts require manual review" {
    for lines in 'true && umask 027' 'umask 027; echo SECRET' $'if true; then\numask 027\nfi'; do
        printf '%s\n' "$lines" > "$RLCH_CIS_5_4_3_3_BASHRC"; setting 'umask 027'; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "recursive hidden sh and top sh.local are selected nested sh.local is not" {
    mkdir -p "$RLCH_CIS_5_4_3_3_PROFILE_D/.hidden/nested"
    printf 'umask 077\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/.hidden/nested/.policy.sh"
    printf 'umask 000\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/.hidden/nested/sh.local"
    run check; [ "$status" -eq 0 ]
    printf 'umask 022\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/sh.local"; run check; [ "$status" -eq 1 ]
}
@test "multiple files mixed masks and unusual filenames are collected safely" {
    printf 'umask 077\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/space * ; $.sh"; run check; [ "$status" -eq 0 ]
    printf 'umask 022\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/weak.sh"; run check; [ "$status" -eq 1 ]
}
@test "scripts with no active umask are never executed" {
    setting "touch '$BATS_TEST_TMPDIR/executed'"
    printf 'umask 027\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/policy.sh"; run check; [ "$status" -eq 0 ]; [ ! -e "$BATS_TEST_TMPDIR/executed" ]
}
@test "missing fixed files are non compliant and never fabricated" {
    setting 'umask 027'
    rm "$RLCH_CIS_5_4_3_3_BASHRC"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_BASHRC" ]
}
@test "missing profile directory cannot be automatically fabricated" {
    rmdir "$RLCH_CIS_5_4_3_3_PROFILE_D"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]
}
@test "symlink nonregular unreadable fixed inputs are errors" {
    for file in "$RLCH_CIS_5_4_3_3_BASHRC" "$RLCH_CIS_5_4_3_3_LOGIN_DEFS" "$RLCH_CIS_5_4_3_3_PROFILE"; do
        cp "$file" "$BATS_TEST_TMPDIR/saved"
        for kind in link dir fifo unreadable; do
            rm -rf "$file"; case "$kind" in link) ln -s "$BATS_TEST_TMPDIR/saved" "$file";; dir) mkdir "$file";; fifo) mkfifo "$file";; unreadable) cp "$BATS_TEST_TMPDIR/saved" "$file"; chmod 000 "$file";; esac
            run check; [ "$status" -eq 2 ]
        done
        rm -f "$file"; cp "$BATS_TEST_TMPDIR/saved" "$file"
    done
}
@test "symlink directory or nested entry sh nonregular and unreadable are errors" {
    ln -s "$BATS_TEST_TMPDIR" "$RLCH_CIS_5_4_3_3_PROFILE_D/link"; run check; [ "$status" -eq 2 ]; rm "$RLCH_CIS_5_4_3_3_PROFILE_D/link"
    for kind in dir fifo unreadable; do
        path="$RLCH_CIS_5_4_3_3_PROFILE_D/policy.sh"
        case "$kind" in dir) mkdir "$path";; fifo) mkfifo "$path";; unreadable) touch "$path"; chmod 000 "$path";; esac
        run check; [ "$status" -eq 2 ]
        rm -rf "$path"
    done
}
@test "NUL controls and parent symlinks are rejected" {
    printf 'umask 027\000\n' > "$RLCH_CIS_5_4_3_3_BASHRC"; run check; [ "$status" -eq 2 ]
    printf 'umask 027\n' > "$RLCH_CIS_5_4_3_3_BASHRC"; ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/link"
    RLCH_CIS_5_4_3_3_BASHRC="$BATS_TEST_TMPDIR/link/bashrc"; run check; [ "$status" -eq 2 ]
}
@test "TMOUT file and state preserved by umask creation and rollback" {
    printf 'typeset -xr TMOUT=600\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/tmout.sh"
    mkdir "$RLCH_CIS_5_4_3_3_PROFILE_D/.rlch-5.4.3.2"; printf 'previous\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/.rlch-5.4.3.2/marker"
    before=$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/tmout.sh" "$RLCH_CIS_5_4_3_3_PROFILE_D/.rlch-5.4.3.2/marker")
    created; run rollback; [ "$status" -eq 4 ]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/tmout.sh" "$RLCH_CIS_5_4_3_3_PROFILE_D/.rlch-5.4.3.2/marker")" ]
}
@test "creation validates permissions private state and idempotence" {
    created
    run check; [ "$status" -eq 0 ]; [ "$(stat -c %a "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")" = 644 ]
    [ "$(stat -c %a "$RLCH_CIS_5_4_3_3_STATE")" = 700 ]
    before=$(stat -c '%i:%y:%z' "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")
    run apply; [ "$status" -eq 0 ]; [ "$before" = "$(stat -c '%i:%y:%z' "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")" ]
}
@test "rollback deletes only created file and state then is no op" {
    printf '# unrelated\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/unrelated.sh"
    before=$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/unrelated.sh")
    created; run rollback; [ "$status" -eq 4 ]
    [ ! -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
    [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/unrelated.sh")" ]
    run rollback; [ "$status" -eq 0 ]; run check; [ "$status" -eq 1 ]
}
@test "existing rlch-umask.sh never overwritten even comment only" {
    printf '# administrator file\n' > "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"
    before=$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")
    run apply; [ "$status" -eq 2 ]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "existing weak umask stays untouched and manual error" {
    setting 'umask 022'; before=$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE")
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_3_PROFILE")" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "non root or writable destination denies creation" {
    printf '#!/usr/bin/env bash\necho 1000\n' > "$RLCH_CIS_5_4_3_3_ID_COMMAND"
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
    printf '#!/usr/bin/env bash\necho 0\n' > "$RLCH_CIS_5_4_3_3_ID_COMMAND"
    chmod 0777 "$RLCH_CIS_5_4_3_3_PROFILE_D"; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "unsafe existing state is not touched" {
    ln -s "$BATS_TEST_TMPDIR" "$RLCH_CIS_5_4_3_3_STATE"
    run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 2 ]; [ -L "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "rollback rejects content edits metadata edits replacements removal and symlink" {
    created; target="$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"
    printf '# changed SECRET\n' >> "$target"; run rollback; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "rollback rejects mode change" {
    created; chmod 0600 "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "rollback rejects inode replacement even same content" {
    created; cp "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" "$BATS_TEST_TMPDIR/copy"
    rm "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; cp "$BATS_TEST_TMPDIR/copy" "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "rollback rejects administrator removal and symlink replacement" {
    created; rm "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; run rollback; [ "$status" -eq 2 ]
    ln -s "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; run rollback; [ "$status" -eq 2 ]
}
@test "observed check concurrent input change is error" {
    setting 'umask 027'
    eval "$(declare -f rlch_umask_scan | sed '1s/rlch_umask_scan/original_scan/')"
    rlch_umask_scan() { original_scan "$@"; printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_3_PROFILE"; }
    run check; [ "$status" -eq 2 ]
}
@test "atomic creation refuses competing administrator target" {
    rlch_tmout_link() { printf '# administrator\n' > "$2"; /usr/bin/ln -- "$1" "$2"; }
    run apply; [ "$status" -eq 2 ]; [ "$(cat "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh")" = '# administrator' ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "publication failure after link restores immediately" {
    rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "post apply validation failure restores immediately" {
    validate() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "failed restoration keeps state for explicit recovery" {
    validate() { return 1; }; rlch_tmout_remove() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE/installed" ]; [ -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]
    rlch_tmout_remove() { /usr/bin/rm -- "$1"; }
    run rollback; [ "$status" -eq 4 ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "post apply concurrent modification refuses destructive restoration" {
    validate() { printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; return 1; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]; [ -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]
}
@test "transaction lock blocks concurrent rollback" {
    created
    exec {held}<"$RLCH_CIS_5_4_3_3_STATE"; flock -x "$held"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]; exec {held}<&-
}
@test "earlier account root files and per control state remain unchanged" {
    mkdir "$BATS_TEST_TMPDIR/previous-state"
    for name in shadow passwd group previous_defs root_bashrc bash_profile; do printf 'previous SECRET\n' > "$BATS_TEST_TMPDIR/$name"; done
    printf 'previous\n' > "$BATS_TEST_TMPDIR/previous-state/marker"
    before=$(sha256sum "$BATS_TEST_TMPDIR/"{shadow,passwd,group,previous_defs,root_bashrc,bash_profile} "$BATS_TEST_TMPDIR/previous-state/marker")
    created; run rollback; [ "$status" -eq 4 ]
    [ "$before" = "$(sha256sum "$BATS_TEST_TMPDIR/"{shadow,passwd,group,previous_defs,root_bashrc,bash_profile} "$BATS_TEST_TMPDIR/previous-state/marker")" ]
}
@test "post apply harmless administrator edit still prevents success and deletion" {
    validate() { printf '# administrator\n' >> "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh"; check; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_STATE" ]; [ -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]
}
@test "configuration change between check and publication stops apply" {
    eval "$(declare -f rlch_tmout_writable_directory | sed '1s/rlch_tmout_writable_directory/original_directory/')"
    rlch_tmout_writable_directory() { original_directory "$@"; printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_3_PROFILE"; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "input read failure is error rather than missing definition" {
    rlch_umask_scan() { return 2; }
    run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
@test "rollback rejects unsafe journal files" {
    created; rm "$RLCH_CIS_5_4_3_3_STATE/identity"; ln -s "$RLCH_CIS_5_4_3_3_PROFILE" "$RLCH_CIS_5_4_3_3_STATE/identity"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]
}
@test "payload creation failure before mutation leaves no artificial state" {
    rlch_tmout_payload_identity() { return 2; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_3_PROFILE_D/rlch-umask.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_3_STATE" ]
}
