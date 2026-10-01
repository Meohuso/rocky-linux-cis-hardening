#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_5_4_3_2_PROFILE="$BATS_TEST_TMPDIR/profile"
    export RLCH_CIS_5_4_3_2_PROFILE_D="$BATS_TEST_TMPDIR/profile.d"
    export RLCH_CIS_5_4_3_2_STATE="$RLCH_CIS_5_4_3_2_PROFILE_D/.rlch-5.4.3.2"
    export RLCH_CIS_5_4_3_2_ID_COMMAND="$BATS_TEST_TMPDIR/id"
    printf '#!/usr/bin/env bash\necho 0\n' > "$RLCH_CIS_5_4_3_2_ID_COMMAND"
    chmod 0755 "$RLCH_CIS_5_4_3_2_ID_COMMAND"
    mkdir "$RLCH_CIS_5_4_3_2_PROFILE_D"
    printf '# ordinary profile\n' > "$RLCH_CIS_5_4_3_2_PROFILE"
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/3/2/module.sh"
}
setting() { printf '%s\n' "$1" > "$RLCH_CIS_5_4_3_2_PROFILE"; }
created() { local code=0; apply || code=$?; [ "$code" -eq 4 ]; }
@test "metadata exact L1 mapping" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/5/4/3/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 5.4.3.2 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_accounts_tmout ]
}
@test "typeset 900 and declare 900 are compliant" {
    for command in typeset declare; do setting "$command -xr TMOUT=900"; run check; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]; done
}
@test "bounds 1 300 600 900 pass without mutation" {
    for value in 1 300 600 900; do
        setting "typeset -xr TMOUT=$value"
        before=$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE")
        run apply; [ "$status" -eq 0 ]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE")" ]
        [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
    done
}
@test "0 901 and negative literal are non compliant" {
    for value in 0 901 -1; do setting "typeset -xr TMOUT=$value"; run check; [ "$status" -eq 1 ]; done
}
@test "nonnumeric reference substitutions and huge values are errors without source leakage" {
    for value in SECRET '$SECRET' '$(touch SECRET)' '`touch SECRET`' 99999999999999999999999999; do
        setting "typeset -xr TMOUT=$value"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
    [ ! -e SECRET ]
}
@test "leading zero ambiguity is error" {
    for value in 0900 0600 01; do setting "typeset -xr TMOUT=$value"; run check; [ "$status" -eq 2 ]; done
}
@test "plain assignment export readonly separate and other options are not OVAL equivalent" {
    for line in 'TMOUT=900' 'export TMOUT=900' 'readonly TMOUT=900' 'declare -rx TMOUT=900' 'declare -x TMOUT=900' 'typeset -r TMOUT=900' 'TMOUT = 900'; do
        setting "$line"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]
    done
    setting $'TMOUT=900\nreadonly TMOUT\nexport TMOUT'; run check; [ "$status" -eq 1 ]
}
@test "no occurrence and commented occurrence are non compliant" {
    setting $'# typeset -xr TMOUT=900\n  # declare -xr TMOUT=0'; run check; [ "$status" -eq 1 ]
}
@test "spaces tabs inline comments and no final newline handled" {
    printf '\tdeclare\t-xr\tTMOUT=600  # comment SECRET ${ignored}' > "$RLCH_CIS_5_4_3_2_PROFILE"
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
}
@test "unsafe comment adjacency quotes and trailing shell commands are errors" {
    for line in 'typeset -xr TMOUT=900#SECRET' 'typeset -xr TMOUT="900"' 'typeset -xr TMOUT=900; echo SECRET' 'typeset -xr TMOUT=900 ignored'; do
        setting "$line"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "multiple different stricter declarations across files pass" {
    setting $'typeset -xr TMOUT=300\ndeclare -xr TMOUT=600'
    printf 'typeset -xr TMOUT=1\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/first.sh"
    printf 'declare -xr TMOUT=900\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/second.sh"
    run check; [ "$status" -eq 0 ]
}
@test "any weak occurrence fails regardless of order or file" {
    for lines in $'typeset -xr TMOUT=901\ndeclare -xr TMOUT=300' $'typeset -xr TMOUT=300\ndeclare -xr TMOUT=901'; do setting "$lines"; run check; [ "$status" -eq 1 ]; done
    setting 'typeset -xr TMOUT=300'; printf 'declare -xr TMOUT=0\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/weak.sh"
    run check; [ "$status" -eq 1 ]
}
@test "hidden sh filenames are included non sh files are excluded" {
    setting '# no timeout'; printf 'typeset -xr TMOUT=900\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/.hidden.sh"
    printf 'typeset -xr TMOUT=0\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/ignored.conf"
    run check; [ "$status" -eq 0 ]
}
@test "conditional function and continuation contexts are manual errors" {
    for lines in $'if true; then\ntypeset -xr TMOUT=900\nfi' $'f() {\ntypeset -xr TMOUT=900\n}' $'typeset -xr \\\nTMOUT=900'; do setting "$lines"; run check; [ "$status" -eq 2 ]; done
}
@test "unrelated standard profile logic is not executed" {
    setting "if true; then touch '$BATS_TEST_TMPDIR/executed'; fi"
    printf 'typeset -xr TMOUT=900\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/policy.sh"
    run check; [ "$status" -eq 0 ]; [ ! -e "$BATS_TEST_TMPDIR/executed" ]
}
@test "missing profile or directory safely audited but not created by apply" {
    rm "$RLCH_CIS_5_4_3_2_PROFILE"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]
    setting '# restored'; rmdir "$RLCH_CIS_5_4_3_2_PROFILE_D"
    run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D" ]
}
@test "missing profile with safe profile.d declaration passes static audit" {
    rm "$RLCH_CIS_5_4_3_2_PROFILE"; printf 'typeset -xr TMOUT=900\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/policy.sh"
    run check; [ "$status" -eq 0 ]
}
@test "profile symlink directory fifo unreadable are errors" {
    cp "$RLCH_CIS_5_4_3_2_PROFILE" "$BATS_TEST_TMPDIR/original"
    for kind in link dir fifo unreadable; do
        rm -rf "$RLCH_CIS_5_4_3_2_PROFILE"
        case "$kind" in link) ln -s "$BATS_TEST_TMPDIR/original" "$RLCH_CIS_5_4_3_2_PROFILE";; dir) mkdir "$RLCH_CIS_5_4_3_2_PROFILE";; fifo) mkfifo "$RLCH_CIS_5_4_3_2_PROFILE";; unreadable) cp "$BATS_TEST_TMPDIR/original" "$RLCH_CIS_5_4_3_2_PROFILE"; chmod 000 "$RLCH_CIS_5_4_3_2_PROFILE";; esac
        run check; [ "$status" -eq 2 ]
    done
}
@test "profile.d symlink non directory unreadable and unsearchable are errors" {
    for kind in link file unreadable unsearchable; do
        rm -rf "$RLCH_CIS_5_4_3_2_PROFILE_D"
        case "$kind" in link) ln -s "$BATS_TEST_TMPDIR" "$RLCH_CIS_5_4_3_2_PROFILE_D";; file) touch "$RLCH_CIS_5_4_3_2_PROFILE_D";; unreadable) mkdir "$RLCH_CIS_5_4_3_2_PROFILE_D"; chmod 0111 "$RLCH_CIS_5_4_3_2_PROFILE_D";; unsearchable) mkdir "$RLCH_CIS_5_4_3_2_PROFILE_D"; chmod 0444 "$RLCH_CIS_5_4_3_2_PROFILE_D";; esac
        run check; [ "$status" -eq 2 ]
    done
}
@test "sh symlink directory fifo unreadable and control filename are errors" {
    for kind in link dir fifo unreadable control; do
        rm -rf "$RLCH_CIS_5_4_3_2_PROFILE_D"; mkdir "$RLCH_CIS_5_4_3_2_PROFILE_D"
        path="$RLCH_CIS_5_4_3_2_PROFILE_D/entry.sh"
        case "$kind" in link) ln -s "$RLCH_CIS_5_4_3_2_PROFILE" "$path";; dir) mkdir "$path";; fifo) mkfifo "$path";; unreadable) touch "$path"; chmod 000 "$path";; control) touch "$RLCH_CIS_5_4_3_2_PROFILE_D/"$'SECRET\n.sh';; esac
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "parent symlink and NUL CR content are errors" {
    for char in '\000' '\r'; do printf "# text${char}\n" > "$RLCH_CIS_5_4_3_2_PROFILE"; run check; [ "$status" -eq 2 ]; done
    setting '# profile'; ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/link"
    RLCH_CIS_5_4_3_2_PROFILE="$BATS_TEST_TMPDIR/link/profile"; run check; [ "$status" -eq 2 ]
}
@test "unusual spaces glob and shell characters in sh filenames are safe" {
    printf 'typeset -xr TMOUT=900\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/space * ; \$.sh"
    run check; [ "$status" -eq 0 ]
}
@test "creation validates permissions private state and idempotence" {
    created
    run check; [ "$status" -eq 0 ]; [ "$(stat -c %a "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")" = 644 ]
    [ "$(stat -c %a "$RLCH_CIS_5_4_3_2_STATE")" = 700 ]
    before=$(stat -c '%i:%y:%z' "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")
    run apply; [ "$status" -eq 0 ]; [ "$before" = "$(stat -c '%i:%y:%z' "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")" ]
}
@test "rollback deletes only created file and state then is no op" {
    printf '# unrelated\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/unrelated.sh"
    before=$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE_D/unrelated.sh")
    created; run rollback; [ "$status" -eq 4 ]
    [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
    [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE_D/unrelated.sh")" ]
    run rollback; [ "$status" -eq 0 ]; run check; [ "$status" -eq 1 ]
}
@test "existing tmout.sh never overwritten even comment only" {
    printf '# administrator file\n' > "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"
    before=$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")
    run apply; [ "$status" -eq 2 ]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "existing weak timeout stays untouched and manual error" {
    setting 'declare -xr TMOUT=901'; before=$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE")
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]; [ "$before" = "$(sha256sum "$RLCH_CIS_5_4_3_2_PROFILE")" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "non root or writable destination denies creation" {
    printf '#!/usr/bin/env bash\necho 1000\n' > "$RLCH_CIS_5_4_3_2_ID_COMMAND"
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
    printf '#!/usr/bin/env bash\necho 0\n' > "$RLCH_CIS_5_4_3_2_ID_COMMAND"
    chmod 0777 "$RLCH_CIS_5_4_3_2_PROFILE_D"; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "unsafe existing state is not touched" {
    ln -s "$BATS_TEST_TMPDIR" "$RLCH_CIS_5_4_3_2_STATE"
    run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 2 ]; [ -L "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "rollback rejects content edits metadata edits replacements removal and symlink" {
    created; target="$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"
    printf '# changed SECRET\n' >> "$target"; run rollback; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "rollback rejects mode change" {
    created; chmod 0600 "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "rollback rejects inode replacement even same content" {
    created; cp "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" "$BATS_TEST_TMPDIR/copy"
    rm "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; cp "$BATS_TEST_TMPDIR/copy" "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "rollback rejects administrator removal and symlink replacement" {
    created; rm "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; run rollback; [ "$status" -eq 2 ]
    ln -s "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; run rollback; [ "$status" -eq 2 ]
}
@test "observed check concurrent input change is error" {
    setting 'typeset -xr TMOUT=900'
    eval "$(declare -f rlch_tmout_scan_file | sed '1s/rlch_tmout_scan_file/original_scan/')"
    rlch_tmout_scan_file() { original_scan "$@"; printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_2_PROFILE"; }
    run check; [ "$status" -eq 2 ]
}
@test "atomic creation refuses competing administrator target" {
    rlch_tmout_link() { printf '# administrator\n' > "$2"; /usr/bin/ln -- "$1" "$2"; }
    run apply; [ "$status" -eq 2 ]; [ "$(cat "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh")" = '# administrator' ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "publication failure after link restores immediately" {
    rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "post apply validation failure restores immediately" {
    validate() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "failed restoration keeps state for explicit recovery" {
    validate() { return 1; }; rlch_tmout_remove() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE/installed" ]; [ -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]
    rlch_tmout_remove() { /usr/bin/rm -- "$1"; }
    run rollback; [ "$status" -eq 4 ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "post apply concurrent modification refuses destructive restoration" {
    validate() { printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; return 1; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]; [ -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]
}
@test "transaction lock blocks concurrent rollback" {
    created
    exec {held}<"$RLCH_CIS_5_4_3_2_STATE"; flock -x "$held"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]; exec {held}<&-
}
@test "earlier account root files and per control state remain unchanged" {
    mkdir "$BATS_TEST_TMPDIR/previous-state"
    for name in shadow passwd group login.defs bashrc bash_profile; do printf 'previous SECRET\n' > "$BATS_TEST_TMPDIR/$name"; done
    printf 'previous\n' > "$BATS_TEST_TMPDIR/previous-state/marker"
    before=$(sha256sum "$BATS_TEST_TMPDIR/"{shadow,passwd,group,login.defs,bashrc,bash_profile} "$BATS_TEST_TMPDIR/previous-state/marker")
    created; run rollback; [ "$status" -eq 4 ]
    [ "$before" = "$(sha256sum "$BATS_TEST_TMPDIR/"{shadow,passwd,group,login.defs,bashrc,bash_profile} "$BATS_TEST_TMPDIR/previous-state/marker")" ]
}
@test "post apply harmless administrator edit still prevents success and deletion" {
    validate() { printf '# administrator\n' >> "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh"; check; }
    run apply; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_STATE" ]; [ -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]
}
@test "configuration change between check and publication stops apply" {
    eval "$(declare -f rlch_tmout_writable_directory | sed '1s/rlch_tmout_writable_directory/original_directory/')"
    rlch_tmout_writable_directory() { original_directory "$@"; printf '# concurrent\n' >> "$RLCH_CIS_5_4_3_2_PROFILE"; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "input read failure is error rather than missing definition" {
    rlch_tmout_scan_file() { return 2; }
    run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
@test "rollback rejects unsafe journal files" {
    created; rm "$RLCH_CIS_5_4_3_2_STATE/identity"; ln -s "$RLCH_CIS_5_4_3_2_PROFILE" "$RLCH_CIS_5_4_3_2_STATE/identity"
    run rollback; [ "$status" -eq 2 ]; [ -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]
}
@test "payload creation failure before mutation leaves no artificial state" {
    rlch_tmout_payload_identity() { return 2; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_5_4_3_2_PROFILE_D/tmout.sh" ]; [ ! -e "$RLCH_CIS_5_4_3_2_STATE" ]
}
