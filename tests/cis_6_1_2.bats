#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_6_1_2_CRONTAB="$BATS_TEST_TMPDIR/crontab"
    export RLCH_CIS_6_1_2_ROOT_CRON="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_1_2_CRON_D="$BATS_TEST_TMPDIR/cron.d"
    export RLCH_CIS_6_1_2_DAILY="$BATS_TEST_TMPDIR/cron.daily"
    export RLCH_CIS_6_1_2_WEEKLY="$BATS_TEST_TMPDIR/cron.weekly"
    export RLCH_CIS_6_1_2_STATE="$RLCH_CIS_6_1_2_CRON_D/.rlch-6.1.2"
    export RLCH_CIS_6_1_2_RPM="$BATS_TEST_TMPDIR/rpm"
    export RLCH_CIS_6_1_2_BINARY="$BATS_TEST_TMPDIR/aide"
    export RLCH_CIS_6_1_2_ID_COMMAND="$BATS_TEST_TMPDIR/id"
    export AIDE_CRON_TEST_STATE="$BATS_TEST_TMPDIR/rpm-state"
    echo installed > "$AIDE_CRON_TEST_STATE"
    cat > "$RLCH_CIS_6_1_2_RPM" <<'MOCK'
#!/usr/bin/env bash
case "$(cat "$AIDE_CRON_TEST_STATE")" in
 installed) echo aide;;
 absent) echo 'package aide is not installed'; exit 1;;
 error) echo 'SECRET query error'; exit 2;;
esac
MOCK
    printf '#!/bin/sh\necho 0\n' > "$RLCH_CIS_6_1_2_ID_COMMAND"
    printf '#!/bin/sh\ntouch "%s"\nexit 99\n' "$BATS_TEST_TMPDIR/REAL_AIDE_CALLED" > "$RLCH_CIS_6_1_2_BINARY"
    chmod 0755 "$RLCH_CIS_6_1_2_RPM" "$RLCH_CIS_6_1_2_ID_COMMAND" "$RLCH_CIS_6_1_2_BINARY"
    mkdir "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_DAILY" "$RLCH_CIS_6_1_2_WEEKLY"
    source "${BATS_TEST_DIRNAME}/../modules/cis/6/1/2/module.sh"
    # Simulate root ownership only; CI fixtures are owned by the runner UID.
    rlch_aide_cron_set_owner() { return 0; }
    TARGET="$RLCH_CIS_6_1_2_CRON_D/rlch-aide-check"
}
teardown() { [ ! -e "$BATS_TEST_TMPDIR/REAL_AIDE_CALLED" ]; }
entry() { printf '%s\n' "$1" > "$RLCH_CIS_6_1_2_CRONTAB"; }
created() { local result=0; apply || result=$?; [ "$result" -eq 4 ]; }
script() { printf '#!/bin/sh\n%s\n' "$2" > "$1"; chmod 0755 "$1"; }
@test "metadata has exact single CAS mapping and Level 1" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/6/1/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.1.2 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking ]
}
@test "absent AIDE is noncompliant and apply never installs a package" {
    entry '05 4 * * * root /usr/sbin/aide --check'
    echo absent > "$AIDE_CRON_TEST_STATE"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
}
@test "RPM errors are redacted errors and absent command is an error" {
    echo error > "$AIDE_CRON_TEST_STATE"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    rm "$RLCH_CIS_6_1_2_RPM"; run check; [ "$status" -eq 2 ]
}
@test "no schedules missing fixed files and missing directories are noncompliant" {
    run check; [ "$status" -eq 1 ]
    rmdir "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_DAILY" "$RLCH_CIS_6_1_2_WEEKLY"
    run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]
}
@test "all CAS upstream tabular pass schedules and redirection forms are accepted" {
    for time in '21 21 * * *' '@daily' '21 21 * * 1-2' '21 21 * * 3' '@weekly' '21 21 * * mon'; do
        entry "$time    root    /usr/sbin/aide --check &>/dev/null"
        run check; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]
    done
}
@test "CAS upstream monthly yearly and absent schedules fail" {
    for time in '21 21 1 * *' '21 21 1 2 *' '@monthly' '@yearly'; do entry "$time root /usr/sbin/aide --check"; run check; [ "$status" -eq 1 ]; done
    rm "$RLCH_CIS_6_1_2_CRONTAB"; run check; [ "$status" -eq 1 ]
}
@test "numeric days zero through seven named days ranges and hourly shortcut pass" {
    for day in 0 1 2 3 4 5 6 7 mon tue wed thu fri sat sun 0-7 1-5; do entry "05 4 * * $day root /usr/sbin/aide --check"; run check; [ "$status" -eq 0 ]; done
    entry '@hourly root /usr/sbin/aide --check'; run check; [ "$status" -eq 0 ]
}
@test "CAS excluded stepped and list schedules and leading whitespace are not promoted" {
    for time in '*/5 4 * * *' '5 4 * * 1,3' '5 * * * *'; do entry "$time root /usr/sbin/aide --check"; run check; [ "$status" -eq 1 ]; done
    entry ' 05 4 * * * root /usr/sbin/aide --check'; run check; [ "$status" -eq 1 ]
}
@test "tab whitespace multiple entries blank lines and comments accepted without execution" {
    printf '# SECRET /usr/sbin/aide --check\n\nMAILTO=root\n05\t4\t*\t*\t*\troot\t/usr/sbin/aide\t--check > /dev/null 2>&1\n' > "$RLCH_CIS_6_1_2_CRONTAB"
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
}
@test "wrong user wrong binary and missing check do not satisfy the control" {
    for line in '05 4 * * * nobody /usr/sbin/aide --check' '05 4 * * * root /bin/aide --check' '05 4 * * * root /usr/sbin/aide --version'; do entry "$line"; run check; [ "$status" -eq 1 ]; done
}
@test "cron.d scheduling among multiple safely read irrelevant files passes" {
    printf '# unrelated\n' > "$RLCH_CIS_6_1_2_CRON_D/other"
    printf '@weekly root /usr/sbin/aide --check\n' > "$RLCH_CIS_6_1_2_CRON_D/aide-check"
    run check; [ "$status" -eq 0 ]
}
@test "root crontab uses no user field and rejects OVAL optional root token" {
    printf '05 4 * * * /usr/sbin/aide --check\n' > "$RLCH_CIS_6_1_2_ROOT_CRON"
    run check; [ "$status" -eq 0 ]
    printf '@weekly root /usr/sbin/aide --check\n' > "$RLCH_CIS_6_1_2_ROOT_CRON"; run check; [ "$status" -eq 2 ]
}
@test "daily and weekly executable shebang scripts support direct and trusted wrappers" {
    for dir in "$RLCH_CIS_6_1_2_DAILY" "$RLCH_CIS_6_1_2_WEEKLY"; do
        script "$dir/aide-check" '/usr/sbin/aide --check'; run check; [ "$status" -eq 0 ]
        script "$dir/aide-check" '/usr/bin/nice /usr/bin/ionice /usr/sbin/aide --check'; run check; [ "$status" -eq 0 ]; rm "$dir/aide-check"
    done
}
@test "upstream bare daily fixture without execute permission or shebang is unsafe" {
    printf '/usr/sbin/aide --check\n' > "$RLCH_CIS_6_1_2_DAILY/aide"
    run check; [ "$status" -eq 2 ]; chmod 0755 "$RLCH_CIS_6_1_2_DAILY/aide"; run check; [ "$status" -eq 2 ]
}
@test "upstream complex daily regenerating and overwriting baseline is rejected" {
    script "$RLCH_CIS_6_1_2_DAILY/aide" $'nice ionice /usr/sbin/aide --check\nnice ionice /usr/sbin/aide --init\n/bin/mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz'
    run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
}
@test "commented scheduling and irrelevant scripts do not pass" {
    entry '# 05 4 * * * root /usr/sbin/aide --check'
    script "$RLCH_CIS_6_1_2_DAILY/other" 'echo unrelated'
    run check; [ "$status" -eq 1 ]
}
@test "shell injection command neutralization wrappers and ambiguous arguments are errors" {
    for command in 'false && /usr/sbin/aide --check' 'echo /usr/sbin/aide --check' '/usr/sbin/aide --check; touch SECRET' '/usr/sbin/aide --check || true' '/usr/sbin/aide --check --config SECRET' '/usr/sbin/aide --init'; do
        entry "05 4 * * * root $command"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "script conditional exit and shell mutations cannot conceal an invocation" {
    for prefix in 'exit 0' 'false &&' 'if false; then' 'PATH=SECRET'; do script "$RLCH_CIS_6_1_2_DAILY/aide" "$prefix"$'\n/usr/sbin/aide --check'; run check; [ "$status" -eq 2 ]; done
}
@test "invalid time field bounds malformed schedule and reverse range are errors" {
    for time in '99 4 * * *' '05 99 * * *' '05 4 0 * *' '05 4 * 13 *' '05 4 * * 9' '05 4 * * 7-0' '@unknown'; do entry "$time root /usr/sbin/aide --check"; run check; [ "$status" -eq 2 ]; done
}
@test "unsafe shell environment missing final newline NUL and CR are errors" {
    entry $'SHELL=/bin/false\n05 4 * * * root /usr/sbin/aide --check'; run check; [ "$status" -eq 2 ]
    printf '05 4 * * * root /usr/sbin/aide --check' > "$RLCH_CIS_6_1_2_CRONTAB"; run check; [ "$status" -eq 2 ]
    for char in '\000' '\r'; do printf "# SECRET${char}\n" > "$RLCH_CIS_6_1_2_CRONTAB"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; done
}
@test "ignored cron filename is error if it contains an AIDE schedule" {
    printf '@daily root /usr/sbin/aide --check\n' > "$RLCH_CIS_6_1_2_CRON_D/aide.bak"
    run check; [ "$status" -eq 2 ]
}
@test "unsafe file does not disappear behind a compliant alternate schedule" {
    entry '@daily root /usr/sbin/aide --check'
    ln -s "$RLCH_CIS_6_1_2_CRONTAB" "$RLCH_CIS_6_1_2_CRON_D/linked"
    run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]
}
@test "symlink directory FIFO and unreadable fixed files are errors" {
    for kind in link directory fifo unreadable; do
        rm -rf "$RLCH_CIS_6_1_2_CRONTAB"
        case "$kind" in link) ln -s "$RLCH_CIS_6_1_2_BINARY" "$RLCH_CIS_6_1_2_CRONTAB";; directory) mkdir "$RLCH_CIS_6_1_2_CRONTAB";; fifo) mkfifo "$RLCH_CIS_6_1_2_CRONTAB";; unreadable) entry '# normal'; chmod 000 "$RLCH_CIS_6_1_2_CRONTAB";; esac
        run check; [ "$status" -eq 2 ]
    done
}
@test "symlink nonregular unreadable and writable cron.d entries are errors" {
    for kind in link directory fifo unreadable writable; do
        file="$RLCH_CIS_6_1_2_CRON_D/bad"; rm -rf "$file"
        case "$kind" in link) ln -s "$RLCH_CIS_6_1_2_BINARY" "$file";; directory) mkdir "$file";; fifo) mkfifo "$file";; unreadable) touch "$file"; chmod 000 "$file";; writable) touch "$file"; chmod 0666 "$file";; esac
        run check; [ "$status" -eq 2 ]
    done
}
@test "unsafe replaced cron directory or parent symlink is an error" {
    mv "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_CRON_D.real"; ln -s "$RLCH_CIS_6_1_2_CRON_D.real" "$RLCH_CIS_6_1_2_CRON_D"
    run check; [ "$status" -eq 2 ]
}
@test "read failure detected without exposing cron content" {
    entry '@daily root /usr/sbin/aide --check'; rlch_aide_cron_scan() { return 2; }
    run check; [ "$status" -eq 2 ]
}
@test "content inode and metadata changes during observation are errors" {
    eval "$(declare -f rlch_aide_cron_scan | sed '1s/rlch_aide_cron_scan/original_scan/')"
    for change in content inode mode; do
        entry '@daily root /usr/sbin/aide --check'; chmod 0644 "$RLCH_CIS_6_1_2_CRONTAB"
        rlch_aide_cron_scan() {
            original_scan "$@"
            case "$change" in content) echo '# edit' >> "$1";; inode) cp -p "$1" "$1.new"; mv "$1.new" "$1";; mode) chmod 0600 "$1";; esac
        }
        run check; [ "$status" -eq 2 ]
    done
}
@test "directory inode replacement during check is detected" {
    entry '@daily root /usr/sbin/aide --check'
    eval "$(declare -f rlch_aide_cron_scan | sed '1s/rlch_aide_cron_scan/original_scan/')"
    rlch_aide_cron_scan() { original_scan "$@"; mv "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_CRON_D.old"; mkdir "$RLCH_CIS_6_1_2_CRON_D"; }
    run check; [ "$status" -eq 2 ]
}
@test "RPM state change during observation is an error" {
    entry '@daily root /usr/sbin/aide --check'
    eval "$(declare -f rlch_aide_cron_scan | sed '1s/rlch_aide_cron_scan/original_scan/')"
    rlch_aide_cron_scan() { original_scan "$@"; echo absent > "$AIDE_CRON_TEST_STATE"; }
    run check; [ "$status" -eq 2 ]
}
@test "compliant apply leaves exact original schedules and no journal" {
    entry '@weekly root /usr/sbin/aide --check'; before=$(stat -c '%i:%a:%y:%z' "$RLCH_CIS_6_1_2_CRONTAB")
    run apply; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(stat -c '%i:%a:%y:%z' "$RLCH_CIS_6_1_2_CRONTAB")" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
}
@test "create dedicated daily schedule mode journal and idempotent second apply" {
    created; [ -f "$TARGET" ]; [ "$(stat -c %a "$TARGET")" = 644 ]; [ "$(stat -c %a "$RLCH_CIS_6_1_2_STATE")" = 700 ]
    grep -Fx '05 4 * * * root /usr/sbin/aide --check' "$TARGET"
    before=$(stat -c '%i:%a:%y:%z' "$TARGET"); run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]
    [ "$before" = "$(stat -c '%i:%a:%y:%z' "$TARGET")" ]
}
@test "rollback removes only exact created inode and second rollback succeeds" {
    created; run rollback; [ "$status" -eq 4 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
    run rollback; [ "$status" -eq 0 ]
}
@test "noncompliant administrator entries are preserved through apply and rollback" {
    entry '05 4 1 * * root /usr/sbin/aide --check'; before=$(sha256sum "$RLCH_CIS_6_1_2_CRONTAB")
    created; run rollback; [ "$status" -eq 4 ]; [ "$before" = "$(sha256sum "$RLCH_CIS_6_1_2_CRONTAB")" ]
}
@test "target or journal collision never overwrites administrator objects" {
    printf 'administrator\n' > "$TARGET"; before=$(sha256sum "$TARGET"); run apply; [ "$status" -eq 2 ]; [ "$before" = "$(sha256sum "$TARGET")" ]
    rm "$TARGET"; mkdir -m 0700 "$RLCH_CIS_6_1_2_STATE"; run apply; [ "$status" -eq 2 ]; [ -d "$RLCH_CIS_6_1_2_STATE" ]
}
@test "binary absent symlink nonexecutable or writable prevents automatic creation" {
    for kind in missing link noexec writable; do
        rm -f "$RLCH_CIS_6_1_2_BINARY"
        case "$kind" in missing) :;; link) ln -s "$RLCH_CIS_6_1_2_RPM" "$RLCH_CIS_6_1_2_BINARY";; noexec) touch "$RLCH_CIS_6_1_2_BINARY"; chmod 0644 "$RLCH_CIS_6_1_2_BINARY";; writable) touch "$RLCH_CIS_6_1_2_BINARY"; chmod 0777 "$RLCH_CIS_6_1_2_BINARY";; esac
        run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
    done
}
@test "create refuses nonroot or unsafe cron directory" {
    printf '#!/bin/sh\necho 1001\n' > "$RLCH_CIS_6_1_2_ID_COMMAND"; run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
    printf '#!/bin/sh\necho 0\n' > "$RLCH_CIS_6_1_2_ID_COMMAND"; chmod 0777 "$RLCH_CIS_6_1_2_CRON_D"; run apply; [ "$status" -eq 2 ]
}
@test "competing target at publication is preserved and empty transaction is removed" {
    rlch_tmout_link() { printf 'third party\n' > "$2"; /usr/bin/ln -- "$1" "$2"; }
    run apply; [ "$status" -eq 2 ]; [ "$(cat "$TARGET")" = 'third party' ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
}
@test "configuration changed before publication aborts without creating a task" {
    rlch_aide_cron_set_owner() { entry '# concurrent edit'; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]; [ -f "$RLCH_CIS_6_1_2_CRONTAB" ]
}
@test "cron directory replaced before publication preserves replacement and journal" {
    rlch_aide_cron_set_owner() { mv "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_CRON_D.old"; mkdir "$RLCH_CIS_6_1_2_CRON_D"; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ -d "$RLCH_CIS_6_1_2_CRON_D.old/.rlch-6.1.2" ]
}
@test "publication failure and failed post-validation restore only created file" {
    rlch_tmout_link() { return 1; }; run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
    rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; }; validate() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
}
@test "failed immediate restoration retains isolated recovery journal" {
    validate() { return 1; }; rlch_tmout_remove() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ -f "$TARGET" ]; [ -d "$RLCH_CIS_6_1_2_STATE" ]
}
@test "rollback refuses modified content permissions owner group or replaced inode" {
    for change in content mode inode; do
        created
        case "$change" in content) echo '# edit' >> "$TARGET";; mode) chmod 0600 "$TARGET";; inode) cp -p "$TARGET" "$TARGET.new"; mv "$TARGET.new" "$TARGET";; esac
        before=$(stat -c '%i:%a:%y:%z' "$TARGET"); run rollback; [ "$status" -eq 2 ]; [ -d "$RLCH_CIS_6_1_2_STATE" ]
        [ "$before" = "$(stat -c '%i:%a:%y:%z' "$TARGET")" ]
        rm "$TARGET"; rm -rf "$RLCH_CIS_6_1_2_STATE"
    done
}
@test "rollback refuses symlink substitution or administrator removal" {
    for change in symlink removed; do
        created; rm "$TARGET"
        if [[ "$change" == symlink ]]; then ln -s "$RLCH_CIS_6_1_2_BINARY" "$TARGET"; fi
        run rollback; [ "$status" -eq 2 ]; [ -d "$RLCH_CIS_6_1_2_STATE" ]
        if [[ "$change" == symlink ]]; then [ -L "$TARGET" ]; rm "$TARGET"; fi
        rm -rf "$RLCH_CIS_6_1_2_STATE"
    done
}
@test "rollback refuses unsafe replaced journal or relocated state" {
    created; chmod 0755 "$RLCH_CIS_6_1_2_STATE"; run rollback; [ "$status" -eq 2 ]; [ -f "$TARGET" ]
    RLCH_CIS_6_1_2_STATE="$BATS_TEST_TMPDIR/other"; mkdir -m 0700 "$RLCH_CIS_6_1_2_STATE"; run rollback; [ "$status" -eq 2 ]
}
@test "independence from AIDE databases config and previous cron-control state" {
    mkdir "$BATS_TEST_TMPDIR/previous"
    for name in aide.conf aide.db.gz aide.db.new.gz cron-state cron-access passwd shadow; do echo previous > "$BATS_TEST_TMPDIR/previous/$name"; done
    before=$(sha256sum "$BATS_TEST_TMPDIR/previous/"*)
    created; run rollback; [ "$status" -eq 4 ]; [ "$before" = "$(sha256sum "$BATS_TEST_TMPDIR/previous/"*)" ]
}

@test "cooperating directory lock blocks apply and rollback without mutation" {
    exec {held}<"$RLCH_CIS_6_1_2_CRON_D"; /usr/bin/flock -n -x "$held"
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; exec {held}<&-
    created; exec {held}<"$RLCH_CIS_6_1_2_CRON_D"; /usr/bin/flock -n -x "$held"
    run rollback; [ "$status" -eq 2 ]; [ -f "$TARGET" ]; exec {held}<&-
    run rollback; [ "$status" -eq 4 ]
}
@test "owner or group drift is detected by the retained identity" {
    eval "$(declare -f rlch_tmout_payload_identity | sed '1s/rlch_tmout_payload_identity/original_identity/')"
    for kind in owner group; do
        created
        rlch_tmout_payload_identity() {
            original_identity "$@" | /usr/bin/awk -v kind="$kind" '''BEGIN {FS=OFS=":"} NR==1 {if(kind=="owner") $3="65534";else $4="65534"} {print}'''
        }
        run rollback; [ "$status" -eq 2 ]; [ -f "$TARGET" ]; [ -d "$RLCH_CIS_6_1_2_STATE" ]
        rm "$TARGET"; rm -rf "$RLCH_CIS_6_1_2_STATE"
        eval "$(declare -f original_identity | sed '1s/original_identity/rlch_tmout_payload_identity/')"
    done
}
@test "binary change before publication and failed ownership setup abort safely" {
    rlch_aide_cron_set_owner() { chmod 0700 "$RLCH_CIS_6_1_2_BINARY"; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
    rlch_aide_cron_set_owner() { return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
}
@test "observed change after publication restores our task and preserves administrator edit" {
    entry '05 4 1 * * root /usr/sbin/aide --check'
    rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; entry '# concurrent administrator edit'; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
    [ "$(cat "$RLCH_CIS_6_1_2_CRONTAB")" = '# concurrent administrator edit' ]
}
@test "partial publication failure restores only our linked inode" {
    rlch_tmout_link() { /usr/bin/ln -- "$1" "$2"; return 1; }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]; [ ! -e "$RLCH_CIS_6_1_2_STATE" ]
}
@test "publication anchored to held directory never writes into its replacement" {
    rlch_tmout_link() {
        mv "$RLCH_CIS_6_1_2_CRON_D" "$RLCH_CIS_6_1_2_CRON_D.old"
        mkdir "$RLCH_CIS_6_1_2_CRON_D"
        printf 'administrator replacement\n' > "$TARGET"
        /usr/bin/ln -- "$1" "$2"
    }
    run apply; [ "$status" -eq 2 ]; [ "$(cat "$TARGET")" = 'administrator replacement' ]
    [ -f "$RLCH_CIS_6_1_2_CRON_D.old/rlch-aide-check" ]; [ -d "$RLCH_CIS_6_1_2_CRON_D.old/.rlch-6.1.2" ]
}
@test "private journal replacement during preparation is retained and never cleaned as ours" {
    rlch_aide_cron_set_owner() {
        mv "$RLCH_CIS_6_1_2_STATE" "$RLCH_CIS_6_1_2_STATE.old"
        mkdir -m 0700 "$RLCH_CIS_6_1_2_STATE"
        echo administrator > "$RLCH_CIS_6_1_2_STATE/payload"
    }
    run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
    [ "$(cat "$RLCH_CIS_6_1_2_STATE/payload")" = administrator ]
    [ -d "$RLCH_CIS_6_1_2_STATE.old" ]
}

@test "environment preload and PATH dependent script wrappers require manual review" {
    entry $'BASH_ENV=/tmp/SECRET\n@daily root /usr/sbin/aide --check'; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    rm "$RLCH_CIS_6_1_2_CRONTAB"
    script "$RLCH_CIS_6_1_2_DAILY/aide" 'nice ionice /usr/sbin/aide --check'; run check; [ "$status" -eq 2 ]
}

@test "malformed steps lists and ranges cannot hide behind a valid alternate entry" {
    for bad in - / '*/0' 1--2 1, 5/ 5//2 4-99; do
        entry "05 4 * * * root /usr/sbin/aide --check"$'\n'"$bad 4 * * * root /usr/sbin/aide --check"
        run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$TARGET" ]
    done
}
