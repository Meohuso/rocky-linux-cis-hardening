#!/usr/bin/env bats
setup() {
    source "${BATS_TEST_DIRNAME}/test_helper.bash"
    source "${BATS_TEST_DIRNAME}/../lib/module_api.sh"
    export RLCH_CIS_6_1_1_CONFIG="$BATS_TEST_TMPDIR/aide.conf"
    export RLCH_CIS_6_1_1_RPM="$BATS_TEST_TMPDIR/rpm"
    export AIDE_TEST_RPM_STATE="$BATS_TEST_TMPDIR/rpm-state"
    export AIDE_TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    echo installed > "$AIDE_TEST_RPM_STATE"
    cat > "$RLCH_CIS_6_1_1_RPM" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AIDE_TEST_CALLS"
[[ "$1" == -q && "$2" == --qf && "$4" == aide ]] || exit 3
case "$(cat "$AIDE_TEST_RPM_STATE")" in
    installed) echo aide;;
    absent) echo 'package aide is not installed'; exit 1;;
    corrupt) echo 'RPMDB SECRET corrupt'; exit 1;;
    error) echo 'RPM SECRET failed' >&2; exit 2;;
    empty) exit 0;;
    wrong) echo 'other-package';;
    duplicate) printf 'aide\naide\n';;
esac
MOCK
    chmod 0755 "$RLCH_CIS_6_1_1_RPM"
    mkdir "$BATS_TEST_TMPDIR/db"
    DBFILE="$BATS_TEST_TMPDIR/db/aide.db.gz"
    printf 'fixture database\n' > "$DBFILE"
    printf '@@define DBDIR %s\ndatabase=file:@@{DBDIR}/aide.db.gz\ndatabase_out=file:@@{DBDIR}/aide.db.new.gz\n' "$BATS_TEST_TMPDIR/db" > "$RLCH_CIS_6_1_1_CONFIG"
    source "${BATS_TEST_DIRNAME}/../modules/cis/6/1/1/module.sh"
    # These mutation mocks must never be invoked by this observation-only module.
    aide() { echo aide >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
    dnf_install_package() { echo install >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
    dnf_remove_package() { echo remove >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
}
@test "Level 1 composite mapping is manual" {
    source "${BATS_TEST_DIRNAME}/../modules/cis/6/1/1/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.1.1 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "installed package and present fixture database pass all observation functions" {
    run check; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run validate; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "RPM package absence is non compliance and apply manual error" {
    echo absent > "$AIDE_TEST_RPM_STATE"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'package is absent'* ]]; run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]
    [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "RPM query errors unexpected success output and unavailable command are errors" {
    for state in corrupt error empty wrong; do echo "$state" > "$AIDE_TEST_RPM_STATE"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; done
    RLCH_CIS_6_1_1_RPM="$BATS_TEST_TMPDIR/missing-rpm"; run check; [ "$status" -eq 2 ]
}
@test "multiple installed RPM instances allowed and binary presence does not substitute" {
    echo duplicate > "$AIDE_TEST_RPM_STATE"; run check; [ "$status" -eq 0 ]
    echo absent > "$AIDE_TEST_RPM_STATE"; touch "$BATS_TEST_TMPDIR/aide"; run check; [ "$status" -eq 1 ]
}
@test "database_in compatibility accepted without RHEL10 replacing baseline" {
    sed -i 's/^database=/database_in=/' "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 0 ]
}
@test "missing config or required directives safely return non compliance" {
    rm "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 1 ]
    printf '# no directives\n' > "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 1 ]
    printf 'database=file:/var/lib/aide/aide.db.gz\n' > "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 1 ]
}
@test "absent and empty database are non compliant but preserved on apply" {
    : > "$DBFILE"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; [ -f "$DBFILE" ]; [ ! -s "$DBFILE" ]
    rm "$DBFILE"; run check; [ "$status" -eq 1 ]; run apply; [ "$status" -eq 2 ]; [ ! -e "$DBFILE" ]
}
@test "only operational database needed new database presence not required" {
    [ ! -e "$BATS_TEST_TMPDIR/db/aide.db.new.gz" ]; run check; [ "$status" -eq 0 ]
    printf 'new fixture\n' > "$BATS_TEST_TMPDIR/db/aide.db.new.gz"; rm "$DBFILE"
    run check; [ "$status" -eq 1 ]
}
@test "comments ignored and identical duplicate first definitions accepted" {
    printf '# database_in=sql:SECRET\n@@define DBDIR %s\n@@define DBDIR %s\ndatabase=file:@@{DBDIR}/aide.db.gz\ndatabase_in=file:@@{DBDIR}/aide.db.gz\n' "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/db" > "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 0 ]; [[ "$output" != *SECRET* ]]
}
@test "conflicting duplicate DBDIR or operational URIs are ambiguous errors" {
    printf '@@define DBDIR /different\n' >> "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 2 ]
    sed -i '$d' "$RLCH_CIS_6_1_1_CONFIG"; printf 'database_in=file:@@{DBDIR}/other.db.gz\n' >> "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 2 ]
}
@test "DBDIR order after the operational URI is supported" {
    printf 'database=file:@@{DBDIR}/aide.db.gz\n@@define DBDIR %s\n' "$BATS_TEST_TMPDIR/db" > "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 0 ]
}
@test "literal absolute RHEL path supported using only mapped fixture observations" {
    printf '@@define DBDIR /var/lib/aide\ndatabase=file:/var/lib/aide/aide.db.gz\n' > "$RLCH_CIS_6_1_1_CONFIG"
    eval "$(declare -f rlch_aide_database_stamp | sed '1s/rlch_aide_database_stamp/original_db_stamp/')"
    rlch_aide_database_stamp() { [[ "$1" == /var/lib/aide/aide.db.gz ]] || return 2; original_db_stamp "$DBFILE"; }
    run check; [ "$status" -eq 0 ]
}
@test "OVAL DBDIR basename composition does not hide actual subdirectory absence" {
    sed -i 's@DBDIR}/aide.db.gz@DBDIR}/nested/aide.db.gz@' "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 1 ]; [[ "$output" == *'path differ'* ]]
    mkdir "$BATS_TEST_TMPDIR/db/nested"; cp "$DBFILE" "$BATS_TEST_TMPDIR/db/nested/aide.db.gz"
    run check; [ "$status" -eq 0 ]; rm "$DBFILE"; run check; [ "$status" -eq 1 ]
}
@test "relative SQL remote unsupported macro and unsupported filename return error" {
    for value in 'file:aide.db.gz' 'sql:SECRET' 'https://SECRET/aide.db' 'file:@@{OTHER}/aide.db.gz' 'file:/var/lib/aide/aide-123.db'; do
        printf '@@define DBDIR %s\ndatabase_in=%s\n' "$BATS_TEST_TMPDIR/db" "$value" > "$RLCH_CIS_6_1_1_CONFIG"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "unrecognized first operational definition is not skipped to a later matching one" {
    printf '@@define DBDIR %s\ndatabase_in=sql:SECRET\ndatabase=file:@@{DBDIR}/aide.db.gz\n' "$BATS_TEST_TMPDIR/db" > "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
}
@test "inline comments leading indentation alternate spacing are unsupported errors" {
    for line in ' database=file:@@{DBDIR}/aide.db.gz' 'database =file:@@{DBDIR}/aide.db.gz' 'database=file:@@{DBDIR}/aide.db.gz # SECRET' 'database malformed'; do
        printf '@@define DBDIR %s\n%s\n' "$BATS_TEST_TMPDIR/db" "$line" > "$RLCH_CIS_6_1_1_CONFIG"
        run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]
    done
}
@test "include conditional dynamic DBDIR and traversal require manual review" {
    for extra in '@@include SECRET' '@@ifhost SECRET' '@@undef DBDIR'; do printf '%s\n' "$extra" >> "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 2 ]; sed -i '$d' "$RLCH_CIS_6_1_1_CONFIG"; done
    printf '@@define DBDIR %s/../db\ndatabase=file:@@{DBDIR}/aide.db.gz\n' "$BATS_TEST_TMPDIR/db" > "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 2 ]
}
@test "symlink directory FIFO unreadable config are errors" {
    cp "$RLCH_CIS_6_1_1_CONFIG" "$BATS_TEST_TMPDIR/saved"
    for kind in link dir fifo unreadable; do
        rm -rf "$RLCH_CIS_6_1_1_CONFIG"
        case "$kind" in link) ln -s "$BATS_TEST_TMPDIR/saved" "$RLCH_CIS_6_1_1_CONFIG";; dir) mkdir "$RLCH_CIS_6_1_1_CONFIG";; fifo) mkfifo "$RLCH_CIS_6_1_1_CONFIG";; unreadable) cp "$BATS_TEST_TMPDIR/saved" "$RLCH_CIS_6_1_1_CONFIG"; chmod 000 "$RLCH_CIS_6_1_1_CONFIG";; esac
        run check; [ "$status" -eq 2 ]
    done
}
@test "symlink directory FIFO unreadable database are errors without overwrite" {
    for kind in link dir fifo unreadable; do
        rm -rf "$DBFILE"
        case "$kind" in link) ln -s "$RLCH_CIS_6_1_1_CONFIG" "$DBFILE";; dir) mkdir "$DBFILE";; fifo) mkfifo "$DBFILE";; unreadable) touch "$DBFILE"; chmod 000 "$DBFILE";; esac
        run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]; [ -e "$DBFILE" ]
    done
}
@test "NUL CR unsupported control config never prints contents" {
    for char in '\000' '\r'; do printf "# SECRET${char}\n" > "$RLCH_CIS_6_1_1_CONFIG"; run check; [ "$status" -eq 2 ]; [[ "$output" != *SECRET* ]]; done
}
@test "parent symlink and unsearchable database ancestor are errors" {
    mv "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/realdb"; ln -s "$BATS_TEST_TMPDIR/realdb" "$BATS_TEST_TMPDIR/db"
    run check; [ "$status" -eq 2 ]; rm "$BATS_TEST_TMPDIR/db"; mv "$BATS_TEST_TMPDIR/realdb" "$BATS_TEST_TMPDIR/db"
    rm "$DBFILE"; chmod 0444 "$BATS_TEST_TMPDIR/db"; run check; [ "$status" -eq 2 ]; chmod 0755 "$BATS_TEST_TMPDIR/db"
}
@test "RPM state changed during check is error" {
    eval "$(declare -f rlch_aide_config_rows | sed '1s/rlch_aide_config_rows/original_rows/')"
    rlch_aide_config_rows() { original_rows "$@"; echo absent > "$AIDE_TEST_RPM_STATE"; }
    run check; [ "$status" -eq 2 ]
}
@test "configuration changed during observation is error" {
    eval "$(declare -f rlch_aide_config_rows | sed '1s/rlch_aide_config_rows/original_rows/')"
    rlch_aide_config_rows() { original_rows "$@"; printf '# changed\n' >> "$RLCH_CIS_6_1_1_CONFIG"; }
    run check; [ "$status" -eq 2 ]
}
@test "database metadata or inode changed during observation is error" {
    eval "$(declare -f rlch_aide_database_stamp | sed '1s/rlch_aide_database_stamp/original_stamp/')"
    rlch_aide_database_stamp() { original_stamp "$@"; printf '# changed\n' >> "$DBFILE"; }
    run check; [ "$status" -eq 2 ]
}
@test "read failure is error rather than absent or non compliant" {
    rlch_aide_config_rows() { return 2; }; run check; [ "$status" -eq 2 ]
}
@test "compliant repeated apply rollback preserve exact content and metadata no state" {
    before=$(sha256sum "$RLCH_CIS_6_1_1_CONFIG" "$DBFILE")
    metadata=$(stat -c '%i:%a:%y:%z' "$DBFILE")
    run apply; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(sha256sum "$RLCH_CIS_6_1_1_CONFIG" "$DBFILE")" ]; [ "$metadata" = "$(stat -c '%i:%a:%y:%z' "$DBFILE")" ]
    [ ! -e "$BATS_TEST_TMPDIR/mutations" ]; [ ! -e "$RLCH_CIS_6_1_1_CONFIG.rlch.bak" ]
}
@test "installation and init success failure or missing-output mocks are never called" {
    for outcome in 0 1 2; do
        aide() { echo "$outcome" >> "$BATS_TEST_TMPDIR/mutations"; return "$outcome"; }
        dnf_install_package() { echo "$outcome" >> "$BATS_TEST_TMPDIR/mutations"; return "$outcome"; }
        echo absent > "$AIDE_TEST_RPM_STATE"; run apply; [ "$status" -eq 2 ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
        echo installed > "$AIDE_TEST_RPM_STATE"; rm -f "$DBFILE"; run apply; [ "$status" -eq 2 ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]; [ ! -e "$DBFILE" ]
    done
}
@test "preexisting administrator database remains intact across all error paths" {
    printf 'administrator SECRET baseline\n' > "$DBFILE"; before=$(sha256sum "$DBFILE")
    echo corrupt > "$AIDE_TEST_RPM_STATE"; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(sha256sum "$DBFILE")" ]; [[ "$output" != *SECRET* ]]
}
@test "previous umask TMOUT account configuration and per-control state unchanged" {
    mkdir "$BATS_TEST_TMPDIR/previous"
    for name in bashrc login.defs profile tmout.sh umask.sh shadow passwd state; do printf 'previous\n' > "$BATS_TEST_TMPDIR/previous/$name"; done
    before=$(sha256sum "$BATS_TEST_TMPDIR/previous/"*)
    run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(sha256sum "$BATS_TEST_TMPDIR/previous/"*)" ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}

@test "database inode replacement with identical bytes is detected and preserved" {
    eval "$(declare -f rlch_aide_database_stamp | sed '1s/rlch_aide_database_stamp/original_stamp/')"
    rlch_aide_database_stamp() {
        original_stamp "$@"
        cp -p "$DBFILE" "$DBFILE.replacement"
        mv "$DBFILE.replacement" "$DBFILE"
    }
    run check; [ "$status" -eq 2 ]
    run rollback; [ "$status" -eq 0 ]; [ -f "$DBFILE" ]
}
@test "database permission change deletion and symlink replacement during observation fail safely" {
    eval "$(declare -f rlch_aide_database_stamp | sed '1s/rlch_aide_database_stamp/original_stamp/')"
    for change in mode delete symlink; do
        rm -f "$DBFILE"; printf 'fixture database\n' > "$DBFILE"; chmod 0644 "$DBFILE"
        rlch_aide_database_stamp() {
            original_stamp "$@"
            case "$change" in
                mode) chmod 0600 "$DBFILE";;
                delete) rm "$DBFILE";;
                symlink) rm "$DBFILE"; ln -s "$RLCH_CIS_6_1_1_CONFIG" "$DBFILE";;
            esac
        }
        run check; [ "$status" -eq 2 ]
        run rollback; [ "$status" -eq 0 ]
        case "$change" in
            mode) [ "$(stat -c %a "$DBFILE")" = 600 ];;
            delete) [ ! -e "$DBFILE" ];;
            symlink) [ -L "$DBFILE" ];;
        esac
    done
}
@test "first definition followed by unsupported definition fails instead of guessing precedence" {
    printf 'database_in=file:relative.db\n' >> "$RLCH_CIS_6_1_1_CONFIG"
    run check; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]
    [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
