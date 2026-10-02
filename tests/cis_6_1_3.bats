#!/usr/bin/env bats
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_1_3_CONFIG="$BATS_TEST_TMPDIR/aide.conf"
    export RLCH_CIS_6_1_3_RPM="$BATS_TEST_TMPDIR/rpm"
    export TOOLS_RPM_STATE="$BATS_TEST_TMPDIR/rpm-state"
    export TOOLS_CALLS="$BATS_TEST_TMPDIR/calls"
    echo installed > "$TOOLS_RPM_STATE"
    cat > "$RLCH_CIS_6_1_3_RPM" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TOOLS_CALLS"
[[ "$1" == -q && "$2" == --qf && "$4" == aide ]] || exit 3
case "$(cat "$TOOLS_RPM_STATE")" in
installed) echo aide;;
duplicate) printf 'aide\naide\n';;
absent) echo 'package aide is not installed'; exit 1;;
corrupt) echo 'SECRET RPM corrupt'; exit 1;;
error) echo 'SECRET RPM error' >&2; exit 2;;
empty) exit 0;;
wrong) echo other;;
esac
MOCK
    chmod 0755 "$RLCH_CIS_6_1_3_RPM"
    ATTRS='p+i+n+u+g+s+b+acl+xattrs+sha512'
    RICHER='p+i+n+u+g+s+b+acl+selinux+xattrs+sha512'
    fixture
    source "$BATS_TEST_DIRNAME/../modules/cis/6/1/3/module.sh"
    aide() { echo aide >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
    dnf_install_package() { echo install >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
    dnf_remove_package() { echo remove >> "$BATS_TEST_TMPDIR/mutations"; return 1; }
}
fixture() {
    local prefix="${1:-/usr/sbin}" attrs="${2:-$ATTRS}" tool
    : > "$RLCH_CIS_6_1_3_CONFIG"
    for tool in auditctl auditd ausearch aureport autrace augenrules; do
        printf '%s/%s %s\n' "$prefix" "$tool" "$attrs" >> "$RLCH_CIS_6_1_3_CONFIG"
    done
    chmod 0644 "$RLCH_CIS_6_1_3_CONFIG"
}
expect() { run check; [ "$status" -eq "$1" ]; [[ "$output" != *SECRET* ]]; }
@test "6.1.3 metadata exact Level 1 enabled no reboot primary mapping" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/1/3/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.1.3 ]; [ "$RLCH_MODULE_LEVEL" = 1 ]
    [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]
    [ "$RLCH_MODULE_OPENSCAP_RULE" = xccdf_org.ssgproject.content_rule_aide_check_audit_tools ]
}
@test "installed and six direct requirements succeed check validate apply rollback" {
    expect 0; run validate; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "package absent is non compliant apply manual ERROR" {
    echo absent > "$TOOLS_RPM_STATE"; expect 1
    run apply; [ "$status" -eq 2 ]; [[ "$output" == *manual* ]]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "RPM query errors and malformed success never become package absence" {
    for value in corrupt error empty wrong; do echo "$value" > "$TOOLS_RPM_STATE"; expect 2; done
}
@test "missing RPM command is ERROR" {
    RLCH_CIS_6_1_3_RPM="$BATS_TEST_TMPDIR/missing"; expect 2;
}
@test "multiple installed RPM instances accepted" {
    echo duplicate > "$TOOLS_RPM_STATE"; expect 0;
}
@test "missing configuration is non compliant and never created" {
    rm "$RLCH_CIS_6_1_3_CONFIG"; expect 1; run apply; [ "$status" -eq 2 ]; [ ! -e "$RLCH_CIS_6_1_3_CONFIG" ]
}
@test "empty configuration non compliant preserved on apply" {
    : > "$RLCH_CIS_6_1_3_CONFIG"; expect 1; run apply; [ "$status" -eq 2 ]; [ ! -s "$RLCH_CIS_6_1_3_CONFIG" ]
}
@test "comments-only non compliant" {
    printf '# SECRET\n \t# ignore\n\n' > "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
# Upstream fixture DATA replay from pinned CAS a4b23038, not shell execution:
# correct.pass.sh has --init setup; not_config.fail.sh echoes a sed command.
# Those setup actions are not executed or asserted as production behavior.
@test "CAS correct.pass.sh six usr sbin baseline attributes" {
    fixture /usr/sbin "$ATTRS"; expect 0;
}
@test "CAS correct_with_selinux.pass.sh richer attributes" {
    fixture /usr/sbin "$RICHER"; expect 0;
}
@test "CAS expect_sbin_path.pass.sh legacy path accepted" {
    fixture /sbin "$ATTRS"; expect 0;
}
@test "CAS extra_suffix.fail.sh sha5122 rejected" {
    fixture /usr/sbin "${RICHER}2"; expect 1;
}
@test "CAS not_config.fail.sh no explicit requirements" {
    printf '# no audit tools configured\n' > "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
@test "each of all six individually missing is non compliant" {
    local tool
    for tool in auditctl auditd ausearch aureport autrace augenrules; do fixture; sed -i "\@^/usr/sbin/$tool @d" "$RLCH_CIS_6_1_3_CONFIG"; expect 1; done
}
@test "additional unrelated binaries never replace missing autrace" {
    sed -i '\@/usr/sbin/autrace @d' "$RLCH_CIS_6_1_3_CONFIG"
    for tool in audispd rsyslogd audisp-syslog; do printf '/usr/sbin/%s %s\n' "$tool" "$ATTRS" >> "$RLCH_CIS_6_1_3_CONFIG"; done
    expect 1
}
@test "mixed accepted paths and attribute variants" {
    sed -i "2s@/usr/sbin@/sbin@;4s@$ATTRS@$RICHER@" "$RLCH_CIS_6_1_3_CONFIG"; expect 0
}
@test "selinux only at exact accepted position" {
    fixture /usr/sbin 'p+i+n+u+g+s+b+selinux+acl+xattrs+sha512'; expect 1;
}
@test "sha256 rejected" {
    fixture /usr/sbin 'p+i+n+u+g+s+b+acl+xattrs+sha256'; expect 1;
}
@test "missing sha512 rejected" {
    fixture /usr/sbin 'p+i+n+u+g+s+b+acl+xattrs'; expect 1;
}
@test "missing individual attribute rejected" {
    fixture /usr/sbin 'p+i+n+u+g+s+b+xattrs+sha512'; expect 1;
}
@test "additional attribute rejected" {
    fixture /usr/sbin "$ATTRS+md5"; expect 1;
}
@test "reordered attribute rejected" {
    fixture /usr/sbin 'i+p+n+u+g+s+b+acl+xattrs+sha512'; expect 1;
}
@test "trailing spaces not trimmed unlike shell word splitting" {
    sed -i 's/$/ /' "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
@test "tabs and repeated separator spaces accepted" {
    sed -i 's/ /\t  /' "$RLCH_CIS_6_1_3_CONFIG"; expect 0;
}
@test "leading whitespace does not match anchored OVAL" {
    sed -i '1s/^/ /' "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
@test "inline comment violates exact attributes" {
    sed -i '1s/$/ # SECRET/' "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
@test "case and wrong paths do not satisfy OVAL" {
    for prefix in /usr/bin /bin /opt/sbin; do fixture "$prefix"; expect 1; done
    fixture; sed -i 's/auditctl/AUDITCTL/' "$RLCH_CIS_6_1_3_CONFIG"; expect 1
}
@test "similar tool name suffix never substitutes" {
    sed -i 's/auditctl /auditctl2 /' "$RLCH_CIS_6_1_3_CONFIG"; expect 1;
}
@test "conforming first then bad duplicate is defensive ERROR" {
    printf '/usr/sbin/auditctl %s2\n' "$ATTRS" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2
}
@test "bad first then conforming duplicate remains non compliant" {
    sed -i "1s@$ATTRS@${ATTRS}2@" "$RLCH_CIS_6_1_3_CONFIG"
    printf '/usr/sbin/auditctl %s\n' "$ATTRS" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 1
}
@test "identical conforming duplicates accepted" {
    cat "$RLCH_CIS_6_1_3_CONFIG" >> "$BATS_TEST_TMPDIR/copy"; cat "$BATS_TEST_TMPDIR/copy" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 0;
}
@test "conforming mixed path duplicates accepted" {
    printf '/sbin/auditctl %s\n' "$RICHER" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 0;
}
@test "mixed path good then bad defensive ERROR" {
    printf '/sbin/auditctl sha256\n' >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "mixed path bad first good later still non compliant" {
    sed -i '1s@/usr/sbin/auditctl .*@/sbin/auditctl sha256@' "$RLCH_CIS_6_1_3_CONFIG"
    printf '/usr/sbin/auditctl %s\n' "$ATTRS" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 1
}
@test "static group definitions and unrelated directives not expanded" {
    printf 'NORMAL = p+i+n+u+g\ndatabase=file:@@{DBDIR}/aide.db.gz\nreport_url=stdout\n/etc NORMAL\n@@define DBDIR /var/lib/aide\n' >> "$RLCH_CIS_6_1_3_CONFIG"; expect 0
}
@test "target attribute group requires manual interpretation" {
    sed -i '1s/ .*/ SECRET/' "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "include conditional undef executable macros rejected" {
    for line in '@@include SECRET' '@@ifhost SECRET' '@@undef SECRET' '@@define SECRET @@(exec)'; do fixture; printf '%s\n' "$line" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2; done
}
@test "dynamic target expansion rejected" {
    sed -i '1s/ .*/ @@{SECRET}/' "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "explicit target exclusion or equals rules are ambiguous" {
    for prefix in '!' '=' '-'; do fixture; printf '%s/usr/sbin/auditctl %s\n' "$prefix" "$ATTRS" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2; done
}
@test "commented unsupported syntax ignored" {
    printf '  # @@include SECRET\n# !/usr/sbin/auditctl\n' >> "$RLCH_CIS_6_1_3_CONFIG"; expect 0;
}
@test "no final newline accepted" {
    truncate -s -1 "$RLCH_CIS_6_1_3_CONFIG"; expect 0;
}
@test "NUL CR and other controls are ERROR without contents" {
    for char in '\000' '\r' '\001'; do fixture; printf "# SECRET${char}\n" >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2; done
}
@test "overlong line ERROR even in comment" {
    printf '#%09000d\n' 0 >> "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "oversized file ERROR before parser" {
    truncate -s 1048577 "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "symlink configuration ERROR" {
    mv "$RLCH_CIS_6_1_3_CONFIG" "$BATS_TEST_TMPDIR/saved"; ln -s "$BATS_TEST_TMPDIR/saved" "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "directory or FIFO configuration ERROR without blocking" {
    rm "$RLCH_CIS_6_1_3_CONFIG"; mkdir "$RLCH_CIS_6_1_3_CONFIG"; expect 2
    rmdir "$RLCH_CIS_6_1_3_CONFIG"; mkfifo "$RLCH_CIS_6_1_3_CONFIG"; expect 2
}
@test "unreadable configuration rejected even as root" {
    chmod 000 "$RLCH_CIS_6_1_3_CONFIG"; expect 2;
}
@test "group or world writable configuration ERROR" {
    chmod 0664 "$RLCH_CIS_6_1_3_CONFIG"; expect 2; chmod 0646 "$RLCH_CIS_6_1_3_CONFIG"; expect 2
}
@test "untrusted owner observation ERROR" {
    function /usr/bin/stat() {
        if [[ "$2" == '%u' && "$4" == "$RLCH_CIS_6_1_3_CONFIG" ]]; then
            echo 4294967294
        else command /usr/bin/stat "$@"; fi
    }
    expect 2
}
@test "parent symlink or writable parent ERROR" {
    mkdir "$BATS_TEST_TMPDIR/real"; mv "$RLCH_CIS_6_1_3_CONFIG" "$BATS_TEST_TMPDIR/real/aide.conf"
    ln -s "$BATS_TEST_TMPDIR/real" "$BATS_TEST_TMPDIR/alias"
    RLCH_CIS_6_1_3_CONFIG="$BATS_TEST_TMPDIR/alias/aide.conf"; expect 2
    RLCH_CIS_6_1_3_CONFIG="$BATS_TEST_TMPDIR/real/aide.conf"; chmod 0777 "$BATS_TEST_TMPDIR/real"; expect 2
}
@test "relative and traversal paths rejected" {
    RLCH_CIS_6_1_3_CONFIG=aide.conf; expect 2
    RLCH_CIS_6_1_3_CONFIG="$BATS_TEST_TMPDIR/../$(basename "$BATS_TEST_TMPDIR")/aide.conf"; expect 2
}
@test "RPM state drift during observation ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; echo absent > "$TOOLS_RPM_STATE"; }; expect 2
}
@test "content drift during observation ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; printf '# edit\n' >> "$1"; }; expect 2
}
@test "same bytes inode replacement during observation ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; cp -p "$1" "$1.new"; mv "$1.new" "$1"; }; expect 2
}
@test "permission drift during observation ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; chmod 0600 "$1"; }; expect 2
}
@test "deletion during observation ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; rm "$1"; }; expect 2
}
@test "parser read errors remain ERROR" {
    rlch_aide_tools_rows() { return 2; }; expect 2;
}
@test "opened descriptor mismatch ERROR" {
    eval "$(declare -f rlch_tmout_file_stamp | sed '1s/rlch_tmout_file_stamp/original_stamp/')"
    rlch_tmout_file_stamp() { original_stamp "$@"; printf 'different\n'; }; expect 2
}
@test "compliant repeated apply preserves content inode metadata and no journal" {
    before="$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_6_1_3_CONFIG")$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")"
    run apply; [ "$status" -eq 0 ]; run apply; [ "$status" -eq 0 ]
    after="$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_6_1_3_CONFIG")$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")"
    [ "$before" = "$after" ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "nonconforming repeated apply ERROR and repeated rollback SUCCESS preserve files" {
    fixture /usr/sbin "$ATTRS+md5"; before="$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")"
    run apply; [ "$status" -eq 2 ]; run apply; [ "$status" -eq 2 ]
    run rollback; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")" ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
}
@test "6.1.1 databases and 6.1.2 cron state entirely independent" {
    mkdir "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/cron" "$BATS_TEST_TMPDIR/cron/.rlch-6.1.2"
    printf 'baseline' > "$BATS_TEST_TMPDIR/db/aide.db.gz"
    printf 'new' > "$BATS_TEST_TMPDIR/db/aide.db.new.gz"
    printf 'schedule' > "$BATS_TEST_TMPDIR/cron/rlch-aide-check"
    printf 'state' > "$BATS_TEST_TMPDIR/cron/.rlch-6.1.2/identity"
    export RLCH_CIS_6_1_1_CONFIG="$BATS_TEST_TMPDIR/untouched-611"
    export RLCH_CIS_6_1_2_CRON_D="$BATS_TEST_TMPDIR/cron"
    before="$(find "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/cron" -type f -exec sha256sum {} +)"
    expect 0; run apply; [ "$status" -eq 0 ]; run rollback; [ "$status" -eq 0 ]
    fixture /sbin 'sha256'; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(find "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/cron" -type f -exec sha256sum {} +)" ]
    [ ! -e "$RLCH_CIS_6_1_1_CONFIG" ]; [ ! -e "$BATS_TEST_TMPDIR/mutations" ]
    ! rg --quiet -- 'aide --(init|check)|cron\.d|\.rlch-6\.1\.2' "$BATS_TEST_DIRNAME/../modules/cis/6/1/3/module.sh" "$BATS_TEST_DIRNAME/../lib/aide_audit_tools.sh"
}
@test "change between parser snapshots ERROR" {
    eval "$(declare -f rlch_aide_tools_snapshot | sed '1s/rlch_aide_tools_snapshot/original_snapshot/')"
    rlch_aide_tools_snapshot() {
        original_snapshot "$@" || return 2
        if [[ ! -e "$BATS_TEST_TMPDIR/read-once" ]]; then
            touch "$BATS_TEST_TMPDIR/read-once"; printf '# edit\n' >> "$1"
        fi
    }
    run rlch_aide_tools_rows "$RLCH_CIS_6_1_3_CONFIG" 'auditctl auditd ausearch aureport autrace augenrules' "$ATTRS" "$RICHER"
    [ "$status" -eq 2 ]
}
@test "same-byte replacement across parser read ERROR" {
    eval "$(declare -f rlch_aide_tools_snapshot | sed '1s/rlch_aide_tools_snapshot/original_snapshot/')"
    rlch_aide_tools_snapshot() {
        original_snapshot "$@" || return 2
        if [[ ! -e "$BATS_TEST_TMPDIR/read-once" ]]; then
            touch "$BATS_TEST_TMPDIR/read-once"; cp -p "$1" "$1.new"; mv "$1.new" "$1"
        fi
    }
    run rlch_aide_tools_rows "$RLCH_CIS_6_1_3_CONFIG" 'auditctl auditd ausearch aureport autrace augenrules' "$ATTRS" "$RICHER"
    [ "$status" -eq 2 ]
}
@test "missing configuration appears during check ERROR" {
    rm "$RLCH_CIS_6_1_3_CONFIG"
    rlch_aide_tools_rows() { fixture; return 1; }; expect 2
}
@test "symlink substitution during check ERROR and apply preserves replacement" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; mv "$1" "$1.saved"; ln -s "$1.saved" "$1"; }
    expect 2; run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]; [ -L "$RLCH_CIS_6_1_3_CONFIG" ]
}
@test "snapshot hash-read failure cannot become non compliance" {
    function /usr/bin/sha256sum() { return 1; }
    expect 2
}
@test "owner group timestamp observations change ERROR" {
    eval "$(declare -f rlch_aide_tools_rows | sed '1s/rlch_aide_tools_rows/original_rows/')"
    rlch_aide_tools_rows() { original_rows "$@"; touch -m -t 202001010101 "$1"; }; expect 2
}
@test "multiline separator is not interpreted as direct requirement" {
    sed -i '1s/ /\n/' "$RLCH_CIS_6_1_3_CONFIG"; expect 1
}
@test "unsafe input apply ERROR and rollback preserve inode metadata" {
    chmod 0666 "$RLCH_CIS_6_1_3_CONFIG"
    before="$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_6_1_3_CONFIG")$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")"
    run apply; [ "$status" -eq 2 ]; run rollback; [ "$status" -eq 0 ]
    [ "$before" = "$(stat -c '%d:%i:%u:%g:%a:%s:%y:%z' "$RLCH_CIS_6_1_3_CONFIG")$(sha256sum "$RLCH_CIS_6_1_3_CONFIG")" ]
}
