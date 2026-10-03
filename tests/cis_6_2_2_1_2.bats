#!/usr/bin/env bats
# Fixtures inspired by CAS's neighboring TLS rule are informative, not mapped CIS tests.
setup() {
    source "$BATS_TEST_DIRNAME/test_helper.bash"
    source "$BATS_TEST_DIRNAME/../lib/module_api.sh"
    export RLCH_CIS_6_2_2_1_2_ROOT="$BATS_TEST_TMPDIR/root"
    export RLCH_CIS_6_2_2_1_2_ANALYZE="$BATS_TEST_TMPDIR/analyze"
    export JU_STATE="$BATS_TEST_TMPDIR/state" JU_CALLS="$BATS_TEST_TMPDIR/calls"
    export JU_MAIN="$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf"
    export JU_KEY="$RLCH_CIS_6_2_2_1_2_ROOT/site/SECRET-private.pem"
    mkdir -p "$JU_STATE" "$RLCH_CIS_6_2_2_1_2_ROOT"/{etc,run,usr/local/lib,usr/lib}/systemd/journal-upload.conf.d "$RLCH_CIS_6_2_2_1_2_ROOT/site"
    for name in SECRET-private client ca; do printf '%s\n' '-----BEGIN PRIVATE KEY-----' 'SECRET-PEM-CONTENT' '-----END PRIVATE KEY-----' > "$RLCH_CIS_6_2_2_1_2_ROOT/site/$name.pem"; done
    complete "$JU_MAIN"
    cat > "$RLCH_CIS_6_2_2_1_2_ANALYZE" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$JU_CALLS"
[[ "$LC_ALL" == C && "$SYSTEMD_PAGER" == cat && "$SYSTEMD_COLORS" == 0 && "$SYSTEMD_URLIFY" == 0 && "$1" == --no-pager && "$2" == "--root=$RLCH_CIS_6_2_2_1_2_ROOT" && "$3" == cat-config && "$4" == systemd/journal-upload.conf && $# == 4 ]] || exit 3
[[ ! -e "$JU_STATE/query-error" ]] || { echo SECRET-RAW-ERROR >&2; exit 1; }
if [[ -e "$JU_STATE/nul" ]]; then printf '# %s\n[Upload]\nServerKeyFile=/site/x\0\n' "$JU_MAIN"; exit; fi
if [[ -e "$JU_STATE/large-line" ]]; then printf '%9000s\n' x; exit; fi
if [[ -e "$JU_STATE/large-output" ]]; then /usr/bin/awk 'BEGIN {for(i=0;i<600000;i++) print "# abcdef"}'; exit; fi
if [[ -e "$JU_STATE/program" ]]; then cat "$JU_STATE/program"; exit; fi
/usr/bin/systemd-analyze "$@" || exit
if [[ -e "$JU_STATE/config-drift" ]]; then printf '# changed\n' >> "$JU_MAIN"; fi
if [[ -e "$JU_STATE/config-add" ]]; then printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/99-new.conf"; fi
if [[ $(wc -l < "$JU_CALLS") == 2 ]]; then
    if [[ -e "$JU_STATE/ref-replace" ]]; then mv "$JU_KEY" "$JU_KEY.old"; printf 'SECRET-replacement\n' > "$JU_KEY"; fi
    if [[ -e "$JU_STATE/ref-delete" ]]; then rm "$JU_KEY"; fi
    if [[ -e "$JU_STATE/ref-symlink" ]]; then rm "$JU_KEY"; ln -s ca.pem "$JU_KEY"; fi
    if [[ -e "$JU_STATE/ref-mode" ]]; then chmod 0600 "$JU_KEY"; fi
    if [[ -e "$JU_STATE/ref-content" ]]; then printf 'SECRET-modification\n' >> "$JU_KEY"; fi
    if [[ -e "$JU_STATE/second-error" ]]; then echo SECRET-SECOND >&2; exit 1; fi
fi
MOCK
    chmod 0755 "$RLCH_CIS_6_2_2_1_2_ANALYZE"
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/2/module.sh"
}
complete() {
    printf '[Upload]\nServerKeyFile=/site/SECRET-private.pem\nServerCertificateFile=/site/client.pem\nTrustedCertificateFile=/site/ca.pem\n' > "$1"
}
expect() {
    run check
    [ "$status" -eq "$1" ]
    [[ "$output" != *SECRET* && "$output" != *PEM* && "$output" != *PRIVATE* && "$output" != *"$JU_MAIN"* ]]
}
setting() { printf '%s=%s\n' "$1" "$2" >> "$JU_MAIN"; }
rows() {
    local snapshot
    snapshot="$(rlch_sdconf_snapshot "$RLCH_CIS_6_2_2_1_2_ROOT" "$RLCH_CIS_6_2_2_1_2_ANALYZE" systemd/journal-upload.conf)" || return 2
    rlch_sdconf_scalars "$RLCH_CIS_6_2_2_1_2_ROOT" systemd/journal-upload.conf Upload 'ServerKeyFile ServerCertificateFile TrustedCertificateFile' <<< "$snapshot"
}
manual() { expect 2; [[ "$output" == *'three explicit technical settings'* && "$output" == *'manual review'* ]]; }
unsafe() { expect 2; [[ "$output" == *'unsafe, inaccessible, unsupported or unstable'* ]]; }
teardown() {
    chmod u+r "$JU_MAIN" "$JU_KEY" 2>/dev/null || :
    chmod u+rwx "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d" 2>/dev/null || :
}
@test "62212 exact metadata applicable manual L1 no reboot" {
    source "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/2/metadata.conf"
    [ "$RLCH_MODULE_ID" = 6.2.2.1.2 ]; [ "$RLCH_MODULE_TITLE" = 'Ensure systemd-journal-upload authentication is configured' ]
    [ "$RLCH_MODULE_LEVEL" = 1 ]; [ "$RLCH_MODULE_ENABLED" = true ]; [ "$RLCH_MODULE_REQUIRES_REBOOT" = false ]; [ "$RLCH_MODULE_OPENSCAP_RULE" = manual ]
}
@test "62212 documented manual unmapped CAS without invented RHEL9 CCE" {
    run sed -n '/^## CIS 6.2.2.1.2 /,/^## Known technical debt/p' "$BATS_TEST_DIRNAME/../docs/DEVELOPMENT_STATUS.md"
    [ "$status" -eq 0 ]; [[ "$output" == *'status: manual'* && "$output" == *'no rules:'* && "$output" == *'no related_rules:'* && "$output" == *'No RHEL9 CCE'* ]]
    run cat "$BATS_TEST_DIRNAME/../modules/cis/6/2/2/1/2/metadata.conf"
    [[ "$output" != *CCE-* && "$output" != *xccdf_* && "$output" != *systemd_journal_upload_server_tls* ]]
}
@test "62212 complete main informative CAS-inspired fixture never false SUCCESS" { manual; }
@test "62212 no main no dropins safely observed explicit deficit" { rm "$JU_MAIN"; expect 1; }
@test "62212 empty file safely observed explicit deficit" { : > "$JU_MAIN"; expect 1; }
@test "62212 wrong section safely observed explicit deficit" { sed -i 's/\[Upload\]/[Other]/' "$JU_MAIN"; expect 1; }
@test "62212 case-sensitive section" { sed -i 's/\[Upload\]/[upload]/' "$JU_MAIN"; expect 1; }
@test "62212 case-sensitive keys" { sed -i 's/ServerKeyFile/serverkeyfile/' "$JU_MAIN"; expect 1; }
@test "62212 all commented parameters" { sed -i '/File=/s/^/#/' "$JU_MAIN"; expect 1; }
@test "62212 whitespace tabs blank lines leading comments accepted" {
    printf ' # note\n ; comment\n\n[Upload]\n ServerKeyFile \t=\t /site/SECRET-private.pem \nServerCertificateFile=/site/client.pem\nTrustedCertificateFile=/site/ca.pem\n' > "$JU_MAIN"; manual;
}
@test "62212 wrong-section trailing assignments ignored" { printf '[Other]\nServerKeyFile=/missing\n' >> "$JU_MAIN"; manual; }
@test "62212 repeated section last value used" { printf '[Other]\nServerKeyFile=/missing\n[Upload]\nServerKeyFile=/site/ca.pem\n' >> "$JU_MAIN"; manual; run rows; [[ "$output" == *'|8|/site/ca.pem'* ]]; }
@test "62212 last assignment overrides earlier missing reference" { sed -i 's@/site/SECRET-private.pem@/missing@' "$JU_MAIN"; setting ServerKeyFile /site/ca.pem; manual; }
@test "62212 last empty assignment resets earlier path" { setting ServerKeyFile ''; expect 1; }
@test "62212 empty reset then valid path restores explicit observation" { setting ServerKeyFile ''; setting ServerKeyFile /site/ca.pem; manual; }
@test "62212 URL is no fourth predicate" { setting URL ''; manual; setting URL http://unapproved.example; manual; }
@test "62212 explicit settings not CAS-default path requirement" { manual; [[ "$output" != *'/etc/pki'* ]]; }
@test "62212 split main and dropin informative neighbor fixture" {
    sed -i '/TrustedCertificateFile=/d' "$JU_MAIN"
    printf '[Upload]\nTrustedCertificateFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/30-trust.conf"; manual;
}
@test "62212 native selected provenance" { run rows; [ "$status" -eq 0 ]; [[ "$output" == *"ServerKeyFile|$JU_MAIN|2|/site/SECRET-private.pem"* ]]; }
@test "62212 native dropin override empty produces deficit" { printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/90-reset.conf"; expect 1; }
@test "62212 native basename etc overrides vendor" {
    printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/usr/lib/systemd/journal-upload.conf.d/20-auth.conf"
    printf '[Upload]\nServerKeyFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/20-auth.conf"; manual;
}
@test "62212 native basename run overrides local and vendor" {
    for prefix in usr/lib usr/local/lib; do printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/$prefix/systemd/journal-upload.conf.d/20-auth.conf"; done
    printf '[Upload]\nServerKeyFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/run/systemd/journal-upload.conf.d/20-auth.conf"; manual;
}
@test "62212 native local lib overrides vendor" {
    printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/usr/lib/systemd/journal-upload.conf.d/20-auth.conf"
    printf '[Upload]\nServerKeyFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/usr/local/lib/systemd/journal-upload.conf.d/20-auth.conf"; manual;
}
@test "62212 native lexical priority across directories" {
    printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/10-auth.conf"
    printf '[Upload]\nServerKeyFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/usr/lib/systemd/journal-upload.conf.d/90-auth.conf"; manual;
}
@test "62212 native dev null dropin mask" {
    printf '[Upload]\nServerKeyFile=\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/usr/lib/systemd/journal-upload.conf.d/20-auth.conf"
    ln -s /dev/null "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/20-auth.conf"; manual;
}
@test "62212 native dev null main mask is safely empty" { rm "$JU_MAIN"; ln -s /dev/null "$JU_MAIN"; expect 1; }
@test "62212 sections never carry into separate files" { printf 'ServerKeyFile=/site/ca.pem\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/20-auth.conf"; unsafe; }
@test "62212 malformed section is ambiguous" { printf '[Upload] trailing\n' >> "$JU_MAIN"; unsafe; }
@test "62212 malformed assignment is ambiguous" { printf 'ServerKeyFile /site/ca.pem\n' >> "$JU_MAIN"; unsafe; }
@test "62212 incomplete continuation ambiguous" { printf 'ServerKeyFile=/site/ca.pem\\\n' >> "$JU_MAIN"; unsafe; }
@test "62212 continuation with comments and whitespace" {
    printf 'ServerKeyFile=\\\n# interposed\n; interposed\n /site/ca.pem\n' >> "$JU_MAIN"; manual;
}
@test "62212 missing tool observation error rather than package duplicate" { RLCH_CIS_6_2_2_1_2_ANALYZE="$JU_STATE/no-analyze"; unsafe; }
@test "62212 nonexecutable tool observation error" { chmod 0644 "$RLCH_CIS_6_2_2_1_2_ANALYZE"; unsafe; }
@test "62212 hostile stderr never disclosed" { touch "$JU_STATE/query-error"; unsafe; }
@test "62212 NUL native output rejected before substitution" { touch "$JU_STATE/nul"; unsafe; }
@test "62212 oversized native line rejected" { touch "$JU_STATE/large-line"; unsafe; }
@test "62212 oversized native output rejected" { touch "$JU_STATE/large-output"; unsafe; }
@test "62212 invented native header rejected" { printf '# /SECRET/forged.conf\n[Upload]\n' > "$JU_STATE/program"; unsafe; }
@test "62212 native missing header rejected" { printf '[Upload]\nServerKeyFile=/site/ca.pem\n' > "$JU_STATE/program"; unsafe; }
@test "62212 native duplicate header rejected" { printf '# %s\n[Upload]\n# %s\n' "$JU_MAIN" "$JU_MAIN" > "$JU_STATE/program"; unsafe; }
@test "62212 header-shaped configuration comment rejected" { printf '# /SECRET/forged.conf\n' >> "$JU_MAIN"; unsafe; }
@test "62212 NUL configuration rejected" { printf '\0\n' >> "$JU_MAIN"; unsafe; }
@test "62212 control configuration rejected" { printf '# bad\001\n' >> "$JU_MAIN"; unsafe; }
@test "62212 oversized configuration line rejected" { printf '%9000s\n' x >> "$JU_MAIN"; unsafe; }
@test "62212 oversized configuration rejected" { /usr/bin/awk 'BEGIN{for(i=0;i<160000;i++) print "# abcdef"}' >> "$JU_MAIN"; unsafe; }
@test "62212 unreadable configuration rejected even privileged runner" { chmod 0000 "$JU_MAIN"; unsafe; }
@test "62212 inaccessible dropin directory rejected" { chmod 0000 "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d"; unsafe; }
@test "62212 FIFO configuration rejected without opening" { rm "$JU_MAIN"; mkfifo "$JU_MAIN"; unsafe; }
@test "62212 directory configuration rejected" { rm "$JU_MAIN"; mkdir "$JU_MAIN"; unsafe; }
@test "62212 ordinary config symlink rejected" { mv "$JU_MAIN" "$JU_MAIN.real"; ln -s journal-upload.conf.real "$JU_MAIN"; unsafe; }
@test "62212 ancestor config symlink rejected" { mv "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd" "$RLCH_CIS_6_2_2_1_2_ROOT/etc/real"; ln -s real "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd"; unsafe; }
@test "62212 vendor main alone conservatively unsupported" { mv "$JU_MAIN" "$RLCH_CIS_6_2_2_1_2_ROOT/usr/lib/systemd/journal-upload.conf"; unsafe; }
@test "62212 config content drift rejected" { touch "$JU_STATE/config-drift"; unsafe; }
@test "62212 newly added dropin rejected" { touch "$JU_STATE/config-add"; unsafe; }
@test "62212 replacement reference inode detected" { touch "$JU_STATE/ref-replace"; unsafe; }
@test "62212 disappeared reference detected" { touch "$JU_STATE/ref-delete"; unsafe; }
@test "62212 substituted symlink reference detected" { touch "$JU_STATE/ref-symlink"; unsafe; }
@test "62212 reference mode drift detected without normative permission threshold" { touch "$JU_STATE/ref-mode"; unsafe; }
@test "62212 reference metadata content drift detected without content read" { touch "$JU_STATE/ref-content"; unsafe; }
@test "62212 second query error priority over complete configuration" { touch "$JU_STATE/second-error"; unsafe; }
@test "62212 unsafe reference priority over missing setting" { sed -i '/ServerKeyFile=/d' "$JU_MAIN"; rm "$RLCH_CIS_6_2_2_1_2_ROOT/site/ca.pem"; unsafe; }
@test "62212 nonexistent reference error not technical missing key" { rm "$JU_KEY"; unsafe; }
@test "62212 directory reference error" { rm "$JU_KEY"; mkdir "$JU_KEY"; unsafe; }
@test "62212 FIFO reference error without read" { rm "$JU_KEY"; mkfifo "$JU_KEY"; unsafe; }
@test "62212 symlink reference error including otherwise regular target" { rm "$JU_KEY"; ln -s ca.pem "$JU_KEY"; unsafe; }
@test "62212 dev null reference symlink forbidden unlike config mask" { rm "$JU_KEY"; ln -s /dev/null "$JU_KEY"; unsafe; }
@test "62212 reference ancestor symlink error" { mv "$RLCH_CIS_6_2_2_1_2_ROOT/site" "$RLCH_CIS_6_2_2_1_2_ROOT/real"; ln -s real "$RLCH_CIS_6_2_2_1_2_ROOT/site"; unsafe; }
@test "62212 unreadable regular key metadata accepted without permission policy" { chmod 0000 "$JU_KEY"; manual; }
@test "62212 key content and sensitive filename never disclosed by any API" {
    for api in check validate apply rollback; do run "$api"; [[ "$output" != *SECRET* && "$output" != *PRIVATE* && "$output" != *PEM* && "$output" != *"$JU_KEY"* ]]; done
}
@test "62212 private key content never read or hashed atime sentinel" {
    touch -a -d '2000-01-01 00:00:00 UTC' "$JU_KEY"
    before=$(stat -c '%x' "$JU_KEY")
    for api in check validate apply rollback; do run "$api"; done
    [ "$(stat -c '%x' "$JU_KEY")" = "$before" ]
}
@test "62212 check validate repeated identical results" {
    for state in complete missing unsafe; do
        complete "$JU_MAIN"; rm -f "$JU_STATE/query-error"
        case "$state" in missing) setting ServerKeyFile '';; unsafe) touch "$JU_STATE/query-error";; esac
        run check; result=$status; text=$output
        run validate; [ "$status" -eq "$result" ]; [ "$output" = "$text" ]
        run check; [ "$status" -eq "$result" ]; [ "$output" = "$text" ]
    done
}
@test "62212 apply always ERROR and rollback repeatable SUCCESS never CHANGED" {
    for state in complete missing unsafe; do
        complete "$JU_MAIN"; rm -f "$JU_STATE/query-error"
        case "$state" in missing) setting ServerKeyFile '';; unsafe) touch "$JU_STATE/query-error";; esac
        for iteration in 1 2; do run apply; [ "$status" -eq 2 ]; [[ "$output" == *'manual remediation required'* && "$output" != *SECRET* ]]; run rollback; [ "$status" -eq 0 ]; [ -z "$output" ]; done
    done
}
@test "62212 rollback succeeds with unavailable observation tool and makes no query" { rm "$RLCH_CIS_6_2_2_1_2_ANALYZE"; run rollback; [ "$status" -eq 0 ]; [ ! -e "$JU_CALLS" ]; }
@test "62212 no mutations packages services crypto state backups trust or previous controls" {
    set -o pipefail
    mkdir -p "$BATS_TEST_TMPDIR/bin" "$RLCH_CIS_6_2_2_1_2_ROOT"/{etc/pki/ca-trust,etc/systemd/system,etc/cron.d,etc/aide.d,var/lib/rlch}
    for command in rpm dnf yum systemctl openssl curl wget restorecon setfacl; do
        printf '#!/usr/bin/env bash\nprintf "forbidden\\n" >> "$JU_STATE/forbidden"\nexit 99\n' > "$BATS_TEST_TMPDIR/bin/$command"; chmod +x "$BATS_TEST_TMPDIR/bin/$command"
    done
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
    for file in etc/pki/ca-trust/admin.pem etc/systemd/system/systemd-journal-upload.service etc/systemd/system/systemd-journal-remote.socket etc/cron.d/aide etc/aide.d/admin var/lib/rlch/old-control; do printf 'preserve\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/$file"; done
    before=$(find "$RLCH_CIS_6_2_2_1_2_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)
    inventory=$(find "$RLCH_CIS_6_2_2_1_2_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)
    for iteration in 1 2; do for api in check validate apply rollback; do run "$api"; [ "$status" -ne 4 ]; done; done
    [ "$(find "$RLCH_CIS_6_2_2_1_2_ROOT" -type f -exec sha256sum {} + | LC_ALL=C sort)" = "$before" ]
    [ "$(find "$RLCH_CIS_6_2_2_1_2_ROOT" -printf '%P|%y|%D|%i|%m|%U|%G|%T@|%C@|%l\n' | LC_ALL=C sort)" = "$inventory" ]; [ ! -e "$JU_STATE/forbidden" ]
}
@test "62212 helper direct regular file metadata without credential content" { run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 0 ]; [[ "$output" == *':regular file:'* && "$output" != *SECRET* && "$output" != *PEM* ]]; }
@test "62212 helper direct no read permission required" { chmod 0000 "$JU_KEY"; run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 0 ]; }
@test "62212 helper direct missing path rejected" { run rlch_sdconf_reference_stamp "$JU_KEY.missing"; [ "$status" -eq 2 ]; [ -z "$output" ]; }
@test "62212 helper direct FIFO rejected" { rm "$JU_KEY"; mkfifo "$JU_KEY"; run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 2 ]; }
@test "62212 helper direct directory rejected" { run rlch_sdconf_reference_stamp "$RLCH_CIS_6_2_2_1_2_ROOT/site"; [ "$status" -eq 2 ]; }
@test "62212 helper direct character device rejected" { run rlch_sdconf_reference_stamp /dev/null; [ "$status" -eq 2 ]; }
@test "62212 helper direct socket rejected without opening" {
    python3 - "$JU_KEY.socket" <<'SOCKET' || skip 'Container denies Unix socket creation; CI executes this case'
import socket,sys
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.close()
SOCKET
    run rlch_sdconf_reference_stamp "$JU_KEY.socket"; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "62212 helper direct symlink rejected" { ln -s SECRET-private.pem "$JU_KEY.link"; run rlch_sdconf_reference_stamp "$JU_KEY.link"; [ "$status" -eq 2 ]; }
@test "62212 helper direct canonical literal spaces accepted" { printf 'SECRET\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/site/name with spaces"; run rlch_sdconf_reference_stamp "$RLCH_CIS_6_2_2_1_2_ROOT/site/name with spaces"; [ "$status" -eq 0 ]; }
@test "62212 literal shell characters never evaluated" {
    value='/site/$(touch INJECTED)'; printf 'SECRET\n' > "$RLCH_CIS_6_2_2_1_2_ROOT$value"; setting ServerKeyFile "$value"; manual; [ ! -e INJECTED ];
}
@test "62212 ServerKeyFile absent deterministic deficit" { sed -i "/^ServerKeyFile=/d" "$JU_MAIN"; expect 1; }
@test "62212 ServerKeyFile explicit empty reset deterministic deficit" { setting ServerKeyFile ""; expect 1; }
@test "62212 ServerCertificateFile absent deterministic deficit" { sed -i "/^ServerCertificateFile=/d" "$JU_MAIN"; expect 1; }
@test "62212 ServerCertificateFile explicit empty reset deterministic deficit" { setting ServerCertificateFile ""; expect 1; }
@test "62212 TrustedCertificateFile absent deterministic deficit" { sed -i "/^TrustedCertificateFile=/d" "$JU_MAIN"; expect 1; }
@test "62212 TrustedCertificateFile explicit empty reset deterministic deficit" { setting TrustedCertificateFile ""; expect 1; }
@test "62212 unsupported relative path ERROR never normalized" { setting ServerKeyFile 'relative.pem'; unsafe; }
@test "62212 unsupported tilde path ERROR never normalized" { setting ServerKeyFile '~/key.pem'; unsafe; }
@test "62212 unsupported disable-sentinel path ERROR never normalized" { setting ServerKeyFile '-'; unsafe; }
@test "62212 unsupported trust-all path ERROR never normalized" { setting ServerKeyFile 'all'; unsafe; }
@test "62212 unsupported double-quoted path ERROR never normalized" { setting ServerKeyFile '"/site/ca.pem"'; unsafe; }
@test "62212 unsupported single-quoted path ERROR never normalized" { setting ServerKeyFile ''"'"'/site/ca.pem'"'"''; unsafe; }
@test "62212 unsupported dotdot path ERROR never normalized" { setting ServerKeyFile '/site/../site/ca.pem'; unsafe; }
@test "62212 unsupported dot path ERROR never normalized" { setting ServerKeyFile '/site/./ca.pem'; unsafe; }
@test "62212 unsupported double-slash path ERROR never normalized" { setting ServerKeyFile '/site//ca.pem'; unsafe; }
@test "62212 unsupported backslash path ERROR never normalized" { setting ServerKeyFile '/site/ca\x.pem'; unsafe; }
@test "62212 unsupported pipe path ERROR never normalized" { setting ServerKeyFile '/site/key|other'; unsafe; }
@test "62212 unsupported overlong path ERROR never normalized" { setting ServerKeyFile '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; unsafe; }
@test "62212 helper direct replacement during pathname observations detected" {
    path_calls=0
    rlch_journal_path() { path_calls=$((path_calls+1)); if [ "$path_calls" -eq 2 ]; then mv "$JU_KEY" "$JU_KEY.old"; printf 'SECRET\n' > "$JU_KEY"; fi; }
    run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "62212 helper direct disappearance during pathname observations detected" {
    path_calls=0
    rlch_journal_path() { path_calls=$((path_calls+1)); if [ "$path_calls" -eq 2 ]; then rm "$JU_KEY"; fi; }
    run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "62212 helper direct symlink substitution during pathname observations detected" {
    path_calls=0
    rlch_journal_path() { path_calls=$((path_calls+1)); if [ "$path_calls" -eq 2 ]; then rm "$JU_KEY"; ln -s ca.pem "$JU_KEY"; fi; }
    run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 2 ]; [ -z "$output" ]
}
@test "62212 helper direct control path rejected" { run rlch_sdconf_reference_stamp "$JU_KEY"$'\001'; [ "$status" -eq 2 ]; }
@test "62212 helper direct ancestor symlink rejected" {
    mv "$RLCH_CIS_6_2_2_1_2_ROOT/site" "$RLCH_CIS_6_2_2_1_2_ROOT/real"; ln -s real "$RLCH_CIS_6_2_2_1_2_ROOT/site"
    run rlch_sdconf_reference_stamp "$JU_KEY"; [ "$status" -eq 2 ];
}
@test "62212 helper direct relative path rejected" { run rlch_sdconf_reference_stamp relative.pem; [ "$status" -eq 2 ]; }
@test "62212 empty regular referenced objects remain manual not crypto validated" { : > "$JU_KEY"; manual; }
@test "62212 control native output rejected" { printf '# %s\n[Upload]\n# bad\001\n' "$JU_MAIN" > "$JU_STATE/program"; unsafe; }
@test "62212 BOM configuration rejected" { printf '# bad\357\273\277\n' >> "$JU_MAIN"; unsafe; }
@test "62212 too many configuration files rejected" {
    for ((index=0;index<1024;index++)); do printf '# fixture\n' > "$RLCH_CIS_6_2_2_1_2_ROOT/etc/systemd/journal-upload.conf.d/$index.conf"; done
    unsafe;
}
