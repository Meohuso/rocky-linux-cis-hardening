#!/usr/bin/env bash
# One original pass and one measured pass. Only allowlisted metadata is printed.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/tests"
ln -s "$root/lib" "$tmp/lib"
# Select by exact names, independent of global TAP numbering.
python3 - "$root/tests/identity_observation.bats" "$tmp" <<'PY'
import pathlib
import re
import sys

source, temp = map(pathlib.Path, sys.argv[1:])
names = [
    "projects only numeric UIDs",
    "duplicate names conservative error",
    "malformed passwd field count",
    "malformed group field count",
    "UID bounds and syntax",
    "GID bounds and syntax",
    "NUL bytes rejected",
    "control bytes rejected",
    "NSS duplicate keys rejected",
    "NSS missing keys rejected",
    "NSS unsupported syntax rejected",
    "compat inclusion entries rejected",
    "record length limit",
    "no secrets names or members in diagnostics",
    "stderr even zero status invalidates evidence",
    "aggregate byte volume limit",
    "producer failure does not leak partial projection",
    "stream truncation rejected",
    "line count limit",
    "base mutation while reading detected",
]
names = ["idobs " + name for name in names]
original = source.read_text()
for name in names:
    assert original.count(f'@test "{name}" {{') == 1
(temp / "names").write_text("\n".join(names) + "\n")
(temp / "filter").write_text("^(" + "|".join(names) + ")$")
helper = 'unknown() { run rlch_identity_rows "$1" "$2"; [ "$status" -eq 2 ]; [ -z "$output" ]; }'
valid = '    run rlch_identity_rows "$P" passwd; [ "$status" -eq 0 ]; [ "$output" = $\'0\\n1001\' ]; }'
assert original.count(helper) == 1 and original.count(valid) == 1
measured = r'''
diag_category() {
    case "$1" in
        "") printf empty ;;
        *head*:*[Bb]roken\ pipe*) printf head_broken_pipe ;;
        *[Bb]roken\ pipe*) printf broken_pipe ;;
        *) printf other ;;
    esac
}

diag_measure() {
    local expected=$1 file=$2 kind=$3
    local merged_rc merged_bytes merged_category direct_rc=0 direct_out direct_err
    local separate_rc separate_out separate_err direct_category separate_category
    local key value mask=0 ignored result
    while read -r key value _; do
        if [[ $key == SigIgn: ]]; then mask=$value; break; fi
    done < /proc/self/status
    ignored=$(( (16#$mask >> 12) & 1 ))

    # Preserve default Bats capture; separate/direct calls are supplementary.
    run rlch_identity_rows "$file" "$kind"
    merged_rc=$status
    merged_bytes=$(printf '%s' "$output" | wc -c)
    merged_category=$(diag_category "$output")
    local merged_output=$output
    rlch_identity_rows "$file" "$kind" > "$BATS_TEST_TMPDIR/stdout" 2> "$BATS_TEST_TMPDIR/stderr" || direct_rc=$?
    direct_out=$(wc -c < "$BATS_TEST_TMPDIR/stdout")
    direct_err=$(wc -c < "$BATS_TEST_TMPDIR/stderr")
    direct_category=$(diag_category "$(< "$BATS_TEST_TMPDIR/stderr")")
    run --separate-stderr rlch_identity_rows "$file" "$kind"
    separate_rc=$status
    separate_out=$(printf '%s' "$output" | wc -c)
    separate_err=$(printf '%s' "$stderr" | wc -c)
    separate_category=$(diag_category "$stderr")
    if [[ $expected == 0 ]]; then
        result=valid_witness
    elif (( merged_rc != expected && merged_bytes != 0 )); then
        result=C
    elif (( merged_rc != expected )); then
        result=A
    elif (( merged_bytes != 0 )); then
        result=B
    else
        result=expected
    fi
    printf 'CI302|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$BATS_TEST_DESCRIPTION" "$expected" "$ignored" \
        "$direct_rc" "$direct_out" "$direct_err" "$direct_category" \
        "$merged_rc" "$merged_bytes" "$merged_category" \
        "$separate_rc" "$separate_out" "$separate_err" "$separate_category" "$result" >&3
    status=$merged_rc
    output=$merged_output
}
unknown() { diag_measure 2 "$1" "$2"; [ "$status" -eq 2 ]; [ -z "$output" ]; }
'''
instrumented = original.replace(helper, measured, 1)
instrumented = instrumented.replace(valid, valid.replace('run rlch_identity_rows', 'diag_measure 0'), 1)
instrumented = instrumented.replace('setup() {\n', 'setup() {\n    bats_require_minimum_version 1.5.0\n', 1)
(temp / "tests/measured.bats").write_text(instrumented)
PY

filter=$(< "$tmp/filter")
# Capture all raw output privately; report only a parsed plan, results and metrics.
original_rc=0
measured_rc=0
bats --tap --filter "$filter" "$root/tests/identity_observation.bats" > "$tmp/original.tap" 2>&1 || original_rc=$?
bats --tap --filter "$filter" "$tmp/tests/measured.bats" > "$tmp/measured.tap" 2>&1 || measured_rc=$?
python3 - "$tmp" "$original_rc" "$measured_rc" <<'PY'
import pathlib
import re
import sys

temp = pathlib.Path(sys.argv[1])
names = set((temp / "names").read_text().splitlines())
number = re.compile(r"[0-9]{1,9}")
category = {"empty", "head_broken_pipe", "broken_pipe", "other"}
valid_results = {"A", "B", "C", "expected", "valid_witness"}
for phase, rc in zip(("original", "measured"), sys.argv[2:]):
    observed = set()
    measured = set()
    print(f"phase={phase} bats_exit={rc} selected={len(names)}")
    for line in (temp / f"{phase}.tap").read_text(errors="replace").splitlines():
        match = re.fullmatch(r"(ok|not ok) [0-9]+ (.*)", line)
        if match and match[2] in names:
            observed.add(match[2])
            print(f"{phase}|{match[1]}|{match[2]}")
        if phase != "measured" or not line.startswith("CI302|"):
            continue
        fields = line.split("|")
        if (len(fields) == 16 and fields[1] in names
                and all(number.fullmatch(fields[i]) for i in (2, 3, 4, 5, 6, 8, 9, 11, 12, 13))
                and all(fields[i] in category for i in (7, 10, 14))
                and fields[15] in valid_results):
            measured.add(fields[1])
            print(line)
    if observed != names or (phase == "measured" and measured != names):
        print(f"diagnostic_incomplete observed={len(observed)} measured={len(measured)}")
        sys.exit(1)
print("pipeline_statuses=not_observed (no changes to library pipeline)")
PY

# Experimental byte-accounting matrix; no raw fixture/stream is printed.
export CI302_EXPERIMENT_ROOT="$root"
export CI302_EXPERIMENT_POOL="$tmp/pool"
mkdir "$tmp/pool"
python3 - "$tmp/pool" "$tmp/tests/byte_matrix.bats" <<'PYM'
import pathlib,sys
pool=pathlib.Path(sys.argv[1]);target=pathlib.Path(sys.argv[2])
cases=['complete','empty','single','middle-truncation','complete-row-truncation',
       'before-last','zero-output','producer-error','producer-stderr',
       'missing-marker','false-marker','mutation-during','mutation-before-open',
       'size-change','source-replacement','same-size-mutation',
       'records-65536','records-65537','line-16384','line-16385',
       'bytes-max','bytes-over','early-large','invalid-secret']
def record(mode,i,length=None):
    if mode=='passwd':
        a=f'u{i}:SYNTHETIC_AUTH:{i}:{i}:'.encode();z=b':/:/bin/false'
    elif mode=='group':
        a=f'u{i}:SYNTHETIC_AUTH:{i}:'.encode();z=b''
    else:
        if i==0:return b'passwd: files\n'
        if i==1:return b'group: files\n'
        a=b'#';z=b''
    if length is None:return a+z+b'\n'
    assert length>=len(a)+len(z)
    return a+b'a'*(length-len(a)-len(z))+z+b'\n'
def volume(mode,size):
    out=b'';i=0
    while size-len(out)>16385:
        out+=record(mode,i,16384);i+=1
    out+=record(mode,i,size-len(out)-1)
    assert len(out)==size
    return out
entries=[]
for mode in ('passwd','group','nss'):
    folder=pool/mode;folder.mkdir()
    for case in cases:
        data=b''.join(record(mode,i) for i in range(4));expected=2
        if case=='complete':expected=0
        elif case=='empty':data=b''
        elif case=='single':
            data=record(mode,0);expected=2 if mode=='nss' else 0
        elif case.startswith('records-'):
            count=int(case.split('-')[1]);data=b''.join(record(mode,i) for i in range(count))
            expected=0 if count==65536 else 2
        elif case.startswith('line-'):
            length=int(case.split('-')[1])
            data=(record(mode,0)+record(mode,1) if mode=='nss' else b'')+record(mode,2,length)
            expected=0 if length==16384 else 2
        elif case in ('bytes-max','bytes-over'):
            data=volume(mode,4194286 if case=='bytes-max' else 4194287)
            expected=0 if case=='bytes-max' else 2
        elif case=='early-large':
            bad=b'bad\r:x:1:\n' if mode=='group' else (b'bad\r:x:1:1::/:/bin/false\n' if mode=='passwd' else b'passwd : files\n')
            data=bad+b''.join(record(mode,i) for i in range(9000))
        elif case=='invalid-secret':data=b'SYNTHETIC_PRIVATE_SENTINEL\x00invalid\n'
        path=folder/case;path.write_bytes(data);path.chmod(0o600)
        entries.append((mode,case,expected))
header=r'''
#!/usr/bin/env bats
setup() {
    bats_require_minimum_version 1.5.0
    source "$CI302_EXPERIMENT_ROOT/lib/identity_observation.sh"
}
fd_position() {
    local key value
    while read -r key value _; do
        if [[ $key == pos: ]]; then printf '%s' "$value"; return; fi
    done < "/proc/self/fdinfo/$1"
    printf unknown
}
prepare_case() {
    cp -- "$CI302_EXPERIMENT_POOL/$exp_mode/$exp_case" "$BATS_TEST_TMPDIR/source"
    chmod 0600 "$BATS_TEST_TMPDIR/source"
    : > "$BATS_TEST_TMPDIR/producer"
    unset -f printf 2>/dev/null || :
    if [[ $exp_case == missing-marker ]]; then
        printf() {
            if [[ $1 == 'RLCH-IDENTITY-END\n' ]]; then return 0; fi
            builtin printf "$@"
        }
    fi
    rlch_identity_stamp() {
        _rlch_identity_file_stamp "$1" false
        if [[ $exp_case == mutation-before-open ]]; then builtin printf X >> "$1"; fi
    }
    rlch_identity_stream() {
        local obs_fd pos_before pos_after producer_rc=0
        exec {obs_fd}<&0
        pos_before=$(fd_position "$obs_fd")
        case "$exp_case" in
            middle-truncation) /usr/bin/head -c 5 || producer_rc=$? ;;
            complete-row-truncation)
                if [[ $exp_mode == nss ]]; then /usr/bin/head -n 2 || producer_rc=$?
                else /usr/bin/head -n 1 || producer_rc=$?; fi ;;
            before-last) /usr/bin/head -n 3 || producer_rc=$? ;;
            zero-output) : ;;
            false-marker)
                /usr/bin/head -n 1 || producer_rc=$?
                builtin printf 'RLCH-IDENTITY-END\n' ;;
            *) /usr/bin/cat || producer_rc=$? ;;
        esac
        pos_after=$(fd_position "$obs_fd")
        exec {obs_fd}<&-
        case "$exp_case" in
            producer-error) producer_rc=99 ;;
            producer-stderr) builtin printf 'SYNTHETIC_PRIVATE_SENTINEL\n' >&2 ;;
            mutation-during|size-change) builtin printf X >> "$BATS_TEST_TMPDIR/source" ;;
            same-size-mutation)
                /usr/bin/printf Z | /usr/bin/dd of="$BATS_TEST_TMPDIR/source" bs=1 count=1 conv=notrunc status=none ;;
            source-replacement)
                cp -- "$BATS_TEST_TMPDIR/source" "$BATS_TEST_TMPDIR/replacement"
                mv -- "$BATS_TEST_TMPDIR/replacement" "$BATS_TEST_TMPDIR/source" ;;
        esac
        builtin printf '%s|%s|%s\n' "$pos_before" "$pos_after" "$producer_rc" >> "$BATS_TEST_TMPDIR/producer"
        return "$producer_rc"
    }
}
measure_case() {
    local exp_mode=$1 exp_case=$2 expected=$3
    local source_size stamp_before stamp_after direct_rc=0 direct_out direct_err
    local merged_rc merged_out separate_rc separate_out separate_err stable=0
    local key value ignored=unknown position_before=unknown position_after=unknown producer_rc=unknown
    while read -r key value _; do
        if [[ $key == SigIgn: ]]; then ignored=$(( (16#$value >> 12) & 1 )); fi
    done < /proc/self/status
    prepare_case
    source_size=$(/usr/bin/stat -c %s "$BATS_TEST_TMPDIR/source")
    stamp_before=$(/usr/bin/stat -c '%d|%i|%s|%y|%z' "$BATS_TEST_TMPDIR/source")
    rlch_identity_rows "$BATS_TEST_TMPDIR/source" "$exp_mode" > "$BATS_TEST_TMPDIR/out" 2> "$BATS_TEST_TMPDIR/err" || direct_rc=$?
    stamp_after=$(/usr/bin/stat -c '%d|%i|%s|%y|%z' "$BATS_TEST_TMPDIR/source")
    [[ $stamp_before != "$stamp_after" ]] || stable=1
    direct_out=$(wc -c < "$BATS_TEST_TMPDIR/out")
    direct_err=$(wc -c < "$BATS_TEST_TMPDIR/err")
    IFS='|' read -r position_before position_after producer_rc < "$BATS_TEST_TMPDIR/producer" || :
    local projection_digest
    projection_digest=$(sha256sum < "$BATS_TEST_TMPDIR/out")
    projection_digest=${projection_digest%% *}
    prepare_case
    run rlch_identity_rows "$BATS_TEST_TMPDIR/source" "$exp_mode"
    merged_rc=$status
    merged_out=$(builtin printf '%s' "$output" | wc -c)
    prepare_case
    run --separate-stderr rlch_identity_rows "$BATS_TEST_TMPDIR/source" "$exp_mode"
    separate_rc=$status
    separate_out=$(builtin printf '%s' "$output" | wc -c)
    separate_err=$(builtin printf '%s' "$stderr" | wc -c)
    builtin printf 'BYTE302|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$exp_mode" "$exp_case" "$expected" "$source_size" "$ignored" \
        "$direct_rc" "$direct_out" "$direct_err" "$merged_rc" "$merged_out" \
        "$separate_rc" "$separate_out" "$separate_err" "$stable" \
        "${position_before:-unknown}" "${position_after:-unknown}" "${producer_rc:-unknown}" \
        "$projection_digest" "$BASH_VERSION" "$BATS_VERSION" >&3
    [[ $direct_rc -eq $expected && $merged_rc -eq $expected && $separate_rc -eq $expected ]]
    [[ $direct_err -eq 0 && $separate_err -eq 0 ]]
    if [[ $expected == 2 ]]; then [[ $direct_out -eq 0 && $merged_out -eq 0 && $separate_out -eq 0 ]]; fi
}
'''
tests=''.join(f'@test "bytes {mode} {case}" {{\n    measure_case {mode} {case} {expected}\n}}\n' for mode,case,expected in entries)
target.write_text(header+tests)
(pool/'expected-count').write_text(str(len(entries)))
PYM
matrix_rc=0
bats --tap "$tmp/tests/byte_matrix.bats" > "$tmp/bytes.tap" 2>&1 || matrix_rc=$?
python3 - "$tmp/bytes.tap" "$tmp/pool/expected-count" "$matrix_rc" <<'PYM'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text(errors='replace')
expected=int(pathlib.Path(sys.argv[2]).read_text());measurements=[];results=[]
for line in text.splitlines():
    if re.fullmatch(r'(?:ok|not ok) [0-9]+ bytes (passwd|group|nss) [a-z0-9-]+',line):results.append(line);print(line)
    if line.startswith('BYTE302|'):
        f=line.split('|')
        if (len(f)==21 and f[1] in ('passwd','group','nss') and re.fullmatch('[a-z0-9-]+',f[2])
            and all(re.fullmatch('[0-9]+',f[i]) for i in range(3,15))
            and all(re.fullmatch('[0-9]+|unknown',f[i]) for i in range(15,18))
            and re.fullmatch('[a-f0-9]{64}',f[18])
            and all(re.fullmatch('[0-9A-Za-z()._-]+',f[i]) for i in (19,20))):
            measurements.append(line);print(line)
print(f'byte_matrix expected={expected} measured={len(measurements)} results={len(results)} bats_exit={sys.argv[3]}')
if len(measurements)!=expected or len(results)!=expected:sys.exit(2)
sys.exit(int(sys.argv[3]))
PYM
