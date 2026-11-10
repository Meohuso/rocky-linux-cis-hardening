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
