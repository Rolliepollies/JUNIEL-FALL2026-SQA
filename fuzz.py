import contextlib
import io
import json
import random
import sys
import traceback
from pathlib import Path
from tempfile import TemporaryDirectory

SLIKUBE_DIR = Path(__file__).resolve().parent / "slikube"
sys.path.insert(0, str(SLIKUBE_DIR))

import parser
import scanner
import graphtaint

SEED = 5710
PROPERTY_ROUNDS = 200
ROBUSTNESS_ROUNDS = 300
REPORT_FILE = Path(__file__).resolve().parent / "fuzz_report.json"


def find_names(document):
    names = []
    parser.getValsFromKey(document, "name", names)
    return names


def collect_keys(document):
    keys = []
    parser.getKeyRecursively(document, keys)
    return [entry[0] for entry in keys]


def property_fuzz(rng):
    failures = {}

    with TemporaryDirectory() as directory:
        path = Path(directory) / "configmap.yaml"

        for case in range(1, PROPERTY_ROUNDS + 1):
            name = f"config-{case}-{rng.randrange(10000)}"
            message = rng.choice(["", "null", "yes", "a: b", "x # y", "a\nb"])
            document = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": name},
                "data": {"message": message},
            }
            source = json.dumps(document)
            path.write_text(source, encoding="utf-8")
            filename = str(path)

            checks = {
                "readYAMLAsStr": lambda: parser.readYAMLAsStr(filename) == source,
                "checkParseError": lambda: parser.checkParseError(filename) is True,
                "loadMultiYAML": lambda: parser.loadMultiYAML(filename) == [document],
                "getSingleDict4MultiDocs": lambda: (
                    parser.getSingleDict4MultiDocs([document]) == document
                ),
                "checkIfValidK8SYaml": lambda: (
                    parser.checkIfValidK8SYaml(filename) is True
                ),
                "checkIfWeirdYAML": lambda: (
                    parser.checkIfWeirdYAML("manifests/configmap.yaml") is False
                ),
                "getKeyRecursively": lambda: "message" in collect_keys(document),
                "getValuesRecursively": lambda: (
                    message in list(parser.getValuesRecursively(document))
                ),
                "getValsFromKey": lambda: find_names(document) == [name],
                "keyMiner": lambda: bool(parser.keyMiner(document, name)),
            }

            for function, check in checks.items():
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        ok = check()
                    if not ok:
                        raise AssertionError("Unexpected result")
                except Exception as error:
                    if function not in failures:
                        failures[function] = {
                            "phase": "property",
                            "function": function,
                            "case": case,
                            "exception": type(error).__name__,
                            "message": str(error),
                            "input": source,
                        }

    print("Phase 1: property checks (valid inputs)")
    for function in checks:
        status = "FAIL" if function in failures else "PASS"
        print(f"  {status} {function}")
    return list(failures.values()), list(checks)


def nested(depth):
    value = {"leaf": "x"}
    for level in range(depth):
        value = {f"k{level}": value}
    return value


def random_value(rng):
    choices = [
        lambda: None,
        lambda: rng.randint(-10**6, 10**6),
        lambda: rng.random(),
        lambda: True,
        lambda: "",
        lambda: "".join(chr(rng.randint(1, 0x2FFF)) for _ in range(rng.randint(1, 40))),
        lambda: "x" * rng.randint(1000, 20000),
        lambda: b"\x00\xff",
        lambda: [],
        lambda: (),
        lambda: tuple(random_scalar(rng) for _ in range(rng.randint(1, 5))),
        lambda: [random_scalar(rng) for _ in range(rng.randint(1, 5))],
        lambda: {random_scalar(rng): random_scalar(rng) for _ in range(rng.randint(1, 5))},
        lambda: {"kind": random_scalar(rng), "metadata": random_scalar(rng)},
        lambda: nested(rng.choice([5, 50, 2000])),
    ]
    return rng.choice(choices)()


def describe(value):
    try:
        return repr(value)[:300]
    except RecursionError:
        return f"<{type(value).__name__} nested too deep to print>"


def random_scalar(rng):
    return rng.choice([None, 0, -1, 3.5, "", "a", "name", "kind", True])


BROKEN_YAML = [
    "",
    "   \n\n",
    ": : :\n\t- [",
    "key: [unclosed",
    "a: b\n  c: d\n e: f",
    "---\n---\n---\n",
    "- just\n- a\n- list\n",
    "!!python/object:os.system 'echo hi'",
    "kind: Pod\nmetadata: null\nspec: 7\n",
    "\x00\x01\x02 binary junk",
    "{{ .Values.image.tag }}\nkind: {{ .Chart.Name }}",
    "a: &x [*x]",
]


def random_yaml_text(rng):
    if rng.random() < 0.5:
        return rng.choice(BROKEN_YAML)
    return "".join(rng.choice(" :-[]{}#&*!|>'\"\n\tabckind") for _ in range(rng.randint(0, 200)))


def robustness_fuzz(rng):
    bugs = {}

    def attempt(function, call, describe):
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                call()
        except Exception as error:
            record(function, error, describe)

    def record(function, error, describe):
        frames = [f for f in traceback.extract_tb(error.__traceback__)
                  if Path(f.filename).resolve().parent == SLIKUBE_DIR]
        own = [f for f in frames if f.name == function] or frames
        location = f"{Path(own[-1].filename).name}:{own[-1].lineno}" if own else "?"
        key = (function, type(error).__name__, location)
        if key not in bugs:
            bugs[key] = {
                "phase": "robustness",
                "function": function,
                "exception": type(error).__name__,
                "message": str(error)[:200],
                "location": location,
                "input": describe[:300],
            }

    with TemporaryDirectory() as directory:
        root = Path(directory)
        empty_dir = root / "empty"
        empty_dir.mkdir()

        for case in range(1, ROBUSTNESS_ROUNDS + 1):
            value = random_value(rng)
            other = random_value(rng)
            shown = describe(value)
            pair = f"{shown}, {describe(other)}"[:300]

            text = random_yaml_text(rng)
            yaml_file = root / f"case{case}.yaml"
            yaml_file.write_text(text, encoding="utf-8", errors="replace")
            file_desc = f"file containing {text!r}"

            for name, fn in [
                ("readYAMLAsStr", parser.readYAMLAsStr),
                ("checkParseError", parser.checkParseError),
                ("loadMultiYAML", parser.loadMultiYAML),
                ("checkIfValidK8SYaml", parser.checkIfValidK8SYaml),
            ]:
                attempt(name, lambda: fn(str(yaml_file)), file_desc)
            yaml_file.unlink()

            attempt("checkIfWeirdYAML", lambda: parser.checkIfWeirdYAML(value), shown)
            attempt("keyMiner", lambda: parser.keyMiner(value, other), pair)
            attempt("getKeyRecursively", lambda: parser.getKeyRecursively(value, []), shown)
            attempt("getValuesRecursively", lambda: list(parser.getValuesRecursively(value)), shown)
            attempt("getValsFromKey", lambda: parser.getValsFromKey(value, other, []), pair)
            attempt("getSingleDict4MultiDocs", lambda: parser.getSingleDict4MultiDocs(value), shown)
            attempt("constructHelmString", lambda: graphtaint.constructHelmString(value), shown)

            if case % 30 == 1:
                scan_dir = root / f"scan{case}"
                scan_dir.mkdir()
                if rng.random() < 0.5:
                    (scan_dir / "broken.yaml").write_text(random_yaml_text(rng), encoding="utf-8")
                attempt("runScanner", lambda: scanner.runScanner(str(scan_dir)),
                        f"directory with {len(list(scan_dir.iterdir()))} YAML file(s)")
                attempt("runScanner", lambda: scanner.runScanner(str(empty_dir)), "empty directory")

    print("\nPhase 2: robustness (malformed inputs)")
    if not bugs:
        print("  no crashes found")
    for bug in bugs.values():
        print(f"  BUG {bug['function']}: {bug['exception']} at {bug['location']}")
        print(f"      {bug['message'][:120]}")
        print(f"      input: {bug['input'][:120]}")
    return list(bugs.values())


def main():
    strict = "--strict" in sys.argv
    rng = random.Random(SEED)

    property_failures, functions = property_fuzz(rng)
    robustness_bugs = robustness_fuzz(rng)

    report = {
        "seed": SEED,
        "property_rounds": PROPERTY_ROUNDS,
        "robustness_rounds": ROBUSTNESS_ROUNDS,
        "functions_fuzzed": functions + ["runScanner", "constructHelmString"],
        "property_failures": property_failures,
        "robustness_bugs": robustness_bugs,
    }
    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    total = len(property_failures) + len(robustness_bugs)
    print(f"\n{len(functions) - len(property_failures)}/{len(functions)} methods passed property checks")
    print(f"{len(robustness_bugs)} distinct crash(es) found with malformed inputs")
    print(f"Report written to {REPORT_FILE.name}")
    return 1 if (strict and total) else 0


if __name__ == "__main__":
    raise SystemExit(main())
