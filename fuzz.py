import json
import random
from pathlib import Path
from tempfile import TemporaryDirectory

import parser


def find_names(document):
    names = []
    parser.getValsFromKey(document, "name", names)
    return names


def collect_keys(document):
    keys = []
    parser.getKeyRecursively(document, keys)
    return [entry[0] for entry in keys]


def main():
    seed = 5710
    rounds = 200
    rng = random.Random(seed)
    failures = set()

    with TemporaryDirectory() as directory:
        path = Path(directory) / "configmap.yaml"

        for case in range(1, rounds + 1):
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
                    if not check():
                        raise AssertionError("Unexpected result")
                except Exception as error:
                    if function not in failures:
                        failures.add(function)
                        print(
                            f"FAIL {function}, seed {seed}, case {case}: "
                            f"{type(error).__name__}: {error}\n"
                            f"  Input: {source}"
                        )

    for function in checks:
        status = "FAIL" if function in failures else "PASS"
        print(f"{status} {function}")
    print(f"{len(checks) - len(failures)}/{len(checks)} functions passed all rounds")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())