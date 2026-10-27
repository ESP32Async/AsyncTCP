#!/usr/bin/env python3
"""Check that every test function is actually registered to run.

Unity is told what to run by explicit RUN_TEST lines, so a test that is written but
never listed is silently dead. This fails the build instead.

It also checks that each test is named for its file: tests in test_foo.cpp are
test_foo_*.

    python3 test/check_registration.py
"""

import pathlib
import re
import sys

NATIVE = pathlib.Path(__file__).parent / "test_native"
TESTS = NATIVE / "tests"
MAIN = NATIVE / "test_main.cpp"

DEFINED = re.compile(r"^\s*static\s+void\s+(test_\w+)\s*\(\s*void\s*\)", re.M)
REGISTERED = re.compile(r"^\s*RUN_TEST\s*\(\s*(test_\w+)\s*\)", re.M)
ENTRY = re.compile(r"^\s*void\s+(run_\w+_tests)\s*\(\s*void\s*\)\s*\{", re.M)
CALLED = re.compile(r"^\s*(run_\w+_tests)\s*\(\s*\)\s*;", re.M)


def main() -> int:
    problems = []
    total = 0

    for path in sorted(TESTS.glob("*.cpp")):
        text = path.read_text()
        defined = set(DEFINED.findall(text))
        registered = REGISTERED.findall(text)
        total += len(defined)

        for name in sorted(defined - set(registered)):
            problems.append(f"{path}: {name} is never run -- add RUN_TEST({name})")
        for name in sorted(set(registered) - defined):
            problems.append(f"{path}: RUN_TEST({name}) has no such test")
        for name in sorted({n for n in registered if registered.count(n) > 1}):
            problems.append(f"{path}: {name} is run more than once")

        prefix = path.stem + "_"
        for name in sorted(defined):
            if not name.startswith(prefix):
                problems.append(f"{path}: {name} should be named {prefix}*")

    # A file can be fully self-consistent and still never be reached, if main() does
    # not call its entry point.
    main_text = MAIN.read_text()
    called = set(CALLED.findall(main_text))
    for path in sorted(TESTS.glob("*.cpp")):
        entries = ENTRY.findall(path.read_text())
        if not entries:
            problems.append(f"{path}: no run_*_tests() entry point")
        for entry in entries:
            if entry not in called:
                problems.append(f"{path}: {entry}() is never called from {MAIN.name}")

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1

    print(f"{total} tests, all registered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
